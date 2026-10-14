#!/usr/bin/env python3
"""
purview_connector.py — Microsoft Purview eDiscovery & DSPM for AI Integration
for Google Cloud Gemini Enterprise & NotebookLM Enterprise.

Pushes harvested Gemini Enterprise conversation turns, reasoning traces, and
binary attachments (USER_PROVIDED uploads + AI_GENERATED PDFs, images, slides,
and NotebookLM Studio artifacts) into Microsoft Purview via two native Graph APIs:

1. Track 1 — Purview eDiscovery Custodian Substrate Ingestion (Exchange Online):
   - Writes an immutable, deduplicated compliance message per turn into the
     custodian's Exchange Online mailbox folder (`Gemini Enterprise eDiscovery`)
     with MAPI `PidTagMessageClass` (`0x001A`), searchable `internetMessageHeaders`
     (`X-GE-Session-ID`, `X-GE-Engine-ID`, `X-GE-Turn-Index`), a structured HTML
     Legal Brief body, and native binary `#microsoft.graph.fileAttachment` payloads.
   - Directly searchable and collectible in Microsoft Purview eDiscovery
     (Standard & Premium), Custodian Legal Holds, KQL Content Search, and
     Review Sets.

2. Track 2 — Microsoft Purview DSPM for AI & Audit (`processContent` API):
   - Calls `POST /v1.0/users/{upn}/dataSecurityAndGovernance/processContent`
     with `#microsoft.graph.processConversationMetadata` for both the user prompt
     (`uploadText`) and model response (`downloadText`), populating Purview
     DSPM for AI Activity Explorer, Purview Audit (`AIAppInteraction`), and
     Communication Compliance.
"""

import argparse
import base64
import html
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any, Optional

MS_TENANT_ID = os.environ.get("MS_TENANT_ID", "")
MS_CLIENT_ID = os.environ.get("MS_CLIENT_ID", "")
MS_CLIENT_SECRET = os.environ.get("MS_CLIENT_SECRET", "")
MS_REFRESH_TOKEN = os.environ.get("MS_REFRESH_TOKEN", "")
PURVIEW_FOLDER_NAME = os.environ.get("PURVIEW_EDISCOVERY_FOLDER", "Gemini Enterprise eDiscovery")
PURVIEW_FALLBACK_UPN = os.environ.get("PURVIEW_FALLBACK_UPN", "")
PURVIEW_TARGET_CUSTODIAN_UPN = os.environ.get("PURVIEW_TARGET_CUSTODIAN_UPN", "")
PURVIEW_MESSAGE_CLASS = os.environ.get(
    "PURVIEW_MESSAGE_CLASS",
    "IPM.Note.Google.GeminiEnterprise",
)

SSL_CTX = (
    ssl.create_default_context(cafile="/etc/ssl/cert.pem")
    if os.path.exists("/etc/ssl/cert.pem")
    else ssl.create_default_context()
)

_GRAPH_TOKEN_CACHE: dict[str, tuple[str, float]] = {}
_FOLDER_ID_CACHE: dict[str, str] = {}
TOKEN_CACHE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".purview_token_cache.json")
FIRST_PARTY_OFFICE_CLIENT_ID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"


def load_cached_credentials() -> dict[str, str]:
    if os.path.exists(TOKEN_CACHE_FILE):
        try:
            with open(TOKEN_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def is_purview_configured() -> bool:
    """Returns True if Microsoft Entra ID / Purview Graph credentials are set."""
    if MS_TENANT_ID and MS_CLIENT_ID and (MS_CLIENT_SECRET or MS_REFRESH_TOKEN):
        return True
    cached = load_cached_credentials()
    return bool(cached.get("tenant_id") and cached.get("client_id") and cached.get("refresh_token"))


def run_device_code_login(tenant_id: str, client_id: str = FIRST_PARTY_OFFICE_CLIENT_ID) -> str:
    """Runs OAuth 2.0 Device Code flow against Microsoft Entra ID and caches the refresh_token."""
    dc_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/devicecode"
    scope = "https://graph.microsoft.com/.default offline_access"
    req = urllib.request.Request(
        dc_url,
        data=urllib.parse.urlencode({"client_id": client_id, "scope": scope}).encode("utf-8"),
        method="POST",
    )
    with urllib.request.urlopen(req, context=SSL_CTX, timeout=15) as resp:
        dc_data = json.loads(resp.read().decode("utf-8"))

    print("\n======================================================================")
    print("MICROSOFT ENTRA ID / PURVIEW DEVICE LOGIN")
    print("======================================================================")
    print(f"  {dc_data.get('message')}")
    print("======================================================================\n", flush=True)

    token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    interval = int(dc_data.get("interval", 5))
    expires_at = time.time() + int(dc_data.get("expires_in", 900))
    device_code = dc_data["device_code"]

    while time.time() < expires_at:
        time.sleep(interval)
        poll_form = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": device_code,
        }).encode("utf-8")
        try:
            with urllib.request.urlopen(
                urllib.request.Request(token_url, data=poll_form, method="POST"),
                context=SSL_CTX,
                timeout=15,
            ) as p_resp:
                tok_payload = json.loads(p_resp.read().decode("utf-8"))
                access_token = tok_payload["access_token"]
                refresh_token = tok_payload.get("refresh_token", "")
                if refresh_token:
                    with open(TOKEN_CACHE_FILE, "w", encoding="utf-8") as f:
                        json.dump(
                            {
                                "tenant_id": tenant_id,
                                "client_id": client_id,
                                "refresh_token": refresh_token,
                            },
                            f,
                        )
                    os.chmod(TOKEN_CACHE_FILE, 0o600)
                print("[+] Microsoft Entra ID / Purview authentication succeeded!", flush=True)
                return access_token
        except urllib.error.HTTPError as e:
            err_json = json.loads(e.read().decode("utf-8", errors="ignore") or "{}")
            err_code = err_json.get("error", "")
            if err_code in ("authorization_pending", "slow_down"):
                continue
            raise RuntimeError(f"Device code login failed: {err_json}") from e

    raise TimeoutError("Device code login timed out.")


def get_graph_access_token(
    tenant_id: str = "",
    client_id: str = "",
    client_secret: str = "",
    refresh_token: str = "",
) -> str:
    """Obtains a Microsoft Graph OAuth 2.0 Bearer token via client_credentials or refresh_token."""
    cached_creds = load_cached_credentials()
    t_id = tenant_id or MS_TENANT_ID or cached_creds.get("tenant_id", "")
    c_id = client_id or MS_CLIENT_ID or cached_creds.get("client_id", "")
    c_sec = client_secret or MS_CLIENT_SECRET
    r_tok = refresh_token or MS_REFRESH_TOKEN or cached_creds.get("refresh_token", "")

    if not t_id or not c_id:
        raise RuntimeError("MS_TENANT_ID and MS_CLIENT_ID are required for Microsoft Purview integration.")

    cache_key = f"{t_id}:{c_id}:{'refresh' if r_tok else 'app'}"
    now = time.time()
    cached = _GRAPH_TOKEN_CACHE.get(cache_key)
    if cached and cached[1] > now + 60:
        return cached[0]

    token_url = f"https://login.microsoftonline.com/{t_id}/oauth2/v2.0/token"
    if r_tok:
        form = {
            "grant_type": "refresh_token",
            "client_id": c_id,
            "refresh_token": r_tok,
            "scope": "https://graph.microsoft.com/.default offline_access",
        }
        if c_sec:
            form["client_secret"] = c_sec
    else:
        form = {
            "grant_type": "client_credentials",
            "client_id": c_id,
            "client_secret": c_sec,
            "scope": "https://graph.microsoft.com/.default",
        }

    data = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(token_url, data=data, method="POST")
    with urllib.request.urlopen(req, context=SSL_CTX, timeout=20) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
        access_token = payload["access_token"]
        expires_in = float(payload.get("expires_in", 3599))
        if payload.get("refresh_token") and os.path.exists(TOKEN_CACHE_FILE):
            try:
                with open(TOKEN_CACHE_FILE, "w", encoding="utf-8") as f:
                    json.dump(
                        {"tenant_id": t_id, "client_id": c_id, "refresh_token": payload["refresh_token"]},
                        f,
                    )
            except Exception:
                pass
        _GRAPH_TOKEN_CACHE[cache_key] = (access_token, now + expires_in)
        return access_token


def graph_api_request(
    method: str,
    url: str,
    graph_token: str,
    payload: Optional[dict] = None,
) -> dict:
    """Executes an HTTPS request against Microsoft Graph v1.0 with automatic 429 retry."""
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {
        "Authorization": f"Bearer {graph_token}",
        "Accept": "application/json",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"

    for attempt in range(5):
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, context=SSL_CTX, timeout=30) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < 4:
                wait_sec = float(e.headers.get("Retry-After") or (2 ** attempt))
                time.sleep(min(wait_sec, 10.0))
                continue
            raise
    return {}


_UPN_RESOLUTION_CACHE: dict[str, str] = {}


def resolve_custodian_upn(user_iam_principal: str, graph_token: str = "") -> str:
    """
    Extracts the Microsoft Entra ID UPN from a Google Cloud WIF principal.
    Supports both email subjects (`user@domain.com`) and Entra Object ID GUID
    subjects (`00000000-0000-0000-0000-000000000000`), resolving GUIDs via Graph.
    If `PURVIEW_TARGET_CUSTODIAN_UPN` is set, routes to that custodian mailbox.
    """
    if PURVIEW_TARGET_CUSTODIAN_UPN:
        return PURVIEW_TARGET_CUSTODIAN_UPN.strip()
    if not user_iam_principal:
        return PURVIEW_FALLBACK_UPN

    sub = user_iam_principal.strip()
    if "/subject/" in sub:
        sub = sub.split("/subject/", 1)[1].strip()
    elif ":" in sub and "@" in sub:
        sub = sub.split(":", 1)[1].strip()

    if "@" in sub:
        return sub

    if sub in _UPN_RESOLUTION_CACHE:
        return _UPN_RESOLUTION_CACHE[sub]

    # Check if `sub` is an Entra Object ID UUID (e.g. 00000000-0000-0000-0000-000000000000)
    if graph_token and len(sub) == 36 and sub.count("-") == 4:
        # 1. Fast-path: check if the JWT token itself belongs to this `oid`
        try:
            jwt_parts = graph_token.split(".")
            if len(jwt_parts) >= 2:
                jwt_claims = json.loads(base64.urlsafe_b64decode(jwt_parts[1] + "===").decode("utf-8"))
                if str(jwt_claims.get("oid") or "").lower() == sub.lower():
                    jwt_upn = str(jwt_claims.get("upn") or jwt_claims.get("unique_name") or "").strip()
                    if jwt_upn and "@" in jwt_upn:
                        _UPN_RESOLUTION_CACHE[sub] = jwt_upn
                        return jwt_upn
        except Exception:
            pass

        # 2. Fallback: query Microsoft Graph /v1.0/users/{uuid}
        try:
            u_info = graph_api_request(
                "GET",
                f"https://graph.microsoft.com/v1.0/users/{urllib.parse.quote(sub)}?$select=userPrincipalName,mail",
                graph_token,
            )
            upn = str(u_info.get("userPrincipalName") or u_info.get("mail") or "").strip()
            if upn and "@" in upn:
                _UPN_RESOLUTION_CACHE[sub] = upn
                return upn
        except Exception:
            pass

    return PURVIEW_FALLBACK_UPN


def ensure_compliance_mail_folder(
    custodian_upn: str,
    graph_token: str,
    folder_name: str = PURVIEW_FOLDER_NAME,
) -> str:
    """
    Ensures the dedicated `Gemini Enterprise eDiscovery` folder exists in the
    custodian's Exchange Online mailbox and returns its Graph folder ID.
    """
    cache_key = f"{custodian_upn.lower()}::{folder_name}"
    if cache_key in _FOLDER_ID_CACHE:
        return _FOLDER_ID_CACHE[cache_key]

    encoded_upn = urllib.parse.quote(custodian_upn, safe="")
    escaped_name = folder_name.replace("'", "''")
    filter_q = urllib.parse.quote(f"displayName eq '{escaped_name}'")
    list_url = f"https://graph.microsoft.com/v1.0/users/{encoded_upn}/mailFolders?$filter={filter_q}&$select=id,displayName"

    res = graph_api_request("GET", list_url, graph_token)
    folders = res.get("value", [])
    if folders:
        folder_id = folders[0]["id"]
        _FOLDER_ID_CACHE[cache_key] = folder_id
        return folder_id

    create_url = f"https://graph.microsoft.com/v1.0/users/{encoded_upn}/mailFolders"
    created = graph_api_request(
        "POST",
        create_url,
        graph_token,
        {"displayName": folder_name, "isHidden": False},
    )
    folder_id = created["id"]
    _FOLDER_ID_CACHE[cache_key] = folder_id
    return folder_id


def check_turn_already_ingested(
    custodian_upn: str,
    folder_id: str,
    internet_message_id: str,
    graph_token: str,
) -> Optional[str]:
    """Checks if a compliance item with `internet_message_id` already exists in the folder."""
    encoded_upn = urllib.parse.quote(custodian_upn, safe="")
    escaped_mid = internet_message_id.replace("'", "''")
    filter_q = urllib.parse.quote(f"internetMessageId eq '{escaped_mid}'")
    url = (
        f"https://graph.microsoft.com/v1.0/users/{encoded_upn}/mailFolders/{folder_id}/messages"
        f"?$filter={filter_q}&$select=id,subject,internetMessageId&$top=1"
    )
    try:
        res = graph_api_request("GET", url, graph_token)
        items = res.get("value", [])
        if items:
            return items[0]["id"]
    except Exception:
        pass
    return None


def build_legal_brief_html(turn_row: dict[str, Any]) -> str:
    """Formats a Gemini Enterprise / NotebookLM turn into a self-contained HTML Legal Brief for Purview Review Sets."""
    engine_id = html.escape(str(turn_row.get("engine_id") or "gemini-enterprise"))
    session_id = html.escape(str(turn_row.get("session_id") or ""))
    session_title = html.escape(str(turn_row.get("session_display_name") or session_id))
    turn_idx = html.escape(str(turn_row.get("turn_index") or 1))
    event_ts = html.escape(str(turn_row.get("event_timestamp") or ""))
    principal = html.escape(str(turn_row.get("user_iam_principal") or ""))
    model_name = html.escape(str(turn_row.get("model_name") or "Gemini Enterprise Assistant"))
    transcript_uri = html.escape(str(turn_row.get("session_transcript_gcs_uri") or ""))

    prompt_html = html.escape(str(turn_row.get("prompt_text") or "")).replace("\n", "<br/>")
    thought_raw = str(turn_row.get("thought_text") or "").strip()
    thought_html = html.escape(thought_raw).replace("\n", "<br/>")
    response_html = html.escape(str(turn_row.get("response_text") or "")).replace("\n", "<br/>")

    files = turn_row.get("files") or []
    file_rows_html = ""
    for f in files:
        if not isinstance(f, dict):
            continue
        f_src = html.escape(str(f.get("file_source") or ""))
        f_name = html.escape(str(f.get("file_name") or ""))
        f_mime = html.escape(str(f.get("mime_type") or ""))
        f_size = html.escape(str(f.get("byte_size") or 0))
        f_sha = html.escape(str(f.get("sha256") or ""))
        f_crc = html.escape(str(f.get("crc32c") or ""))
        f_gcs = html.escape(str(f.get("gcs_uri") or ""))
        file_rows_html += f"""
        <tr>
          <td style="padding:6px 8px;border:1px solid #cbd5e1;font-family:monospace;font-size:11px;">{f_src}</td>
          <td style="padding:6px 8px;border:1px solid #cbd5e1;font-weight:600;">{f_name}</td>
          <td style="padding:6px 8px;border:1px solid #cbd5e1;font-family:monospace;font-size:11px;">{f_mime}</td>
          <td style="padding:6px 8px;border:1px solid #cbd5e1;text-align:right;">{f_size} B</td>
          <td style="padding:6px 8px;border:1px solid #cbd5e1;font-family:monospace;font-size:10px;word-break:break-all;">
            <div><b>SHA-256:</b> {f_sha}</div>
            <div><b>CRC32C:</b> {f_crc}</div>
            <div><b>GCS URI:</b> {f_gcs}</div>
          </td>
        </tr>
        """

    files_section = ""
    if file_rows_html:
        files_section = f"""
        <h3 style="color:#0f172a;font-size:14px;margin-top:20px;border-bottom:1px solid #e2e8f0;padding-bottom:4px;">
          4. Cryptographic Chain-of-Custody Artifact Manifest ({len(files)} Attached File(s))
        </h3>
        <table style="width:100%;border-collapse:collapse;font-size:12px;margin-top:8px;">
          <thead>
            <tr style="background:#f1f5f9;color:#334155;text-align:left;">
              <th style="padding:6px 8px;border:1px solid #cbd5e1;">Source</th>
              <th style="padding:6px 8px;border:1px solid #cbd5e1;">File Name</th>
              <th style="padding:6px 8px;border:1px solid #cbd5e1;">MIME Type</th>
              <th style="padding:6px 8px;border:1px solid #cbd5e1;">Size</th>
              <th style="padding:6px 8px;border:1px solid #cbd5e1;">Integrity Checksums &amp; Immutable Archive URI</th>
            </tr>
          </thead>
          <tbody>
            {file_rows_html}
          </tbody>
        </table>
        """

    thought_section = ""
    if thought_raw:
        thought_section = f"""
        <h3 style="color:#4338ca;font-size:14px;margin-top:20px;border-bottom:1px solid #e0e7ff;padding-bottom:4px;">
          2. Model Internal Reasoning / Chain-of-Thought Trace (THOUGHT_TEXT)
        </h3>
        <div style="background:#eef2ff;border-left:4px solid #6366f1;padding:12px;font-family:monospace;font-size:12px;color:#1e1b4b;line-height:1.5;">
          {thought_html}
        </div>
        """

    return f"""<!DOCTYPE html>
<html>
<body style="font-family:'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1e293b;line-height:1.6;max-width:920px;margin:0 auto;padding:16px;">
  <div style="border:1px solid #cbd5e1;border-radius:6px;overflow:hidden;">
    <div style="background:#0f172a;color:#ffffff;padding:12px 16px;">
      <div style="font-size:11px;text-transform:uppercase;letter-spacing:1px;color:#94a3b8;">
        Google Cloud Gemini Enterprise · Microsoft Purview eDiscovery Record
      </div>
      <div style="font-size:16px;font-weight:700;margin-top:2px;">
        {session_title} — Turn #{turn_idx}
      </div>
    </div>
    <div style="padding:16px;">
      <table style="width:100%;border-collapse:collapse;font-size:12px;background:#f8fafc;border:1px solid #e2e8f0;margin-bottom:16px;">
        <tr>
          <td style="padding:6px 10px;font-weight:600;color:#475569;width:180px;">Event Timestamp (UTC):</td>
          <td style="padding:6px 10px;font-family:monospace;">{event_ts}</td>
          <td style="padding:6px 10px;font-weight:600;color:#475569;width:160px;">Engine / App ID:</td>
          <td style="padding:6px 10px;font-family:monospace;">{engine_id}</td>
        </tr>
        <tr>
          <td style="padding:6px 10px;font-weight:600;color:#475569;">Session / Notebook ID:</td>
          <td style="padding:6px 10px;font-family:monospace;">{session_id}</td>
          <td style="padding:6px 10px;font-weight:600;color:#475569;">Turn Index:</td>
          <td style="padding:6px 10px;font-family:monospace;">{turn_idx}</td>
        </tr>
        <tr>
          <td style="padding:6px 10px;font-weight:600;color:#475569;">Federated WIF Principal:</td>
          <td style="padding:6px 10px;font-family:monospace;" colspan="3">{principal}</td>
        </tr>
        <tr>
          <td style="padding:6px 10px;font-weight:600;color:#475569;">Model / Agent Identity:</td>
          <td style="padding:6px 10px;font-family:monospace;" colspan="3">{model_name}</td>
        </tr>
        <tr>
          <td style="padding:6px 10px;font-weight:600;color:#475569;">GCS WORM Transcript:</td>
          <td style="padding:6px 10px;font-family:monospace;" colspan="3">{transcript_uri}</td>
        </tr>
      </table>

      <h3 style="color:#0f172a;font-size:14px;margin-top:16px;border-bottom:1px solid #e2e8f0;padding-bottom:4px;">
        1. Custodian Prompt / Input (PROMPT_TEXT)
      </h3>
      <div style="background:#f8fafc;border-left:4px solid #0284c7;padding:12px;font-size:13px;color:#0f172a;">
        {prompt_html}
      </div>

      {thought_section}

      <h3 style="color:#0f172a;font-size:14px;margin-top:20px;border-bottom:1px solid #e2e8f0;padding-bottom:4px;">
        3. Gemini Enterprise Response / Output (RESPONSE_TEXT)
      </h3>
      <div style="background:#ffffff;border:1px solid #e2e8f0;border-left:4px solid #10b981;padding:12px;font-size:13px;color:#0f172a;">
        {response_html}
      </div>

      {files_section}
    </div>
  </div>
</body>
</html>"""


def download_gcs_bytes(gcs_uri: str, gcp_token: str, project_id: str) -> bytes:
    """Downloads raw binary bytes from `gs://bucket/object` for attachment to Purview eDiscovery items."""
    if not gcs_uri.startswith("gs://"):
        raise ValueError(f"Invalid GCS URI: {gcs_uri}")
    bucket, obj_path = gcs_uri[5:].split("/", 1)
    encoded_obj = urllib.parse.quote(obj_path, safe="")
    url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/{encoded_obj}?alt=media"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {gcp_token}",
            "X-Goog-User-Project": project_id,
        },
    )
    with urllib.request.urlopen(req, context=SSL_CTX, timeout=30) as resp:
        return resp.read()


def push_turn_to_purview_ediscovery_mailbox(
    turn_row: dict[str, Any],
    graph_token: str,
    gcp_token: str = "",
    project_id: str = "",
    folder_name: str = PURVIEW_FOLDER_NAME,
) -> dict[str, Any]:
    """
    Track 1: Writes a conversation turn and its binary attachments (`USER_PROVIDED`,
    `AI_GENERATED`, `NOTEBOOK_STUDIO_ARTIFACT`) into the custodian's Exchange Online
    `Gemini Enterprise eDiscovery` compliance folder so it is indexed by Microsoft
    Purview eDiscovery Content Search, Custodian Holds, and Review Sets.
    """
    custodian_upn = resolve_custodian_upn(str(turn_row.get("user_iam_principal") or ""), graph_token=graph_token)
    if not custodian_upn:
        return {"status": "skipped", "reason": "No resolves custodian UPN"}

    engine_id = str(turn_row.get("engine_id") or "gemini-enterprise")
    session_id = str(turn_row.get("session_id") or "unknown")
    turn_idx = int(turn_row.get("turn_index") or 1)
    session_title = str(turn_row.get("session_display_name") or session_id)[:100]
    event_ts = str(turn_row.get("event_timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    if " " in event_ts and "T" not in event_ts:
        event_ts = event_ts.replace(" ", "T").replace(" UTC", "Z")

    internet_msg_id = f"<ge-ediscovery-{engine_id}-{session_id}-turn-{turn_idx}@gemini.cloud.google.com>"
    folder_id = ensure_compliance_mail_folder(custodian_upn, graph_token, folder_name=folder_name)

    existing_id = check_turn_already_ingested(custodian_upn, folder_id, internet_msg_id, graph_token)
    if existing_id:
        return {
            "status": "already_exists",
            "message_id": existing_id,
            "custodian_upn": custodian_upn,
            "internet_message_id": internet_msg_id,
        }

    # Build binary `#microsoft.graph.fileAttachment` payloads (for files <= 3 MB inline)
    attachments: list[dict[str, Any]] = []
    files = turn_row.get("files") or []
    for f in files:
        if not isinstance(f, dict):
            continue
        f_gcs = str(f.get("gcs_uri") or "")
        f_name = str(f.get("file_name") or f.get("file_id") or "artifact.bin")
        f_mime = str(f.get("mime_type") or "application/octet-stream")
        f_bytes: Optional[bytes] = f.get("_raw_bytes")
        if f_bytes is None and f_gcs.startswith("gs://") and gcp_token and (
            not f_gcs.endswith("/notebook_archive.json")
        ):
            try:
                f_bytes = download_gcs_bytes(f_gcs, gcp_token, project_id)
            except Exception as e:
                print(f"  [!] Could not fetch binary {f_gcs} for Purview attachment: {e}")
        if f_bytes and len(f_bytes) <= 3 * 1024 * 1024:
            attachments.append({
                "@odata.type": "#microsoft.graph.fileAttachment",
                "name": f_name,
                "contentType": f_mime,
                "contentBytes": base64.b64encode(f_bytes).decode("ascii"),
            })

    # Custom headers (Max 5 per message creation in Graph API)
    headers_list = [
        {"name": "X-GE-Engine-ID", "value": engine_id[:200]},
        {"name": "X-GE-Session-ID", "value": session_id[:200]},
        {"name": "X-GE-Turn-Index", "value": str(turn_idx)},
        {"name": "X-GE-Artifact-Count", "value": str(len(files))},
        {"name": "X-GE-Archive-URI", "value": str(turn_row.get("session_transcript_gcs_uri") or "")[:200]},
    ]

    msg_payload: dict[str, Any] = {
        "subject": f"[Gemini Enterprise eDiscovery] {session_title} (Session {session_id} · Turn #{turn_idx})",
        "importance": "normal",
        "isDraft": False,
        "internetMessageId": internet_msg_id,
        "internetMessageHeaders": headers_list,
        "from": {
            "emailAddress": {
                "name": f"{custodian_upn.split('@')[0]} (via Gemini Enterprise)",
                "address": custodian_upn,
            }
        },
        "sender": {
            "emailAddress": {
                "name": f"Google Gemini Enterprise ({engine_id})",
                "address": custodian_upn,
            }
        },
        "toRecipients": [
            {
                "emailAddress": {
                    "name": custodian_upn,
                    "address": custodian_upn,
                }
            }
        ],
        "body": {
            "contentType": "HTML",
            "content": build_legal_brief_html(turn_row),
        },
        "singleValueExtendedProperties": [
            # PidTagMessageClass (0x001A) -> identifies item class in Purview eDiscovery
            {
                "id": "String 0x001A",
                "value": PURVIEW_MESSAGE_CLASS,
            },
            # PR_MESSAGE_FLAGS (0x0E07) = 1 (MSGFLAG_READ, non-draft received compliance item)
            {
                "id": "Integer 0x0E07",
                "value": "1",
            },
            # PR_CLIENT_SUBMIT_TIME (0x0039) & PR_MESSAGE_DELIVERY_TIME (0x0E06)
            {
                "id": "SystemTime 0x0039",
                "value": event_ts,
            },
            {
                "id": "SystemTime 0x0E06",
                "value": event_ts,
            },
        ],
    }
    if attachments:
        msg_payload["attachments"] = attachments

    encoded_upn = urllib.parse.quote(custodian_upn, safe="")
    create_msg_url = f"https://graph.microsoft.com/v1.0/users/{encoded_upn}/mailFolders/{folder_id}/messages"
    created = graph_api_request("POST", create_msg_url, graph_token, msg_payload)
    return {
        "status": "created",
        "message_id": created.get("id"),
        "custodian_upn": custodian_upn,
        "folder_id": folder_id,
        "internet_message_id": internet_msg_id,
        "attachments_count": len(attachments),
    }


def push_turn_to_purview_process_content(
    turn_row: dict[str, Any],
    graph_token: str,
    app_client_id: str = "",
) -> dict[str, Any]:
    """
    Track 2: Pushes the prompt (`uploadText`) and model response (`downloadText`)
    to Microsoft Graph `POST /v1.0/users/{upn}/dataSecurityAndGovernance/processContent`
    (`#microsoft.graph.processConversationMetadata`) for Purview DSPM for AI,
    Purview Audit (`AIAppInteraction`), and DLP evaluation.
    """
    custodian_upn = resolve_custodian_upn(str(turn_row.get("user_iam_principal") or ""), graph_token=graph_token)
    if not custodian_upn:
        return {"status": "skipped", "reason": "No resolved custodian UPN"}

    engine_id = str(turn_row.get("engine_id") or "gemini-enterprise")
    session_id = str(turn_row.get("session_id") or str(uuid.uuid4()))
    turn_idx = int(turn_row.get("turn_index") or 1)
    event_ts = str(turn_row.get("event_timestamp") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    if " " in event_ts and "T" not in event_ts:
        event_ts = event_ts.replace(" ", "T").replace(" UTC", "Z")

    prompt_text = str(turn_row.get("prompt_text") or "")
    response_text = str(turn_row.get("response_text") or "")
    files = turn_row.get("files") or []
    accessed_resources = []
    for f in files:
        if not isinstance(f, dict):
            continue
        accessed_resources.append({
            "identifier": str(f.get("file_id") or f.get("file_name") or "artifact"),
            "name": str(f.get("file_name") or "artifact"),
            "url": str(f.get("console_url") or f.get("gcs_uri") or ""),
            "accessType": "write" if f.get("file_source") == "AI_GENERATED" else "read",
            "status": "success",
            "isCrossPromptInjectionDetected": False,
        })

    encoded_upn = urllib.parse.quote(custodian_upn, safe="")
    url = f"https://graph.microsoft.com/v1.0/users/{encoded_upn}/dataSecurityAndGovernance/processContent"
    c_id = app_client_id or MS_CLIENT_ID or "00000000-0000-0000-0000-000000000000"

    results = {}
    for idx, (activity, text_val, label) in enumerate([
        ("uploadText", prompt_text, f"Gemini Enterprise Prompt (Turn #{turn_idx})"),
        ("downloadText", response_text, f"Gemini Enterprise Response (Turn #{turn_idx})"),
    ]):
        if not text_val:
            continue
        entry: dict[str, Any] = {
            "@odata.type": "#microsoft.graph.processConversationMetadata",
            "identifier": f"{session_id}-turn-{turn_idx}-{idx + 1}",
            "name": label,
            "correlationId": session_id,
            "sequenceNumber": turn_idx * 2 + idx,
            "isTruncated": False,
            "createdDateTime": event_ts,
            "modifiedDateTime": event_ts,
            "length": len(text_val.encode("utf-8")),
            "content": {
                "@odata.type": "#microsoft.graph.textContent",
                "data": text_val,
            },
            "agents": [
                {
                    "identifier": engine_id,
                    "name": f"Google Cloud Gemini Enterprise ({engine_id})",
                    "version": "v1",
                }
            ],
        }
        if accessed_resources and activity == "downloadText":
            entry["accessedResources_v2"] = accessed_resources

        payload = {
            "contentToProcess": {
                "contentEntries": [entry],
                "activityMetadata": {"activity": activity},
                "deviceMetadata": {
                    "ipAddress": "127.0.0.1",
                    "operatingSystemSpecifications": {
                        "operatingSystemPlatform": "Linux",
                        "operatingSystemVersion": "Google Cloud Run Harvester",
                    },
                },
                "protectedAppMetadata": {
                    "name": "Google Cloud Gemini Enterprise",
                    "version": "1.0",
                    "applicationLocation": {
                        "@odata.type": "#microsoft.graph.policyLocationApplication",
                        "value": c_id,
                    },
                },
                "integratedAppMetadata": {
                    "name": "Google Cloud Gemini Enterprise eDiscovery Harvester",
                    "version": "1.0",
                },
            }
        }
        try:
            resp = graph_api_request("POST", url, graph_token, payload)
            results[activity] = {"status": "succeeded", "policyActions": resp.get("policyActions", [])}
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")[:300]
            results[activity] = {"status": f"http_{e.code}", "detail": err_body}
        except Exception as e:
            results[activity] = {"status": "error", "detail": str(e)}

    return results


def forward_turns_to_purview(
    turns: list[dict[str, Any]],
    gcp_token: str = "",
    project_id: str = "",
    graph_token: str = "",
) -> dict[str, Any]:
    """Forwards a list of harvested turn rows to Microsoft Purview (Track 1 Mailbox + Track 2 processContent)."""
    if not graph_token:
        if not is_purview_configured():
            return {"status": "disabled", "reason": "Purview credentials not configured"}
        graph_token = get_graph_access_token()

    summary = {"total": len(turns), "mailbox_created": 0, "mailbox_existing": 0, "process_content_sent": 0, "errors": []}
    for row in turns:
        try:
            mbx_res = push_turn_to_purview_ediscovery_mailbox(
                row,
                graph_token=graph_token,
                gcp_token=gcp_token,
                project_id=project_id,
            )
            if mbx_res.get("status") == "created":
                summary["mailbox_created"] += 1
                print(
                    f"  [+] Purview eDiscovery Mailbox Item created: {mbx_res.get('custodian_upn')} "
                    f"| Session {row.get('session_id')} Turn #{row.get('turn_index')} "
                    f"| Attachments: {mbx_res.get('attachments_count', 0)}"
                )
            elif mbx_res.get("status") == "already_exists":
                summary["mailbox_existing"] += 1
                print(
                    f"  [=] Purview eDiscovery Mailbox Item already exists: {mbx_res.get('custodian_upn')} "
                    f"| Session {row.get('session_id')} Turn #{row.get('turn_index')}"
                )
        except Exception as e:
            err_msg = f"Mailbox push error for {row.get('session_id')} turn {row.get('turn_index')}: {e}"
            print(f"  [!] {err_msg}")
            summary["errors"].append(err_msg)

        try:
            pc_res = push_turn_to_purview_process_content(row, graph_token=graph_token)
            if any(v.get("status") == "succeeded" for v in pc_res.values() if isinstance(v, dict)):
                summary["process_content_sent"] += 1
        except Exception as e:
            print(f"  [!] processContent warning for {row.get('session_id')}: {e}")

    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sync harvested Gemini Enterprise turns & binary attachments to Microsoft Purview eDiscovery."
    )
    parser.add_argument("--project-id", default=os.environ.get("GCP_PROJECT_ID", ""), help="Google Cloud Project ID")
    parser.add_argument(
        "--engine-id",
        default=os.environ.get("GE_ENGINE_ID", ""),
        help="Optional Gemini Enterprise Engine ID filter (e.g. my-enterprise-engine_1234567890)",
    )
    parser.add_argument("--session-id", default="", help="Optional specific session ID to push to Purview")
    parser.add_argument("--tenant-id", default=MS_TENANT_ID, help="Microsoft Entra ID Tenant ID")
    parser.add_argument("--target-custodian-upn", default=PURVIEW_TARGET_CUSTODIAN_UPN, help="Optional target M365 custodian mailbox UPN")
    parser.add_argument("--device-login", action="store_true", help="Authenticate interactively via https://login.microsoft.com/device")
    parser.add_argument("--limit", type=int, default=25, help="Max turns to sync from BigQuery (default: 25)")
    args = parser.parse_args()

    if args.target_custodian_upn:
        PURVIEW_TARGET_CUSTODIAN_UPN = args.target_custodian_upn.strip()

    if not args.project_id:
        print("Error: --project-id (or GCP_PROJECT_ID) is required.")
        raise SystemExit(1)

    graph_tok = ""
    if args.device_login:
        if not args.tenant_id:
            print("Error: --tenant-id (or MS_TENANT_ID) is required with --device-login.")
            raise SystemExit(1)
        graph_tok = run_device_code_login(args.tenant_id)

    import subprocess
    gcp_tok = subprocess.check_output(
        ["gcloud", "auth", "print-access-token"],
        stdin=subprocess.DEVNULL,
        timeout=8,
    ).decode("utf-8").strip()

    from portal.server import run_bq_query
    where_clauses = ["1=1"]
    params = []
    if args.engine_id:
        where_clauses.append("engine_id = @engine_id")
        params.append({"name": "engine_id", "parameterType": {"type": "STRING"}, "parameterValue": {"value": args.engine_id}})
    if args.session_id:
        where_clauses.append("session_id = @session_id")
        params.append({"name": "session_id", "parameterType": {"type": "STRING"}, "parameterValue": {"value": args.session_id}})

    sql = f"""
        SELECT
          FORMAT_TIMESTAMP('%Y-%m-%dT%H:%M:%SZ', event_timestamp) AS event_timestamp,
          engine_id,
          session_id,
          session_display_name,
          turn_index,
          user_iam_principal,
          model_name,
          prompt_text,
          response_text,
          thought_text,
          session_transcript_gcs_uri,
          files
        FROM `{args.project_id}.ge_ediscovery.conversation_turns`
        WHERE {' AND '.join(where_clauses)}
        ORDER BY event_timestamp DESC
        LIMIT {int(args.limit)}
    """
    rows = run_bq_query(args.project_id, sql, params)
    print(f"[*] Fetched {len(rows)} turn(s) from {args.project_id}.ge_ediscovery.conversation_turns")
    res = forward_turns_to_purview(rows, gcp_token=gcp_tok, project_id=args.project_id, graph_token=graph_tok)
    print(json.dumps(res, indent=2))
