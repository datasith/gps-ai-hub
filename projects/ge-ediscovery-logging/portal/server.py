#!/usr/bin/env python3
"""
server.py — Self-Contained Cloud Run Backend & Static SPA Host for the
Gemini Enterprise & NotebookLM Enterprise Compliance & eDiscovery Review Portal.

Serves:
  - Compiled React 18 SPA static assets from ./dist
  - GET /api/config       -> Runtime configuration & reviewer identity
  - GET /api/logs         -> Live BigQuery `conversation_turns` + GCS notebook archives
                             transformed into Unified ComplianceDataResponse
  - GET /api/search       -> Parameterized BigQuery search across sessions & notebooks
  - GET /api/signed-url   -> Proxied media stream URL for authorized GCS archive objects
  - GET /api/media        -> Direct GCS binary streaming with HTTP Range (206 Partial Content)
                             support for HTML5 audio/video, PDF.js canvas, images, and slides
"""

import json
import mimetypes
import os
import re
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROJECT_ID = os.environ.get("GCP_PROJECT_ID", "")
BQ_DATASET = os.environ.get("BQ_DATASET", "ge_ediscovery")
BQ_TABLE = os.environ.get("BQ_TABLE", "conversation_turns")
REVIEWER_EMAIL = os.environ.get("PORTAL_REVIEWER_EMAIL", "compliance-reviewer@enterprise.internal")
REVIEWER_NAME = os.environ.get("PORTAL_REVIEWER_NAME", "Compliance & Legal Reviewer")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(BASE_DIR, "dist")

SSL_CTX = (
    ssl.create_default_context(cafile="/etc/ssl/cert.pem")
    if os.path.exists("/etc/ssl/cert.pem")
    else ssl.create_default_context()
)

_GCP_TOKEN_CACHE: dict[str, tuple[str, float]] = {}
_LOGS_CACHE: dict[str, object] = {"data": None, "timestamp": 0.0}
_NB_ARCHIVE_CACHE: dict[str, dict] = {}
CACHE_TTL_SECONDS = 30.0


def get_bucket_name(project_id: str) -> str:
    return os.environ.get("GCS_BUCKET_NAME") or f"{project_id}-ge-ediscovery"


def get_gcp_access_token() -> str:
    """Obtains a Google Cloud OAuth2 access token from the Cloud Run Metadata Server or gcloud CLI."""
    now = time.time()
    cached = _GCP_TOKEN_CACHE.get("default")
    if cached and cached[1] > now + 60:
        return cached[0]

    meta_url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    req = urllib.request.Request(meta_url, headers={"Metadata-Flavor": "Google"})
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            token = data["access_token"]
            expires_in = float(data.get("expires_in", 300))
            _GCP_TOKEN_CACHE["default"] = (token, now + expires_in)
            return token
    except Exception:
        pass

    try:
        token = subprocess.check_output(
            ["gcloud", "auth", "print-access-token"],
            stdin=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=8,
        ).decode("utf-8").strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        raise RuntimeError(
            "Local gcloud credentials have expired (Reauthentication required). "
            "Run `gcloud auth login` in your terminal to refresh your cloudtop session."
        ) from e
    _GCP_TOKEN_CACHE["default"] = (token, now + 300)
    return token


def extract_email_from_principal(principal: str) -> str:
    """Extracts the human subject/email from a WIF principal or IAM principal string."""
    if not principal:
        return "unattributed@enterprise.internal"
    if "/subject/" in principal:
        return principal.split("/subject/", 1)[1].strip()
    if ":" in principal and "@" in principal:
        return principal.split(":", 1)[1].strip()
    return principal.strip()


def validate_archive_gcs_uri(gcs_uri: str, allowed_bucket: str) -> tuple[str, str]:
    """
    Strictly validates that `gcs_uri` points to an object inside `allowed_bucket`
    with no path traversal segments. Returns (bucket_name, object_path).
    """
    if not gcs_uri or not gcs_uri.startswith("gs://"):
        raise ValueError("Invalid GCS URI scheme")
    without_scheme = gcs_uri[5:]
    if "/" not in without_scheme:
        raise ValueError("Missing GCS object path")
    bucket, obj_path = without_scheme.split("/", 1)
    if bucket != allowed_bucket:
        raise PermissionError(f"Access denied: bucket '{bucket}' is not the authorized compliance archive bucket")
    norm_path = os.path.normpath(obj_path)
    if norm_path.startswith("..") or "/../" in f"/{obj_path}/" or "\\.." in obj_path:
        raise PermissionError("Path traversal detected in GCS URI")
    return bucket, obj_path


def run_bq_query(project_id: str, sql: str, query_params: list[dict] | None = None) -> list[dict]:
    """Executes a Standard SQL query against BigQuery REST API and returns a list of dict rows."""
    gcp_token = get_gcp_access_token()
    url = f"https://bigquery.googleapis.com/bigquery/v2/projects/{project_id}/queries"
    payload: dict[str, object] = {
        "query": sql,
        "useLegacySql": False,
        "timeoutMs": 20000,
    }
    if query_params:
        payload["parameterMode"] = "NAMED"
        payload["queryParameters"] = query_params

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {gcp_token}",
            "Content-Type": "application/json",
            "X-Goog-User-Project": project_id,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, context=SSL_CTX, timeout=25) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    schema_fields = data.get("schema", {}).get("fields", [])
    rows_raw = data.get("rows", [])

    def _parse_value(val: object, field_schema: dict) -> object:
        if val is None:
            return None
        mode = field_schema.get("mode", "NULLABLE")
        ftype = field_schema.get("type", "STRING")
        if mode == "REPEATED":
            if not isinstance(val, list):
                return []
            sub_schema = {**field_schema, "mode": "NULLABLE"}
            return [_parse_value(item.get("v"), sub_schema) for item in val if isinstance(item, dict)]
        if ftype in ("RECORD", "STRUCT"):
            if not isinstance(val, dict):
                return {}
            sub_fields = field_schema.get("fields", [])
            f_vals = val.get("f", [])
            return {
                sf["name"]: _parse_value(f_vals[idx].get("v") if idx < len(f_vals) else None, sf)
                for idx, sf in enumerate(sub_fields)
            }
        if ftype in ("INTEGER", "INT64"):
            try:
                return int(val)
            except Exception:
                return 0
        if ftype in ("FLOAT", "FLOAT64", "NUMERIC"):
            try:
                return float(val)
            except Exception:
                return 0.0
        if ftype in ("TIMESTAMP",):
            try:
                epoch = float(val)
                return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))
            except Exception:
                return str(val)
        return val

    parsed_rows: list[dict] = []
    for r in rows_raw:
        f_vals = r.get("f", [])
        row_dict = {}
        for idx, sf in enumerate(schema_fields):
            raw_v = f_vals[idx].get("v") if idx < len(f_vals) else None
            row_dict[sf["name"]] = _parse_value(raw_v, sf)
        parsed_rows.append(row_dict)
    return parsed_rows


def fetch_gcs_json_cached(gcs_uri: str, allowed_bucket: str, project_id: str) -> dict:
    """Fetches and caches a JSON archive object (such as notebook_archive.json) from GCS."""
    if gcs_uri in _NB_ARCHIVE_CACHE:
        return _NB_ARCHIVE_CACHE[gcs_uri]
    try:
        bucket, obj_path = validate_archive_gcs_uri(gcs_uri, allowed_bucket)
        gcp_token = get_gcp_access_token()
        encoded_obj = urllib.parse.quote(obj_path, safe="")
        url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/{encoded_obj}?alt=media"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {gcp_token}",
                "X-Goog-User-Project": project_id,
            },
        )
        with urllib.request.urlopen(req, context=SSL_CTX, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if isinstance(data, dict):
                _NB_ARCHIVE_CACHE[gcs_uri] = data
                return data
    except Exception:
        pass
    return {}


def build_compliance_dataset(project_id: str, force_refresh: bool = False) -> dict:
    """
    Queries `ge_ediscovery.conversation_turns` and transforms rows into the
    ComplianceDataResponse structure expected by the React Review Portal.
    """
    now = time.time()
    if not force_refresh and _LOGS_CACHE["data"] is not None and (now - float(_LOGS_CACHE["timestamp"])) < CACHE_TTL_SECONDS:
        return _LOGS_CACHE["data"]  # type: ignore[return-value]

    if force_refresh:
        _NB_ARCHIVE_CACHE.clear()

    allowed_bucket = get_bucket_name(project_id)
    sql = f"""
        SELECT
          session_id,
          turn_index,
          query_id,
          assist_answer_id,
          engine_id,
          location,
          user_iam_principal,
          session_display_name,
          prompt_text,
          response_text,
          thought_text,
          model_name,
          session_transcript_gcs_uri,
          session_transcript_console_url,
          files,
          event_timestamp,
          harvested_at
        FROM `{project_id}.{BQ_DATASET}.{BQ_TABLE}`
        ORDER BY event_timestamp DESC, session_id, turn_index ASC
        LIMIT 2000
    """
    rows = run_bq_query(project_id, sql)

    processed_logs: list[dict] = []
    sources: list[dict] = []
    chat: list[dict] = []
    studio: list[dict] = []
    notebook_raw_logs: list[dict] = []
    seen_nb_archives: set[str] = set()

    for r in rows:
        engine_id = str(r.get("engine_id") or "")
        session_id = str(r.get("session_id") or "")
        turn_index = int(r.get("turn_index") or 1)
        principal = str(r.get("user_iam_principal") or "")
        user_email = extract_email_from_principal(principal)
        event_ts = str(r.get("event_timestamp") or r.get("harvested_at") or "")
        files_list = r.get("files") if isinstance(r.get("files"), list) else []
        transcript_uri = str(r.get("session_transcript_gcs_uri") or "")

        if engine_id.startswith("notebooklm-enterprise"):
            nb_id = session_id
            raw_disp = str(r.get("session_display_name") or "")
            nb_title = re.sub(r"^\[NotebookLM\]\s*", "", raw_disp).strip() or f"Notebook {nb_id[:8]}"
            prompt_txt = str(r.get("prompt_text") or "")
            resp_txt = str(r.get("response_text") or "")
            query_id = str(r.get("query_id") or f"{nb_id}_turn_{turn_index}")

            notebook_raw_logs.append({
                "event_id": query_id,
                "event_time": event_ts,
                "notebook_id": nb_id,
                "notebook_title": nb_title,
                "user_email": user_email,
            })

            if not prompt_txt.startswith("[NotebookLM Notebook & Source Inventory]") or not files_list:
                chat.append({
                    "event_id": query_id,
                    "event_time": event_ts,
                    "project_id": project_id,
                    "location": str(r.get("location") or "global"),
                    "notebook_id": nb_id,
                    "notebook_title": nb_title,
                    "user_email": user_email,
                    "turn_id": query_id,
                    "user_query": prompt_txt,
                    "model_response": resp_txt,
                    "citations": [],
                })

            # Enrich sources and studio artifacts from notebook_archive.json (once per notebook)
            if transcript_uri and transcript_uri not in seen_nb_archives:
                seen_nb_archives.add(transcript_uri)
                nb_archive = fetch_gcs_json_cached(transcript_uri, allowed_bucket, project_id)
                enriched_srcs = nb_archive.get("enriched_sources") if isinstance(nb_archive.get("enriched_sources"), list) else []
                archived_studio = nb_archive.get("studio_artifacts") if isinstance(nb_archive.get("studio_artifacts"), list) else []

                if enriched_srcs:
                    for s_idx, s_obj in enumerate(enriched_srcs):
                        if not isinstance(s_obj, dict):
                            continue
                        sid = (
                            s_obj.get("sourceId", {}).get("id")
                            or str(s_obj.get("name") or "").split("/")[-1]
                            or f"src_{s_idx}"
                        )
                        stitle = str(s_obj.get("title") or f"Source {sid}")
                        smeta = s_obj.get("metadata") if isinstance(s_obj.get("metadata"), dict) else {}
                        web_meta = smeta.get("webScrapeMetadata") if isinstance(smeta.get("webScrapeMetadata"), dict) else {}
                        gdrive_meta = smeta.get("googleDocsMetadata") if isinstance(smeta.get("googleDocsMetadata"), dict) else {}
                        yt_meta = smeta.get("youtubeMetadata") if isinstance(smeta.get("youtubeMetadata"), dict) else {}

                        src_url = str(web_meta.get("url") or s_obj.get("url") or "")
                        if yt_meta.get("videoId") and not src_url:
                            src_url = f"https://www.youtube.com/watch?v={yt_meta['videoId']}"

                        if yt_meta:
                            skind = "YOUTUBE"
                        elif gdrive_meta:
                            skind = "GOOGLE_DRIVE"
                        elif web_meta or src_url:
                            skind = "WEB_URL"
                        else:
                            skind = "FILE"

                        matched_file = next(
                            (f for f in files_list if isinstance(f, dict) and f.get("file_id") == sid),
                            {},
                        )
                        sources.append({
                            "event_id": f"{nb_id}_src_{sid}",
                            "event_time": str(smeta.get("sourceAddedTimestamp") or event_ts),
                            "project_id": project_id,
                            "location": str(r.get("location") or "global"),
                            "notebook_id": nb_id,
                            "notebook_title": nb_title,
                            "user_email": user_email,
                            "source_id": sid,
                            "source_title": stitle,
                            "source_type": skind,
                            "source_kind": skind,
                            "source_status": str(s_obj.get("status") or "COMPLETE"),
                            "word_count": int(smeta.get("wordCount") or 0),
                            "token_count": int(smeta.get("tokenCount") or 0),
                            "source_url": src_url,
                            "original_url": src_url,
                            "gcs_uri": str(matched_file.get("gcs_uri") or transcript_uri),
                            "sha256_hash": str(matched_file.get("sha256") or ""),
                            "crc32c_hash": str(matched_file.get("crc32c") or ""),
                            "content_preview": f"NotebookLM grounded source ({smeta.get('wordCount', 0)} words, {smeta.get('tokenCount', 0)} tokens)",
                            "raw_source_json": json.dumps(s_obj),
                        })
                else:
                    for f in files_list:
                        if not isinstance(f, dict) or f.get("file_source") != "NOTEBOOK_SOURCE":
                            continue
                        sid = str(f.get("file_id") or "")
                        sources.append({
                            "event_id": f"{nb_id}_src_{sid}",
                            "event_time": event_ts,
                            "project_id": project_id,
                            "location": str(r.get("location") or "global"),
                            "notebook_id": nb_id,
                            "notebook_title": nb_title,
                            "user_email": user_email,
                            "source_id": sid,
                            "source_title": str(f.get("file_name") or sid),
                            "source_type": "FILE",
                            "source_kind": "FILE",
                            "source_status": "COMPLETE",
                            "word_count": int(f.get("byte_size") or 0),
                            "gcs_uri": str(f.get("gcs_uri") or ""),
                            "sha256_hash": str(f.get("sha256") or ""),
                            "crc32c_hash": str(f.get("crc32c") or ""),
                            "content_preview": str(f.get("mime_type") or ""),
                        })

                for st_obj in archived_studio:
                    if not isinstance(st_obj, dict):
                        continue
                    art_id = str(st_obj.get("artifact_id") or "")
                    modality = str(st_obj.get("modality") or "REPORT")
                    st_title = str(st_obj.get("title") or modality)
                    studio.append({
                        "event_id": f"{nb_id}_studio_{art_id}",
                        "event_time": str(st_obj.get("created_at") or event_ts),
                        "project_id": project_id,
                        "location": str(r.get("location") or "global"),
                        "notebook_id": nb_id,
                        "notebook_title": nb_title,
                        "user_email": user_email,
                        "artifact_id": art_id,
                        "artifact_type": modality,
                        "artifact_title": st_title,
                        "title": st_title,
                        "artifact_status": str(st_obj.get("state") or "COMPLETED"),
                        "gcs_uri": str(st_obj.get("gcs_uri") or ""),
                        "mime_type": str(st_obj.get("mime_type") or ""),
                        "size_bytes": int(st_obj.get("byte_size") or 0),
                        "sha256_hash": str(st_obj.get("sha256") or ""),
                        "note_content": str(st_obj.get("extracted_text") or ""),
                    })
            continue

        # Gemini Enterprise Chat turn
        model_name = str(r.get("model_name") or "")
        model_lower = model_name.lower()
        input_artifacts: list[dict] = []
        output_artifacts: list[dict] = []

        for f in files_list:
            if not isinstance(f, dict):
                continue
            f_gcs = str(f.get("gcs_uri") or "")
            art_item = {
                "file_id": str(f.get("file_id") or ""),
                "file_name": str(f.get("file_name") or "artifact"),
                "mime_type": str(f.get("mime_type") or "application/octet-stream"),
                "gcs_uri": f_gcs,
                "sha256": str(f.get("sha256") or ""),
                "crc32c": str(f.get("crc32c") or ""),
                "size_bytes": int(f.get("byte_size") or 0),
                "turn_index": turn_index,
                "preview_url": f"/api/media?gcs_uri={urllib.parse.quote(f_gcs)}" if f_gcs else "",
                "web_url": str(f.get("console_url") or ""),
            }
            if f.get("file_source") == "USER_PROVIDED":
                input_artifacts.append(art_item)
            else:
                output_artifacts.append(art_item)

        if "deep_research" in model_lower:
            surface = "DEEP_RESEARCH"
            agent_name = model_name or "Deep Research Agent"
        elif "agent:adk" in model_lower or any(a["mime_type"] == "application/pdf" for a in output_artifacts):
            surface = "HIGH_CODE_AGENT"
            agent_name = model_name or "ADK Custom Agent"
        elif "agent:" in model_lower:
            surface = "NO_CODE_AGENT"
            agent_name = model_name or "Gemini Enterprise Agent"
        else:
            surface = "REGULAR_CHAT_AGENT"
            agent_name = model_name or "Gemini Enterprise Assistant"

        processed_logs.append({
            "insert_id": f"{session_id}_turn_{turn_index}",
            "timestamp": event_ts,
            "receive_timestamp": str(r.get("harvested_at") or event_ts),
            "project_id": project_id,
            "location": str(r.get("location") or "global"),
            "engine_id": engine_id,
            "user_email": user_email,
            "user_id": principal,
            "principal_type": "WORKFORCE_IDENTITY" if "workforcePools" in principal else "IAM_USER",
            "service_name": "discoveryengine.googleapis.com",
            "method_name": "StreamAssist",
            "interaction_surface": surface,
            "agent_id": model_name,
            "agent_name": agent_name,
            "session_id": session_id,
            "session_path": transcript_uri,
            "turn_count": turn_index,
            " query_id": str(r.get("query_id") or ""),
            "answer_id": str(r.get("assist_answer_id") or ""),
            "state": "SUCCEEDED",
            "archive_status": "COMPLETE",
            "input_text": str(r.get("prompt_text") or ""),
            "output_text": str(r.get("response_text") or ""),
            "reasoning_text": str(r.get("thought_text") or ""),
            "input_artifacts": input_artifacts,
            "output_artifacts": output_artifacts,
            "citations": [],
            "gcs_raw_Conversation_uri": transcript_uri,
        })

    result = {
        "processed_logs": processed_logs,
        "sources": sources,
        "chat": chat,
        "studio": studio,
        "notebook_raw_logs": notebook_raw_logs,
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "is_live": True,
    }
    _LOGS_CACHE["data"] = result
    _LOGS_CACHE["timestamp"] = now
    return result


class PortalRequestHandler(BaseHTTPRequestHandler):
    def send_security_headers(self, is_media: bool = False) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        if is_media:
            self.send_header("Content-Security-Policy", "default-src 'none'; sandbox")
        else:
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; "
                "script-src 'self' https://cdnjs.cloudflare.com; "
                "worker-src 'self' blob: https://cdnjs.cloudflare.com; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src 'self' https://fonts.gstatic.com data:; "
                "img-src 'self' data: blob: https:; "
                "media-src 'self' blob:; "
                "frame-src https://www.youtube.com; "
                "connect-src 'self' https://cdnjs.cloudflare.com; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "frame-ancestors 'none'",
            )

    def get_authenticated_reviewer(self) -> tuple[str, str]:
        """Extracts the verified reviewer identity from Cloud Run IAP headers when present."""
        iap_email = self.headers.get("X-Goog-Authenticated-User-Email", "").strip()
        if iap_email:
            if ":" in iap_email:
                iap_email = iap_email.split(":", 1)[1].strip()
            return iap_email, iap_email.split("@")[0]
        iap_jwt = self.headers.get("X-Goog-IAP-JWT-Assertion", "").strip()
        if iap_jwt and iap_jwt.count(".") == 2:
            try:
                import base64
                payload_b64 = iap_jwt.split(".")[1]
                payload_b64 += "=" * (-len(payload_b64) % 4)
                claims = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
                email = str(claims.get("email") or "").strip()
                if email:
                    return email, email.split("@")[0]
            except Exception:
                pass
        return REVIEWER_EMAIL, REVIEWER_NAME

    def emit_access_audit_log(self, action: str, target: str, extra: dict | None = None) -> None:
        """Emits a structured Cloud Logging audit entry for every eDiscovery compliance access."""
        reviewer_email, _ = self.get_authenticated_reviewer()
        forwarded_for = self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        entry = {
            "severity": "INFO",
            "event_type": "ediscovery_portal_access_audit",
            "reviewer_email": reviewer_email,
            "action": action,
            "target": target,
            "remote_ip": forwarded_for or self.client_address[0],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if extra:
            entry.update(extra)
        print(json.dumps(entry), flush=True)

    def send_json(self, status_code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_security_headers(is_media=False)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/healthz":
            self.send_json(200, {"status": "ok", "service": "ge-ediscovery-portal"})
            return

        if path == "/api/config":
            rev_email, rev_name = self.get_authenticated_reviewer()
            self.send_json(200, {
                "project_id": PROJECT_ID,
                "bq_dataset": BQ_DATASET,
                "gcs_bucket": get_bucket_name(PROJECT_ID),
                "reviewer_email": rev_email,
                "reviewer_name": rev_name,
            })
            return

        if path == "/api/logs":
            force_refresh = qs.get("force_refresh", ["false"])[0].lower() == "true"
            self.emit_access_audit_log("LIST_COMPLIANCE_LOGS", f"{PROJECT_ID}.{BQ_DATASET}.{BQ_TABLE}", {"force_refresh": force_refresh})
            try:
                data = build_compliance_dataset(PROJECT_ID, force_refresh=force_refresh)
                self.send_json(200, data)
            except Exception as e:
                print(f"[!] Error in /api/logs: {e}")
                self.send_json(500, {"error": "Failed to query compliance dataset"})
            return

        if path == "/api/search":
            q = (qs.get("q", [""])[0] or "").strip()
            user_email = (qs.get("user_email", [""])[0] or "").strip().lower()
            if len(q) < 2:
                self.send_json(200, {"matched_sessions": [], "matched_notebooks": [], "total_matches": 0})
                return
            self.emit_access_audit_log("SEARCH_COMPLIANCE_LOGS", f"{PROJECT_ID}.{BQ_DATASET}.{BQ_TABLE}", {"query_length": len(q), "filtered_user": user_email})
            try:
                sql = f"""
                    SELECT DISTINCT
                      session_id,
                      engine_id
                    FROM `{PROJECT_ID}.{BQ_DATASET}.{BQ_TABLE}`
                    WHERE (
                      SEARCH((prompt_text, response_text, thought_text, files), @search_term)
                      OR LOWER(prompt_text) LIKE CONCAT('%', LOWER(@search_term), '%')
                      OR LOWER(response_text) LIKE CONCAT('%', LOWER(@search_term), '%')
                      OR LOWER(session_display_name) LIKE CONCAT('%', LOWER(@search_term), '%')
                      OR LOWER(user_iam_principal) LIKE CONCAT('%', LOWER(@search_term), '%')
                    )
                    AND (@user_email = '' OR LOWER(user_iam_principal) LIKE CONCAT('%', @user_email, '%'))
                    LIMIT 200
                """
                params = [
                    {
                        "name": "search_term",
                        "parameterType": {"type": "STRING"},
                        "parameterValue": {"value": q},
                    },
                    {
                        "name": "user_email",
                        "parameterType": {"type": "STRING"},
                        "parameterValue": {"value": user_email},
                    },
                ]
                rows = run_bq_query(PROJECT_ID, sql, params)
                matched_sessions = [
                    str(r["session_id"])
                    for r in rows
                    if not str(r.get("engine_id") or "").startswith("notebooklm-enterprise")
                ]
                matched_notebooks = [
                    str(r["session_id"])
                    for r in rows
                    if str(r.get("engine_id") or "").startswith("notebooklm-enterprise")
                ]
                self.send_json(200, {
                    "matched_sessions": matched_sessions,
                    "matched_notebooks": matched_notebooks,
                    "total_matches": len(matched_sessions) + len(matched_notebooks),
                })
            except Exception as e:
                print(f"[!] Error in /api/search: {e}")
                self.send_json(500, {"error": "Search query failed"})
            return

        if path == "/api/signed-url":
            gcs_uri = (qs.get("gcs_uri", [""])[0] or "").strip()
            try:
                validate_archive_gcs_uri(gcs_uri, get_bucket_name(PROJECT_ID))
                proxy_url = f"/api/media?gcs_uri={urllib.parse.quote(gcs_uri)}"
                self.send_json(200, {"url": proxy_url, "gcs_uri": gcs_uri})
            except PermissionError as e:
                self.send_json(403, {"error": str(e)})
            except ValueError as e:
                self.send_json(400, {"error": str(e)})
            return

        if path == "/api/media":
            gcs_uri = (qs.get("gcs_uri", [""])[0] or "").strip()
            is_download = qs.get("download", ["false"])[0].lower() == "true"
            try:
                bucket, obj_path = validate_archive_gcs_uri(gcs_uri, get_bucket_name(PROJECT_ID))
            except PermissionError as e:
                self.send_json(403, {"error": str(e)})
                return
            except ValueError as e:
                self.send_json(400, {"error": str(e)})
                return

            self.emit_access_audit_log("STREAM_ARCHIVE_MEDIA", gcs_uri, {"download": is_download})
            try:
                gcp_token = get_gcp_access_token()
                encoded_obj = urllib.parse.quote(obj_path, safe="")
                media_url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/{encoded_obj}?alt=media"
                headers = {
                    "Authorization": f"Bearer {gcp_token}",
                    "X-Goog-User-Project": PROJECT_ID,
                }
                range_header = self.headers.get("Range")
                if range_header:
                    headers["Range"] = range_header

                req = urllib.request.Request(media_url, headers=headers)
                with urllib.request.urlopen(req, context=SSL_CTX, timeout=60) as gcs_resp:
                    status_code = gcs_resp.getcode() or 200
                    content_type = gcs_resp.headers.get("Content-Type") or "application/octet-stream"
                    fname = os.path.basename(obj_path)
                    if content_type == "application/octet-stream":
                        guessed_type, _ = mimetypes.guess_type(fname)
                        if guessed_type:
                            content_type = guessed_type

                    # Prevent Stored XSS via active web content types (.html, .svg, .xml):
                    # never render HTML/SVG/XML inline as executable documents under the portal origin.
                    lower_fname = fname.lower()
                    lower_ct = content_type.lower()
                    is_active_web_doc = (
                        lower_fname.endswith((".html", ".htm", ".svg", ".xml", ".xhtml"))
                        or "html" in lower_ct
                        or "svg" in lower_ct
                        or "xml" in lower_ct
                    )
                    if is_active_web_doc:
                        content_type = "text/plain; charset=utf-8"
                        is_download = True

                    data = gcs_resp.read()
                    self.send_response(status_code)
                    self.send_security_headers(is_media=True)
                    self.send_header("Content-Type", content_type)
                    self.send_header("Content-Length", str(len(data)))
                    self.send_header("Accept-Ranges", "bytes")
                    content_range = gcs_resp.headers.get("Content-Range")
                    if content_range:
                        self.send_header("Content-Range", content_range)
                    disp = "attachment" if is_download else "inline"
                    safe_fname = re.sub(r'[^A-Za-z0-9._-]', '_', fname)
                    self.send_header("Content-Disposition", f'{disp}; filename="{safe_fname}"')
                    self.end_headers()
                    self.wfile.write(data)
            except urllib.error.HTTPError as e:
                self.send_json(e.code, {"error": f"GCS media fetch failed (HTTP {e.code})"})
            except Exception as e:
                print(f"[!] Error streaming /api/media for {gcs_uri}: {e}")
                self.send_json(500, {"error": "Internal media streaming error"})
            return

        # Serve compiled SPA static files from DIST_DIR with SPA index.html fallback
        rel_path = path.lstrip("/") or "index.html"
        candidate = os.path.realpath(os.path.join(DIST_DIR, rel_path))
        dist_real = os.path.realpath(DIST_DIR)
        if not candidate.startswith(dist_real) or not os.path.isfile(candidate):
            candidate = os.path.join(dist_real, "index.html")

        if not os.path.isfile(candidate):
            self.send_json(404, {"error": "Static build not found. Run npm run build in portal/."})
            return

        ctype, _ = mimetypes.guess_type(candidate)
        with open(candidate, "rb") as f:
            content = f.read()
        self.send_response(200)
        self.send_security_headers(is_media=False)
        self.send_header("Content-Type", ctype or "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    server = ThreadingHTTPServer(("0.0.0.0", port), PortalRequestHandler)
    print(f"[*] Gemini Enterprise eDiscovery Review Portal listening on http://0.0.0.0:{port}")
    server.serve_forever()
