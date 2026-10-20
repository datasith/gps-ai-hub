# Google Cloud GPS AI Hub

Welcome to the **Google Cloud GPS AI Hub** repository (`gps-ai-hub`). This repository houses enterprise reference architectures, production-grade Model Context Protocol (MCP) connectors, and technical demonstrations for **Gemini Enterprise**.

> **Acknowledgements & Attribution**: MCP connectors are based on original work and reference architecture by **Upasana Pati** ([upasana1105/UP_Demos/byomcp](https://github.com/upasana1105/UP_Demos/tree/main/byomcp)).

> **Disclaimer**: This repository and its contents are provided for illustration and educational purposes only as example code. This is not an official Google product or officially supported Google Cloud project. This code is provided as-is for demonstration purposes and is NOT intended or supported for production workloads. The views, code, and opinions expressed in this repository are those of the author(s) and do not necessarily reflect the position, opinions, or official policy of Google LLC or Google Cloud Platform.

---

## 🍂 Gemini Weekly Updates (`/Gemini_Weekly_Updates`)

- 📬 **[Gemini Enterprise Weekly & Monthly Customer Executive Briefing Architecture](https://github.com/peterfishergcp/gps-ai-hub/tree/main/projects/Gemini_Weekly_Updates)**:
  - Reference architecture and seasonal HTML/Markdown template suite (showcased with an **October Autumn Harvest 🍂** aesthetic) enabling Customer Engineers (CEs), FSRs, and AI Specialists to generate high-touch executive updates for strategic accounts.
  - Pairs **Customer-Aware Relevance Filtering** (intersecting global Gemini Enterprise & Antigravity release notes with a customer's deployed connectors and compliance posture) with a **Mandatory CE Human-in-the-Loop (HITL) Review Gate** via Google Workspace Gmail Drafts (`users.drafts.create`), ensuring subtle connector permission changes (e.g., SharePoint `Sites.Selected` vs. `AllSites.Read`) and active support cases (`CS-xxxxx` / `FE-xxxxx`) are accurately surfaced.

---

## 🔍 Output AI Verification Loop (`/Output AI Verification Loop`)

- 🛡️ **[Output Engineering & Dual-Model Adversarial Verification Skill (`output-engineer`)](https://github.com/peterfishergcp/gps-ai-hub/tree/main/projects/Output%20AI%20Verification%20Loop)**:
  - Portable **Jetski / Antigravity Skill (`SKILL.md`)** and **5-Tab Interactive HTML Review Canvas** engineered for Customer Engineers (CEs), Solutions Architects, and Field Specialists to audit AI-generated security questionnaire responses, RFPs, and architecture proposals in under 3 minutes.
  - Deconstructs technical drafts into **4 Verifiable Output Modalities**: (1) **ASD-STE100 Controlled Technical English** ($\le 20$w procedural / $\le 25$w descriptive sentence caps with a deterministic `check_ste100.py` validator), (2) **Declarative Mermaid.js Topology & Sequence Diagrams**, (3) **Interactive HTML Review Canvas (`review_canvas_template.html`)**, and (4) **Timestamped Explainer Storyboards with Browser Voice Narration**.
  - Includes a **Dual-Model Challenger-Defender Benchmark** comparing **Gemini Pro (`gemini-3.1-pro-high`)** and **Claude Opus (`opus-5.5-high`)** side-by-side on an enterprise security architecture audit.

---

## 📊 Gemini Enterprise Token Consumption & WIF Usage Telemetry (`/ge-token-tracking`)

- 📈 **[Gemini Enterprise Token Consumption, Model Breakdown & Workforce Identity (WIF) Usage Dashboard](https://github.com/peterfishergcp/gps-ai-hub/tree/main/projects/ge-token-tracking)**:
  - Lightweight, zero-KMS, zero-Cloud-Storage token tracking and FinOps chargeback solution derived from `ge-ediscovery-logging`, purpose-built for higher-education institutions, public-sector agencies, and enterprises that need per-user and per-model token observability without full eDiscovery file archival.
  - Automates OpenTelemetry trace enablement (`enable_ge_observability.py`, supporting `--no-sensitive-logging` for FERPA/privacy-sensitive environments) and joins Cloud Trace (`trace_link._AllSpans`) with Gemini Enterprise activity logs in BigQuery (`v_gemini_token_usage_by_user` and `v_token_usage_summary_by_principal`).
  - Includes a focused **Cloud Run Token Consumption & WIF Usage Dashboard (`dashboard/`)** with multi-instance filtering (`ALL` or per `engine_id`), 4 executive KPI cards, Chart.js visualizations (**Token Usage by Model**, **Token Usage by WIF Principal**, **Daily Token Consumption Trend**), a searchable WIF Identity Attribution table, and 1-click **CSV & HTML Chargeback Reports**.

---

## 🔎 Gemini Enterprise eDiscovery, Compliance Review Portal & Microsoft Purview Integration (`/ge-ediscovery-logging`)

- 🗄️ **[Gemini Enterprise Server-Side eDiscovery Capture, Cloud Storage Archival, BigQuery Forensic Reporting, Compliance Review Portal & Microsoft Purview eDiscovery Connector](https://github.com/peterfishergcp/gps-ai-hub/tree/main/projects/ge-ediscovery-logging)**:
  - Zero-browser-plugin, 100% server-side eDiscovery and compliance pipeline for **Gemini Enterprise** and **NotebookLM Enterprise** deployments backed by **Workforce Identity Federation (WIF)** and **Google Cloud KMS (`asymmetricSign` — zero private keys on disk)**.
  - Captures full untruncated user prompts, model responses, internal model reasoning (`thought_text`), user-uploaded attachments (`USER_PROVIDED`), AI-generated PDFs/images/Canvas HTML slide decks (`AI_GENERATED`), and all 12 **NotebookLM Enterprise Studio** modalities with `SHA-256` & `CRC32C` chain-of-custody verification into **Cloud Storage** and **BigQuery**, paired with a drift-safe **`geUserNoDelete`** custom IAM role to prevent session deletion before harvest.
  - Includes a self-contained **React 18 Compliance & Legal Brief Narrative Review Portal (`portal/`)** on Cloud Run, pre-built BigQuery forensic views (`v_ediscovery_file_audit`, `v_notebooklm_forensic_audit`, `v_jailbreak_and_security_detections`, `fn_user_forensic_report`), and a dual-track **Microsoft Purview eDiscovery & DSPM for AI Connector (`purview_connector.py`)** that pushes HTML Legal Briefs + native binary `#microsoft.graph.fileAttachment` payloads into Exchange Online custodian mailboxes for **Purview eDiscovery Cases, Holds, Searches, and Review Sets**.

---

## 🌐 Gemini Enterprise Smart Router (`/ge-smart-router`)

- 🔀 **[Gemini Enterprise Smart Group Router](https://github.com/peterfishergcp/gps-ai-hub/tree/main/projects/ge-smart-router)**:
  - Identity-aware routing dispatcher for multi-instance Gemini Enterprise deployments under a single unified DNS domain.
  - Couples Google Cloud External Application Load Balancer and Identity-Aware Proxy (IAP) to dynamically route users to their assigned Gemini Enterprise application based on Cloud Identity / Workspace group membership.

---

## 🎯 Gemini Enterprise Skills (`/ge_skills`)

Domain-specific **Gemini Enterprise Skills (`SKILL.md`)** and companion connectors that enforce deterministic workflows, citation fidelity, and URL formatting.

- 📄 **[Microsoft 365 SharePoint & Outlook Federated Quality Skills (`ge_m365_connector_skill`)](https://github.com/peterfishergcp/gps-ai-hub/tree/main/projects/ge_skills/ge_m365_connector_skill)**:
  - Zero-infrastructure quality enhancer skills for the **Standard SharePoint Federated Connector**, **Outlook Connector**, and custom Graph MCP servers (`m365_combined_skill`, `sharepoint_federated_skill`, `outlook_connector_skill`).
  - Enforces file-type-aware URL formatting (`.pdf#page=N` physical page calculation vs. `.docx?web=1` Word Online browser viewing without file downloads) and strict Outlook temporal search & thread aggregation.

---

## 🔌 Gemini Enterprise MCP Connectors (`/ge_mcp`)

Enterprise-grade Model Context Protocol (MCP) servers and integrations that bridge enterprise systems and specialized models directly into **Gemini Enterprise**.

### 🌟 Featured Connectors:

- 🛡️ **[Microsoft Work IQ MCP + Purview Sensitivity Label & AES-256 Encryption Enforcement](https://github.com/peterfishergcp/gps-ai-hub/tree/main/projects/ge_mcp/WorkIQ%20MCP%20Purview)**:
  - Zero-infrastructure BYO MCP integration connecting Gemini Enterprise (with Workforce Identity Federation) directly to Microsoft's managed **Work IQ MCP Server (`https://workiq.svc.cloud.microsoft/mcp`)**.
  - Demonstrates real-time **Microsoft Purview Sensitivity Label & AES-256 Rights Management (RMS) Encryption** enforcement—decrypting and summarizing authorized confidential documents while natively blocking restricted documents based on the signed-in user's identity.

- 🧠 **[Claude Sonnet 5 Model Garden MCP Server](https://github.com/peterfishergcp/gps-ai-hub/tree/main/projects/ge_mcp/claude_mcp_sonnet)**:
  - Bring-Your-Own (BYO) MCP Connector wrapping Anthropic Claude Sonnet 5 (`publishers/anthropic/models/claude-sonnet-5`) from the Agent Platform Model Garden into Cloud Run.
  - Enables Gemini Enterprise users to access Claude Sonnet 5 for search, deep coding, 1M token context analysis, and no-code agent workflows with Google IAM token pass-through.

- 📁 **[Customize SharePoint MCP Server](https://github.com/peterfishergcp/gps-ai-hub/tree/main/projects/ge_mcp/customize-sharepoint-mcp-server)**:
  - Autonomous SharePoint document management, site navigation, and deep-link citation rendering via Microsoft Graph.
  - Page-level citations (`#page=N`), multi-format text extraction (`.docx`, `.pptx`, `.xlsx`), and 12 read/write actions protected by Gemini Enterprise Action Approval dialogs.

- ✉️ **[Microsoft Outlook MCP Server](https://github.com/peterfishergcp/gps-ai-hub/tree/main/projects/ge_mcp/customize_outlook_mcp)**:
  - Seamless AI interaction with Outlook Mail, Calendar, and Contacts via Microsoft Graph.
  - Date-aware temporal search, conversation thread retrieval, multi-email batching, calendar event creation, and contacts lookup.

- 📂 **[Universal SharePoint MCP Server](https://github.com/peterfishergcp/gps-ai-hub/tree/main/projects/ge_mcp/sharepoint-mcp-server)**:
  - Reference implementation for SharePoint and OneDrive enterprise document connectivity.

---

## 🔒 Security & Governance

- **Delegated OAuth 2.0 & Identity Pass-Through**: MCP connectors support user Bearer token delegation directly to target endpoints with granular RBAC.
- **Zero Static Secrets**: Eliminates static API keys in favor of short-lived OAuth 2.0 / IAM tokens.
- **Enterprise Consent Dialogs**: All data modification actions trigger native Gemini Enterprise action approval dialogs.
- **Cloud Audit Logging**: All model and tool invocations are tracked and auditable under enterprise Google Cloud boundaries.
