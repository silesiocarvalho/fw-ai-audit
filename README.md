# FW AI Audit v1.0.0 — Multi-Vendor Firewall Security Assessment Platform

A web-based security assessment platform with automated SSH + Management API audit,
AI-powered risk analysis (multi-provider via LiteLLM), security compliance mapping
(NIST CSF 2.0, ISO 27001, PCI DSS, MITRE ATT&CK), manual review workbench,
and multi-format report generation (PDF, Excel, CSV, Word).

---

## Project Structure

```
fw-ai-audit/
├── backend/
│   ├── main.py              ← FastAPI app (API Gateway + WebSocket)
│   ├── credential_vault.py  ← Fernet-encrypted session-scoped credential store
│   ├── session_manager.py   ← Session state machine + manual guidance
│   ├── audit_runner.py      ← Background audit thread + WebSocket progress events
│   └── persistence.py       ← Atomic JSON session persistence (no credentials)
├── frontend/
│   └── index.html           ← Single-page application (intake → audit → workbench → export)
├── tools/
│   ├── audit_tool.py        ← SSH + cpapi audit engine (61 CIS checks)
│   ├── ai_analyzer.py       ← LiteLLM enrichment (3 passes: risk → chains → narrative)
│   ├── report_generator.py  ← PDF / Excel / CSV / Word export
│   └── compliance_mappings.py ← CIS → NIST CSF 2.0 / ISO 27001 / PCI DSS / MITRE ATT&CK
├── data-source/             ← Reference PDFs (Admin Guide, API docs)
├── security-compliance/     ← CIS Benchmark PDFs, NIST CSF, PCI DSS reference docs
├── reports/                 ← Generated assessment reports saved here
├── sessions/                ← Session state JSON files (no credentials)
├── tests/
│   └── test_backend.py      ← Integration tests (vault, sessions, API, reports)
├── pyproject.toml           ← Dependencies (uv-managed)
├── .python-version          ← Pins Python 3.12
├── .env                     ← No real keys — per-session keys via intake form
├── .mcp.json                ← CP MCP server config (dev-only, credentials via env vars)
├── start.sh                 ← uv sync + uvicorn launcher
└── README.md
```

---

## Quick Start

### 1. Prerequisites

```bash
# Python 3.12+ and uv required
uv --version   # install from https://docs.astral.sh/uv if missing

# Install all dependencies
uv sync
```

### 2. Start the Server

```bash
# Preferred — loads .env and starts uvicorn
bash start.sh

# Or directly
uv run uvicorn backend.main:app --reload
```

Open your browser: **http://localhost:8000**

### 3. (Optional) Use Claude Code for development

```bash
# Install Claude Code
npm install -g @anthropic/claude-code

# Launch from the project root
cd fw-ai-audit
claude
```

Claude Code can help with:
- Debugging SSH prompt regex (`audit_tool.py:GaiaClishSession._drain()`)
- Fixing check regressions — paste the raw Clish output, get a targeted fix
- Adding new CIS checks or adapting existing ones
- Extending report formats or compliance mappings

> **Before sharing any credentials with Claude Code, read the [Credential Safety warning](#️-warning--claude-code--credentials) below.**

---

## Using the Tool

### Phase 1 — Client Setup
Fill in:
- **Firewall IP** — the IP address you can SSH to
- **Username / Password** — Gaia admin credentials
- **CP Management API Key** — optional, enables Section 3 automated checks
- **Anthropic API Key** — your `sk-ant-...` key for AI analysis
- **Organization, Device Role, Industry** — context for the AI narrative

Click **Start Assessment →**

### Phase 2 — Automated Audit
Watch the live terminal as 61 CIS checks run via SSH.
After the audit, Claude API runs three analysis passes:
1. Risk enrichment per finding
2. Attack chain correlation
3. Executive and technical narrative

This takes 2–5 minutes depending on firewall response time and API latency.

### Phase 3 — Manual Review
The workbench shows all manual checks with:
- Exact location in SmartConsole or Gaia
- Step-by-step verification instructions
- Pass/Fail criteria
- Evidence and notes fields

Work through each check. Click **Save Finding** after each one.
The progress bar fills as you complete checks.

Once all checks are resolved, **Finalize Report →** becomes active.

### Phase 4 — Export
Download:
- **PDF** — client deliverable (cover page, exec summary, findings, attack chains)
- **Excel** — 5-sheet workbook for GRC teams
- **CSV** — flat file for import into tracking systems

---

## Testing Without a Firewall

To test the UI and report pipeline without an actual firewall,
use Claude Code:

```
Tell Claude Code:
"Create a mock SSH session that returns realistic Gaia R82 
Clish output for all audit_tool.py checks. Inject it so 
the web app runs a full assessment against a fake device."
```

Or load a pre-existing raw JSON:
- Place a `cis_audit_YYYYMMDD.json` in the `reports/` folder
- Claude Code can wire the `/audit/start` endpoint to load it instead of SSH

---

## Troubleshooting with Claude Code

**SSH connects but commands return empty:**
```
"The Gaia Clish prompt on my firewall looks like 'hostname>'. 
Debug the _drain() method in audit_runner.py and fix the 
PROMPT_RE regex."
```

**A specific check returns ERROR:**
```
"Check 2.2.1 returns ERROR. The raw output from the firewall 
was: [paste output]. Fix the regex in audit_tool.py check_2_2_1."
```

**WebSocket not connecting:**
```
"The WebSocket connection to /ws/{session_id} is failing.
Read main.py and debug the connection. My browser shows: [error]"
```

**PDF layout issues:**
```
"The PDF cover page cuts off the executive summary text.
Fix the ReportLab layout in report_generator.py."
```

---

## Security Notes

- Credentials are **never** stored on disk
- Credentials are **never** sent to the AI model
- All credentials are Fernet-encrypted in-memory (`CredentialVault`) for the session lifetime
- All session data is destroyed on `DELETE /api/sessions/{id}` or when the server restarts
- The tool operates in **read-only** mode — no changes are made to the firewall

### ⚠️ Warning — Claude Code & Credentials

**Never type firewall passwords, Management API keys, or AI provider keys into a Claude Code chat message.**

When credentials appear in a conversation, they are stored in the session's context for its duration and cannot be retroactively removed. This applies even though Claude Code does not persist conversations to disk.

**Always enter credentials through the browser intake form** — credentials go directly to the encrypted `CredentialVault` and never appear in conversation history.

If credentials were shared in a chat session:
1. **Rotate the Management API key** — SmartConsole → Manage & Settings → Permissions & Administrators
2. **Rotate the AI provider key** — from the provider dashboard (Groq, Anthropic, OpenAI, etc.)
3. **Delete the conversation** — from claude.ai after the session ends
4. **Delete the session** — `DELETE /api/sessions/{id}` to clear the in-memory vault

### Using MCP Tools for Live Verification

The `quantum-management` MCP server lets Claude Code query SmartConsole directly (e.g. to verify a disputed finding). MCP credentials must be set as **environment variables before starting Claude Code** — never written to `.mcp.json` directly.

```bash
export MANAGEMENT_HOST="<IP>"
export API_KEY="<API_KEY>"
export USERNAME="<USERNAME>"
export PASSWORD="<PASSWORD>"
claude   # MCP picks up env vars at startup
```

If MCP is not configured, Claude Code can verify findings directly via the `cpapi` SDK — credentials are passed inline, used in memory, and gone when the script exits. See `CLAUDE.md` for details.

---

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/sessions` | Create session, store credentials |
| GET | `/api/sessions/{id}` | Session state + summary |
| POST | `/api/sessions/{id}/audit/start` | Start SSH audit (async) |
| GET | `/api/sessions/{id}/workbench` | Manual checks + guidance |
| POST | `/api/sessions/{id}/manual/{cid}` | Submit manual finding |
| GET | `/api/sessions/{id}/report` | Current report JSON |
| POST | `/api/sessions/{id}/report/finalize` | Finalize with AI pass |
| GET | `/api/sessions/{id}/export/{fmt}` | Download PDF/Excel/CSV |
| DELETE | `/api/sessions/{id}` | Destroy session |
| WS | `/ws/{id}` | Real-time progress stream |
