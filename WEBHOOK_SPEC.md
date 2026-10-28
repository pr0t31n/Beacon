# Beacon Webhook Integration Spec

Beacon accepts status updates from external security tools via authenticated webhooks. Two modes are available:

- **Generic** — you format the payload to Beacon's prescribed schema
- **Provider-specific** — Beacon parses the tool's native webhook format

Both modes use the same bearer-token authentication and appear on the same dashboard.

---

## Authentication

All webhook endpoints require an `Authorization: Bearer <token>` header.

- Tokens should be high-entropy random strings (32+ hex characters recommended). Generate one with: `python3 -c "import secrets; print(secrets.token_hex(32))"`
- Tokens are SHA-256 hashed before storage — Beacon never stores the plaintext.
- **Trust on first use (TOFU):** The first push with a new `(source, token_hash)` pair auto-registers the source. Subsequent pushes from that source must use the same token.
- A missing, empty, or mismatched token returns HTTP 401.

---

## Generic Webhook

```
POST /api/webhook
Content-Type: application/json
Authorization: Bearer <token>
```

### Request Body

```json
{
  "source":           "my-scanner",
  "source_version":   "3.2.1",
  "event":            "status_update",
  "task_id":          "scan-2026-10-28-001",
  "task_name":        "Full network scan — 10.0.0.0/16",
  "status":           "running",
  "progress":         0.42,
  "started_at":       "2026-10-28T01:00:00Z",
  "ended_at":         null,
  "message":          "Phase 3/5 — service enumeration",
  "findings_summary": {
    "CRITICAL": 2,
    "HIGH": 5,
    "MEDIUM": 12,
    "LOW": 8,
    "INFO": 30
  },
  "metadata":         {}
}
```

### Field Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `source` | string | **Yes** | Tool identifier (e.g. `my-scanner`, `internal-sast`). Used to group tasks on the dashboard. Max 100 chars. |
| `task_id` | string | **Yes** | Unique identifier for this scan/run. Must be unique per source. Max 200 chars. |
| `task_name` | string | **Yes** | Human-readable name for this task. Shown on the dashboard. Max 300 chars. |
| `status` | string | **Yes** | One of: `queued`, `running`, `paused`, `complete`, `failed`, `cancelled` |
| `source_version` | string | No | Version of the reporting tool. |
| `event` | string | No | Event type: `status_update` (default), `started`, `completed`, `failed`. Used for logging; `status` is the authoritative state. |
| `progress` | float\|null | No | 0.0 to 1.0. `null` or omitted = indeterminate. |
| `started_at` | string | No | ISO 8601 timestamp when the task started. |
| `ended_at` | string\|null | No | ISO 8601 timestamp when the task ended. `null` = still running. |
| `message` | string | No | Current status text (phase name, step description). Max 500 chars. |
| `findings_summary` | object | No | Finding counts keyed by risk level. Keys must be UPPERCASE: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. Values are integers. |
| `metadata` | object | No | Opaque key-value data. Stored by Beacon but not interpreted or displayed. Max 10KB serialized. |

### Behavior

- **Idempotent by `(source, task_id)`** — sending the same `task_id` from the same `source` updates the existing task rather than creating a duplicate. Latest push wins.
- Missing optional fields are left unchanged from the previous push (not reset to null).
- A push with `status: "complete"`, `"failed"`, or `"cancelled"` marks the task terminal. Subsequent updates to the same `task_id` are accepted (a tool may rerun).

### Response

**Success (200):**
```json
{
  "status": "ok",
  "source_id": "a1b2c3d4",
  "received_at": "2026-10-28T01:00:05Z"
}
```

**Errors:**

| Code | Body | Cause |
|---|---|---|
| 400 | `{"error": "..."}` | Missing required field, invalid JSON, malformed payload |
| 401 | `{"error": "..."}` | Missing/empty/mismatched bearer token |
| 413 | `{"error": "..."}` | Payload exceeds 1MB |

---

## Provider-Specific Webhooks

```
POST /api/webhook/<provider>
Content-Type: application/json
Authorization: Bearer <token>
```

Same bearer-token authentication. Beacon parses the provider's native webhook payload and normalizes it into the internal status model.

### Supported Providers

| Provider slug | Tool | Configuration path |
|---|---|---|
| `nessus` | Tenable Nessus | Settings > Notifications > Webhook URL |
| `qualys` | Qualys VM/PC | Notifications > Add Webhook |
| `insightvm` | Rapid7 InsightVM | Administration > Notification Methods > Webhook |
| `openvas` | OpenVAS / Greenbone | Alerts > Method: HTTP Get/POST |
| `burp_enterprise` | Burp Suite Enterprise | Settings > Webhooks |
| `checkmarx` | Checkmarx One / SAST | Settings > Webhooks |
| `trivy` | Aqua Trivy | CI pipeline `curl` POST or Trivy Server webhook config |
| `veracode` | Veracode | Admin > Webhooks |
| `gophish` | GoPhish | Campaign > Webhook URL |
| `semgrep` | Semgrep Cloud | Settings > Notifications > Webhook |
| `sonarqube` | SonarQube | Administration > Configuration > Webhooks |
| `snyk` | Snyk | Org Settings > Integrations > Webhooks |
| `codeql` | GitHub CodeQL | Repo Settings > Webhooks > Select `code_scanning_alert` event |

### Configuration

In each tool, set the webhook URL to:

```
https://<beacon-host>:9443/api/webhook/<provider>
```

For tools that support custom headers, add:
```
Authorization: Bearer <your-beacon-token>
```

For tools that don't support custom auth headers (e.g. some GoPhish versions), append the token as a query parameter:
```
https://<beacon-host>:9443/api/webhook/gophish?token=<your-beacon-token>
```

Query-parameter auth is accepted on all provider endpoints as a fallback.

### Provider-Specific Notes

**Nessus** — Beacon parses the scan status webhook (`scan.completed`, `scan.started`, etc.). Findings summary is extracted from the `severitycount` object if present.

**Qualys** — Beacon accepts the notification payload from VM scans. Maps Qualys severity levels (1-5) to CRITICAL/HIGH/MEDIUM/LOW/INFO.

**InsightVM** — Beacon parses the scan event notification. Maps InsightVM risk scores to standard risk levels.

**OpenVAS** — Beacon accepts the HTTP alert payload. Task status is derived from the alert condition (task run status changed).

**Burp Enterprise** — Beacon parses scan event webhooks (`scan_started`, `scan_succeeded`, `scan_failed`). Issue counts are mapped by confidence/severity.

**Checkmarx** — Beacon parses the scan completion webhook. Maps Checkmarx severity values to standard risk levels.

**Trivy** — Beacon accepts a POST of Trivy's JSON report output. Vulnerability counts are extracted by severity.

**Veracode** — Beacon parses the scan status change webhook. Maps Veracode severity (0-5) to standard risk levels.

**GoPhish** — Beacon parses campaign event webhooks (`email_sent`, `email_opened`, `clicked_link`, `submitted_data`). Progress is derived from `(events received / emails sent)`. Findings summary maps to: compromised credentials = CRITICAL, clicked links = HIGH, opened emails = MEDIUM, sent = INFO.

**Semgrep** — Beacon parses the deployment notification webhook. Finding counts by severity are extracted from the results summary.

**SonarQube** — Beacon parses the analysis completion webhook (`project_analysis_complete`). Quality gate status and issue counts by severity are extracted.

**Snyk** — Beacon parses the project snapshot webhook. Vulnerability counts by severity are mapped to standard risk levels.

**CodeQL** — Beacon parses GitHub's `code_scanning_alert` webhook event. Alert rule severity is mapped to standard risk levels. Handles `created`, `fixed`, `reopened`, `closed_by_user` actions.

### Unrecognized Providers

A POST to `/api/webhook/<unknown>` returns HTTP 400 with `{"error": "Unknown provider: <unknown>", "supported": [...]}`.

---

## Examples

### Test Connectivity

```bash
curl -sk -X POST https://beacon.local:9443/api/ping \
  -H "Authorization: Bearer abc123def456"
```

Response: `{"ok": true, "version": "1.2.0"}`

### Generic — Start a Scan

```bash
curl -sk -X POST https://beacon.local:9443/api/webhook \
  -H "Authorization: Bearer abc123def456" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "internal-nmap",
    "task_id": "scan-001",
    "task_name": "Perimeter scan — 203.0.113.0/24",
    "status": "running",
    "started_at": "2026-10-28T01:00:00Z",
    "message": "Host discovery"
  }'
```

### Generic — Progress Update

```bash
curl -sk -X POST https://beacon.local:9443/api/webhook \
  -H "Authorization: Bearer abc123def456" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "internal-nmap",
    "task_id": "scan-001",
    "task_name": "Perimeter scan — 203.0.113.0/24",
    "status": "running",
    "progress": 0.65,
    "message": "Service enumeration — 165/254 hosts",
    "findings_summary": {"HIGH": 3, "MEDIUM": 7, "LOW": 12, "INFO": 45}
  }'
```

### Generic — Scan Complete

```bash
curl -sk -X POST https://beacon.local:9443/api/webhook \
  -H "Authorization: Bearer abc123def456" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "internal-nmap",
    "task_id": "scan-001",
    "task_name": "Perimeter scan — 203.0.113.0/24",
    "status": "complete",
    "progress": 1.0,
    "ended_at": "2026-10-28T03:45:00Z",
    "message": "Scan finished — 254 hosts, 1847 services",
    "findings_summary": {"CRITICAL": 1, "HIGH": 8, "MEDIUM": 22, "LOW": 31, "INFO": 103}
  }'
```

---

## Dashboard

Webhook sources appear in a dedicated section below Crucible engagements. Each source is rendered as a card showing:

- Source name and version
- Last update timestamp (relative)
- Tasks grouped by status (running first, then queued, paused, complete, failed)
- Per-task: name, status icon, progress bar (when available), current message, findings summary
- Overall findings rollup across all active tasks for that source

---

## Security Notes

- Generate tokens with sufficient entropy: `python3 -c "import secrets; print(secrets.token_hex(32))"`
- Beacon validates `Content-Type: application/json` on all webhook endpoints.
- Request body is capped at **1 MB**. Payloads exceeding this limit receive HTTP 413.
- All data rendered on the dashboard is HTML-escaped to prevent stored XSS from compromised webhook sources.
- Webhook endpoints accept only POST. Other methods return 405.
- Beacon does not follow redirects or make outbound requests in response to webhook data.
- Token-based auth means anyone with the token can write status data for that source. Protect tokens accordingly. Tokens do not grant access to the dashboard (that uses separate session-based auth).
- Future: per-source rate limiting (120 requests/minute) may be enforced. Design integrations to push at reasonable intervals (30s minimum recommended).
