<details>
<summary><strong>FULL DISCLOSURE</strong> — AI Development & Legal Notice</summary>

---

### AI Development Disclosure

This tool is part of the **pr0t31n toolkit**, a collection of security testing and penetration testing automation tools. The toolkit was created through AI-assisted development, guided by the professional experience and domain expertise of a cybersecurity consultant and penetration tester. Ya, I named it after myself - but to be fair, AI is horrible at naming things.

**The pr0t31n toolkit exists to serve two purposes:**

1. **Automate repetitive penetration testing workflow steps.** Security assessments involve significant amounts of repetitive, procedural work — running sequential tool chains, parsing outputs, correlating findings across tools, and managing engagement data. Automating these steps frees testers to focus on the work that requires human judgment: manual testing, creative attack paths, analysis, and reporting.

2. **Demonstrate the benefits and failures of AI-assisted development.** This toolkit is a real-world case study in building production security tooling with AI assistance. It demonstrates both what AI-assisted development can accomplish and where it falls short. The quality of AI-generated code varies significantly — between context refreshes, the output can range from senior/principal-level software engineering to the work of a still-in-school intern. This inconsistency is itself part of the demonstration.

In the interest of transparency, every tool in the pr0t31n toolkit carries this disclosure. The creator believes that AI-assisted development should be acknowledged openly, not concealed. Users, reviewers, and anyone examining this code should know how it was built so they can evaluate it accordingly.

---

### Legal & Authorization Notice

> **⚠ WARNING: AUTHORIZED USE ONLY**

This tool is designed and intended **exclusively** for use in **authorized security testing engagements**. "Authorized" means **all** of the following conditions are met:

- **Explicit Written Permission.** You possess explicit, documented, written authorization from the owner or authorized representative of the target system(s), network(s), or application(s) to conduct security testing. Verbal agreements are not sufficient.
- **Defined Scope.** The authorization clearly defines the scope of testing, including which systems, networks, IP ranges, applications, and/or endpoints are included. You must not exceed the boundaries of this defined scope under any circumstances.
- **Defined Timeframe.** The authorization specifies the dates and times during which testing is permitted. Testing outside the authorized window is unauthorized testing.
- **Rules of Engagement.** You are operating under a set of rules of engagement (RoE) or equivalent governing document that establishes acceptable testing methods, escalation procedures, emergency contacts, and any restrictions or exclusions.
- **Legal Compliance.** Your testing complies with all applicable local, state, national, and international laws and regulations, including but not limited to the Computer Fraud and Abuse Act (CFAA), the General Data Protection Regulation (GDPR), and equivalent legislation in your jurisdiction.

**Prohibited uses** include but are not limited to: unauthorized access to or testing of any system; testing against systems without explicit written authorization; any activity that violates applicable laws; use for malicious purposes including data theft, extortion, sabotage, or disruption of services; distribution intended to facilitate unauthorized access; and use without a clear legal basis.

**THIS TOOL IS PROVIDED "AS IS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

The creator(s) and contributor(s) accept no responsibility or liability for any damage, loss, legal consequence, or other harm resulting from the use or misuse of this tool — including damage to systems or data, legal penalties or prosecution, loss of data or revenue, and any direct, indirect, incidental, special, consequential, or punitive damages.

**By using this tool, you acknowledge that you are solely responsible for ensuring that your use is authorized, lawful, and within the defined scope of your engagement. You assume all risk associated with the use of this tool.**

Security testing is a professional discipline with significant ethical and legal obligations. Users operating in a professional capacity are expected to adhere to the standards and codes of conduct established by recognized industry bodies, including PTES, OWASP, NIST, and any certifying body under which they hold credentials.

---

</details>

# Beacon

Engagement and scan status server for the pr0t31n toolkit. Receives push updates from Crucible instances and third-party security tools via webhooks. Presents a spartan, read-only dashboard showing live progress across all sources.


> **[View full documentation on the Codex Wiki](https://wiki.pr0t31n.com/tools/beacon)** — detailed features, CLI reference, findings catalogue, and integration guides.

## Features

- **Multi-engagement dashboard** — track multiple concurrent engagements from multiple Crucible instances
- **Third-party webhook integration** — Checkmarx One, GoPhish, Semgrep Cloud, SonarQube, Snyk
- **Generic webhook API** — any tool can push status using Beacon's prescribed JSON schema
- **Pre-shared token auth** — TOFU-style registration; tokens SHA-256 hashed at rest
- **TLS 1.2+** — self-signed cert auto-generated on first run
- **Auto-cleanup** — engagements and webhook sources purge after 30 days of inactivity
- **Retroactive data** — late-connecting Crucible sends full history on first push
- **Spartan UI** — risk-severity pills, progress bars, tool status table, 60s auto-refresh

## Requirements

- Python 3.10+
- Flask 3.0+

## Installation

```bash
cd /opt/pr0t31n/Beacon
python3 install.py
```

First run generates:
- `ssl.crt` / `ssl.key` — self-signed TLS certificate
- `.auth.json` — dashboard credentials (default: `admin` / `t3mpPas$w0rd`, must change on first login)
- `beacon.db` — SQLite database

## Usage

```bash
python3 beacon.py [--port 9443] [--host 0.0.0.0] [--db beacon.db]
```

Dashboard: `https://<host>:9443`

## API

### Push status (Crucible → Beacon)

```
POST /api/status
Authorization: Bearer <token>
Content-Type: application/json

{
  "engagement_id": "uuid",
  "name": "Project Alpha",
  "client_name": "Acme Corp",
  "start_date": "2026-10-20T09:00:00",
  "end_date": "2026-10-25T17:00:00",
  "scopes": ["10.0.0.0/24"],
  "tools": { ... },
  "queue": [ ... ],
  "findings": {"CRITICAL": 2, "HIGH": 8, "MEDIUM": 15, "LOW": 23, "INFO": 41},
  "total_findings": 89,
  "timestamp": "2026-10-20T15:30:00"
}
```

First push with a new `engagement_id` registers the engagement. Subsequent pushes must use the same token.

### Generic webhook (any tool → Beacon)

```
POST /api/webhook
Authorization: Bearer <token>
Content-Type: application/json

{
  "source": "my-scanner",
  "task_id": "scan-001",
  "task_name": "Full network scan",
  "status": "running",
  "progress": 0.42,
  "message": "Phase 3/5 — service enumeration",
  "findings_summary": {"CRITICAL": 2, "HIGH": 5, "MEDIUM": 12, "LOW": 8, "INFO": 30}
}
```

Required fields: `source`, `task_id`, `status`. See `WEBHOOK_SPEC.md` for the full schema.

### Provider-specific webhooks

```
POST /api/webhook/<provider>
Authorization: Bearer <token>
```

Supported providers: `checkmarx`, `gophish`, `semgrep`, `sonarqube`, `snyk`. Each parses the tool's native webhook format. Configure `https://<beacon>:9443/api/webhook/<provider>` as the webhook URL in the tool's settings.

### Dashboard endpoints (session auth)

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Dashboard HTML |
| `/api/engagements` | GET | All active engagements + latest snapshot |
| `/api/engagement/<id>` | GET | Single engagement detail + 24h history |
| `/api/engagement/<id>` | DELETE | Remove engagement |
| `/api/webhook_sources` | GET | All active webhook sources + tasks |
| `/api/webhook_source/<id>` | DELETE | Remove webhook source |
| `/api/webhook/providers` | GET | List supported webhook providers |

## Crucible Integration

In Crucible's engagement settings, configure:
- **Status Server URL** — e.g. `https://beacon.local:9443`
- **Status Server Token** — shared secret for this engagement
- **Enable** — toggle status pushes on/off

Crucible pushes a full status snapshot every 60 seconds. If the connection is established after the engagement has already started, the first push includes all historical tool data.

## Auto-Cleanup

- Engagements with no push for 30 days are automatically deleted
- Snapshots older than 48 hours are pruned to 1-per-hour
- Cleanup runs every hour in a background thread

## Security

- TLS 1.2 minimum with ECDHE cipher suites
- Security headers: HSTS, CSP, X-Frame-Options DENY, nosniff
- Server-side session tokens with sliding expiry
- CSRF protection on all forms
- Bearer tokens SHA-256 hashed in database
