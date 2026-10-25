# Beacon

Engagement status server for the pr0t31n toolkit. Receives push updates from Crucible instances and presents a read-only dashboard showing live engagement progress.

## Features

- **Multi-engagement dashboard** — track multiple concurrent engagements from multiple Crucible instances
- **Pre-shared token auth** — TOFU-style registration; tokens SHA-256 hashed at rest
- **TLS 1.2+** — self-signed cert auto-generated on first run
- **Auto-cleanup** — engagements purge after 30 days of inactivity
- **Retroactive data** — late-connecting Crucible sends full history on first push
- **Spartan UI** — risk-severity pills, tool status table, 60s auto-refresh

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

### Dashboard endpoints (session auth)

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Dashboard HTML |
| `/api/engagements` | GET | All active engagements + latest snapshot |
| `/api/engagement/<id>` | GET | Single engagement detail + 24h history |
| `/api/engagement/<id>` | DELETE | Remove engagement |

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
