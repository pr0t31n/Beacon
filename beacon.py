#!/usr/bin/env python3
"""Beacon — Engagement status server for pr0t31n toolkit.

Receives status pushes from Crucible instances and third-party security
tools via webhooks.  Presents a spartan, read-only dashboard showing
live engagement and scan progress.

Dual-port mode (default):
  --api-port 9443   External API (bearer-token auth only)
  --web-port 9444   Dashboard (session auth, localhost by default)

Single-port mode (legacy):
  --port 9443       All endpoints on one port
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import (Flask, g, jsonify, redirect, render_template,
                   request, session, url_for)
from werkzeug.serving import run_simple

import _auth
try:
    import webhook_parsers as _wp
except ImportError:
    _wp = None

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

_MAX_WEBHOOK_PAYLOAD = 1 * 1024 * 1024  # 1 MB

log = logging.getLogger("beacon")

# ── Dual-port configuration (set in main()) ──────────────────────────────

_API_PORT: int = 9443
_WEB_PORT: int = 9444
_DUAL_PORT: bool = True


def _detect_public_ip() -> str | None:
    import urllib.request
    for url in ("https://api.ipify.org",
                "https://checkip.amazonaws.com",
                "https://ifconfig.me",
                "https://icanhazip.com"):
        try:
            resp = urllib.request.urlopen(url, timeout=5)
            ip = resp.read().decode().strip()
            parts = ip.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return ip
        except Exception:
            continue
    return None

# ── App factory ───────────────────────────────────────────────────────────

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = _auth.load_secret_key()

# ── IP ban / strike tracker ──────────────────────────────────────────────

_BAN_STRIKES = 5
_BAN_DURATION = 300       # seconds
_GLOBAL_RATE_LIMIT = 60   # requests per window per IP
_RATE_WINDOW = 60         # seconds

_strike_lock = threading.Lock()
_ip_strikes: dict[str, list[float]] = {}
_ip_bans: dict[str, float] = {}
_ip_requests: dict[str, list[float]] = {}

_OPAQUE_BODY = b'{"status":"error"}\n'
_OPAQUE_CT = "application/json"


def _get_client_ip() -> str:
    return request.remote_addr or "0.0.0.0"


def _is_banned(ip: str) -> bool:
    with _strike_lock:
        expiry = _ip_bans.get(ip)
        if expiry is None:
            return False
        if time.time() < expiry:
            return True
        del _ip_bans[ip]
        _ip_strikes.pop(ip, None)
        return False


def _record_strike(ip: str) -> None:
    now = time.time()
    with _strike_lock:
        strikes = _ip_strikes.setdefault(ip, [])
        cutoff = now - _BAN_DURATION
        _ip_strikes[ip] = [t for t in strikes if t > cutoff]
        _ip_strikes[ip].append(now)
        if len(_ip_strikes[ip]) >= _BAN_STRIKES:
            _ip_bans[ip] = now + _BAN_DURATION
            log.warning("IP banned for %ds: %s (%d strikes)",
                        _BAN_DURATION, ip, len(_ip_strikes[ip]))


def _check_rate_limit(ip: str) -> bool:
    now = time.time()
    with _strike_lock:
        reqs = _ip_requests.setdefault(ip, [])
        cutoff = now - _RATE_WINDOW
        _ip_requests[ip] = [t for t in reqs if t > cutoff]
        if len(_ip_requests[ip]) >= _GLOBAL_RATE_LIMIT:
            return False
        _ip_requests[ip].append(now)
        return True


def _opaque(status: int = 403):
    from flask import Response
    return Response(_OPAQUE_BODY, status=status, content_type=_OPAQUE_CT)


def _evict_expired_entries() -> None:
    now = time.time()
    with _strike_lock:
        for ip in [k for k, v in _ip_bans.items() if v <= now]:
            del _ip_bans[ip]
            _ip_strikes.pop(ip, None)
        cutoff = now - _RATE_WINDOW
        for ip in [k for k, v in _ip_requests.items() if not v or v[-1] < cutoff]:
            del _ip_requests[ip]

# ── Login rate limiting ──────────────────────────────────────────────────

_LOGIN_LOCK = threading.Lock()
_login_attempts: dict[str, list[float]] = {}
_LOGIN_MAX = 5
_LOGIN_WINDOW = 300


def _check_login_rate(ip: str) -> bool:
    now = time.time()
    with _LOGIN_LOCK:
        attempts = _login_attempts.setdefault(ip, [])
        cutoff = now - _LOGIN_WINDOW
        _login_attempts[ip] = [t for t in attempts if t > cutoff]
        return len(_login_attempts[ip]) < _LOGIN_MAX


def _record_login_attempt(ip: str) -> None:
    with _LOGIN_LOCK:
        _login_attempts.setdefault(ip, []).append(time.time())

# ── Bearer token validation ──────────────────────────────────────────────

_BEARER_FILE = Path(__file__).resolve().parent / ".bearer_tokens.json"
_bearer_hashes: set[str] = set()
_bearer_lock = threading.Lock()


def _load_bearer_tokens() -> None:
    global _bearer_hashes
    if not _BEARER_FILE.exists():
        _bearer_hashes = set()
        return
    try:
        data = json.loads(_BEARER_FILE.read_text())
        if isinstance(data, list):
            _bearer_hashes = set(data)
        elif isinstance(data, dict):
            _bearer_hashes = set(data.get("hashes", []))
    except (json.JSONDecodeError, OSError):
        _bearer_hashes = set()


def _persist_bearer_tokens() -> None:
    try:
        tmp = _BEARER_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps({"hashes": sorted(_bearer_hashes)}))
        tmp.replace(_BEARER_FILE)
        _BEARER_FILE.chmod(0o600)
    except OSError:
        pass


def register_bearer_token(token: str) -> str:
    h = _hash_token(token)
    with _bearer_lock:
        _bearer_hashes.add(h)
        _persist_bearer_tokens()
    return h


def _validate_bearer(token: str) -> bool:
    if not _bearer_hashes:
        return True
    h = _hash_token(token)
    with _bearer_lock:
        for stored in _bearer_hashes:
            if hmac.compare_digest(h, stored):
                return True
    return False

# ── Database ──────────────────────────────────────────────────────────────

_DB_PATH: Path = Path(__file__).resolve().parent / "beacon.db"
_db_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    client_name   TEXT NOT NULL,
    token_hash    TEXT NOT NULL,
    source_ip     TEXT,
    source_hostname TEXT DEFAULT '',
    start_date    TEXT,
    end_date      TEXT,
    created_at    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    active        INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id   TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    received_at     TEXT NOT NULL,
    snapshot_json   TEXT NOT NULL,
    UNIQUE(engagement_id, received_at)
);

CREATE INDEX IF NOT EXISTS idx_snapshots_eng
    ON snapshots(engagement_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_engagements_last_seen
    ON engagements(last_seen);

CREATE TABLE IF NOT EXISTS webhook_sources (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    provider      TEXT NOT NULL DEFAULT 'generic',
    token_hash    TEXT NOT NULL,
    source_ip     TEXT,
    created_at    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    active        INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS webhook_tasks (
    id            TEXT NOT NULL,
    source_id     TEXT NOT NULL REFERENCES webhook_sources(id) ON DELETE CASCADE,
    task_name     TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'unknown',
    progress      REAL,
    started_at    TEXT,
    ended_at      TEXT,
    message       TEXT DEFAULT '',
    findings_json TEXT,
    metadata_json TEXT DEFAULT '{}',
    first_seen    TEXT NOT NULL,
    last_updated  TEXT NOT NULL,
    PRIMARY KEY (source_id, id)
);

CREATE INDEX IF NOT EXISTS idx_webhook_tasks_source
    ON webhook_tasks(source_id, last_updated DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_sources_last_seen
    ON webhook_sources(last_seen);
"""


def _init_db(db_path: Path) -> None:
    with sqlite3.connect(str(db_path)) as conn:
        conn.executescript(_SCHEMA)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(engagements)").fetchall()}
        if "source_hostname" not in cols:
            conn.execute("ALTER TABLE engagements ADD COLUMN source_hostname TEXT DEFAULT ''")
            conn.commit()
        tables = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        if "webhook_sources" not in tables or "webhook_tasks" not in tables:
            conn.executescript(_SCHEMA)
            conn.commit()


def _get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(str(_DB_PATH))
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def _close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

# ── Helpers ───────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _relative_time(iso_str: str) -> str:
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - dt
        secs = int(delta.total_seconds())
        if secs < 60:
            return "just now"
        if secs < 3600:
            m = secs // 60
            return f"{m} min ago"
        if secs < 86400:
            h = secs // 3600
            return f"{h}h ago"
        d = secs // 86400
        return f"{d}d ago"
    except Exception:
        return iso_str or "—"


app.jinja_env.globals["relative_time"] = _relative_time

# ── Security middleware ───────────────────────────────────────────────────

_LOGIN_PATHS = {"/auth/login", "/auth/logout", "/auth/session-expired",
                "/auth/change-password"}
_BEARER_API = {"/api/status", "/api/ping"}


@app.before_request
def _before():
    ip = _get_client_ip()

    if _is_banned(ip):
        return _opaque()

    if not _check_rate_limit(ip):
        _record_strike(ip)
        return _opaque(429)

    path = request.path
    port = int(request.environ.get("SERVER_PORT", 0))

    if _DUAL_PORT and port == _API_PORT:
        if path in _BEARER_API or path == "/api/webhook" or path.startswith("/api/webhook/"):
            return None
        _record_strike(ip)
        return _opaque(404)

    if path.startswith("/static/"):
        return None
    if path in _LOGIN_PATHS:
        return None
    if path in _BEARER_API or path == "/api/webhook" or path.startswith("/api/webhook/"):
        return None

    gate = _auth.auth_gate()
    if gate is not None:
        return gate
    return None


@app.after_request
def _after(response):
    response = _auth.apply_security_headers(response)
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)
    return response

# ── Custom error handlers ────────────────────────────────────────────────

@app.errorhandler(404)
def _err_404(e):
    _record_strike(_get_client_ip())
    return _opaque(404)


@app.errorhandler(405)
def _err_405(e):
    _record_strike(_get_client_ip())
    return _opaque(405)


@app.errorhandler(500)
def _err_500(e):
    return _opaque(500)

# ── Auth routes (login / logout / change-password) ───────────────────────

auth_bp = _auth.make_auth_blueprint() if hasattr(_auth, "make_auth_blueprint") else None

if auth_bp is None:
    from flask import Blueprint
    auth_bp = Blueprint("auth", __name__)

    @auth_bp.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        csrf = _auth.generate_csrf()
        ip = _get_client_ip()
        if request.method == "POST":
            if not _check_login_rate(ip):
                error = "Too many attempts. Try again later."
            elif not _auth.check_csrf(request.form.get("csrf_token")):
                error = "Invalid request."
            else:
                username = request.form.get("username", "")
                password = request.form.get("password", "")
                _record_login_attempt(ip)
                if _auth.verify_credentials(username, password):
                    _auth.validate_csrf(request.form.get("csrf_token"))
                    session["authenticated"] = True
                    session["username"] = username
                    session["session_token"] = _auth.create_session_token()
                    return redirect(url_for("dashboard"))
                error = "Invalid credentials."
        return render_template("login.html", error=error, csrf_token=csrf)

    @auth_bp.route("/logout")
    def logout():
        _auth.revoke_session_token(session.get("session_token"))
        session.clear()
        return redirect(url_for("auth.login"))

    @auth_bp.route("/session-expired")
    def session_expired():
        return redirect(url_for("auth.login"))

    @auth_bp.route("/change-password", methods=["GET", "POST"])
    def change_password():
        error = None
        success = None
        csrf = _auth.generate_csrf()
        if request.method == "POST":
            if not _auth.check_csrf(request.form.get("csrf_token")):
                error = "Invalid request."
            else:
                _auth.validate_csrf(request.form.get("csrf_token"))
                current = request.form.get("current_password", "")
                new_user = request.form.get("new_username", "").strip()
                new_pass = request.form.get("new_password", "")
                confirm = request.form.get("confirm_password", "")
                if not _auth.check_current_password(current):
                    error = "Current password is incorrect."
                elif new_pass != confirm:
                    error = "Passwords do not match."
                elif len(new_pass) < 10:
                    error = "Password must be at least 10 characters."
                else:
                    pw_err = _auth.is_weak_password(new_pass, new_user or _auth.get_username())
                    if pw_err:
                        error = pw_err
                    elif new_user:
                        un_err = _auth.is_weak_username(new_user)
                        if un_err:
                            error = un_err
                        else:
                            _auth.update_credentials(new_user, new_pass)
                            session["username"] = new_user
                            success = "Credentials updated."
                    else:
                        _auth.update_password(new_pass)
                        success = "Password updated."
                csrf = _auth.generate_csrf()
        return render_template("change_password.html", error=error,
                               success=success, csrf_token=csrf,
                               must_change=_auth.must_change_password(),
                               current_username=_auth.get_username())

app.register_blueprint(auth_bp, url_prefix="/auth")

# ── Opaque bearer auth ──────────────────────────────────────────────────

def _auth_bearer_opaque():
    ip = _get_client_ip()
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        _record_strike(ip)
        return None, _opaque(403)
    token = auth_header[7:].strip()
    if not token:
        _record_strike(ip)
        return None, _opaque(403)
    if not _validate_bearer(token):
        _record_strike(ip)
        return None, _opaque(403)
    return token, None

# ── API: Ping ────────────────────────────────────────────────────────────

@app.route("/api/ping", methods=["POST"])
def api_ping():
    _, err = _auth_bearer_opaque()
    if err:
        return err
    return jsonify({"ok": True})

# ── API: Status push ─────────────────────────────────────────────────────

@app.route("/api/status", methods=["POST"])
def api_status():
    token, err = _auth_bearer_opaque()
    if err:
        return err
    token_h = _hash_token(token)

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        _record_strike(_get_client_ip())
        return _opaque(400)

    eng_id = data.get("engagement_id")
    if not eng_id or not isinstance(eng_id, str):
        _record_strike(_get_client_ip())
        return _opaque(400)

    name = str(data.get("name", ""))[:200]
    client = str(data.get("client_name", ""))[:200]
    now = _now_iso()
    source_ip = request.remote_addr or ""
    source_hostname = str(data.get("source_hostname", ""))[:253]

    with _db_lock:
        db = _get_db()
        row = db.execute("SELECT token_hash FROM engagements WHERE id = ?",
                         (eng_id,)).fetchone()
        if row is None:
            db.execute(
                "INSERT INTO engagements "
                "(id, name, client_name, token_hash, source_ip, source_hostname, "
                "start_date, end_date, created_at, last_seen)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (eng_id, name, client, token_h, source_ip, source_hostname,
                 str(data.get("start_date", ""))[:30],
                 str(data.get("end_date", ""))[:30],
                 now, now),
            )
        else:
            if not hmac.compare_digest(row["token_hash"], token_h):
                _record_strike(_get_client_ip())
                return _opaque(403)
            db.execute(
                "UPDATE engagements SET name=?, client_name=?, source_ip=?, "
                "source_hostname=?, start_date=?, end_date=?, last_seen=?, "
                "active=1 WHERE id=?",
                (name, client, source_ip, source_hostname,
                 str(data.get("start_date", ""))[:30],
                 str(data.get("end_date", ""))[:30],
                 now, eng_id),
            )

        snapshot = json.dumps(data, default=str)
        db.execute(
            "INSERT OR REPLACE INTO snapshots (engagement_id, received_at, snapshot_json)"
            " VALUES (?, ?, ?)",
            (eng_id, now, snapshot),
        )
        db.commit()

    return jsonify({"status": "ok", "received_at": now}), 200

# ── API: Webhook receiver ────────────────────────────────────────────────

_VALID_STATUSES = {"queued", "running", "paused", "complete", "failed", "cancelled", "unknown"}


def _upsert_webhook_source(db, token_hash, provider, source_name, source_ip, now):
    row = db.execute(
        "SELECT id, token_hash FROM webhook_sources WHERE token_hash = ?",
        (token_hash,)).fetchone()
    if row is not None:
        db.execute(
            "UPDATE webhook_sources SET last_seen=?, source_ip=?, active=1 WHERE id=?",
            (now, source_ip, row["id"]))
        return row["id"]
    src_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO webhook_sources (id, name, provider, token_hash, source_ip, "
        "created_at, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (src_id, source_name[:200], provider, token_hash, source_ip, now, now))
    return src_id


def _upsert_webhook_task(db, source_id, parsed, now):
    task_id = str(parsed.get("task_id", ""))[:500]
    if not task_id:
        return
    status = parsed.get("status", "unknown")
    if status not in _VALID_STATUSES:
        status = "unknown"
    findings = parsed.get("findings_summary")
    findings_j = json.dumps(findings, default=str) if findings else None
    meta_j = json.dumps(parsed.get("metadata", {}), default=str)[:65536]

    existing = db.execute(
        "SELECT id FROM webhook_tasks WHERE source_id=? AND id=?",
        (source_id, task_id)).fetchone()
    if existing:
        db.execute(
            "UPDATE webhook_tasks SET task_name=?, status=?, progress=?, "
            "started_at=COALESCE(?, started_at), ended_at=?, message=?, "
            "findings_json=COALESCE(?, findings_json), metadata_json=?, "
            "last_updated=? WHERE source_id=? AND id=?",
            (str(parsed.get("task_name", ""))[:500], status,
             parsed.get("progress"), parsed.get("started_at"),
             parsed.get("ended_at"), str(parsed.get("message", ""))[:2000],
             findings_j, meta_j, now, source_id, task_id))
    else:
        db.execute(
            "INSERT INTO webhook_tasks (id, source_id, task_name, status, progress, "
            "started_at, ended_at, message, findings_json, metadata_json, "
            "first_seen, last_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (task_id, source_id, str(parsed.get("task_name", ""))[:500],
             status, parsed.get("progress"), parsed.get("started_at"),
             parsed.get("ended_at"), str(parsed.get("message", ""))[:2000],
             findings_j, meta_j, now, now))


def _process_webhook(provider):
    token, err = _auth_bearer_opaque()
    if err:
        return err

    ip = _get_client_ip()
    cl = request.content_length or 0
    if cl > _MAX_WEBHOOK_PAYLOAD:
        _record_strike(ip)
        return _opaque(413)

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        _record_strike(ip)
        return _opaque(400)

    if _wp is None and provider != "generic":
        _record_strike(ip)
        return _opaque(400)

    if provider == "generic":
        parsed = {
            "source": str(data.get("source", "generic"))[:200],
            "source_version": str(data.get("source_version", ""))[:50],
            "task_id": data.get("task_id"),
            "task_name": data.get("task_name", ""),
            "status": data.get("status", "unknown"),
            "progress": data.get("progress"),
            "started_at": data.get("started_at"),
            "ended_at": data.get("ended_at"),
            "message": data.get("message", ""),
            "findings_summary": data.get("findings_summary"),
            "metadata": data.get("metadata", {}),
        }
        if not parsed["task_id"]:
            _record_strike(ip)
            return _opaque(400)
    else:
        parsed = _wp.parse(provider, data)
        if parsed is None:
            _record_strike(ip)
            return _opaque(400)

    token_h = _hash_token(token)
    now = _now_iso()
    source_ip = request.remote_addr or ""
    source_name = str(parsed.get("source", provider))[:200]

    with _db_lock:
        db = _get_db()
        src_id = _upsert_webhook_source(db, token_h, provider, source_name, source_ip, now)
        _upsert_webhook_task(db, src_id, parsed, now)
        db.commit()

    return jsonify({"status": "ok", "source_id": src_id, "received_at": now}), 200


@app.route("/api/webhook", methods=["POST"])
def api_webhook_generic():
    return _process_webhook("generic")


@app.route("/api/webhook/<provider>", methods=["POST"])
def api_webhook_provider(provider):
    if _wp is None or provider not in _wp.PARSERS:
        _record_strike(_get_client_ip())
        return _opaque(400)
    return _process_webhook(provider)

# ── API: Webhook source management (session auth) ────────────────────────

@app.route("/api/webhook_sources")
def api_webhook_sources():
    db = _get_db()
    rows = db.execute(
        "SELECT * FROM webhook_sources WHERE active=1 ORDER BY last_seen DESC"
    ).fetchall()
    result = []
    for r in rows:
        tasks = db.execute(
            "SELECT * FROM webhook_tasks WHERE source_id=? "
            "ORDER BY CASE status "
            "  WHEN 'running' THEN 0 WHEN 'queued' THEN 1 WHEN 'paused' THEN 2 "
            "  WHEN 'unknown' THEN 3 WHEN 'complete' THEN 4 WHEN 'failed' THEN 5 "
            "  WHEN 'cancelled' THEN 6 ELSE 9 END, last_updated DESC",
            (r["id"],)).fetchall()
        task_list = []
        for t in tasks:
            findings = None
            if t["findings_json"]:
                try:
                    findings = json.loads(t["findings_json"])
                except (json.JSONDecodeError, TypeError):
                    pass
            task_list.append({
                "id": t["id"],
                "task_name": t["task_name"],
                "status": t["status"],
                "progress": t["progress"],
                "started_at": t["started_at"],
                "ended_at": t["ended_at"],
                "message": t["message"],
                "findings_summary": findings,
                "last_updated": t["last_updated"],
            })
        prov_name = r["provider"]
        if _wp and hasattr(_wp, "PROVIDER_NAMES"):
            prov_name = _wp.PROVIDER_NAMES.get(r["provider"], r["provider"])
        result.append({
            "id": r["id"],
            "name": r["name"],
            "provider": r["provider"],
            "provider_name": prov_name,
            "source_ip": r["source_ip"],
            "last_seen": r["last_seen"],
            "created_at": r["created_at"],
            "tasks": task_list,
        })
    return jsonify(result)


@app.route("/api/webhook_source/<source_id>", methods=["DELETE"])
def api_webhook_source_delete(source_id):
    with _db_lock:
        db = _get_db()
        db.execute("DELETE FROM webhook_tasks WHERE source_id=?", (source_id,))
        db.execute("DELETE FROM webhook_sources WHERE id=?", (source_id,))
        db.commit()
    return jsonify({"status": "deleted"}), 200


@app.route("/api/webhook/providers")
def api_webhook_providers():
    if _wp is None:
        return jsonify({"providers": {"generic": "Generic"}})
    return jsonify({"providers": _wp.PROVIDER_NAMES})

# ── API: Dashboard data (session auth) ───────────────────────────────────

@app.route("/api/engagements")
def api_engagements():
    db = _get_db()
    rows = db.execute(
        "SELECT e.*, s.snapshot_json FROM engagements e "
        "LEFT JOIN snapshots s ON s.engagement_id = e.id "
        "AND s.received_at = (SELECT MAX(s2.received_at) FROM snapshots s2 "
        "WHERE s2.engagement_id = e.id) "
        "WHERE e.active = 1 ORDER BY e.last_seen DESC"
    ).fetchall()
    result = []
    for r in rows:
        snap = {}
        if r["snapshot_json"]:
            try:
                snap = json.loads(r["snapshot_json"])
            except (json.JSONDecodeError, TypeError):
                pass
        result.append({
            "id": r["id"],
            "name": r["name"],
            "client_name": r["client_name"],
            "start_date": r["start_date"],
            "end_date": r["end_date"],
            "last_seen": r["last_seen"],
            "source_ip": r["source_ip"],
            "source_hostname": r["source_hostname"] or "",
            "snapshot": snap,
        })
    return jsonify(result)


@app.route("/api/engagement/<eng_id>")
def api_engagement_detail(eng_id):
    db = _get_db()
    eng = db.execute("SELECT * FROM engagements WHERE id = ?",
                     (eng_id,)).fetchone()
    if eng is None:
        return _opaque(404)

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    snaps = db.execute(
        "SELECT received_at, snapshot_json FROM snapshots "
        "WHERE engagement_id = ? AND received_at >= ? "
        "ORDER BY received_at DESC",
        (eng_id, cutoff),
    ).fetchall()

    history = []
    for s in snaps:
        try:
            history.append({
                "received_at": s["received_at"],
                "data": json.loads(s["snapshot_json"]),
            })
        except (json.JSONDecodeError, TypeError):
            pass

    return jsonify({
        "id": eng["id"],
        "name": eng["name"],
        "client_name": eng["client_name"],
        "start_date": eng["start_date"],
        "end_date": eng["end_date"],
        "last_seen": eng["last_seen"],
        "source_ip": eng["source_ip"],
        "source_hostname": eng["source_hostname"] or "",
        "created_at": eng["created_at"],
        "history": history,
    })


@app.route("/api/engagement/<eng_id>", methods=["DELETE"])
def api_engagement_delete(eng_id):
    with _db_lock:
        db = _get_db()
        db.execute("DELETE FROM snapshots WHERE engagement_id = ?", (eng_id,))
        db.execute("DELETE FROM engagements WHERE id = ?", (eng_id,))
        db.commit()
    return jsonify({"status": "deleted"}), 200

# ── Dashboard ─────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("dashboard.html", version=VERSION)

# ── Auto-cleanup ──────────────────────────────────────────────────────────

_TTL_DAYS = 30
_PRUNE_HOURS = 48
_CLEANUP_INTERVAL = 3600

def _cleanup_loop():
    while True:
        time.sleep(_CLEANUP_INTERVAL)
        try:
            _run_cleanup()
            _evict_expired_entries()
        except Exception as exc:
            log.warning("cleanup error: %s", exc)


def _run_cleanup():
    cutoff_ttl = (datetime.now(timezone.utc) - timedelta(days=_TTL_DAYS)).isoformat()
    cutoff_prune = (datetime.now(timezone.utc) - timedelta(hours=_PRUNE_HOURS)).isoformat()

    with _db_lock:
        conn = sqlite3.connect(str(_DB_PATH))
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            deleted = conn.execute(
                "DELETE FROM engagements WHERE last_seen < ?", (cutoff_ttl,)
            ).rowcount

            rows = conn.execute(
                "SELECT id, engagement_id, received_at FROM snapshots "
                "WHERE received_at < ? ORDER BY engagement_id, received_at",
                (cutoff_prune,),
            ).fetchall()

            keep_ids = set()
            current_eng = None
            current_hour = None
            for sid, eid, rat in rows:
                hour = rat[:13]
                if eid != current_eng or hour != current_hour:
                    keep_ids.add(sid)
                    current_eng = eid
                    current_hour = hour

            remove_ids = [r[0] for r in rows if r[0] not in keep_ids]
            if remove_ids:
                placeholders = ",".join("?" * len(remove_ids))
                conn.execute(
                    f"DELETE FROM snapshots WHERE id IN ({placeholders})",
                    remove_ids,
                )

            wh_deleted = conn.execute(
                "DELETE FROM webhook_sources WHERE last_seen < ?", (cutoff_ttl,)
            ).rowcount
            wh_tasks = conn.execute(
                "DELETE FROM webhook_tasks WHERE last_updated < ?", (cutoff_ttl,)
            ).rowcount

            conn.commit()
            if deleted or remove_ids or wh_deleted:
                conn.execute("VACUUM")
                log.info("cleanup: removed %d engagements, pruned %d snapshots, "
                         "removed %d webhook sources, %d webhook tasks",
                         deleted, len(remove_ids), wh_deleted, wh_tasks)
        finally:
            conn.close()

# ── Main ──────────────────────────────────────────────────────────────────

def main():
    global _DB_PATH, _API_PORT, _WEB_PORT, _DUAL_PORT
    parser = argparse.ArgumentParser(description="Beacon")
    parser.add_argument("--port", type=int, default=None,
                        help="Single-port mode (API + dashboard on one port)")
    parser.add_argument("--api-port", type=int, default=9443,
                        help="API port (bearer-token endpoints, default 9443)")
    parser.add_argument("--web-port", type=int, default=9444,
                        help="Dashboard port (session-auth, default 9444)")
    parser.add_argument("--web-host", default="127.0.0.1",
                        help="Dashboard bind address (default 127.0.0.1)")
    parser.add_argument("--host", default="0.0.0.0",
                        help="API bind address (default 0.0.0.0)")
    parser.add_argument("--db", default=str(_DB_PATH))
    parser.add_argument("--register-token", metavar="TOKEN",
                        help="Register a bearer token and exit")
    args = parser.parse_args()

    _DB_PATH = Path(args.db)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    _init_db(_DB_PATH)
    _auth.init_auth()
    _load_bearer_tokens()

    if args.register_token:
        h = register_bearer_token(args.register_token)
        print(f"Token registered (hash: {h[:12]}...)")
        print(f"Total tokens: {len(_bearer_hashes)}")
        return

    if args.port is not None:
        _API_PORT = args.port
        _WEB_PORT = args.port
        _DUAL_PORT = False
    else:
        _API_PORT = args.api_port
        _WEB_PORT = args.web_port
        _DUAL_PORT = _API_PORT != _WEB_PORT

    cleanup = threading.Thread(target=_cleanup_loop, daemon=True)
    cleanup.start()

    pub_ip = _detect_public_ip()
    ctx = _auth.make_ssl_context(extra_ips=[pub_ip] if pub_ip else None)

    wp_count = len(_wp.PARSERS) if _wp else 0
    print(f"\n  Beacon v{VERSION}")
    if _DUAL_PORT:
        print(f"  API:       https://{args.host}:{_API_PORT}  (external)")
        print(f"  Dashboard: https://{args.web_host}:{_WEB_PORT}  (local)")
    else:
        print(f"  https://{args.host}:{_API_PORT}")
    print(f"  Database:  {_DB_PATH}")
    if pub_ip:
        print(f"  Public IP: {pub_ip}")
    print(f"  Webhooks:  {wp_count} providers" if wp_count else
          "  Webhooks:  generic only")
    if _bearer_hashes:
        print(f"  Tokens:    {len(_bearer_hashes)} registered")
    else:
        print("  Tokens:    none (all bearer tokens accepted)")
    print()

    if _DUAL_PORT:
        def _run_api():
            run_simple(args.host, _API_PORT, app, ssl_context=ctx,
                       threaded=True, use_reloader=False)

        api_thread = threading.Thread(target=_run_api, daemon=True)
        api_thread.start()
        run_simple(args.web_host, _WEB_PORT, app, ssl_context=ctx,
                   threaded=True, use_reloader=False)
    else:
        app.run(host=args.host, port=_API_PORT, ssl_context=ctx, threaded=True)


if __name__ == "__main__":
    main()
