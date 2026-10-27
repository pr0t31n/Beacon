#!/usr/bin/env python3
"""Beacon — Engagement status server for pr0t31n Crucible.

Receives status pushes from one or more Crucible instances and presents
a spartan, read-only dashboard showing live engagement progress.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import (Flask, g, jsonify, redirect, render_template,
                   request, session, url_for)

import _auth

VERSION = Path(__file__).resolve().parent.joinpath("VERSION").read_text().strip()

log = logging.getLogger("beacon")

# ── App factory ───────────────────────────────────────────────────────────

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = _auth.load_secret_key()

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
"""


def _init_db(db_path: Path) -> None:
    with sqlite3.connect(str(db_path)) as conn:
        conn.executescript(_SCHEMA)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(engagements)").fetchall()}
        if "source_hostname" not in cols:
            conn.execute("ALTER TABLE engagements ADD COLUMN source_hostname TEXT DEFAULT ''")
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

_PUBLIC_API = {"/api/status", "/api/ping"}

@app.before_request
def _before():
    path = request.path
    if path.startswith("/static/"):
        return None
    if path in _PUBLIC_API:
        return None
    gate = _auth.auth_gate()
    if gate is not None:
        return gate
    return None


@app.after_request
def _after(response):
    return _auth.apply_security_headers(response)


# ── Auth routes (login / logout / change-password) ───────────────────────

auth_bp = _auth.make_auth_blueprint() if hasattr(_auth, "make_auth_blueprint") else None

# If _auth doesn't have a blueprint factory, build routes inline
if auth_bp is None:
    from flask import Blueprint
    auth_bp = Blueprint("auth", __name__)

    @auth_bp.route("/login", methods=["GET", "POST"])
    def login():
        error = None
        csrf = _auth.generate_csrf()
        if request.method == "POST":
            if not _auth.check_csrf(request.form.get("csrf_token")):
                error = "Invalid request token."
            else:
                username = request.form.get("username", "")
                password = request.form.get("password", "")
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
                error = "Invalid request token."
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


# ── API: Ping (bearer-token auth, no side effects) ────────────────────────

@app.route("/api/ping", methods=["POST"])
def api_ping():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401
    token = auth_header[7:].strip()
    if not token:
        return jsonify({"error": "Empty bearer token"}), 401
    return jsonify({"ok": True, "version": VERSION})


# ── API: Status push (bearer-token auth) ─────────────────────────────────

@app.route("/api/status", methods=["POST"])
def api_status():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401
    token = auth_header[7:].strip()
    if not token:
        return jsonify({"error": "Empty bearer token"}), 401
    token_h = _hash_token(token)

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid JSON payload"}), 400

    eng_id = data.get("engagement_id")
    if not eng_id or not isinstance(eng_id, str):
        return jsonify({"error": "Missing engagement_id"}), 400

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
            if row["token_hash"] != token_h:
                return jsonify({"error": "Token mismatch"}), 401
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
        return jsonify({"error": "Not found"}), 404

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
_CLEANUP_INTERVAL = 3600  # 1 hour

def _cleanup_loop():
    while True:
        time.sleep(_CLEANUP_INTERVAL)
        try:
            _run_cleanup()
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

            conn.commit()
            if deleted or remove_ids:
                conn.execute("VACUUM")
                log.info("cleanup: removed %d engagements, pruned %d snapshots",
                         deleted, len(remove_ids))
        finally:
            conn.close()


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    global _DB_PATH
    parser = argparse.ArgumentParser(description="Beacon — engagement status server")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--db", default=str(_DB_PATH))
    args = parser.parse_args()

    _DB_PATH = Path(args.db)

    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    _init_db(_DB_PATH)
    _auth.init_auth()

    cleanup = threading.Thread(target=_cleanup_loop, daemon=True)
    cleanup.start()

    print(f"\n  Beacon v{VERSION}")
    print(f"  https://{args.host}:{args.port}")
    print(f"  Database: {_DB_PATH}\n")

    ctx = _auth.make_ssl_context()
    app.run(host=args.host, port=args.port, ssl_context=ctx, threaded=True)


if __name__ == "__main__":
    main()
