"""_auth.py — Authentication, TLS and security hardening for pr0t31n Flask apps.

Drop this file into any app directory. It self-references its own location so
all credential / cert / key files land in the same folder as app.py.
"""
from __future__ import annotations

import json
import os
import secrets
import ssl
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from flask import redirect, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

# ── Directory (same folder this file lives in, i.e. the app root) ────────────
_DIR = Path(__file__).parent.resolve()

_DEFAULT_USERNAME = "admin"
_DEFAULT_PASSWORD = "t3mpPas$w0rd"

# ── Credential policy ─────────────────────────────────────────────────────────

_BLOCKED_USERNAMES: frozenset = frozenset({
    "admin", "administrator", "root", "user", "users", "guest", "test",
    "demo", "superuser", "super", "sysadmin", "operator", "manager",
    "owner", "service", "support", "helpdesk", "webmaster", "postmaster",
    "nobody", "default", "anonymous", "anon", "public", "system",
    "login", "logon", "access", "account", "info", "mail", "noreply",
})

_BLOCKED_PASSWORDS: frozenset = frozenset({
    "password", "password1", "password123", "passwords",
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "qwerty", "qwerty123", "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "abc123", "letmein", "welcome", "welcome1", "welcome123",
    "admin", "admin123", "admin1234", "administrator",
    "changeme", "change_me", "changeme1", "iloveyou",
    "monkey", "dragon", "master", "shadow", "sunshine",
    "princess", "superman", "batman", "trustno1",
    "baseball", "football", "soccer", "hockey", "hockey1",
    "pass", "pass123", "pass1234", "passw0rd",
    "test", "test123", "test1234", "testing",
    "guest", "login", "logon", "access",
    "t3mppass", _DEFAULT_PASSWORD.lower(),
})

def is_weak_username(username: str) -> Optional[str]:
    """Return an error string if the username is invalid, else None."""
    if not username:
        return "Username cannot be empty."
    if len(username) < 3:
        return "Username must be at least 3 characters."
    if len(username) > 32:
        return "Username must be 32 characters or fewer."
    if username.lower() in _BLOCKED_USERNAMES:
        return f"'{username}' is not allowed. Choose a unique username."
    return None

def is_weak_password(password: str, username: str = "") -> Optional[str]:
    """Return an error string if the password is too common or matches the username, else None."""
    if password.lower() in _BLOCKED_PASSWORDS:
        return "That password is too common. Choose a stronger password."
    if username and password.lower() == username.lower():
        return "Password cannot be the same as the username."
    return None

# ── Persistent secret key ─────────────────────────────────────────────────────

def load_secret_key() -> str:
    """Return a persistent 64-hex-char secret key, creating the file on first run."""
    key_file = _DIR / ".secret_key"
    if key_file.exists():
        key = key_file.read_text().strip()
        if len(key) >= 32:
            return key
    key = secrets.token_hex(32)
    key_file.write_text(key + "\n")
    key_file.chmod(0o600)
    return key

# ── Credential store ──────────────────────────────────────────────────────────

_AUTH_FILE = _DIR / ".auth.json"

def init_auth() -> None:
    """Create default credentials if the auth file does not exist."""
    if not _AUTH_FILE.exists():
        _write_auth({
            "username": _DEFAULT_USERNAME,
            "password_hash": generate_password_hash(_DEFAULT_PASSWORD),
            "must_change": True,
        })
    _load_session_tokens()

def _load_auth() -> dict:
    return json.loads(_AUTH_FILE.read_text())

def _write_auth(data: dict) -> None:
    _AUTH_FILE.write_text(json.dumps(data, indent=2))
    _AUTH_FILE.chmod(0o600)

def verify_credentials(username: str, password: str) -> bool:
    try:
        data = _load_auth()
        return (data.get("username") == username and
                check_password_hash(data.get("password_hash", ""), password))
    except Exception:
        return False

def is_default_credentials(username: str, password: str) -> bool:
    return username == _DEFAULT_USERNAME and password == _DEFAULT_PASSWORD

def is_blocked_username(username: str) -> bool:
    return username.lower() in _BLOCKED_USERNAMES

def is_blocked_password(password: str) -> bool:
    return password.lower() in _BLOCKED_PASSWORDS

def must_change_password() -> bool:
    try:
        return bool(_load_auth().get("must_change"))
    except Exception:
        return False

def get_username() -> str:
    try:
        return _load_auth().get("username", "admin")
    except Exception:
        return "admin"

def check_current_password(password: str) -> bool:
    try:
        return check_password_hash(_load_auth().get("password_hash", ""), password)
    except Exception:
        return False

def update_password(new_password: str) -> None:
    data = _load_auth()
    data["password_hash"] = generate_password_hash(new_password)
    data["must_change"] = False
    _write_auth(data)

def update_credentials(new_username: str, new_password: str) -> None:
    """Replace username and password atomically. Clears must_change flag."""
    _write_auth({
        "username": new_username,
        "password_hash": generate_password_hash(new_password),
        "must_change": False,
    })

# ── CSRF (server-side synchronizer token, persisted to survive restarts) ─────

_CSRF_FILE = _DIR / ".csrf_tokens.json"
_csrf_store: dict = {}
_csrf_lock = threading.Lock()

def _load_csrf_store() -> None:
    global _csrf_store
    try:
        if _CSRF_FILE.exists():
            data = json.loads(_CSRF_FILE.read_text())
            now = time.time()
            _csrf_store = {t: exp for t, exp in data.items()
                          if isinstance(exp, (int, float)) and exp > now}
    except (json.JSONDecodeError, OSError):
        _csrf_store = {}

def _persist_csrf_store() -> None:
    try:
        _CSRF_FILE.write_text(json.dumps(_csrf_store))
        _CSRF_FILE.chmod(0o600)
    except OSError:
        pass

_load_csrf_store()

def generate_csrf() -> str:
    """Issue a one-time CSRF token stored server-side (no cookie/session needed)."""
    token = secrets.token_hex(16)
    now = time.time()
    with _csrf_lock:
        expired = [t for t, exp in list(_csrf_store.items()) if exp < now]
        for t in expired:
            del _csrf_store[t]
        _csrf_store[token] = now + 3600   # valid for 1 hour
        _persist_csrf_store()
    return token

def validate_csrf(token: Optional[str]) -> bool:
    """Consume and validate a CSRF token from the server-side store."""
    if not token:
        return False
    with _csrf_lock:
        expiry = _csrf_store.pop(token, None)
        if expiry is not None:
            _persist_csrf_store()
    if expiry is None:
        return False
    return time.time() < expiry

def check_csrf(token: Optional[str]) -> bool:
    """Validate a CSRF token WITHOUT consuming it (for login page)."""
    if not token:
        return False
    with _csrf_lock:
        expiry = _csrf_store.get(token)
    if expiry is None:
        return False
    return time.time() < expiry

# ── TLS ───────────────────────────────────────────────────────────────────────

_CIPHERS = (
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!SRP:!3DES"
)

def _local_ips_for_cert(extra_ips=None, extra_dns=None) -> str:
    """Return a comma-separated SAN string covering all local IPv4 addresses."""
    ips: set = {"127.0.0.1"}
    dns_names: set = {"localhost"}
    if extra_ips:
        ips.update(extra_ips)
    if extra_dns:
        dns_names.update(extra_dns)
    try:
        if os.path.exists("/sbin/ip") or os.path.exists("/usr/sbin/ip"):
            out = subprocess.check_output(["ip", "-4", "addr"], text=True, timeout=5)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    ip = line.split()[1].split("/")[0]
                    if not ip.startswith("127."):
                        ips.add(ip)
        else:
            out = subprocess.check_output(["ifconfig"], text=True, timeout=5)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet ") and "127.0.0.1" not in line:
                    parts = line.split()
                    idx = parts.index("inet") + 1
                    ip = parts[idx]
                    if not ip.startswith("127."):
                        ips.add(ip)
    except Exception:
        pass
    parts = [f"IP:{ip}" for ip in sorted(ips)]
    parts.extend(f"DNS:{d}" for d in sorted(dns_names))
    return ",".join(parts)


def _read_cert_sans(cert_path) -> tuple[set, set]:
    """Read IP and DNS SANs from an existing certificate."""
    ips, dns_names = set(), set()
    try:
        out = subprocess.check_output(
            ["openssl", "x509", "-noout", "-ext", "subjectAltName",
             "-in", str(cert_path)],
            text=True, timeout=5, stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            for part in line.split(","):
                part = part.strip()
                if part.startswith("IP Address:"):
                    ips.add(part.split(":", 1)[1].strip())
                elif part.startswith("DNS:"):
                    dns_names.add(part.split(":", 1)[1].strip())
    except Exception:
        pass
    return ips, dns_names


def make_ssl_context(extra_ips=None, extra_dns=None) -> ssl.SSLContext:
    """Return a hardened SSLContext, generating a self-signed cert if absent or stale."""
    cert = _DIR / "ssl.crt"
    key  = _DIR / "ssl.key"
    san = _local_ips_for_cert(extra_ips=extra_ips, extra_dns=extra_dns)
    if cert.exists() and key.exists():
        cert_ips, cert_dns = _read_cert_sans(cert)
        required_ips = {p.split(":", 1)[1] for p in san.split(",") if p.startswith("IP:")}
        required_dns = {p.split(":", 1)[1] for p in san.split(",") if p.startswith("DNS:")}
        if not required_ips.issubset(cert_ips) or not required_dns.issubset(cert_dns):
            cert.unlink(missing_ok=True)
            key.unlink(missing_ok=True)
    if not cert.exists() or not key.exists():
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:4096",
                "-nodes", "-days", "3650",
                "-keyout", str(key), "-out", str(cert),
                "-subj", "/C=US/ST=Local/L=Local/O=pr0t31n/CN=localhost",
                "-addext", f"subjectAltName={san}",
            ],
            check=True, capture_output=True,
        )
        key.chmod(0o600)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        ctx.set_ciphers(_CIPHERS)
    except ssl.SSLError:
        pass  # fall back to platform defaults if the cipher string is rejected
    return ctx

# ── Security headers ──────────────────────────────────────────────────────────

_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'self'; "
    "form-action 'self'"
)

def apply_security_headers(response):
    h = response.headers
    h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    h["Content-Security-Policy"]   = _CSP
    h["X-Frame-Options"]           = "DENY"
    h["X-Content-Type-Options"]    = "nosniff"
    h["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    h["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
    h["X-XSS-Protection"]          = "1; mode=block"
    # Prevent browsers from caching HTML pages — a cached login page
    # carries a stale CSRF token, causing the first login attempt after
    # session timeout to fail with "Invalid request token."
    h["Cache-Control"]             = "no-store, no-cache, must-revalidate, max-age=0"
    h["Pragma"]                    = "no-cache"
    return response

# ── Request gate ──────────────────────────────────────────────────────────────

_PUBLIC = {"/auth/login", "/auth/logout", "/auth/session-expired", "/auth/change-password", "/api/status", "/api/ping"}

# ── Server-side session tokens ───────────────────────────────────────────────
_session_tokens: dict = {}
_session_lock = threading.Lock()
_SESSION_TOKENS_FILE = _DIR / ".session_tokens.json"

def _persist_session_tokens() -> None:
    """Save session tokens to disk for crash recovery."""
    try:
        tmp = _SESSION_TOKENS_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(_session_tokens))
        tmp.replace(_SESSION_TOKENS_FILE)
    except OSError:
        pass

def _load_session_tokens() -> None:
    """Load persisted session tokens on startup."""
    global _session_tokens
    if not _SESSION_TOKENS_FILE.exists():
        return
    try:
        data = json.loads(_SESSION_TOKENS_FILE.read_text())
        if isinstance(data, dict):
            cutoff = time.time() - 1800
            _session_tokens = {t: ts for t, ts in data.items()
                               if isinstance(ts, (int, float)) and ts > cutoff}
    except (json.JSONDecodeError, OSError):
        pass

def create_session_token() -> str:
    """Issue a server-side session token. Call on successful login."""
    token = secrets.token_hex(24)
    with _session_lock:
        _session_tokens[token] = time.time()
        _persist_session_tokens()
    return token

def revoke_session_token(token: Optional[str]) -> None:
    """Remove a session token. Call on logout."""
    if not token:
        return
    with _session_lock:
        _session_tokens.pop(token, None)
        _persist_session_tokens()

def _validate_session_token(token: Optional[str]) -> bool:
    """Check whether the session token exists server-side. Refreshes timestamp (sliding expiry)."""
    if not token:
        return False
    with _session_lock:
        ts = _session_tokens.get(token)
        if ts is not None:
            _session_tokens[token] = time.time()
    return ts is not None

_last_prune_time: float = 0.0
_PRUNE_INTERVAL: float = 300.0

def _prune_session_tokens(max_age: int = 1800) -> None:
    """Remove tokens older than max_age seconds. Runs at most every 5 min."""
    global _last_prune_time
    now = time.time()
    if now - _last_prune_time < _PRUNE_INTERVAL:
        return
    _last_prune_time = now
    cutoff = now - max_age
    with _session_lock:
        expired = [t for t, ts in _session_tokens.items() if ts < cutoff]
        for t in expired:
            del _session_tokens[t]

def auth_gate():
    """Call from app.before_request. Returns a redirect Response if auth needed, else None."""
    path = request.path
    if path.startswith("/static/") or path.startswith("/socket.io/"):
        return None
    if path in _PUBLIC:
        return None
    if not session.get("authenticated") or not _validate_session_token(session.get("session_token")):
        revoke_session_token(session.get("session_token"))
        session.clear()
        if path.startswith("/api/"):
            from flask import jsonify
            return jsonify({"error": "Session expired", "authenticated": False}), 401
        resp = redirect(url_for("auth.session_expired"))
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        return resp
    if must_change_password() and path != "/auth/change-password":
        return redirect(url_for("auth.change_password"))
    _prune_session_tokens()
    return None
