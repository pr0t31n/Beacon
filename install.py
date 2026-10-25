#!/usr/bin/env python3
"""Beacon installer — multi-platform."""
import subprocess
import sys
import os
import shutil
from pathlib import Path

TOOL_NAME = "Beacon"
MIN_PYTHON = (3, 10)
_DIR = Path(__file__).parent.resolve()


def _run(cmd, check=True):
    print(f"  → {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    return subprocess.run(cmd, shell=isinstance(cmd, str), check=check)


def _has(binary):
    return shutil.which(binary) is not None


def install_pip_deps():
    """Always last. Always --break-system-packages."""
    req = _DIR / "requirements.txt"
    if req.exists():
        _run([sys.executable, "-m", "pip", "install",
              "--break-system-packages", "-r", str(req)])


def main():
    if sys.version_info < MIN_PYTHON:
        v = ".".join(map(str, MIN_PYTHON))
        print(f"ERROR: Python {v}+ required")
        sys.exit(1)

    print(f"\n{TOOL_NAME} — Installation\n")

    # Python dependencies
    print("[1/3] Installing Python dependencies ...")
    install_pip_deps()

    # Initialise auth (TLS cert + default credentials)
    print("[2/3] Initialising authentication ...")
    sys.path.insert(0, str(_DIR))
    import _auth
    _auth.init_auth()

    # Initialise database
    print("[3/3] Initialising database ...")
    import sqlite3
    db_path = _DIR / "beacon.db"
    schema = """
    CREATE TABLE IF NOT EXISTS engagements (
        id TEXT PRIMARY KEY, name TEXT NOT NULL, client_name TEXT NOT NULL,
        token_hash TEXT NOT NULL, source_ip TEXT, start_date TEXT, end_date TEXT,
        created_at TEXT NOT NULL, last_seen TEXT NOT NULL, active INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
        received_at TEXT NOT NULL, snapshot_json TEXT NOT NULL,
        UNIQUE(engagement_id, received_at)
    );
    CREATE INDEX IF NOT EXISTS idx_snapshots_eng ON snapshots(engagement_id, received_at DESC);
    CREATE INDEX IF NOT EXISTS idx_engagements_last_seen ON engagements(last_seen);
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.executescript(schema)
    print(f"  Database: {db_path}")

    print(f"\n{TOOL_NAME} installed. Start with: python3 beacon.py")
    print(f"  Default port: 9443")
    print(f"  Default credentials: admin / t3mpPas$w0rd (change on first login)\n")


if __name__ == "__main__":
    main()
