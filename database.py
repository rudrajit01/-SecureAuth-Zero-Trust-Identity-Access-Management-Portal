"""
database.py
-----------
SQLite database setup and helper functions.
All schema tables are defined here. Sensitive columns (phone, address, MFA secret)
are stored in encrypted format at rest (refer to security.py -> encrypt / decrypt).
"""
import os
import sqlite3
from datetime import datetime

from flask import g

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.environ.get("SECUREAUTH_INSTANCE", os.path.join(BASE_DIR, "instance"))  # Secret keys (Key Vault pattern)
DB_PATH = os.environ.get("SECUREAUTH_DB", os.path.join(BASE_DIR, "secureauth.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    username         TEXT UNIQUE NOT NULL,
    email            TEXT UNIQUE NOT NULL,
    password_hash    TEXT NOT NULL,              -- bcrypt hash (plain text password is never stored)
    role             TEXT NOT NULL DEFAULT 'user', -- RBAC: admin / manager / user
    phone_enc        TEXT,                       -- AES (Fernet) encrypted
    address_enc      TEXT,                       -- AES (Fernet) encrypted
    mfa_secret_enc   TEXT,                       -- TOTP secret, encrypted
    mfa_enabled      INTEGER NOT NULL DEFAULT 0,
    failed_attempts  INTEGER NOT NULL DEFAULT 0,
    locked_until     TEXT,                       -- Account lockout timestamp (brute-force defense)
    is_active        INTEGER NOT NULL DEFAULT 1,
    pim_eligible     INTEGER NOT NULL DEFAULT 0, -- PIM: eligible for temporary admin role elevation?
    created_at       TEXT NOT NULL,
    last_login       TEXT
);

CREATE TABLE IF NOT EXISTS trusted_devices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL,
    device_hash  TEXT NOT NULL,
    user_agent   TEXT,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    UNIQUE(user_id, device_hash)
);

CREATE TABLE IF NOT EXISTS known_locations (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL,
    location    TEXT NOT NULL,
    first_seen  TEXT NOT NULL,
    UNIQUE(user_id, location)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    user_id     INTEGER,
    username    TEXT,
    event       TEXT NOT NULL,
    severity    TEXT NOT NULL DEFAULT 'info',   -- info / low / medium / high / critical
    details     TEXT,
    ip          TEXT,
    location    TEXT,
    risk_score  INTEGER
);

CREATE TABLE IF NOT EXISTS pim_activations (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id        INTEGER NOT NULL,
    role           TEXT NOT NULL,
    justification  TEXT NOT NULL,
    start_time     TEXT NOT NULL,
    end_time       TEXT NOT NULL,
    status         TEXT NOT NULL DEFAULT 'active'  -- active / expired / revoked
);

CREATE TABLE IF NOT EXISTS dlp_scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    user_id     INTEGER NOT NULL,
    source      TEXT NOT NULL,
    label       TEXT NOT NULL,
    action      TEXT NOT NULL,
    summary     TEXT NOT NULL    -- Stores masked findings only; raw content is never persisted
);

CREATE TABLE IF NOT EXISTS policies (
    key    TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
"""

# Default values for Conditional Access and security policies
DEFAULT_POLICIES = {
    "max_failed_attempts": "5",         # Lock account after this many consecutive failed attempts
    "lockout_minutes": "15",            # Lockout duration in minutes
    "session_timeout_minutes": "15",    # Idle session timeout in minutes
    "mfa_risk_threshold": "30",         # Risk score >= threshold -> MFA required
    "block_risk_threshold": "60",       # Risk score >= threshold -> Sign-in blocked
    "block_high_risk": "1",             # 1 = Block high risk sign-ins, 0 = Require MFA only
    "always_mfa_privileged": "1",       # Enforce MFA for privileged roles (admin/manager) at all times
    "unusual_hour_start": "0",          # Start of unusual sign-in hours (00:00)
    "unusual_hour_end": "5",            # End of unusual sign-in hours (05:00)
    "pim_max_minutes": "60",            # Maximum duration for temporary admin access in minutes
}


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    for k, v in DEFAULT_POLICIES.items():
        con.execute("INSERT OR IGNORE INTO policies(key, value) VALUES (?, ?)", (k, v))
    con.commit()
    con.close()


def get_policy(key, cast=int):
    row = get_db().execute("SELECT value FROM policies WHERE key=?", (key,)).fetchone()
    value = row["value"] if row else DEFAULT_POLICIES[key]
    return cast(value)


def all_policies():
    rows = get_db().execute("SELECT key, value FROM policies").fetchall()
    return {r["key"]: r["value"] for r in rows}
