"""
security.py
-----------
Core security engine. Each component corresponds directly to cybersecurity principles:

  * hash_password / verify_password  -> Cryptographic Hashing (bcrypt with salt)
  * encrypt / decrypt                -> Encryption at rest (AES via Fernet, Key Vault pattern)
  * TOTP helpers                     -> Multi-Factor Authentication (MFA)
  * calculate_risk                   -> Identity Protection (sign-in risk evaluation)
  * decide_access                    -> Conditional Access policy engine
  * log_event                        -> Auditing / SIEM telemetry
  * csrf helpers                     -> Application security (Cross-Site Request Forgery prevention)
"""
import hashlib
import io
import os
import re
import secrets

import bcrypt
import pyotp
import qrcode
import qrcode.image.svg
from cryptography.fernet import Fernet, InvalidToken
from flask import request, session

from database import INSTANCE_DIR, get_db, get_policy, now_str

# ---------------------------------------------------------------------------
# 1) HASHING  (Passwords)
# ---------------------------------------------------------------------------
# bcrypt generates a unique salt for each password and employs adaptive work factors,
# mitigating brute-force and precomputed rainbow-table attacks.

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    except ValueError:
        return False


def password_policy_errors(password: str, username: str = "") -> list:
    """Enforces strong password policy (aligned with NIST / Microsoft standards)."""
    errors = []
    if len(password) < 8:
        errors.append("Password must be at least 8 characters long.")
    if len(password.encode()) > 64:
        errors.append("Password cannot exceed 64 characters (bcrypt limit: 72 bytes).")
    if not re.search(r"[A-Z]", password):
        errors.append("Password must contain at least one capital letter (A-Z).")
    if not re.search(r"[a-z]", password):
        errors.append("Password must contain at least one lowercase letter (a-z).")
    if not re.search(r"\d", password):
        errors.append("Password must contain at least one digit (0-9).")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("Password must contain at least one special character (@, #, $ ...).")
    if username and username.lower() in password.lower():
        errors.append("Password cannot contain the username.")
    common = {"password", "123456", "qwerty", "admin", "welcome", "letmein"}
    if any(c in password.lower() for c in common):
        errors.append("Password is too common; please choose a more unique password.")
    return errors


# ---------------------------------------------------------------------------
# 2) ENCRYPTION  (Sensitive data at rest)
# ---------------------------------------------------------------------------
# Encryption keys are isolated from the database file (Key Vault pattern):
# even in the event of database exfiltration, data cannot be decrypted without the key.

KEY_FILE = os.path.join(INSTANCE_DIR, "encryption.key")


def _load_key() -> bytes:
    env_key = os.environ.get("SECUREAUTH_ENC_KEY")
    if env_key:
        return env_key.encode()
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    if not os.path.exists(KEY_FILE):
        with open(KEY_FILE, "wb") as f:
            f.write(Fernet.generate_key())
    with open(KEY_FILE, "rb") as f:
        return f.read().strip()


_fernet = None


def _cipher() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_key())
    return _fernet


def encrypt(plain: str) -> str:
    if not plain:
        return ""
    return _cipher().encrypt(plain.encode()).decode()


def decrypt(token: str) -> str:
    if not token:
        return ""
    try:
        return _cipher().decrypt(token.encode()).decode()
    except InvalidToken:
        return "[decryption failed]"


def mask(value: str, visible: int = 4) -> str:
    if not value:
        return ""
    return "•" * max(len(value) - visible, 0) + value[-visible:]


# ---------------------------------------------------------------------------
# 3) MFA  (TOTP - Google / Microsoft Authenticator)
# ---------------------------------------------------------------------------

def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureAuth")


def verify_totp(secret: str, code: str) -> bool:
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return False
    # valid_window=1 permits a +/- 30-second window to accommodate time drift
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def qr_svg(data: str) -> str:
    """Generates an inline SVG string for the QR code without external imaging libraries."""
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=10)
    buf = io.BytesIO()
    img.save(buf)
    svg = buf.getvalue().decode()
    return svg[svg.find("<svg"):]


# ---------------------------------------------------------------------------
# 4) DEVICE IDENTIFICATION
# ---------------------------------------------------------------------------

DEVICE_COOKIE = "sa_device"


def get_device_id() -> str:
    """Reads device cookie from request or generates a new unique token."""
    return request.cookies.get(DEVICE_COOKIE) or secrets.token_urlsafe(24)


def device_hash(device_id: str) -> str:
    ua = request.headers.get("User-Agent", "")
    return hashlib.sha256(f"{device_id}|{ua}".encode()).hexdigest()


def client_ip() -> str:
    fwd = request.headers.get("X-Forwarded-For", "")
    return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "unknown")


def short_ua() -> str:
    ua = request.headers.get("User-Agent", "Unknown")
    browser = next((b for b in ["Edg", "Chrome", "Firefox", "Safari", "Opera"] if b in ua), "Browser")
    browser = "Edge" if browser == "Edg" else browser
    osname = next((o for o in ["Windows", "Android", "iPhone", "Mac OS", "Linux"] if o in ua), "Unknown OS")
    return f"{browser} on {osname}"


# ---------------------------------------------------------------------------
# 5) IDENTITY PROTECTION  -> Sign-in Risk Score
# ---------------------------------------------------------------------------

def calculate_risk(user_id: int, dev_hash: str, location: str, hour: int):
    """
    Computes sign-in risk score (0-100), modeled on Microsoft Entra ID Protection.
    Returns: (score, level, reasons[])
    """
    db = get_db()
    score, reasons = 0, []

    has_any_device = db.execute(
        "SELECT 1 FROM trusted_devices WHERE user_id=? LIMIT 1", (user_id,)).fetchone()
    known_device = db.execute(
        "SELECT 1 FROM trusted_devices WHERE user_id=? AND device_hash=?",
        (user_id, dev_hash)).fetchone()
    if not known_device:
        score += 30
        reasons.append("New / unrecognized device" + ("" if has_any_device else " (initial sign-in)"))

    known_loc = db.execute(
        "SELECT 1 FROM known_locations WHERE user_id=? AND location=?",
        (user_id, location)).fetchone()
    has_any_loc = db.execute(
        "SELECT 1 FROM known_locations WHERE user_id=? LIMIT 1", (user_id,)).fetchone()
    if not known_loc and has_any_loc:
        score += 25
        reasons.append(f"New location: {location}")
    if not location.endswith("India"):
        score += 20
        reasons.append("Sign-in from outside India (foreign location)")

    start, end = get_policy("unusual_hour_start"), get_policy("unusual_hour_end")
    if start <= hour < end:
        score += 20
        reasons.append(f"Sign-in at unusual hour ({hour:02d}:00)")

    recent_fail = db.execute(
        "SELECT COUNT(*) c FROM audit_logs WHERE user_id=? AND event='LOGIN_FAILED' "
        "AND ts >= datetime('now','localtime','-15 minutes')", (user_id,)).fetchone()["c"]
    if recent_fail >= 2:
        score += 15
        reasons.append(f"{recent_fail} failed sign-in attempts in the last 15 minutes")

    score = min(score, 100)
    if score >= get_policy("block_risk_threshold"):
        level = "high"
    elif score >= get_policy("mfa_risk_threshold"):
        level = "medium"
    else:
        level = "low"
    return score, level, reasons


# ---------------------------------------------------------------------------
# 6) CONDITIONAL ACCESS  -> Policy decision
# ---------------------------------------------------------------------------

def decide_access(user, risk_level: str) -> str:
    """
    Zero Trust: "Never trust, always verify".
    Returns: 'block' | 'mfa_setup' | 'mfa' | 'allow'
    """
    if risk_level == "high" and get_policy("block_high_risk") == 1:
        return "block"
    if not user["mfa_enabled"]:
        return "mfa_setup"          # Mandatory MFA enrollment (Security Defaults)
    if risk_level in ("medium", "high"):
        return "mfa"
    if user["role"] in ("admin", "manager") and get_policy("always_mfa_privileged") == 1:
        return "mfa"
    return "allow"                  # Low risk + trusted device -> seamless sign-in


# ---------------------------------------------------------------------------
# 7) AUDIT LOGGING  (SIEM)
# ---------------------------------------------------------------------------

def log_event(event, severity="info", details="", user_id=None, username=None,
              location=None, risk_score=None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs(ts,user_id,username,event,severity,details,ip,location,risk_score) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (now_str(), user_id, username, event, severity, details, client_ip(), location, risk_score))
    db.commit()


# ---------------------------------------------------------------------------
# 8) CSRF PROTECTION
# ---------------------------------------------------------------------------

def csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(32)
    return session["_csrf"]


def csrf_valid() -> bool:
    sent = request.form.get("_csrf", "")
    return bool(sent) and secrets.compare_digest(sent, session.get("_csrf", ""))
