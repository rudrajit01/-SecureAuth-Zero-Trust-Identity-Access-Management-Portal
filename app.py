"""
SecureAuth - Zero Trust Identity & Access Management Portal
============================================================
Practical implementation of concepts from Security, Compliance,
and Identity Fundamentals (SC-900 syllabus).

Run:   python app.py      ->  http://127.0.0.1:5000
"""
import csv
import io
import json
import os
import re
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, session, url_for)

import dlp
from database import (DB_PATH, INSTANCE_DIR, all_policies, close_db, get_db,
                      get_policy, init_db, now_str, DEFAULT_POLICIES)
from security import (DEVICE_COOKIE, calculate_risk, client_ip, csrf_token,
                      csrf_valid, decide_access, decrypt, device_hash, encrypt,
                      get_device_id, hash_password, log_event, mask,
                      new_totp_secret, password_policy_errors, qr_svg,
                      short_ua, totp_uri, verify_password, verify_totp)

# ---------------------------------------------------------------------------
# App configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)


def _secret_key():
    """Flask session signing key - persisted securely to local file."""
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    path = os.path.join(INSTANCE_DIR, "flask_secret.key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


CROSS_SITE = os.environ.get("SECUREAUTH_CROSS_SITE") == "1"   # For cross-site / online preview environments

app.config.update(
    SECRET_KEY=_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,                   # Prevents client-side script access (mitigates XSS)
    SESSION_COOKIE_SAMESITE="None" if CROSS_SITE else "Lax",  # Mitigates Cross-Site Request Forgery (CSRF)
    SESSION_COOKIE_SECURE=CROSS_SITE,               # Enforce HTTPS in production environments
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,             # 2 MB upload threshold
)

DEMO_MODE = os.environ.get("SECUREAUTH_DEMO", "1") == "1"
DEMO_LOCATIONS = ["Ludhiana, India", "Delhi, India", "Mumbai, India",
                  "Dubai, UAE", "London, UK", "Moscow, Russia", "New York, USA"]
ROLES = ["user", "manager", "admin"]

app.teardown_appcontext(close_db)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def parse_dt(s):
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S") if s else None


def get_user(uid):
    return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def active_pim(uid):
    return get_db().execute(
        "SELECT * FROM pim_activations WHERE user_id=? AND status='active' ORDER BY id DESC LIMIT 1",
        (uid,)).fetchone()


def expire_pim():
    """Automatically revokes expired temporary admin privileges (Just-In-Time access)."""
    db = get_db()
    rows = db.execute("SELECT p.*, u.username FROM pim_activations p JOIN users u ON u.id=p.user_id "
                      "WHERE p.status='active' AND p.end_time <= ?", (now_str(),)).fetchall()
    for r in rows:
        db.execute("UPDATE pim_activations SET status='expired' WHERE id=?", (r["id"],))
        db.commit()
        log_event("PIM_EXPIRED", "medium", f"Temporary '{r['role']}' role expired",
                  r["user_id"], r["username"])


def role_required(*roles):
    """RBAC decorator: restricts route access to authorized roles."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not g.user:
                return redirect(url_for("login"))
            if g.role not in roles:
                log_event("ACCESS_DENIED", "medium",
                          f"Role '{g.role}' attempted unauthorized access to '{request.path}'",
                          g.user["id"], g.user["username"])
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not g.user:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        return fn(*a, **kw)
    return wrapper


# ---------------------------------------------------------------------------
# Request hooks  (Zero Trust: verify explicitly on every request)
# ---------------------------------------------------------------------------
@app.before_request
def before():
    g.user, g.role, g.pim = None, None, None

    if request.method == "POST" and not csrf_valid():
        abort(400, "Invalid CSRF token - please refresh the page and try again.")

    if request.endpoint == "static":
        return

    expire_pim()

    uid = session.get("uid")
    if not uid:
        return
    user = get_user(uid)
    if not user or not user["is_active"]:
        session.clear()
        flash("Your account has been disabled. Please contact an administrator.", "danger")
        return redirect(url_for("login"))

    # Idle session timeout
    timeout = get_policy("session_timeout_minutes")
    last = session.get("last_active", 0)
    if datetime.now().timestamp() - last > timeout * 60:
        log_event("SESSION_TIMEOUT", "info", f"{timeout} min inactivity", uid, user["username"])
        session.clear()
        flash(f"Session expired due to {timeout} minutes of inactivity. Please sign in again.", "warning")
        return redirect(url_for("login"))
    session["last_active"] = datetime.now().timestamp()

    g.user = user
    g.pim = active_pim(uid)
    g.role = g.pim["role"] if g.pim else user["role"]   # Elevated role if PIM is active


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; form-action 'self'")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.context_processor
def inject():
    return dict(csrf_token=csrf_token, demo_mode=DEMO_MODE, demo_locations=DEMO_LOCATIONS,
                user=g.get("user"), role=g.get("role"), pim=g.get("pim"))


@app.template_filter("fromjson")
def fromjson(s):
    try:
        return json.loads(s)
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard" if session.get("uid") else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        username = f.get("username", "").strip()
        email = f.get("email", "").strip().lower()
        password = f.get("password", "")
        phone = f.get("phone", "").strip()
        errors = []
        if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username):
            errors.append("Username must be 3-20 characters long (letters, numbers, underscores).")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            errors.append("Please provide a valid email address.")
        if phone and not re.fullmatch(r"(\+91)?[6-9]\d{9}", phone.replace(" ", "")):
            errors.append("Please provide a valid Indian mobile number.")
        if password != f.get("confirm", ""):
            errors.append("Passwords do not match.")
        errors += password_policy_errors(password, username)
        db = get_db()
        if db.execute("SELECT 1 FROM users WHERE username=? OR email=?", (username, email)).fetchone():
            errors.append("Username or email is already registered.")
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html", form=f)

        db.execute("INSERT INTO users(username,email,password_hash,role,phone_enc,created_at) "
                   "VALUES (?,?,?,?,?,?)",
                   (username, email, hash_password(password), "user", encrypt(phone), now_str()))
        db.commit()
        uid = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()["id"]
        log_event("USER_REGISTERED", "info", "New user account created (role: user)", uid, username)
        flash("Account created successfully! Please sign in. MFA setup is required on initial sign-in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form={})


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("uid"):
        return redirect(url_for("dashboard"))
    if request.method == "GET":
        return render_template("login.html")

    db = get_db()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    location = request.form.get("location") if DEMO_MODE else None
    location = location if location in DEMO_LOCATIONS else "Ludhiana, India"
    hour_raw = request.form.get("hour", "") if DEMO_MODE else ""
    hour = int(hour_raw) if hour_raw.isdigit() and 0 <= int(hour_raw) <= 23 else datetime.now().hour
    generic = "Invalid username or password."

    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        log_event("LOGIN_FAILED", "low", "Unknown username", None, username, location)
        flash(generic, "danger")
        return render_template("login.html", last_user=username)

    if not user["is_active"]:
        log_event("LOGIN_DISABLED_ACCOUNT", "medium", "Sign-in attempt on disabled account",
                  user["id"], username, location)
        flash("This account has been disabled by an administrator.", "danger")
        return render_template("login.html", last_user=username)

    # ---- Account lockout check (brute-force defense)
    locked_until = parse_dt(user["locked_until"])
    if locked_until and locked_until > datetime.now():
        log_event("LOGIN_WHILE_LOCKED", "medium", "Sign-in attempt on locked account",
                  user["id"], username, location)
        flash(f"Account is locked until {locked_until.strftime('%H:%M:%S')} to prevent brute-force attacks.", "danger")
        return render_template("login.html", last_user=username)

    # ---- Password verification (bcrypt)
    if not verify_password(password, user["password_hash"]):
        max_fail = get_policy("max_failed_attempts")
        fails = user["failed_attempts"] + 1
        if fails >= max_fail:
            until = datetime.now() + timedelta(minutes=get_policy("lockout_minutes"))
            db.execute("UPDATE users SET failed_attempts=0, locked_until=? WHERE id=?",
                       (until.strftime("%Y-%m-%d %H:%M:%S"), user["id"]))
            db.commit()
            log_event("ACCOUNT_LOCKED", "high",
                      f"{max_fail} failed password attempts - possible brute-force attack",
                      user["id"], username, location)
            flash(f"{max_fail} failed attempts! Account locked for {get_policy('lockout_minutes')} minutes.", "danger")
        else:
            db.execute("UPDATE users SET failed_attempts=? WHERE id=?", (fails, user["id"]))
            db.commit()
            log_event("LOGIN_FAILED", "low", f"Incorrect password (attempt {fails}/{max_fail})",
                      user["id"], username, location)
            flash(f"{generic} ({max_fail - fails} attempt(s) remaining before account lockout)", "danger")
        return render_template("login.html", last_user=username)

    # ---- Valid credentials -> Identity Protection & Conditional Access evaluation
    device_id = get_device_id()
    dev_hash = device_hash(device_id)
    score, level, reasons = calculate_risk(user["id"], dev_hash, location, hour)
    decision = decide_access(user, level)

    if decision == "block":
        log_event("LOGIN_BLOCKED_RISK", "critical",
                  f"High risk sign-in blocked. Reasons: {'; '.join(reasons)}",
                  user["id"], username, location, score)
        return render_template("blocked.html", score=score, reasons=reasons, location=location)

    session.clear()
    session.update(pending_uid=user["id"], pending_location=location, pending_dev=dev_hash,
                   pending_device_id=device_id, pending_score=score, pending_level=level,
                   pending_reasons=reasons, pending_at=datetime.now().timestamp(), mfa_tries=0)

    if decision == "mfa_setup":
        return redirect(url_for("mfa_setup"))
    if decision == "mfa":
        return redirect(url_for("mfa_verify"))
    return complete_login("Password (trusted device, low risk)")


def pending_user():
    """Retrieves pre-authenticated user pending MFA completion (valid for 5 minutes)."""
    uid = session.get("pending_uid")
    if not uid or datetime.now().timestamp() - session.get("pending_at", 0) > 300:
        session.clear()
        return None
    return get_user(uid)


def complete_login(method):
    """Completes sign-in: registers device/location, issues fresh session, logs audit event."""
    db = get_db()
    uid = session["pending_uid"]
    user = get_user(uid)
    loc, dev, dev_id = session["pending_location"], session["pending_dev"], session["pending_device_id"]
    score, level, reasons = session["pending_score"], session["pending_level"], session["pending_reasons"]
    ts = now_str()

    db.execute("UPDATE users SET last_login=?, failed_attempts=0, locked_until=NULL WHERE id=?", (ts, uid))
    db.execute("INSERT INTO trusted_devices(user_id,device_hash,user_agent,first_seen,last_seen) "
               "VALUES (?,?,?,?,?) ON CONFLICT(user_id,device_hash) DO UPDATE SET last_seen=excluded.last_seen",
               (uid, dev, short_ua(), ts, ts))
    db.execute("INSERT OR IGNORE INTO known_locations(user_id,location,first_seen) VALUES (?,?,?)",
               (uid, loc, ts))
    db.commit()

    # Regenerate session to prevent session fixation attacks
    session.clear()
    session.update(uid=uid, login_at=ts, last_active=datetime.now().timestamp(),
                   login_location=loc, login_score=score, login_level=level,
                   login_reasons=reasons, login_method=method)
    sev = {"low": "info", "medium": "medium", "high": "high"}[level]
    log_event("LOGIN_SUCCESS", sev, f"Method: {method}. Risk: {level.upper()}"
              + (f" ({'; '.join(reasons)})" if reasons else ""), uid, user["username"], loc, score)
    flash(f"Welcome, {user['username']}! Sign-in successful.", "success")

    resp = redirect(url_for("dashboard"))
    resp.set_cookie(DEVICE_COOKIE, dev_id, max_age=365 * 24 * 3600, httponly=True,
                    samesite=app.config["SESSION_COOKIE_SAMESITE"],
                    secure=app.config["SESSION_COOKIE_SECURE"])
    return resp


@app.route("/mfa/setup", methods=["GET", "POST"])
def mfa_setup():
    user = pending_user()
    if not user:
        flash("Sign-in session expired. Please sign in again.", "warning")
        return redirect(url_for("login"))
    if user["mfa_enabled"]:
        return redirect(url_for("mfa_verify"))

    if "pending_secret" not in session:
        session["pending_secret"] = new_totp_secret()
    secret = session["pending_secret"]

    if request.method == "POST":
        if verify_totp(secret, request.form.get("code")):
            db = get_db()
            db.execute("UPDATE users SET mfa_secret_enc=?, mfa_enabled=1 WHERE id=?",
                       (encrypt(secret), user["id"]))
            db.commit()
            session.pop("pending_secret", None)
            log_event("MFA_REGISTERED", "info", "Authenticator application registered (TOTP)",
                      user["id"], user["username"], session.get("pending_location"))
            return complete_login("Password + MFA (first-time registration)")
        flash("Invalid verification code. Please enter the current 6-digit code from your authenticator app.", "danger")

    return render_template("mfa_setup.html", qr=qr_svg(totp_uri(secret, user["username"])),
                           secret=secret, username=user["username"])


@app.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    user = pending_user()
    if not user:
        flash("Sign-in session expired. Please sign in again.", "warning")
        return redirect(url_for("login"))
    if not user["mfa_enabled"]:
        return redirect(url_for("mfa_setup"))

    if request.method == "POST":
        if verify_totp(decrypt(user["mfa_secret_enc"]), request.form.get("code")):
            return complete_login("Password + MFA (TOTP)")
        session["mfa_tries"] = session.get("mfa_tries", 0) + 1
        log_event("MFA_FAILED", "medium", f"Incorrect MFA code (attempt {session['mfa_tries']}/5)",
                  user["id"], user["username"], session.get("pending_location"))
        if session["mfa_tries"] >= 5:
            log_event("MFA_ABUSE", "high", "5 consecutive failed MFA attempts - sign-in terminated. Credential compromise suspected.",
                      user["id"], user["username"], session.get("pending_location"))
            session.clear()
            flash("Too many incorrect MFA attempts. Sign-in session terminated.", "danger")
            return redirect(url_for("login"))
        flash("Invalid MFA code. Please try again.", "danger")

    return render_template("mfa_verify.html", username=user["username"],
                           score=session.get("pending_score"), level=session.get("pending_level"),
                           reasons=session.get("pending_reasons", []))


@app.route("/logout", methods=["POST"])
def logout():
    if g.user:
        log_event("LOGOUT", "info", "User signed out", g.user["id"], g.user["username"])
    session.clear()
    flash("You have been signed out.", "info")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    uid = g.user["id"]
    my_events = db.execute("SELECT * FROM audit_logs WHERE user_id=? ORDER BY id DESC LIMIT 6",
                           (uid,)).fetchall()
    ctx = dict(my_events=my_events)

    if g.role in ("admin", "manager"):
        today = datetime.now().strftime("%Y-%m-%d")
        q = lambda sql, *p: db.execute(sql, p).fetchone()[0]
        ctx["stats"] = {
            "users": q("SELECT COUNT(*) FROM users"),
            "mfa": q("SELECT COUNT(*) FROM users WHERE mfa_enabled=1"),
            "logins_today": q("SELECT COUNT(*) FROM audit_logs WHERE event='LOGIN_SUCCESS' AND ts LIKE ?", today + "%"),
            "failed_today": q("SELECT COUNT(*) FROM audit_logs WHERE event='LOGIN_FAILED' AND ts LIKE ?", today + "%"),
            "locked": q("SELECT COUNT(*) FROM users WHERE locked_until > ?", now_str()),
            "blocked": q("SELECT COUNT(*) FROM audit_logs WHERE event='LOGIN_BLOCKED_RISK'"),
            "alerts": q("SELECT COUNT(*) FROM audit_logs WHERE severity IN ('high','critical')"),
            "dlp": q("SELECT COUNT(*) FROM dlp_scans WHERE label IN ('Confidential','Highly Confidential')"),
            "pim": q("SELECT COUNT(*) FROM pim_activations WHERE status='active'"),
        }
        # Last 7 days sign-in chart
        chart = []
        for i in range(6, -1, -1):
            d = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
            ok = q("SELECT COUNT(*) FROM audit_logs WHERE event='LOGIN_SUCCESS' AND ts LIKE ?", d + "%")
            bad = q("SELECT COUNT(*) FROM audit_logs WHERE event IN ('LOGIN_FAILED','LOGIN_BLOCKED_RISK',"
                    "'ACCOUNT_LOCKED','MFA_FAILED') AND ts LIKE ?", d + "%")
            chart.append({"day": d[5:], "ok": ok, "bad": bad})
        ctx["chart"] = chart
        ctx["chart_max"] = max([max(c["ok"], c["bad"]) for c in chart] + [1])
        ctx["alerts"] = db.execute("SELECT * FROM audit_logs WHERE severity IN ('high','critical') "
                                   "ORDER BY id DESC LIMIT 6").fetchall()
        ctx["risk_dist"] = {lvl: q("SELECT COUNT(*) FROM audit_logs WHERE event='LOGIN_SUCCESS' AND details LIKE ?",
                                   f"%Risk: {lvl.upper()}%") for lvl in ("low", "medium", "high")}
    return render_template("dashboard.html", **ctx)


# ---------------------------------------------------------------------------
# My Profile  (Encryption demo + password change + devices)
# ---------------------------------------------------------------------------
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    db = get_db()
    uid = g.user["id"]
    if request.method == "POST":
        action = request.form.get("action")
        if action == "details":
            phone = request.form.get("phone", "").strip().replace(" ", "")
            address = request.form.get("address", "").strip()[:200]
            if phone and not re.fullmatch(r"(\+91)?[6-9]\d{9}", phone):
                flash("Please provide a valid Indian mobile number.", "danger")
            else:
                db.execute("UPDATE users SET phone_enc=?, address_enc=? WHERE id=?",
                           (encrypt(phone), encrypt(address), uid))
                db.commit()
                log_event("PROFILE_UPDATED", "info", "Profile contact details updated (stored encrypted)", uid, g.user["username"])
                flash("Profile details updated and encrypted successfully.", "success")
        elif action == "password":
            cur, new = request.form.get("current", ""), request.form.get("new", "")
            if not verify_password(cur, g.user["password_hash"]):
                flash("Current password is incorrect.", "danger")
            elif new != request.form.get("confirm", ""):
                flash("New passwords do not match.", "danger")
            elif errs := password_policy_errors(new, g.user["username"]):
                for e in errs:
                    flash(e, "danger")
            else:
                db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new), uid))
                db.commit()
                log_event("PASSWORD_CHANGED", "medium", "Password updated by user", uid, g.user["username"])
                flash("Password changed successfully.", "success")
        elif action == "remove_device":
            db.execute("DELETE FROM trusted_devices WHERE id=? AND user_id=?",
                       (request.form.get("device_id"), uid))
            db.commit()
            log_event("DEVICE_REMOVED", "info", "Trusted device removed", uid, g.user["username"])
            flash("Trusted device removed. Secondary MFA will be required on next sign-in from this device.", "info")
        return redirect(url_for("profile"))

    user = get_user(uid)
    devices = db.execute("SELECT * FROM trusted_devices WHERE user_id=? ORDER BY last_seen DESC", (uid,)).fetchall()
    locations = db.execute("SELECT * FROM known_locations WHERE user_id=?", (uid,)).fetchall()
    return render_template("profile.html", u=user, phone=decrypt(user["phone_enc"]),
                           address=decrypt(user["address_enc"]), devices=devices, locations=locations)


# ---------------------------------------------------------------------------
# PIM - Privileged Identity Management (Just-In-Time admin elevation)
# ---------------------------------------------------------------------------
@app.route("/pim", methods=["GET", "POST"])
@login_required
def pim():
    db = get_db()
    uid = g.user["id"]
    if request.method == "POST":
        action = request.form.get("action")
        if action == "activate":
            just = request.form.get("justification", "").strip()
            mins = int(request.form.get("minutes", "30") or 30)
            max_m = get_policy("pim_max_minutes")
            if not g.user["pim_eligible"] or g.user["role"] == "admin":
                abort(403)
            if g.pim:
                flash("Administrator role is already active.", "info")
            elif len(just) < 10:
                flash("Business justification must be at least 10 characters long.", "danger")
            elif not verify_totp(decrypt(g.user["mfa_secret_enc"]), request.form.get("code")):
                log_event("PIM_MFA_FAILED", "high", "Failed MFA verification during PIM activation attempt", uid, g.user["username"])
                flash("Invalid MFA code. Fresh MFA verification is required for privileged role elevation.", "danger")
            else:
                mins = max(5, min(mins, max_m))
                start = datetime.now()
                end = start + timedelta(minutes=mins)
                db.execute("INSERT INTO pim_activations(user_id,role,justification,start_time,end_time) "
                           "VALUES (?,?,?,?,?)", (uid, "admin", just, start.strftime("%Y-%m-%d %H:%M:%S"),
                                                   end.strftime("%Y-%m-%d %H:%M:%S")))
                db.commit()
                log_event("PIM_ACTIVATED", "high", f"Temporary ADMIN role activated for {mins} min. Reason: {just}",
                          uid, g.user["username"])
                flash(f"Administrator role activated for {mins} minutes (valid until {end.strftime('%H:%M')}).", "success")
        elif action == "deactivate" and g.pim:
            db.execute("UPDATE pim_activations SET status='revoked', end_time=? WHERE id=?",
                       (now_str(), g.pim["id"]))
            db.commit()
            log_event("PIM_DEACTIVATED", "medium", "User deactivated temporary admin role manually", uid, g.user["username"])
            flash("Temporary administrator role deactivated.", "info")
        elif action == "revoke" and g.role == "admin":
            pid = request.form.get("pid")
            row = db.execute("SELECT p.*, u.username FROM pim_activations p JOIN users u ON u.id=p.user_id "
                             "WHERE p.id=?", (pid,)).fetchone()
            if row and row["status"] == "active":
                db.execute("UPDATE pim_activations SET status='revoked', end_time=? WHERE id=?", (now_str(), pid))
                db.commit()
                log_event("PIM_REVOKED", "high", f"Administrator revoked temporary role for {row['username']}",
                          uid, g.user["username"])
                flash(f"Administrator access for {row['username']} has been revoked.", "success")
        return redirect(url_for("pim"))

    history = db.execute("SELECT * FROM pim_activations WHERE user_id=? ORDER BY id DESC LIMIT 10", (uid,)).fetchall()
    all_acts = None
    if g.role == "admin":
        all_acts = db.execute("SELECT p.*, u.username FROM pim_activations p JOIN users u ON u.id=p.user_id "
                              "ORDER BY p.id DESC LIMIT 25").fetchall()
    remaining = None
    if g.pim:
        remaining = int((parse_dt(g.pim["end_time"]) - datetime.now()).total_seconds() // 60) + 1
    return render_template("pim.html", history=history, all_acts=all_acts, remaining=remaining,
                           max_minutes=get_policy("pim_max_minutes"))


# ---------------------------------------------------------------------------
# DLP Scanner  (Microsoft Purview concept)
# ---------------------------------------------------------------------------
@app.route("/dlp", methods=["GET", "POST"])
@login_required
def dlp_scan():
    db = get_db()
    result, source = None, None
    if request.method == "POST":
        text = request.form.get("text", "")
        file = request.files.get("file")
        if file and file.filename:
            ext = os.path.splitext(file.filename)[1].lower()
            if ext not in dlp.ALLOWED_EXT:
                flash(f"Only {', '.join(sorted(dlp.ALLOWED_EXT))} files are allowed.", "danger")
                return redirect(url_for("dlp_scan"))
            try:
                text = dlp.extract_text(file.filename, file.read())
            except Exception:
                flash("Failed to read file content.", "danger")
                return redirect(url_for("dlp_scan"))
            source = os.path.basename(file.filename)[:80]
        else:
            source = "Pasted text"
        if not text.strip():
            flash("Please enter text or upload a file to scan.", "warning")
            return redirect(url_for("dlp_scan"))

        result = dlp.scan_text(text)
        summary = {k: {"count": v["count"], "samples": v["samples"]} for k, v in result["findings"].items()}
        db.execute("INSERT INTO dlp_scans(ts,user_id,source,label,action,summary) VALUES (?,?,?,?,?,?)",
                   (now_str(), g.user["id"], source, result["label"], result["action"], json.dumps(summary)))
        db.commit()
        sev = {0: "info", 1: "info", 2: "medium", 3: "high"}[result["level"]]
        found = ", ".join(f"{k} x{v['count']}" for k, v in result["findings"].items()) or "none"
        log_event("DLP_SCAN", sev, f"[{result['label']}] {source}: {found}", g.user["id"], g.user["username"])

    if g.role in ("admin", "manager"):
        history = db.execute("SELECT d.*, u.username FROM dlp_scans d JOIN users u ON u.id=d.user_id "
                             "ORDER BY d.id DESC LIMIT 15").fetchall()
    else:
        history = db.execute("SELECT d.*, ? AS username FROM dlp_scans d WHERE user_id=? ORDER BY id DESC LIMIT 15",
                             (g.user["username"], g.user["id"])).fetchall()
    return render_template("dlp.html", result=result, source=source, history=history)


# ---------------------------------------------------------------------------
# Audit Logs  (SIEM) - manager & admin
# ---------------------------------------------------------------------------
def _audit_query():
    sql, params = "SELECT * FROM audit_logs WHERE 1=1", []
    q = request.args.get("q", "").strip()
    ev = request.args.get("event", "")
    sev = request.args.get("severity", "")
    if q:
        sql += " AND (username LIKE ? OR details LIKE ? OR ip LIKE ?)"
        params += [f"%{q}%"] * 3
    if ev:
        sql += " AND event=?"
        params.append(ev)
    if sev == "alerts":
        sql += " AND severity IN ('high','critical')"
    elif sev:
        sql += " AND severity=?"
        params.append(sev)
    return sql + " ORDER BY id DESC", params


@app.route("/audit")
@role_required("admin", "manager")
def audit():
    db = get_db()
    sql, params = _audit_query()
    logs = db.execute(sql + " LIMIT 300", params).fetchall()
    events = [r[0] for r in db.execute("SELECT DISTINCT event FROM audit_logs ORDER BY event")]
    return render_template("audit.html", logs=logs, events=events, args=request.args)


@app.route("/audit/export")
@role_required("admin", "manager")
def audit_export():
    sql, params = _audit_query()
    rows = get_db().execute(sql, params).fetchall()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "timestamp", "username", "event", "severity", "details", "ip", "location", "risk_score"])
    for r in rows:
        w.writerow([r["id"], r["ts"], r["username"], r["event"], r["severity"], r["details"],
                    r["ip"], r["location"], r["risk_score"]])
    log_event("AUDIT_EXPORTED", "medium", f"Exported {len(rows)} audit records to CSV",
              g.user["id"], g.user["username"])
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=audit_logs.csv"})


# ---------------------------------------------------------------------------
# User management - admin (manager read-only)
# ---------------------------------------------------------------------------
@app.route("/admin/users")
@role_required("admin", "manager")
def admin_users():
    users = get_db().execute("SELECT * FROM users ORDER BY id").fetchall()
    return render_template("admin_users.html", users=users, now=now_str())


@app.route("/admin/users/<int:uid>", methods=["GET", "POST"])
@role_required("admin", "manager")
def admin_user_detail(uid):
    db = get_db()
    u = get_user(uid) or abort(404)
    if request.method == "POST":
        if g.role != "admin":
            abort(403)
        action = request.form.get("action")
        me = g.user["id"]
        if uid == me and action in ("role", "toggle_active"):
            flash("You cannot modify your own role or active status (safety control).", "warning")
            return redirect(url_for("admin_user_detail", uid=uid))
        if action == "role":
            new = request.form.get("role")
            if new in ROLES and new != u["role"]:
                db.execute("UPDATE users SET role=? WHERE id=?", (new, uid))
                log_event("ROLE_CHANGED", "high", f"{u['username']}: {u['role']} -> {new}", me, g.user["username"])
                flash(f"Role updated to '{new}'.", "success")
        elif action == "toggle_active":
            db.execute("UPDATE users SET is_active=? WHERE id=?", (0 if u["is_active"] else 1, uid))
            log_event("USER_DISABLED" if u["is_active"] else "USER_ENABLED", "high",
                      f"Account: {u['username']}", me, g.user["username"])
            flash("Account status updated.", "success")
        elif action == "unlock":
            db.execute("UPDATE users SET locked_until=NULL, failed_attempts=0 WHERE id=?", (uid,))
            log_event("ACCOUNT_UNLOCKED", "medium", f"Administrator unlocked account for {u['username']}", me, g.user["username"])
            flash("Account unlocked successfully.", "success")
        elif action == "pim":
            db.execute("UPDATE users SET pim_eligible=? WHERE id=?", (0 if u["pim_eligible"] else 1, uid))
            log_event("PIM_ELIGIBILITY_CHANGED", "medium",
                      f"{u['username']} PIM eligible: {'No' if u['pim_eligible'] else 'Yes'}", me, g.user["username"])
            flash("PIM eligibility updated.", "success")
        elif action == "reset_mfa":
            db.execute("UPDATE users SET mfa_enabled=0, mfa_secret_enc=NULL WHERE id=?", (uid,))
            db.execute("DELETE FROM trusted_devices WHERE user_id=?", (uid,))
            log_event("MFA_RESET", "high", f"MFA reset for {u['username']} (lost device)", me, g.user["username"])
            flash("MFA credentials reset. The user must re-enroll MFA on their next sign-in.", "success")
        db.commit()
        return redirect(url_for("admin_user_detail", uid=uid))

    devices = db.execute("SELECT * FROM trusted_devices WHERE user_id=?", (uid,)).fetchall()
    locations = db.execute("SELECT * FROM known_locations WHERE user_id=?", (uid,)).fetchall()
    events = db.execute("SELECT * FROM audit_logs WHERE user_id=? OR details LIKE ? ORDER BY id DESC LIMIT 15",
                        (uid, f"%{u['username']}%")).fetchall()
    show_plain = g.role == "admin"
    return render_template("admin_user_detail.html", u=u, devices=devices, locations=locations, events=events,
                           roles=ROLES, now=now_str(),
                           phone=decrypt(u["phone_enc"]) if show_plain else mask(decrypt(u["phone_enc"])),
                           address=decrypt(u["address_enc"]) if show_plain else "(hidden - admin only)")


# ---------------------------------------------------------------------------
# Conditional Access policies - admin
# ---------------------------------------------------------------------------
POLICY_META = [
    ("max_failed_attempts", "Maximum failed password attempts before lockout", 1, 20),
    ("lockout_minutes", "Account lockout duration (minutes)", 1, 1440),
    ("session_timeout_minutes", "Idle session timeout (minutes)", 1, 240),
    ("mfa_risk_threshold", "Risk score threshold requiring MFA challenge (0-100)", 0, 100),
    ("block_risk_threshold", "Risk score threshold for High Risk (0-100)", 0, 100),
    ("block_high_risk", "Block sign-in on High Risk? (1 = Yes, 0 = Require MFA only)", 0, 1),
    ("always_mfa_privileged", "Require MFA for Admin/Manager roles always (1 = Yes)", 0, 1),
    ("unusual_hour_start", "Unusual hours start time (hour, 0-23)", 0, 23),
    ("unusual_hour_end", "Unusual hours end time (hour, 0-24)", 0, 24),
    ("pim_max_minutes", "Maximum duration for temporary PIM elevation (minutes)", 5, 480),
]


@app.route("/admin/policies", methods=["GET", "POST"])
@role_required("admin")
def admin_policies():
    db = get_db()
    if request.method == "POST":
        if request.form.get("action") == "reset":
            for k, v in DEFAULT_POLICIES.items():
                db.execute("UPDATE policies SET value=? WHERE key=?", (v, k))
            changes = ["Reset all policies to defaults"]
        else:
            changes = []
            current = all_policies()
            for key, _label, lo, hi in POLICY_META:
                raw = request.form.get(key, "")
                if not raw.lstrip("-").isdigit() or not lo <= int(raw) <= hi:
                    flash(f"Value for '{key}' must be between {lo} and {hi}.", "danger")
                    return redirect(url_for("admin_policies"))
                if str(int(raw)) != current.get(key):
                    changes.append(f"{key}: {current.get(key)} -> {int(raw)}")
                    db.execute("UPDATE policies SET value=? WHERE key=?", (str(int(raw)), key))
        db.commit()
        if changes:
            log_event("POLICY_CHANGED", "high", "; ".join(changes), g.user["id"], g.user["username"])
            flash("Policies updated successfully.", "success")
        return redirect(url_for("admin_policies"))
    return render_template("policies.html", meta=POLICY_META, values=all_policies())


# ---------------------------------------------------------------------------
# Error pages
# ---------------------------------------------------------------------------
@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(405)
@app.errorhandler(413)
def errors(e):
    msgs = {403: "Access Denied: Your assigned role lacks permission to access this resource (RBAC).",
            404: "Page not found.", 413: "Payload too large (maximum allowed file size is 2 MB).",
            405: "Method not allowed for this endpoint.", 400: getattr(e, "description", "Bad request")}
    return render_template("error.html", code=e.code, msg=msgs.get(e.code, str(e))), e.code


# ---------------------------------------------------------------------------
# First run: database + demo users
# ---------------------------------------------------------------------------
def seed():
    import sqlite3
    init_db()
    con = sqlite3.connect(DB_PATH)
    if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        demo = [("admin", "admin@secureauth.local", "Admin@123", "admin", "9876500001", "Admin Block, Ludhiana", 0),
                ("manager1", "manager@secureauth.local", "Manager@123", "manager", "9876500002", "Model Town, Ludhiana", 1),
                ("user1", "user1@secureauth.local", "User@123", "user", "9876500003", "Sarabha Nagar, Ludhiana", 0)]
        for un, em, pw, role, ph, addr, pim_ok in demo:
            con.execute("INSERT INTO users(username,email,password_hash,role,phone_enc,address_enc,pim_eligible,created_at) "
                        "VALUES (?,?,?,?,?,?,?,?)",
                        (un, em, hash_password(pw), role, encrypt(ph), encrypt(addr), pim_ok, now_str()))
        con.commit()
        print("\n  Demo accounts provisioned:")
        print("    admin    / Admin@123    (Admin)")
        print("    manager1 / Manager@123  (Manager, PIM eligible)")
        print("    user1    / User@123     (User)\n")
    con.close()


seed()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"  SecureAuth is running at ->  http://127.0.0.1:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
