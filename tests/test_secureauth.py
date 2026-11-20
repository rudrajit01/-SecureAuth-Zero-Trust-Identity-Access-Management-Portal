"""
SecureAuth - Automated Test Suite
=================================
Automated test suite covering all security controls and IAM capabilities.
To execute from the project root:

    python -m unittest discover -s tests -v

Each test executes against an isolated temporary SQLite database.
"""
import contextlib
import io
import os
import re
import shutil
import sqlite3
import sys
import tempfile
import unittest
import warnings
import zipfile

warnings.simplefilter("ignore", ResourceWarning)

TMP = tempfile.mkdtemp(prefix="secureauth_test_")
os.environ["SECUREAUTH_DB"] = os.path.join(TMP, "test.db")
os.environ["SECUREAUTH_INSTANCE"] = os.path.join(TMP, "instance")
os.environ["SECUREAUTH_DEMO"] = "1"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import pyotp                     # noqa: E402
with contextlib.redirect_stdout(io.StringIO()):
    import app as A              # noqa: E402
import database                  # noqa: E402
import dlp                       # noqa: E402
from security import decrypt     # noqa: E402

SAMPLE = os.path.join(ROOT, "sample_data")


class Base(unittest.TestCase):
    @staticmethod
    def read(name):
        with open(os.path.join(SAMPLE, name), encoding="utf8") as f:
            return f.read()

    def setUp(self):
        path = os.path.join(TMP, f"{self._testMethodName}.db")
        if os.path.exists(path):
            os.remove(path)
        database.DB_PATH = A.DB_PATH = path
        with contextlib.redirect_stdout(io.StringIO()):
            A.seed()
        A.app.testing = True
        self.secrets = {}

    # ---------------------------------------------------------------- helpers
    def client(self):
        return A.app.test_client()

    def token(self, c, url="/login"):
        m = re.search(r'name="_csrf" value="([^"]+)"', c.get(url).get_data(as_text=True))
        return m.group(1) if m else ""

    def post(self, c, url, data=None, page=None, **kw):
        data = dict(data or {})
        data["_csrf"] = self.token(c, page or url)
        return c.post(url, data=data, **kw)

    def login(self, c, user, pw, loc="Ludhiana, India", hour="12"):
        return self.post(c, "/login", dict(username=user, password=pw, location=loc, hour=hour))

    def code(self, user):
        return pyotp.TOTP(self.secrets[user]).now()

    def full_login(self, c, user, pw, loc="Ludhiana, India", hour="12"):
        """Sign-in + MFA (handles setup or verification as required)."""
        r = self.login(c, user, pw, loc, hour)
        where = r.headers.get("Location", "")
        if where.endswith("/mfa/setup"):
            html = c.get("/mfa/setup").get_data(as_text=True)
            self.secrets[user] = re.search(r'class="secret">([A-Z2-7]+)<', html).group(1)
            r = self.post(c, "/mfa/setup", dict(code=self.code(user)))
        elif where.endswith("/mfa/verify"):
            r = self.post(c, "/mfa/verify", dict(code=self.code(user)))
        return r

    def logout(self, c):
        self.post(c, "/logout", page="/dashboard")

    def db(self):
        con = sqlite3.connect(database.DB_PATH)
        con.row_factory = sqlite3.Row
        self.addCleanup(con.close)
        return con

    def events(self, name):
        return self.db().execute("SELECT * FROM audit_logs WHERE event=?", (name,)).fetchall()


# =========================================================================
class T1_Authentication(Base):
    def test_01_password_stored_as_bcrypt_hash(self):
        row = self.db().execute("SELECT password_hash FROM users WHERE username='user1'").fetchone()
        self.assertTrue(row[0].startswith("$2b$12$"))
        self.assertNotIn("User@123", row[0])

    def test_02_weak_password_rejected_strong_accepted(self):
        c = self.client()
        r = self.post(c, "/register", dict(username="rohit", email="r@x.com", password="hello", confirm="hello"))
        self.assertIn("capital letter", r.get_data(as_text=True))
        r = self.post(c, "/register", dict(username="rohit", email="r@x.com", password="Str0ng#Pass",
                                            confirm="Str0ng#Pass", phone="9812345678"))
        self.assertTrue(r.headers["Location"].endswith("/login"))
        row = self.db().execute("SELECT role FROM users WHERE username='rohit'").fetchone()
        self.assertEqual(row["role"], "user")      # Least privilege by default

    def test_03_very_long_password_handled(self):
        c = self.client()
        long_pw = "Aa1@" + "x" * 100
        r = self.post(c, "/register", dict(username="longpw", email="l@x.com", password=long_pw, confirm=long_pw))
        self.assertEqual(r.status_code, 200)
        self.assertIn("64 characters", r.get_data(as_text=True))
        r = self.login(c, "user1", long_pw)
        self.assertEqual(r.status_code, 200)

    def test_04_duplicate_username_rejected(self):
        c = self.client()
        r = self.post(c, "/register", dict(username="user1", email="new@x.com", password="Str0ng#Pass", confirm="Str0ng#Pass"))
        self.assertIn("already registered", r.get_data(as_text=True))

    def test_05_sql_injection_fails(self):
        c = self.client()
        r = self.login(c, "admin' OR '1'='1' --", "anything")
        self.assertIn("Invalid username or password", r.get_data(as_text=True))
        r = self.login(c, "admin", "' OR '1'='1")
        self.assertNotIn("Location", r.headers)


# =========================================================================
class T2_MFA(Base):
    def test_06_first_login_forces_mfa_setup(self):
        c = self.client()
        r = self.login(c, "user1", "User@123")
        self.assertTrue(r.headers["Location"].endswith("/mfa/setup"))
        html = c.get("/mfa/setup").get_data(as_text=True)
        self.assertIn("<svg", html)                          # QR code inline SVG
        self.assertEqual(c.get("/dashboard").status_code, 302)  # Inaccessible without completing MFA
        r = self.post(c, "/mfa/setup", dict(code="000000"))
        self.assertIn("Invalid verification code", r.get_data(as_text=True))
        secret = re.search(r'class="secret">([A-Z2-7]+)<', html).group(1)
        r = self.post(c, "/mfa/setup", dict(code=pyotp.TOTP(secret).now()))
        self.assertTrue(r.headers["Location"].endswith("/dashboard"))
        self.assertEqual(len(self.events("MFA_REGISTERED")), 1)

    def test_07_five_wrong_mfa_codes_cancel_login(self):
        c = self.client()
        self.full_login(c, "user1", "User@123")
        self.logout(c)
        self.login(c, "user1", "User@123", "Moscow, Russia")
        for _ in range(5):
            r = self.post(c, "/mfa/verify", dict(code="111111"))
        self.assertTrue(r.headers["Location"].endswith("/login"))
        self.assertEqual(len(self.events("MFA_ABUSE")), 1)


# =========================================================================
class T3_ConditionalAccess(Base):
    def test_08_trusted_device_low_risk_no_mfa(self):
        c = self.client()
        self.full_login(c, "user1", "User@123")
        self.logout(c)
        r = self.login(c, "user1", "User@123")
        self.assertTrue(r.headers["Location"].endswith("/dashboard"))

    def test_09_new_foreign_location_requires_mfa(self):
        c = self.client()
        self.full_login(c, "user1", "User@123")
        self.logout(c)
        r = self.login(c, "user1", "User@123", "Moscow, Russia")
        self.assertTrue(r.headers["Location"].endswith("/mfa/verify"))
        html = c.get("/mfa/verify").get_data(as_text=True)
        self.assertIn("New location: Moscow, Russia", html)
        self.assertIn(">45<", html)

    def test_10_high_risk_blocked(self):
        c = self.client()
        self.full_login(c, "user1", "User@123")
        self.logout(c)
        r = self.login(c, "user1", "User@123", "Moscow, Russia", "2")
        self.assertIn("Sign-in blocked", r.get_data(as_text=True))
        self.assertEqual(len(self.events("LOGIN_BLOCKED_RISK")), 1)
        locs = [x[0] for x in self.db().execute("SELECT location FROM known_locations")]
        self.assertNotIn("Moscow, Russia", locs)       # Untrusted blocked location not persisted

    def test_11_admin_always_mfa(self):
        c = self.client()
        self.full_login(c, "admin", "Admin@123")
        self.logout(c)
        r = self.login(c, "admin", "Admin@123")
        self.assertTrue(r.headers["Location"].endswith("/mfa/verify"))

    def test_12_policy_change_high_risk_mfa_instead_of_block(self):
        con = self.db()
        con.execute("UPDATE policies SET value='0' WHERE key='block_high_risk'")
        con.commit()
        c = self.client()
        self.full_login(c, "user1", "User@123")
        self.logout(c)
        r = self.login(c, "user1", "User@123", "Moscow, Russia", "2")
        self.assertTrue(r.headers["Location"].endswith("/mfa/verify"))


# =========================================================================
class T4_Lockout(Base):
    def test_13_brute_force_lockout_and_unlock(self):
        c = self.client()
        for _ in range(5):
            r = self.login(c, "manager1", "Wrong@123")
        self.assertIn("lock", r.get_data(as_text=True).lower())
        r = self.login(c, "manager1", "Manager@123")
        self.assertIn("Account is locked", r.get_data(as_text=True))
        self.assertEqual(len(self.events("ACCOUNT_LOCKED")), 1)
        a = self.client()
        self.full_login(a, "admin", "Admin@123")
        self.post(a, "/admin/users/2", dict(action="unlock"))
        r = self.login(c, "manager1", "Manager@123")
        self.assertTrue(r.headers["Location"].endswith("/mfa/setup"))


# =========================================================================
class T5_RBAC(Base):
    def test_14_role_permissions(self):
        u = self.client()
        self.full_login(u, "user1", "User@123")
        for p in ["/audit", "/admin/users", "/admin/policies", "/audit/export"]:
            self.assertEqual(u.get(p).status_code, 403, p)
        m = self.client()
        self.full_login(m, "manager1", "Manager@123")
        self.assertEqual(m.get("/audit").status_code, 200)
        self.assertEqual(m.get("/admin/users").status_code, 200)
        self.assertEqual(m.get("/admin/policies").status_code, 403)
        r = self.post(m, "/admin/users/3", dict(action="role", role="admin"))
        self.assertEqual(r.status_code, 403)
        a = self.client()
        self.full_login(a, "admin", "Admin@123")
        for p in ["/audit", "/admin/users", "/admin/policies", "/admin/users/3", "/pim", "/dlp", "/profile"]:
            self.assertEqual(a.get(p).status_code, 200, p)
        self.assertGreaterEqual(len(self.events("ACCESS_DENIED")), 4)

    def test_15_admin_cannot_change_own_role(self):
        a = self.client()
        self.full_login(a, "admin", "Admin@123")
        self.post(a, "/admin/users/1", dict(action="role", role="user"))
        self.assertEqual(self.db().execute("SELECT role FROM users WHERE id=1").fetchone()[0], "admin")

    def test_16_disabled_user_kicked_out(self):
        u = self.client()
        self.full_login(u, "user1", "User@123")
        a = self.client()
        self.full_login(a, "admin", "Admin@123")
        self.post(a, "/admin/users/3", dict(action="toggle_active"))
        r = u.get("/dashboard")
        self.assertTrue(r.headers["Location"].endswith("/login"))


# =========================================================================
class T6_PIM(Base):
    def test_17_pim_activation_rules(self):
        u = self.client()
        self.full_login(u, "user1", "User@123")
        self.assertEqual(self.post(u, "/pim", dict(action="activate", justification="x" * 20,
                                                   minutes="30", code=self.code("user1"))).status_code, 403)
        m = self.client()
        self.full_login(m, "manager1", "Manager@123")
        r = self.post(m, "/pim", dict(action="activate", justification="short", minutes="30",
                                      code=self.code("manager1")), follow_redirects=True)
        self.assertIn("10 characters", r.get_data(as_text=True))
        r = self.post(m, "/pim", dict(action="activate", justification="Unlock user ticket 101",
                                      minutes="30", code="000000"), follow_redirects=True)
        self.assertIn("Invalid MFA code", r.get_data(as_text=True))
        self.assertEqual(m.get("/admin/policies").status_code, 403)
        self.post(m, "/pim", dict(action="activate", justification="Unlock user ticket 101",
                                  minutes="30", code=self.code("manager1")))
        self.assertEqual(m.get("/admin/policies").status_code, 200)   # Elevated to admin
        self.assertEqual(len(self.events("PIM_ACTIVATED")), 1)

    def test_18_pim_auto_expiry(self):
        m = self.client()
        self.full_login(m, "manager1", "Manager@123")
        self.post(m, "/pim", dict(action="activate", justification="Unlock user ticket 101",
                                  minutes="30", code=self.code("manager1")))
        con = self.db()
        con.execute("UPDATE pim_activations SET end_time='2000-01-01 00:00:00'")
        con.commit()
        self.assertEqual(m.get("/admin/policies").status_code, 403)
        self.assertEqual(len(self.events("PIM_EXPIRED")), 1)

    def test_19_admin_can_revoke(self):
        m = self.client()
        self.full_login(m, "manager1", "Manager@123")
        self.post(m, "/pim", dict(action="activate", justification="Unlock user ticket 101",
                                  minutes="30", code=self.code("manager1")))
        a = self.client()
        self.full_login(a, "admin", "Admin@123")
        pid = self.db().execute("SELECT id FROM pim_activations").fetchone()[0]
        self.post(a, "/pim", dict(action="revoke", pid=pid))
        self.assertEqual(m.get("/admin/policies").status_code, 403)


# =========================================================================
class T7_Encryption(Base):
    def test_20_sensitive_data_encrypted_at_rest(self):
        c = self.client()
        self.full_login(c, "user1", "User@123")
        self.post(c, "/profile", dict(action="details", phone="9811122233", address="Model Town Ludhiana"))
        row = self.db().execute("SELECT * FROM users WHERE username='user1'").fetchone()
        self.assertNotIn("9811122233", row["phone_enc"])
        self.assertTrue(row["phone_enc"].startswith("gAAAA"))          # Fernet (AES) token
        self.assertEqual(decrypt(row["phone_enc"]), "9811122233")
        self.assertNotEqual(row["mfa_secret_enc"], self.secrets["user1"])
        self.assertEqual(decrypt(row["mfa_secret_enc"]), self.secrets["user1"])
        with open(database.DB_PATH, "rb") as f:
            self.assertNotIn(b"9811122233", f.read())

    def test_21_key_stored_separately(self):
        self.assertTrue(os.path.exists(os.path.join(os.environ["SECUREAUTH_INSTANCE"], "encryption.key")))
        tables = [r[0] for r in self.db().execute("SELECT name FROM sqlite_master WHERE type='table'")]
        self.assertNotIn("keys", tables)


# =========================================================================
class T8_WebSecurity(Base):
    def test_22_csrf_protection(self):
        c = self.client()
        r = c.post("/login", data=dict(username="user1", password="User@123"))
        self.assertEqual(r.status_code, 400)

    def test_23_idle_session_timeout(self):
        c = self.client()
        self.full_login(c, "user1", "User@123")
        with c.session_transaction() as s:
            s["last_active"] -= 16 * 60
        r = c.get("/dashboard")
        self.assertTrue(r.headers["Location"].endswith("/login"))
        self.assertEqual(len(self.events("SESSION_TIMEOUT")), 1)

    def test_24_security_headers_and_cookies(self):
        c = self.client()
        r = c.get("/login")
        for h in ["Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy"]:
            self.assertIn(h, r.headers)
        r = self.full_login(c, "user1", "User@123")
        cookies = " ".join(r.headers.getlist("Set-Cookie")).lower()
        self.assertIn("httponly", cookies)

    def test_25_xss_escaped(self):
        c = self.client()
        self.full_login(c, "user1", "User@123")
        r = self.post(c, "/dlp", dict(file=(io.BytesIO(b"hello"), "<script>alert(1)</script>.txt")),
                      page="/dlp", content_type="multipart/form-data")
        html = r.get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_26_session_regenerated_after_login(self):
        c = self.client()
        self.token(c)
        with c.session_transaction() as s:
            s["attacker"] = "fixed"
        self.full_login(c, "user1", "User@123")
        with c.session_transaction() as s:
            self.assertNotIn("attacker", s)


# =========================================================================
class T9_DLP(Base):
    def test_27_sample_file_highly_confidential(self):
        r = dlp.scan_text(self.read("customer_records.txt"))
        self.assertEqual(r["label"], "Highly Confidential")
        f = r["findings"]
        self.assertEqual(f["Aadhaar Number"]["count"], 2)
        self.assertEqual(f["Credit/Debit Card"]["count"], 1)    # Invalid Luhn checksum not detected
        self.assertEqual(f["PAN Card"]["count"], 2)
        self.assertIn("Password in text", f)

    def test_28_other_labels(self):
        self.assertEqual(dlp.scan_text(self.read("meeting_notes.txt"))["label"], "Internal")
        self.assertEqual(dlp.scan_text(self.read("public_notice.txt"))["label"], "Public")
        self.assertEqual(dlp.scan_text("PAN: ABCPK1234F")["label"], "Confidential")
        self.assertEqual(dlp.scan_text("Order 123456789012 and 234567890123")["total"], 0)  # Invalid checksums

    def test_29_upload_types_and_limits(self):
        c = self.client()
        self.full_login(c, "user1", "User@123")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("word/document.xml", "<w:p><w:t>PAN ABCPS1234K</w:t></w:p>")
        buf.seek(0)
        r = self.post(c, "/dlp", dict(file=(buf, "kyc.docx")), page="/dlp", content_type="multipart/form-data")
        self.assertIn("Confidential", r.get_data(as_text=True))
        r = self.post(c, "/dlp", dict(file=(io.BytesIO(b"x"), "virus.exe")), page="/dlp",
                      content_type="multipart/form-data", follow_redirects=True)
        self.assertIn("files are allowed", r.get_data(as_text=True))
        r = self.post(c, "/dlp", dict(file=(io.BytesIO(b"a" * (3 * 1024 * 1024)), "big.txt")), page="/dlp",
                      content_type="multipart/form-data")
        self.assertEqual(r.status_code, 413)

    def test_30_raw_data_not_stored(self):
        c = self.client()
        self.full_login(c, "user1", "User@123")
        self.post(c, "/dlp", dict(text="Aadhaar 2345 6789 0124 card 4111 1111 1111 1111"), page="/dlp")
        con = self.db()
        dump = " ".join(str(tuple(r)) for t in ["dlp_scans", "audit_logs"] for r in con.execute(f"SELECT * FROM {t}"))
        self.assertNotIn("6789 0124", dump)
        self.assertNotIn("4111 1111 1111 1111", dump)
        self.assertIn("0124", dump)       # Only masked trailing characters stored


# =========================================================================
class T10_AuditAndAdmin(Base):
    def test_31_audit_log_and_csv_export(self):
        a = self.client()
        self.full_login(a, "admin", "Admin@123")
        r = a.get("/audit/export")
        self.assertEqual(r.mimetype, "text/csv")
        self.assertIn("LOGIN_SUCCESS", r.get_data(as_text=True))
        self.assertEqual(len(self.events("AUDIT_EXPORTED")), 1)
        r = a.get("/audit?severity=alerts")
        self.assertEqual(r.status_code, 200)

    def test_32_policy_validation(self):
        a = self.client()
        self.full_login(a, "admin", "Admin@123")
        vals = {k: v for k, v in database.DEFAULT_POLICIES.items()}
        vals["mfa_risk_threshold"] = "500"
        r = self.post(a, "/admin/policies", vals, follow_redirects=True)
        self.assertIn("must be between", r.get_data(as_text=True))
        vals["mfa_risk_threshold"] = "40"
        self.post(a, "/admin/policies", vals)
        v = self.db().execute("SELECT value FROM policies WHERE key='mfa_risk_threshold'").fetchone()[0]
        self.assertEqual(v, "40")
        self.assertEqual(len(self.events("POLICY_CHANGED")), 1)

    def test_33_password_change(self):
        c = self.client()
        self.full_login(c, "user1", "User@123")
        self.post(c, "/profile", dict(action="password", current="User@123", new="N3w#Secure", confirm="N3w#Secure"))
        self.logout(c)
        self.assertIn("Invalid", self.login(c, "user1", "User@123").get_data(as_text=True))
        self.assertIn("/dashboard", self.login(c, "user1", "N3w#Secure").headers.get("Location", ""))

    def test_34_remove_device_requires_mfa_again(self):
        c = self.client()
        self.full_login(c, "user1", "User@123")
        did = self.db().execute("SELECT id FROM trusted_devices").fetchone()[0]
        self.post(c, "/profile", dict(action="remove_device", device_id=did))
        self.logout(c)
        r = self.login(c, "user1", "User@123")
        self.assertTrue(r.headers["Location"].endswith("/mfa/verify"))

    def test_35_admin_reset_mfa(self):
        u = self.client()
        self.full_login(u, "user1", "User@123")
        self.logout(u)
        a = self.client()
        self.full_login(a, "admin", "Admin@123")
        self.post(a, "/admin/users/3", dict(action="reset_mfa"))
        r = self.login(u, "user1", "User@123")
        self.assertTrue(r.headers["Location"].endswith("/mfa/setup"))

    def test_36_all_pages_render(self):
        a = self.client()
        self.full_login(a, "admin", "Admin@123")
        for p in ["/dashboard", "/profile", "/dlp", "/pim", "/audit", "/audit?severity=alerts&q=admin",
                  "/admin/users", "/admin/users/1", "/admin/users/2", "/admin/users/3", "/admin/policies"]:
            self.assertEqual(a.get(p).status_code, 200, p)
        self.assertEqual(a.get("/does-not-exist").status_code, 404)
        c = self.client()
        for p in ["/login", "/register"]:
            self.assertEqual(c.get(p).status_code, 200, p)


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
