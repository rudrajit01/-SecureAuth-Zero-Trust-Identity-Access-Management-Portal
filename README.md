# 🛡️ SecureAuth: Zero Trust Identity & Access Management Portal

> **Curriculum Alignment:** *Security, Compliance, and Identity Fundamentals* (Certiport / Microsoft SC-900 Syllabus)  
> **Technology Stack:** Python 3.8+ · Flask · SQLite · HTML5 / CSS3 (Self-contained, operates offline without external CDN dependencies)

SecureAuth is a reference web portal that practically demonstrates the **Zero Trust Security Architecture** (*"Never trust, always verify"*). It translates core theoretical concepts from **Security**, **Compliance**, and **Identity** into fully operational, production-modeled capabilities.

---

## ▶️ Quickstart Guide (Windows / Linux / macOS)

```bash
# 1. Navigate to the project directory
cd SecureAuth

# 2. Install required dependencies (initial setup only)
pip install -r requirements.txt

# 3. Launch the application
python app.py
```
Open your browser and navigate to: **http://127.0.0.1:5000**

> On Windows, you can also launch the application directly by double-clicking **`run.bat`**.

### Demo Accounts (Auto-provisioned on initial launch)
| Username | Password | Role | Description |
|---|---|---|---|
| `admin` | `Admin@123` | Admin | Full administrative access & policy control |
| `manager1` | `Manager@123` | Manager | Operational access (Audit/DLP) & PIM-eligible |
| `user1` | `User@123` | User | Standard user access (Least Privilege) |

> 📱 **Initial Sign-In:** Multi-Factor Authentication (MFA) enrollment is required on first login. Scan the displayed QR code using **Google Authenticator**, **Microsoft Authenticator**, or any standard TOTP app.  
> 🔄 **Reset Database:** To reset the database to default state, remove the `secureauth.db` file and restart the application.

---

## ✨ Feature-to-Curriculum Mapping

| # | Feature | Certification & Architecture Concept |
|---|---|---|
| 1 | **Bcrypt Password Hashing** (with per-user cryptographic salt) + NIST-aligned complexity validation + live strength meter | Cryptographic Hashing, Secure Authentication |
| 2 | **Multi-Factor Authentication (MFA)** via RFC 6238 TOTP (Google / Microsoft Authenticator, SVG QR codes) | Multi-Factor Authentication (MFA), Strong Auth |
| 3 | **Role-Based Access Control (RBAC):** Admin, Manager, and User roles with strictly segregated privileges | RBAC, Authorization, Principle of Least Privilege |
| 4 | **Sign-In Risk Evaluation (0–100):** Real-time anomaly detection for new devices, unfamiliar locations, foreign origins, unusual hours, and rapid failed attempts | Microsoft Entra ID Protection, Adaptive Risk |
| 5 | **Conditional Access Engine:** Dynamic enforcement rules (`Low` → Allow, `Medium` → MFA Challenge, `High` → Block) with admin customization | Conditional Access, Zero Trust Policy Enforcement |
| 6 | **Privileged Identity Management (PIM):** Just-In-Time (JIT) admin role elevation requiring mandatory justification, step-up MFA, and auto-expiration | Privileged Identity Management (PIM), JIT Access |
| 7 | **Data Encryption at Rest:** AES-128 (Fernet) field-level encryption for phone, address, and TOTP keys, separated from database | Data Encryption at Rest, Azure Key Vault Pattern |
| 8 | **Comprehensive Audit Logging & SIEM:** Centralized audit telemetry with real-time incident alerting, keyword/severity filters, and CSV export | Auditing, SIEM (Microsoft Sentinel), Compliance |
| 9 | **Account Lockout Protection:** Automated account lockout after 5 consecutive failed password attempts | Brute-Force & Credential-Stuffing Mitigation |
| 10 | **Data Loss Prevention (DLP) Scanner:** Inspects Indian and global identifiers (Aadhaar, PAN, Payment Cards, Passports, IFSC, Email, Phone) with Verhoeff/Luhn checksum verification and automated sensitivity classification | Microsoft Purview, Data Loss Prevention, Classification |
| 11 | **Device Trust & Known Locations:** Device fingerprinting and location history for frictionless authentication | Device-based Conditional Access |
| 12 | **Defense in Depth:** Inactivity timeouts, anti-CSRF token validation, HttpOnly cookie flags, CSP and anti-sniff security headers, session-fixation rotation | Defense in Depth, Application Security |
| 13 | **Modern Enterprise UI/UX:** Dark & Light theme toggle, real-time ticking PIM countdown, drag-and-drop DLP upload, one-click demo credentials, instant table filtering, and copy-to-clipboard micro-interactions | Modern UI/UX, Operational Usability |

---

## 🎤 Demonstration Script (~10-Minute Walkthrough)

**1. User Registration & Cryptographic Hashing**
- On `/register`, enter a weak password (`hello`) to view real-time policy errors.
- Complete registration using a compliant password.
- Navigate to `/profile` to view how the password is saved as a one-way **bcrypt hash** and how contact details are stored as **AES ciphertext**.

**2. Multi-Factor Authentication Enrollment**
- Sign in with `user1`. Because MFA is mandatory under security defaults, the **MFA Setup** screen appears with an SVG QR code.
- Scan the QR code using Google/Microsoft Authenticator and submit the 6-digit TOTP code.

**3. Trusted Device Sign-In (Low Risk)**
- Sign out and sign in again from the same browser with simulated location *Ludhiana, India*.
- Sign-in completes seamlessly without an MFA prompt because the device is trusted and the evaluated risk is low.

**4. Conditional Access: Medium Risk Challenge**
- Expand *"🧪 Demo: Simulate sign-in location & time"* on `/login` and select **Moscow, Russia**.
- Risk score evaluates to **45 (MEDIUM)**; the user is challenged for **MFA verification**, with contextual risk factors displayed on-screen.

**5. Conditional Access: High Risk Block**
- Set Location to **Moscow, Russia** and Time to **02:00** on `/login`.
- Risk score evaluates to **65 (HIGH)**. Sign-in is **blocked immediately**, even though the entered password was valid.

**6. Brute-Force Protection & Account Lockout**
- Submit an incorrect password 5 times for `manager1`.
- The account transitions to **Locked** status, preventing further authentication attempts even with the correct password.

**7. Role-Based Access Control (RBAC)**
- As `user1`, attempt to access `/audit` or `/admin/users` directly. The system returns **403 Access Denied**.

**8. Administrative Operations & Governance**
- Sign in as `admin` (privileged accounts enforce MFA challenge on every sign-in).
- Inspect **Security Alerts** to review the blocked login attempt and account lockout incident.
- Navigate to **Users** → open `manager1` → click **Unlock** to restore the account.
- Review encrypted vs. decrypted data views.
- Under **Audit Logs**, filter by event or severity and click **Export CSV**.

**9. Privileged Identity Management (PIM / Just-In-Time Elevation)**
- Sign in as `manager1` and open the **PIM** dashboard.
- Enter a business justification (e.g., *"Unlock locked customer account - Ticket #1024"*) and enter a fresh TOTP code.
- The user is granted temporary **Admin** privileges for 30 minutes, unlocking access to administrative settings.
- The elevated role automatically expires when the timer lapses or can be manually revoked.

**10. Data Loss Prevention (DLP) Scanner**
- Navigate to `/dlp` and upload `sample_data/customer_records.txt`.
- The scanner detects Aadhaar and credit card records, classifies the file as **🏷️ Highly Confidential**, and triggers a **BLOCK** policy action with all sensitive numbers masked.
- Upload `meeting_notes.txt` (**Internal**) and `public_notice.txt` (**Public**).
- Notice that random numbers are not misidentified thanks to algorithmic checksum validation (Verhoeff and Luhn).

---

## ✅ Automated Testing Suite

SecureAuth includes **36 automated unit tests** (`tests/test_secureauth.py`). The test suite validates password hashing, MFA enforcement, Conditional Access logic, account lockout, RBAC permissions, PIM workflows, data encryption, CSRF/XSS defenses, DLP parsing, and audit trails.

```bash
python -m unittest discover -s tests -v
```
Output: `Ran 36 tests ... OK` ✔️ *(Each test runs against an isolated, temporary SQLite database to prevent data pollution).*

---

## 🧮 Sign-In Risk Scoring Model

| Anomaly Signal | Risk Points | Context / Rationale |
|---|---|---|
| New / Unrecognized Device | +30 | Device fingerprint unseen for this account |
| Unfamiliar Location | +25 | Geographic origin not in user's sign-in history |
| Sign-in Outside India | +20 | Cross-border connection / foreign IP |
| Unusual Hour (00:00 – 05:00) | +20 | Activity during typical off-peak window |
| 2+ Failed Sign-ins within 15 min | +15 | Potential brute-force or credential guessing |

* **0–29 → LOW:** Allow seamless sign-in for trusted devices.
* **30–59 → MEDIUM:** Require secondary MFA verification challenge.
* **60+ → HIGH:** Block sign-in attempt and log critical security alert.

*All thresholds and policy actions are dynamically configurable from the **Conditional Access** admin panel.*

---

## 📁 Repository Structure

```
SecureAuth/
├── app.py               # Flask application routes: auth, dashboard, PIM, DLP, admin
├── security.py          # Security engine: bcrypt hashing, AES encryption, TOTP, risk scoring, CSRF
├── dlp.py               # DLP scanner: regex patterns, Verhoeff/Luhn checksums, classification
├── database.py          # SQLite schema initialization, policy defaults, helper methods
├── requirements.txt     # Python package requirements
├── run.bat              # Windows one-click startup launcher
├── templates/           # Jinja2 HTML templates
├── static/              # Custom styling (style.css) and client-side logic (app.js)
├── sample_data/         # Synthetic files for DLP scanning demonstration
├── tests/               # 36 automated unit and integration tests (unittest)
├── instance/            # Auto-generated secret keys (encryption.key & flask_secret.key)
└── secureauth.db        # Auto-generated SQLite database
```

## 🗄️ Database Tables
* `users` · `trusted_devices` · `known_locations` · `audit_logs` · `pim_activations` · `dlp_scans` · `policies`

---

## ⚠️ Architectural Considerations & Production Roadmap

* **Geolocation:** The current demonstration environment allows simulated location selection via dropdown. Production deployments should resolve location via IP intelligence services (e.g., MaxMind GeoIP or Azure IP Intelligence).
* **Transport Security:** Production hosting must enforce TLS/HTTPS with `SESSION_COOKIE_SECURE = True` behind an enterprise WSGI/ASGI server (e.g., Gunicorn or Waitress).
* **Enterprise Roadmap:** Integration with Microsoft Entra ID via OpenID Connect / SAML 2.0, webhook/email notifications for high-severity alerts, formal approval workflows for PIM elevation, and native PDF/binary parsing for DLP scanning.
