"""
dlp.py
------
Data Loss Prevention (DLP) Scanner -> Microsoft Purview concept.

Scans text or uploaded files for sensitive data patterns (in the Indian context),
assigns a sensitivity label, and determines policy enforcement actions.

Detection combines regex matching with algorithmic checksum validation:
  * Aadhaar     -> Verhoeff checksum algorithm
  * Credit card -> Luhn checksum algorithm
This prevents false positives.
"""
import io
import re
import zipfile

# ---------------------------------------------------------------- checksums

_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def verhoeff_valid(num: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(num)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(ch)]]
    return c == 0


def luhn_valid(num: str) -> bool:
    total, alt = 0, False
    for ch in reversed(num):
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


# ---------------------------------------------------------------- rules
# (name, regex, validator, sensitivity level)
# Level: 3 = Highly Confidential, 2 = Confidential, 1 = Internal

def _digits(s):
    return re.sub(r"\D", "", s)


RULES = [
    ("Aadhaar Number", re.compile(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"),
     lambda m: verhoeff_valid(_digits(m)), 3),
    ("Credit/Debit Card", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
     lambda m: 13 <= len(_digits(m)) <= 19 and luhn_valid(_digits(m)), 3),
    ("PAN Card", re.compile(r"\b[A-Z]{3}[PCHABGJLFT][A-Z]\d{4}[A-Z]\b"), None, 2),
    ("Passport Number", re.compile(r"\b[A-PR-WY][1-9]\d{6}\b"), None, 2),
    ("IFSC Code", re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"), None, 2),
    ("Password in text", re.compile(r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*\S+"), None, 3),
    ("Mobile Number", re.compile(r"(?<!\d)(?:\+91[ -]?|0)?[6-9]\d{9}(?!\d)"), None, 1),
    ("Email Address", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), None, 1),
]

LABELS = {
    0: ("Public", "No sensitive data detected.", "Allow - Safe for external sharing"),
    1: ("Internal", "Personal contact information detected.", "Allow - Confidential to organization only"),
    2: ("Confidential", "Government ID / financial records detected.", "Warn - Encrypt prior to sharing"),
    3: ("Highly Confidential", "Critical sensitive records detected (Aadhaar, payment card, or credentials).",
        "BLOCK - External sharing prohibited; security incident logged"),
}


def mask_value(name: str, value: str) -> str:
    v = value.strip()
    if name == "Email Address":
        user, _, dom = v.partition("@")
        return (user[:2] + "•" * max(len(user) - 2, 1)) + "@" + dom
    if name == "Password in text":
        key = re.split(r"[:=]", v, maxsplit=1)[0]
        return key.strip() + ": ••••••••"
    keep = 4
    chars = [c for c in v]
    alnum_idx = [i for i, c in enumerate(chars) if c.isalnum()]
    for i in alnum_idx[:-keep]:
        chars[i] = "•"
    return "".join(chars)


def scan_text(text: str) -> dict:
    """Scans text and returns detected findings, sensitivity label, and action."""
    findings = {}
    taken = []   # Track matched spans to avoid duplicate or overlapping matches
    max_level = 0

    for name, rx, validator, level in RULES:
        for m in rx.finditer(text):
            s, e = m.span()
            if any(s < te and e > ts for ts, te in taken):
                continue
            if validator and not validator(m.group()):
                continue
            taken.append((s, e))
            findings.setdefault(name, {"count": 0, "samples": [], "level": level})
            findings[name]["count"] += 1
            if len(findings[name]["samples"]) < 3:
                findings[name]["samples"].append(mask_value(name, m.group()))
            max_level = max(max_level, level)

    label, reason, action = LABELS[max_level]
    return {
        "findings": findings,
        "total": sum(f["count"] for f in findings.values()),
        "level": max_level,
        "label": label,
        "reason": reason,
        "action": action,
        "chars": len(text),
    }


ALLOWED_EXT = {".txt", ".csv", ".log", ".json", ".md", ".docx"}


def extract_text(filename: str, data: bytes) -> str:
    """Extracts text from uploaded files (supports plain text and docx via xml parsing)."""
    name = filename.lower()
    if name.endswith(".docx"):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            xml = z.read("word/document.xml").decode("utf8", "ignore")
        xml = re.sub(r"</w:p>", "\n", xml)
        return re.sub(r"<[^>]+>", "", xml)
    return data.decode("utf8", "ignore")
