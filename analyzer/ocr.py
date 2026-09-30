"""OCR-based analysis of an email *screenshot* image.

This is a fundamentally more limited analysis than header-based
analysis: a screenshot only shows what a mail client rendered on
screen. It never contains SPF/DKIM/DMARC results, the Received chain,
or a link's real destination (only its visible display text) -- those
live in headers that no screenshot exposes. This module extracts
whatever visible text it can and runs the same conservative,
phrase/heuristic-based checks used for pasted message bodies.

OCR runs entirely locally via the Tesseract engine (through
pytesseract) -- the image is never uploaded anywhere.
"""

from __future__ import annotations

import os
import re
import shutil
from io import BytesIO

from . import content, risk_engine, utils

try:
    import pytesseract
    from PIL import Image
    OCR_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when deps are missing
    OCR_AVAILABLE = False

if OCR_AVAILABLE and not shutil.which("tesseract"):
    # A fresh install's PATH update (e.g. via winget) doesn't take effect
    # until a new terminal session starts. Fall back to the well-known
    # Windows install locations so the app works immediately either way.
    for _candidate in (
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    ):
        if os.path.isfile(_candidate):
            pytesseract.pytesseract.tesseract_cmd = _candidate
            break

MAX_IMAGE_BYTES = 5 * 1024 * 1024  # 5 MB -- images are heavier than plain text
ALLOWED_IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"}

_indicator = utils.build_indicator

_SENDER_LINE_RE = re.compile(
    r"([A-Za-z0-9 .,'\-]{0,60}?)\s*[<(]\s*([\w.+\-]+@[\w\-]+\.[\w.\-]+)\s*[>)]",
)
_BARE_EMAIL_RE = re.compile(r"[\w.+\-]+@[\w\-]+\.[\w.\-]+")
_SUBJECT_LINE_RE = re.compile(r"^\s*(?:subject)\s*[:\-]\s*(.+)$", re.IGNORECASE | re.MULTILINE)


class OCRError(ValueError):
    """Raised when the image can't be read or OCR can't run at all."""


def extract_text_from_image(image_bytes: bytes) -> str:
    if not OCR_AVAILABLE:
        raise OCRError(
            "OCR support is not available on this system (pytesseract/Pillow "
            "or the Tesseract engine is missing).")
    try:
        image = Image.open(BytesIO(image_bytes))
        image.load()
    except Exception as exc:
        raise OCRError(f"Could not read the uploaded image: {exc}") from exc
    try:
        return pytesseract.image_to_string(image)
    except Exception as exc:
        raise OCRError(f"OCR failed: {exc}") from exc


def guess_sender(ocr_text: str):
    """Best-effort extraction of a display name / email address from
    OCR'd text. Screenshots rarely label this cleanly, so this looks for
    a "Name <email@domain>" pattern first, then falls back to any bare
    email address near the top of the text (senders are almost always
    shown near the top of a rendered message)."""
    head = "\n".join(ocr_text.splitlines()[:15])
    match = _SENDER_LINE_RE.search(head)
    if match:
        return match.group(1).strip(" ,") or None, match.group(2)
    bare = _BARE_EMAIL_RE.search(head) or _BARE_EMAIL_RE.search(ocr_text)
    return (None, bare.group(0)) if bare else (None, None)


def guess_subject(ocr_text: str):
    match = _SUBJECT_LINE_RE.search(ocr_text)
    return match.group(1).strip() if match else None


def _sender_domain_indicators(display_name, sender_domain):
    indicators = []
    if not sender_domain:
        return indicators

    if display_name:
        brand = utils.detect_display_name_brand_impersonation(display_name, sender_domain)
        if brand:
            indicators.append(_indicator(
                "display_name_brand_impersonation", "HIGH",
                "Display name claims to be a well-known brand",
                f"The visible sender name ('{display_name}') mentions "
                f"'{brand}', but the visible address domain "
                f"('{sender_domain}') is unrelated to that brand.",
                what="The human-readable sender name references a "
                     "well-known company, but the visible email address "
                     "domain does not belong to that company.",
                why="Impersonating a trusted brand's name while sending "
                    "from an unrelated address is one of the most common "
                    "real-world phishing techniques.",
                check="Look at the actual email address, not just the "
                      "display name, before trusting this message."))

    lookalike = utils.detect_lookalike_domain(sender_domain)
    if lookalike:
        indicators.append(_indicator(
            "lookalike_domain", "HIGH", "Possible lookalike sender domain",
            f"Visible sender domain '{sender_domain}' resembles the "
            f"brand '{lookalike}' but is not that brand's domain.",
            what="Character substitution makes this domain visually "
                 "resemble a well-known brand.",
            why="Lookalike domains are a classic phishing technique.",
            check="Compare character-by-character with the brand's "
                  "real, known domain."))
    else:
        impersonation = utils.detect_brand_impersonation(sender_domain)
        if impersonation:
            indicators.append(_indicator(
                "brand_impersonation_domain", "HIGH",
                "Sender domain contains a well-known brand name",
                f"Visible sender domain '{sender_domain}' contains the "
                f"brand name '{impersonation}' but is not that brand's "
                f"own domain.",
                what="The brand name appears in this domain, but in a "
                     "position that is not the brand's real domain.",
                why="Embedding a trusted brand name in an unrelated "
                    "domain is a common phishing tactic.",
                check="Compare with the brand's real, known domain."))

    keyword = utils.suspicious_keyword_in_domain(sender_domain)
    if keyword:
        indicators.append(_indicator(
            "suspicious_domain_keyword", "LOW",
            "Suspicious keyword detected in sender domain",
            f"Visible sender domain '{sender_domain}' contains the "
            f"keyword '{keyword}'.",
            what=f"The domain includes the word '{keyword}'.",
            why="This keyword alone does not indicate malicious intent, "
                "but is worth reviewing alongside other indicators.",
            check="Look at who actually controls this domain."))

    return indicators


def analyze_image(image_bytes: bytes) -> dict:
    """Run OCR plus conservative text-based heuristics on an email
    screenshot. Deliberately does NOT attempt SPF/DKIM/DMARC or
    Received-chain analysis, and cannot check link text-vs-destination
    mismatches -- a screenshot never exposes a link's real underlying
    href, only whatever text is visibly rendered. See README for this
    limitation.
    """
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise OCRError("Image exceeds the 5 MB size limit.")

    ocr_text = extract_text_from_image(image_bytes)
    if not ocr_text.strip():
        raise OCRError(
            "No readable text was found in the image. Try a clearer or "
            "higher-resolution screenshot.")

    display_name, sender_address = guess_sender(ocr_text)
    subject = guess_subject(ocr_text)
    sender_domain = utils.extract_domain(sender_address) if sender_address else None

    indicator_list = []
    indicator_list.extend(_sender_domain_indicators(display_name, sender_domain))
    indicator_list.extend(content.check_urgency_language(ocr_text, None))
    indicator_list.extend(content.check_financial_prize_language(ocr_text, None))
    indicator_list.extend(content.check_credential_request_language(ocr_text, None))
    indicator_list.extend(content.check_legal_threat_language(ocr_text, None))
    indicator_list.extend(content.check_job_scam_language(ocr_text, None))
    indicator_list.extend(content.check_contact_email_mismatch(ocr_text, sender_address))

    links = content.extract_links(ocr_text, None)
    indicator_list.extend(content.check_link_domains(links))
    indicator_list.extend(content.check_link_obfuscation(links))

    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    indicator_list.sort(key=lambda i: severity_order.get(i["severity"], 3))
    summary = risk_engine.summarize(indicator_list)

    return {
        "score": summary["score"],
        "risk_level": summary["risk_level"],
        "ocr_text": ocr_text,
        "guessed_sender_name": display_name,
        "guessed_sender_address": sender_address,
        "guessed_sender_domain": sender_domain,
        "guessed_subject": subject,
        "links": [
            {"href": link["href"], "domain": utils.extract_url_hostname(link["href"])}
            for link in links
        ],
        "indicators": indicator_list,
    }
