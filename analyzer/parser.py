"""Raw email header parsing.

Uses only Python's built-in ``email`` module plus some line-level regex
checks (the ``email`` package is deliberately lenient about malformed
input, so we do our own pass to catch the kinds of formatting problems
that are themselves security-relevant, e.g. mismatched angle brackets).
"""

from __future__ import annotations

import re
from email import message_from_string
from email.policy import compat32

MAX_INPUT_BYTES = 1 * 1024 * 1024  # 1 MB

COMMON_HEADERS = ("From", "To", "Subject", "Date", "Message-ID")
SINGLE_INSTANCE_HEADERS = (
    "From", "To", "Subject", "Date", "Reply-To", "Return-Path",
    "Message-ID", "Content-Type", "MIME-Version",
)
LONG_HEADER_THRESHOLD = 1000
ENCODED_WORD_RE = re.compile(r"=\?[^?]+\?[bBqQ]\?[^?]*\?=")

_HEADER_START_RE = re.compile(r"^[!-9;-~]+:")  # RFC 5322 field-name, no colon


class HeaderParseError(ValueError):
    """Raised when the supplied text cannot reasonably be parsed as headers."""


def _split_header_only(raw_text: str) -> str:
    """Return only the header portion of a raw message (drop any body)."""
    normalized = raw_text.replace("\r\n", "\n").replace("\r", "\n")
    if "\n\n" in normalized:
        head, _, _ = normalized.partition("\n\n")
        return head
    return normalized


def find_malformed_lines(header_text: str):
    """Line-level sanity check independent of the ``email`` parser.

    Flags lines that are neither a valid ``Name: value`` header start nor
    a folded continuation line (leading whitespace).
    """
    malformed = []
    lines = header_text.split("\n")
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        if line[0] in (" ", "\t"):
            continue  # folded continuation of the previous header
        if _HEADER_START_RE.match(line):
            continue
        malformed.append({"line_number": index, "content": line.strip()[:200]})
    return malformed


def find_bracket_mismatches(header_text: str):
    """Detect headers with unbalanced angle brackets, e.g. ``a@b.com>``."""
    issues = []
    for name, value in re.findall(r"^([A-Za-z][\w\-]*):[ \t]*(.*)$", header_text, re.MULTILINE):
        if value.count("<") != value.count(">"):
            issues.append({"header": name, "value": value.strip()[:200]})
    return issues


def find_long_headers(header_text: str, threshold: int = LONG_HEADER_THRESHOLD):
    long_headers = []
    for name, value in re.findall(r"^([A-Za-z][\w\-]*):[ \t]*(.*)$", header_text, re.MULTILINE):
        if len(value) > threshold:
            long_headers.append({"header": name, "length": len(value)})
    return long_headers


def find_suspicious_encoded_headers(header_text: str):
    """Look for MIME encoded-words (RFC 2047) that fail to decode cleanly
    or are unusually long, which can be used to obscure header content."""
    suspicious = []
    for name, value in re.findall(r"^([A-Za-z][\w\-]*):[ \t]*(.*)$", header_text, re.MULTILINE):
        words = ENCODED_WORD_RE.findall(value)
        if not words:
            continue
        total_len = sum(len(w) for w in words)
        try:
            from email.header import decode_header
            decode_header(value)
            decodes_cleanly = True
        except Exception:
            decodes_cleanly = False
        if not decodes_cleanly or total_len > 300:
            suspicious.append({"header": name, "encoded_length": total_len,
                                "decodes_cleanly": decodes_cleanly})
    return suspicious


def parse_headers(raw_text: str) -> dict:
    """Parse raw header text into a structured dictionary.

    Returns a dict with keys:
        basic, received_raw, all_headers, duplicate_headers,
        missing_common_headers, malformed_lines, bracket_mismatches,
        long_headers, suspicious_encoded_headers, raw_header_text
    """
    if raw_text is None or not raw_text.strip():
        raise HeaderParseError("No header content was supplied.")

    if len(raw_text.encode("utf-8", errors="ignore")) > MAX_INPUT_BYTES:
        raise HeaderParseError("Input exceeds the 1 MB size limit.")

    header_text = _split_header_only(raw_text)

    try:
        msg = message_from_string(header_text, policy=compat32)
    except Exception as exc:  # pragma: no cover - email parser is very lenient
        raise HeaderParseError(f"Unable to parse headers: {exc}") from exc

    all_headers = [(name, str(value)) for name, value in msg.items()]
    if not all_headers:
        raise HeaderParseError("No recognizable email headers were found.")

    def get(name):
        return msg.get(name)

    def get_all(name):
        return msg.get_all(name) or []

    basic = {
        "from": get("From"),
        "to": get("To"),
        "cc": get("Cc"),
        "reply_to": get("Reply-To"),
        "subject": get("Subject"),
        "date": get("Date"),
        "message_id": get("Message-ID"),
        "return_path": get("Return-Path"),
        "mime_version": get("MIME-Version"),
        "content_type": get("Content-Type"),
    }

    received_raw = get_all("Received")

    duplicate_headers = []
    seen_counts = {}
    for name, _ in all_headers:
        key = name.title()
        seen_counts[key] = seen_counts.get(key, 0) + 1
    for name in SINGLE_INSTANCE_HEADERS:
        if seen_counts.get(name, 0) > 1:
            duplicate_headers.append({"header": name, "count": seen_counts[name]})

    missing_common_headers = [h for h in COMMON_HEADERS if not get(h)]

    return {
        "basic": basic,
        "received_raw": received_raw,
        "all_headers": all_headers,
        "duplicate_headers": duplicate_headers,
        "missing_common_headers": missing_common_headers,
        "malformed_lines": find_malformed_lines(header_text),
        "bracket_mismatches": find_bracket_mismatches(header_text),
        "long_headers": find_long_headers(header_text),
        "suspicious_encoded_headers": find_suspicious_encoded_headers(header_text),
        "raw_header_text": header_text,
        "authentication_results_raw": get_all("Authentication-Results"),
        "received_spf_raw": get_all("Received-SPF"),
        "dkim_signature_raw": get_all("DKIM-Signature"),
    }
