"""Transparent, configurable risk scoring.

The score is a "Suspicion Score", not a probability of phishing. Edit
``WEIGHTS`` below to tune how much each indicator contributes -- this is
the single place that controls scoring behavior.
"""

from __future__ import annotations

MAX_SCORE = 100

# code -> points contributed each time that indicator is found.
WEIGHTS = {
    "spf_fail": 20,
    "spf_softfail": 10,
    "spf_none": 5,
    "spf_error": 3,
    "dkim_fail": 15,
    "dkim_none": 5,
    "dkim_error": 3,
    "dmarc_fail": 25,
    "dmarc_none": 8,
    "dmarc_error": 3,
    "conflicting_auth_results": 15,
    "reply_to_mismatch": 15,
    "return_path_mismatch": 10,
    "dkim_domain_mismatch": 10,
    "sender_identity_domain_mismatch": 10,
    "malformed_header": 10,
    "malformed_header_line": 10,
    "malformed_received_header": 10,
    "duplicate_header": 5,
    "suspicious_domain_keyword": 10,
    "lookalike_domain": 15,
    "brand_impersonation_domain": 15,
    "display_name_brand_impersonation": 15,
    "excessive_subdomains": 8,
    "invalid_received_ip": 10,
    "private_ip_unexpected": 5,
    "future_timestamp": 10,
    "extremely_old_timestamp": 5,
    "invalid_date_format": 5,
    "timestamp_inconsistency": 10,
    "date_routing_inconsistency": 10,
    "invalid_hop_timestamp": 5,
    "missing_message_id": 5,
    "invalid_message_id_format": 5,
    "message_id_domain_mismatch": 5,
    "missing_common_header": 3,
    "suspicious_encoded_header": 8,
    "extremely_long_header": 5,
    # Body/link content checks (analyzer.content) -- see README for why
    # these exist alongside the header-only checks above.
    "link_text_href_mismatch": 20,
    "link_ip_url": 15,
    "link_lookalike_domain": 15,
    "link_brand_impersonation": 15,
    "link_shortener": 8,
    "link_suspicious_keyword": 5,
    "urgency_language": 8,
    "link_userinfo_trick": 20,
    "link_punycode_domain": 12,
    "financial_prize_language": 10,
    "credential_request_language": 20,
    "suspicious_attachment": 20,
    "legal_threat_language": 20,
    "job_scam_language": 10,
    "contact_email_mismatch": 15,
}

RISK_THRESHOLDS = (
    (19, "LOW"),
    (39, "MODERATE"),
    (69, "HIGH"),
    (100, "CRITICAL"),
)

_LEVEL_ORDER = ["LOW", "MODERATE", "HIGH", "CRITICAL"]

# A severity floor for the overall risk level, independent of the pure
# point total. Rationale: a single HIGH-severity indicator -- an explicit
# credential request, a law-enforcement extortion threat, a confirmed
# link mismatch -- represents a strong, specific finding on its own and
# should never be undersold as merely LOW/MODERATE just because few
# other indicators happened to fire alongside it. This matters most for
# image-based (OCR) analysis, which has structurally fewer simultaneous
# signals available than full header analysis (no SPF/DKIM/DMARC, no
# Received chain), so a single strong finding there is proportionally
# more significant, not less.
_SEVERITY_FLOOR = {"HIGH": "HIGH", "MEDIUM": "MODERATE", "LOW": "LOW"}


def calculate_score(indicators: list) -> int:
    total = sum(WEIGHTS.get(indicator["code"], 5) for indicator in indicators)
    return min(total, MAX_SCORE)


def risk_level(score: int) -> str:
    for threshold, label in RISK_THRESHOLDS:
        if score <= threshold:
            return label
    return "CRITICAL"


def _severity_floor(indicators: list) -> str:
    floor = "LOW"
    for indicator in indicators:
        candidate = _SEVERITY_FLOOR.get(indicator.get("severity"), "LOW")
        if _LEVEL_ORDER.index(candidate) > _LEVEL_ORDER.index(floor):
            floor = candidate
    return floor


def summarize(indicators: list) -> dict:
    score = calculate_score(indicators)
    level = risk_level(score)
    floor = _severity_floor(indicators)
    if _LEVEL_ORDER.index(floor) > _LEVEL_ORDER.index(level):
        level = floor
    return {
        "score": score,
        "risk_level": level,
    }
