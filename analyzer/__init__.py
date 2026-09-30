"""MailShield analyzer package.

Exposes a single high-level entry point, :func:`analyze_headers`, that
ties together header parsing, authentication analysis, routing
analysis, indicator detection, and risk scoring.
"""

from __future__ import annotations

from email.utils import parseaddr

from . import authentication, content, indicators, parser, risk_engine, routing, utils
from .parser import HeaderParseError

__all__ = ["analyze_headers", "HeaderParseError"]


def analyze_headers(raw_text: str) -> dict:
    """Run the full MailShield analysis pipeline on raw header text.

    Raises :class:`HeaderParseError` if the input cannot be parsed.
    """
    parsed = parser.parse_headers(raw_text)
    auth = authentication.analyze_authentication(parsed)
    hops = routing.parse_received_chain(parsed["received_raw"])
    indicator_list = indicators.generate_indicators(parsed, auth, hops)

    # Header checks above never see the message body. This pass covers a
    # real gap: a scam can have a perfectly clean header (e.g. a
    # compromised legitimate account) while the body carries a fake or
    # mismatched link. Static text/HTML parsing only -- no link is ever
    # fetched over the network.
    from_address = parseaddr(parsed["basic"].get("from") or "")[1]
    content_analysis = content.generate_content_indicators(raw_text, from_address)
    indicator_list.extend(content_analysis["indicators"])

    # Sort worst-first for display: HIGH, MEDIUM, LOW.
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    indicator_list.sort(key=lambda i: severity_order.get(i["severity"], 3))

    summary = risk_engine.summarize(indicator_list)

    basic = parsed["basic"]
    domain_analysis = {
        "from_domain": utils.extract_domain(parseaddr(basic.get("from") or "")[1]),
        "reply_to_domain": utils.extract_domain(parseaddr(basic.get("reply_to") or "")[1]),
        "return_path_domain": utils.extract_domain(parseaddr(basic.get("return_path") or "")[1]),
        "dkim_signing_domain": auth.get("dkim_signing_domain"),
        "message_id_domain": utils.extract_domain(
            (basic.get("message_id") or "").strip("<>")),
    }

    return {
        "score": summary["score"],
        "risk_level": summary["risk_level"],
        "basic": basic,
        "authentication": auth,
        "domain_analysis": domain_analysis,
        "hops": hops,
        "total_hops": len(hops),
        "indicators": indicator_list,
        "header_anomalies": {
            "missing_common_headers": parsed["missing_common_headers"],
            "duplicate_headers": parsed["duplicate_headers"],
            "malformed_lines": parsed["malformed_lines"],
            "bracket_mismatches": parsed["bracket_mismatches"],
            "long_headers": parsed["long_headers"],
            "suspicious_encoded_headers": parsed["suspicious_encoded_headers"],
        },
        "all_headers": parsed["all_headers"],
        "raw_header_text": parsed["raw_header_text"],
        "content_analysis": {
            "has_body": content_analysis["has_body"],
            "links": content_analysis["links"],
            "attachments": content_analysis["attachments"],
        },
    }
