"""Parsing of ``Received:`` header chains into structured mail hops."""

from __future__ import annotations

import re

from . import utils

_FROM_RE = re.compile(r"\bfrom\s+([^\s;()]+)(?:\s*[\(\[]\s*([^)\]]*)\s*[\)\]])?", re.IGNORECASE)
_BY_RE = re.compile(r"\bby\s+([^\s;()]+)", re.IGNORECASE)
_WITH_RE = re.compile(r"\bwith\s+([^\s;()]+)", re.IGNORECASE)
_FOR_RE = re.compile(r"\bfor\s+(<[^>]+>|\S+)", re.IGNORECASE)


def _extract_ip(text: str):
    if not text:
        return None
    for candidate in utils.find_ips(text):
        try:
            import ipaddress
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            continue
    return None


def _parse_single_received(raw_value: str) -> dict:
    normalized = re.sub(r"\s+", " ", raw_value or "").strip()

    # The timestamp is conventionally the text after the final semicolon.
    if ";" in normalized:
        clauses, _, timestamp_part = normalized.rpartition(";")
    else:
        clauses, timestamp_part = normalized, ""

    from_match = _FROM_RE.search(clauses)
    by_match = _BY_RE.search(clauses)
    with_match = _WITH_RE.search(clauses)
    for_match = _FOR_RE.search(clauses)

    from_host = from_match.group(1) if from_match else None
    from_extra = from_match.group(2) if from_match else None
    by_host = by_match.group(1) if by_match else None
    protocol = with_match.group(1) if with_match else None
    recipient = for_match.group(1).strip("<>") if for_match else None

    ip_source = f"{from_extra or ''} {clauses}"
    ip_address = _extract_ip(ip_source)
    ip_class = utils.classify_ip(ip_address) if ip_address else None

    timestamp_str = timestamp_part.strip() or None
    timestamp = utils.safe_parse_date(timestamp_str) if timestamp_str else None

    is_malformed = from_host is None and by_host is None

    return {
        "raw": raw_value.strip(),
        "from_host": from_host,
        "by_host": by_host,
        "protocol": protocol,
        "recipient": recipient,
        "ip_address": ip_address,
        "ip_classification": ip_class,
        "timestamp_str": timestamp_str,
        "timestamp": timestamp,
        "timestamp_valid": timestamp is not None if timestamp_str else None,
        "malformed": is_malformed,
    }


def parse_received_chain(received_raw: list) -> list:
    """Parse a list of raw ``Received`` header values (top-to-bottom, as
    they appear in the message -- i.e. most recent hop first) into a
    chronologically ordered list of hop dicts (oldest/origin hop first)."""
    hops = [_parse_single_received(value) for value in received_raw]
    hops.reverse()  # message order is reverse-chronological
    for index, hop in enumerate(hops, start=1):
        hop["hop_number"] = index
    return hops
