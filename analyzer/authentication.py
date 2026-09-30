"""SPF, DKIM, and DMARC result extraction from header text.

Important: this module only reports the results that the headers
themselves *claim* (e.g. what an upstream mail server wrote into
``Authentication-Results``). It performs no cryptographic verification
and no live SPF/DNS lookups -- see README for why that distinction
matters.
"""

from __future__ import annotations

import re

VALID_RESULTS = {"pass", "fail", "softfail", "neutral", "none",
                  "temperror", "permerror", "bestguesspass", "policy"}

_SPF_RE = re.compile(r"\bspf\s*=\s*(\w+)", re.IGNORECASE)
_DKIM_RE = re.compile(r"\bdkim\s*=\s*(\w+)", re.IGNORECASE)
_DMARC_RE = re.compile(r"\bdmarc\s*=\s*(\w+)", re.IGNORECASE)
_DKIM_D_RE = re.compile(r"[;\s]d\s*=\s*([^;\s]+)", re.IGNORECASE)
_DKIM_S_RE = re.compile(r"[;\s]s\s*=\s*([^;\s]+)", re.IGNORECASE)


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def _extract_all(pattern: re.Pattern, values) -> list:
    results = []
    for raw in values:
        normalized = _normalize(raw)
        for match in pattern.findall(normalized):
            result = match.lower()
            if result in VALID_RESULTS:
                results.append(result)
    return results


def _pick_result(results: list):
    """Authentication-Results headers are prepended by each trusted
    boundary MTA, so the first one in header order is the most recent
    (and most trusted) hop. Later entries are kept only to detect
    conflicts."""
    if not results:
        return "none-reported"
    return results[0]


def analyze_authentication(parsed: dict) -> dict:
    """Analyze SPF/DKIM/DMARC results from already-parsed headers.

    ``parsed`` is the dict returned by ``analyzer.parser.parse_headers``.
    """
    auth_results_raw = parsed.get("authentication_results_raw", [])
    received_spf_raw = parsed.get("received_spf_raw", [])
    dkim_sig_raw = parsed.get("dkim_signature_raw", [])

    spf_results = _extract_all(_SPF_RE, auth_results_raw)
    dkim_results = _extract_all(_DKIM_RE, auth_results_raw)
    dmarc_results = _extract_all(_DMARC_RE, auth_results_raw)

    # Fall back to a dedicated Received-SPF header if Authentication-Results
    # said nothing about SPF.
    if not spf_results and received_spf_raw:
        for raw in received_spf_raw:
            first_word = _normalize(raw).split(" ", 1)[0].lower()
            if first_word in VALID_RESULTS:
                spf_results.append(first_word)

    spf_final = _pick_result(spf_results)
    dkim_final = _pick_result(dkim_results)
    dmarc_final = _pick_result(dmarc_results)

    signing_domain = None
    selector = None
    if dkim_sig_raw:
        first_sig = _normalize(dkim_sig_raw[0])
        d_match = _DKIM_D_RE.search(first_sig)
        s_match = _DKIM_S_RE.search(first_sig)
        signing_domain = d_match.group(1).rstrip(";") if d_match else None
        selector = s_match.group(1).rstrip(";") if s_match else None

    conflicts = []
    if len(set(spf_results)) > 1:
        conflicts.append({"mechanism": "SPF", "results": sorted(set(spf_results))})
    if len(set(dkim_results)) > 1:
        conflicts.append({"mechanism": "DKIM", "results": sorted(set(dkim_results))})
    if len(set(dmarc_results)) > 1:
        conflicts.append({"mechanism": "DMARC", "results": sorted(set(dmarc_results))})

    return {
        "spf": spf_final,
        "dkim": dkim_final,
        "dmarc": dmarc_final,
        "dkim_signing_domain": signing_domain,
        "dkim_selector": selector,
        "spf_all_results": spf_results,
        "dkim_all_results": dkim_results,
        "dmarc_all_results": dmarc_results,
        "conflicts": conflicts,
        "authentication_results_present": bool(auth_results_raw),
    }
