"""Indicator detection.

Every check in this module produces zero or more indicator dicts of the
shape::

    {
        "code": "reply_to_mismatch",
        "severity": "HIGH" | "MEDIUM" | "LOW",
        "title": "...",
        "description": "...",
        "what": "...",   # explanation panel: what happened
        "why": "...",    # explanation panel: why it matters
        "check": "...",  # explanation panel: what an analyst should check
    }

Deliberately conservative wording throughout: an indicator flags
something worth reviewing, never a verdict that a message is malicious.
"""

from __future__ import annotations

from datetime import timedelta
from email.utils import parseaddr

from . import utils

FUTURE_TOLERANCE = timedelta(hours=1)
OLD_THRESHOLD = timedelta(days=365 * 5)
HOP_TIME_TOLERANCE = timedelta(hours=6)
DATE_VS_ROUTING_TOLERANCE = timedelta(hours=48)


_indicator = utils.build_indicator


# ---------------------------------------------------------------------------
# Authentication indicators
# ---------------------------------------------------------------------------

def check_authentication(auth: dict) -> list:
    indicators = []

    spf, dkim, dmarc = auth["spf"], auth["dkim"], auth["dmarc"]

    if spf == "fail":
        indicators.append(_indicator(
            "spf_fail", "HIGH", "SPF authentication failed",
            "The Authentication-Results/Received-SPF header reports spf=fail.",
            what="The sending server's IP address was not authorized to send "
                 "mail for the From domain, according to that domain's SPF record.",
            why="A hard SPF failure is a strong signal of a spoofed sending "
                "server, but it does not by itself prove the message is unsafe.",
            check="Compare the From domain with the server that actually sent "
                  "the message, and review the DKIM/DMARC results alongside it."))
    elif spf == "softfail":
        indicators.append(_indicator(
            "spf_softfail", "MEDIUM", "SPF soft-fail reported",
            "The headers report spf=softfail.",
            what="The domain's SPF record suggests the sending server is "
                 "probably not authorized, but the policy stops short of a hard fail.",
            why="Soft-fail is often used during SPF rollout, but can also "
                "accompany spoofed mail.",
            check="Treat like a weaker version of SPF fail; check DKIM/DMARC too."))
    elif spf in ("none", "none-reported"):
        indicators.append(_indicator(
            "spf_none", "LOW", "No SPF result available",
            "No SPF result was found in the analyzed headers.",
            what="Either the domain has no SPF record, or no server along "
                 "the path recorded an SPF check result.",
            why="Without an SPF result, this authentication mechanism gives "
                "no information either way.",
            check="Consider checking the sending domain's SPF record independently."))
    elif spf in ("temperror", "permerror"):
        indicators.append(_indicator(
            "spf_error", "LOW", f"SPF check reported {spf}",
            f"The SPF mechanism reported an error result: {spf}.",
            what="The SPF check could not be completed cleanly (DNS or "
                 "policy-record error).",
            why="An error result means SPF provided no reliable signal here.",
            check="Do not treat this as pass or fail; look at DKIM/DMARC instead."))

    if dkim == "fail":
        indicators.append(_indicator(
            "dkim_fail", "HIGH", "DKIM authentication failed",
            "The Authentication-Results header reports dkim=fail.",
            what="The DKIM signature attached to the message did not "
                 "validate against the reported signing domain.",
            why="A failed DKIM signature can indicate the message was "
                "altered in transit or the signature was never valid.",
            check="Compare the DKIM signing domain (d=) with the From domain, "
                  "and review SPF/DMARC together."))
    elif dkim in ("none", "none-reported"):
        indicators.append(_indicator(
            "dkim_none", "LOW", "No DKIM signature reported",
            "No DKIM result was found in the analyzed headers.",
            what="The message headers do not show a DKIM result.",
            why="Not every legitimate sender signs with DKIM, so this alone "
                "is weak evidence.",
            check="Weigh this alongside the SPF and DMARC results."))
    elif dkim in ("temperror", "permerror", "neutral"):
        indicators.append(_indicator(
            "dkim_error", "LOW", f"DKIM check reported {dkim}",
            f"The DKIM mechanism reported: {dkim}.",
            what="The DKIM check did not produce a clear pass or fail.",
            why="An inconclusive DKIM result provides no reliable signal.",
            check="Do not treat this as a pass; look at SPF/DMARC instead."))

    if dmarc == "fail":
        indicators.append(_indicator(
            "dmarc_fail", "HIGH", "DMARC authentication failed",
            "The Authentication-Results header reports dmarc=fail.",
            what="The message failed the domain owner's DMARC alignment "
                 "checks (SPF and/or DKIM did not align with the From domain).",
            why="DMARC failure is one of the strongest header-level signals "
                "that a message may be spoofed, though it is still not proof "
                "on its own.",
            check="Compare the From domain against the authenticated SPF/DKIM "
                  "domains, and review how the receiving system handled the "
                  "domain's DMARC policy."))
    elif dmarc == "none":
        indicators.append(_indicator(
            "dmarc_none", "MEDIUM", "No DMARC policy result",
            "The headers report dmarc=none or no DMARC result at all.",
            what="Either the domain publishes no DMARC policy, or the "
                 "policy requests no special handling on failure.",
            why="Domains without an enforced DMARC policy are easier to "
                "spoof convincingly.",
            check="Check the From domain's published DMARC policy independently."))
    elif dmarc in ("temperror", "permerror"):
        indicators.append(_indicator(
            "dmarc_error", "LOW", f"DMARC check reported {dmarc}",
            f"The DMARC mechanism reported an error result: {dmarc}.",
            what="The DMARC check could not be completed cleanly.",
            why="An error result means DMARC provided no reliable signal here.",
            check="Do not treat this as pass or fail."))

    for conflict in auth.get("conflicts", []):
        indicators.append(_indicator(
            "conflicting_auth_results", "HIGH",
            f"Conflicting {conflict['mechanism']} results",
            f"Multiple {conflict['mechanism']} results were found across "
            f"Authentication-Results headers: {', '.join(conflict['results'])}.",
            what="More than one hop reported a different authentication "
                 "result for the same mechanism.",
            why="Conflicting results can indicate a forged Authentication-Results "
                "header inserted before the message reached a trusted boundary.",
            check="Trust only the Authentication-Results header added by your "
                  "own organization's boundary mail server, and verify which "
                  "hop added each header."))

    return indicators


# ---------------------------------------------------------------------------
# Sender identity / domain indicators
# ---------------------------------------------------------------------------

def check_sender_identity(basic: dict, auth: dict) -> list:
    indicators = []

    from_domain = utils.extract_domain(parseaddr(basic.get("from") or "")[1])
    reply_to_domain = utils.extract_domain(parseaddr(basic.get("reply_to") or "")[1])
    return_path_domain = utils.extract_domain(parseaddr(basic.get("return_path") or "")[1])
    dkim_domain = (auth.get("dkim_signing_domain") or "").lower().rstrip(".")

    if reply_to_domain and from_domain and not utils.domains_match(from_domain, reply_to_domain):
        indicators.append(_indicator(
            "reply_to_mismatch", "HIGH", "Reply-To domain differs from From domain",
            f"From domain is '{from_domain}' but Reply-To domain is '{reply_to_domain}'.",
            what="The address a reply would actually go to differs from the "
                 "displayed sender's domain.",
            why="This difference can occur legitimately (e.g. marketing "
                "platforms, helpdesk systems), but it is also a common "
                "phishing technique to redirect replies to an attacker.",
            check="Confirm with the purported sender through a separate "
                  "channel before replying or acting on the message."))

    if return_path_domain and from_domain and not utils.domains_match(from_domain, return_path_domain):
        indicators.append(_indicator(
            "return_path_mismatch", "MEDIUM", "Return-Path domain differs from From domain",
            f"From domain is '{from_domain}' but Return-Path domain is '{return_path_domain}'.",
            what="Bounce messages for this email would be delivered to a "
                 "different domain than the one shown in From.",
            why="This is common with legitimate bulk-mail senders, but can "
                "also indicate a spoofed From address.",
            check="Check whether the Return-Path domain is a known mail "
                  "service provider used by the purported sender."))

    if dkim_domain and from_domain and not utils.domains_match(from_domain, dkim_domain):
        indicators.append(_indicator(
            "dkim_domain_mismatch", "MEDIUM", "DKIM signing domain differs from From domain",
            f"From domain is '{from_domain}' but the DKIM signature domain (d=) is '{dkim_domain}'.",
            what="The domain that cryptographically signed the message is "
                 "not the same as the domain shown in From.",
            why="Many legitimate services sign on behalf of a customer "
                "domain, but this is also how strict DMARC alignment checks "
                "catch spoofing.",
            check="Verify whether the signing domain is a mail service the "
                  "sender is known to use."))

    return indicators


def check_display_name_impersonation(basic: dict) -> list:
    """Catches a scam sent through a fully legitimate, properly
    authenticated mailbox (e.g. a free Gmail/Outlook account) where every
    header-alignment check above passes cleanly, but the human-readable
    From name claims to be a well-known brand while the actual address
    domain has nothing to do with it."""
    display_name, address = parseaddr(basic.get("from") or "")
    domain = utils.extract_domain(address)
    brand = utils.detect_display_name_brand_impersonation(display_name, domain)
    if not brand:
        return []
    return [_indicator(
        "display_name_brand_impersonation", "HIGH",
        "Display name claims to be a well-known brand",
        f"The From display name ('{display_name}') mentions '{brand}', but "
        f"the sending address domain ('{domain}') is unrelated to that brand.",
        what="The human-readable sender name references a well-known "
             "company, but the actual email address domain does not "
             "belong to that company.",
        why="Impersonating a trusted brand's name while sending from an "
            "unrelated address (often a free webmail account) is one of "
            "the most common real-world phishing and business email "
            "compromise techniques, because most mail clients display the "
            "name far more prominently than the address underneath it. "
            "This can catch a scam even when SPF/DKIM/DMARC all pass, "
            "since the message may be genuinely sent from that address.",
        check="Look at the actual email address, not just the display "
              "name, before trusting this message.")]


def check_message_id(basic: dict) -> list:
    indicators = []
    message_id = basic.get("message_id")
    from_domain = utils.extract_domain(parseaddr(basic.get("from") or "")[1])

    if not message_id:
        indicators.append(_indicator(
            "missing_message_id", "LOW", "Missing Message-ID header",
            "The analyzed headers do not include a Message-ID header.",
            what="No unique Message-ID was present.",
            why="Legitimate mail servers almost always add a Message-ID; "
                "its absence is a minor irregularity.",
            check="Consider this alongside other header anomalies."))
        return indicators

    message_id = message_id.strip()
    if not (message_id.startswith("<") and message_id.endswith(">") and "@" in message_id):
        indicators.append(_indicator(
            "invalid_message_id_format", "LOW", "Message-ID has an unusual format",
            f"Message-ID '{message_id}' does not match the expected <local@domain> format.",
            what="The Message-ID does not follow the conventional angle-bracket format.",
            why="Malformed Message-IDs are sometimes produced by non-standard "
                "or purpose-built mail-sending tools, including spam tools.",
            check="Note this as a minor irregularity, not proof of anything on its own."))
        return indicators

    mid_domain = utils.extract_domain(message_id.strip("<>"))
    if mid_domain and from_domain and not utils.domains_match(mid_domain, from_domain):
        indicators.append(_indicator(
            "message_id_domain_mismatch", "LOW", "Message-ID domain differs from sender domain",
            f"Message-ID domain is '{mid_domain}' but From domain is '{from_domain}'.",
            what="The domain embedded in the Message-ID does not match the From domain.",
            why="This commonly happens with mailing lists and bulk-mail "
                "platforms, so it is only a weak indicator on its own.",
            check="Cross-check against the SPF/DKIM/DMARC results and the "
                  "sending infrastructure."))
    return indicators


# ---------------------------------------------------------------------------
# Domain heuristics
# ---------------------------------------------------------------------------

def check_domain_heuristics(basic: dict) -> list:
    indicators = []
    checked_domains = {}
    for field in ("from", "reply_to", "return_path"):
        addr = parseaddr(basic.get(field) or "")[1]
        domain = utils.extract_domain(addr)
        if domain:
            checked_domains.setdefault(domain, []).append(field)

    for domain, fields in checked_domains.items():
        if utils.has_excessive_subdomains(domain):
            indicators.append(_indicator(
                "excessive_subdomains", "MEDIUM", "Excessive subdomains detected",
                f"Domain '{domain}' (from {', '.join(fields)}) has an unusually "
                f"deep subdomain structure.",
                what="The domain contains many subdomain labels.",
                why="Attackers sometimes stack subdomains to make a URL/domain "
                    "look like it belongs to a trusted brand.",
                check="Identify the actual registrable domain (the last two "
                      "labels) and verify who controls it."))

        lookalike_brand = utils.detect_lookalike_domain(domain)
        if lookalike_brand:
            indicators.append(_indicator(
                "lookalike_domain", "HIGH", "Possible lookalike domain",
                f"Domain '{domain}' (from {', '.join(fields)}) resembles "
                f"the brand '{lookalike_brand}' but is not that brand's domain.",
                what="Character substitution or added words make this domain "
                     "visually resemble a well-known brand.",
                why="Lookalike domains are a classic phishing technique to "
                    "deceive readers at a glance.",
                check="Compare character-by-character with the brand's real, "
                      "known domain before trusting the message."))
        else:
            impersonated_brand = utils.detect_brand_impersonation(domain)
            if impersonated_brand:
                indicators.append(_indicator(
                    "brand_impersonation_domain", "HIGH",
                    "Domain contains a well-known brand name",
                    f"Domain '{domain}' (from {', '.join(fields)}) contains "
                    f"the brand name '{impersonated_brand}' but is not that "
                    f"brand's own domain.",
                    what="The brand name appears in this domain, but in a "
                         "position that is not the brand's real domain.",
                    why="Embedding a trusted brand name in an unrelated "
                        "domain is a common phishing tactic.",
                    check="Compare with the brand's real, known domain "
                          "before trusting the message."))

        keyword = utils.suspicious_keyword_in_domain(domain)
        if keyword:
            indicators.append(_indicator(
                "suspicious_domain_keyword", "LOW", "Suspicious keyword detected in domain",
                f"Domain '{domain}' (from {', '.join(fields)}) contains the "
                f"keyword '{keyword}'.",
                what=f"The domain includes the word '{keyword}', which is "
                     "common in both legitimate and phishing domains.",
                why="This keyword alone does not indicate malicious intent, "
                    "but combined with other indicators it is worth reviewing.",
                check="Look at who actually registered/controls this domain."))

    return indicators


def check_domain_mismatch(basic: dict) -> list:
    """Broader mismatch check across From/Reply-To/Return-Path domains,
    reported once as a summary-level MEDIUM indicator per the spec."""
    from_domain = utils.extract_domain(parseaddr(basic.get("from") or "")[1])
    reply_domain = utils.extract_domain(parseaddr(basic.get("reply_to") or "")[1])
    if from_domain and reply_domain and not utils.domains_match(from_domain, reply_domain):
        return [_indicator(
            "sender_identity_domain_mismatch", "MEDIUM",
            "Sender identity domains do not match",
            f"From domain: {from_domain} | Reply-To domain: {reply_domain}",
            what="The identity domains used across sender-related headers "
                 "are not consistent.",
            why="Legitimate services sometimes use different domains for "
                "different purposes, but inconsistency is worth reviewing.",
            check="Confirm which domain is authoritative for this sender."
        )]
    return []


# ---------------------------------------------------------------------------
# IP / routing indicators
# ---------------------------------------------------------------------------

def check_ip_and_routing(hops: list) -> list:
    indicators = []
    for hop in hops:
        if hop["malformed"]:
            indicators.append(_indicator(
                "malformed_received_header", "MEDIUM", "Malformed Received header",
                f"Hop {hop['hop_number']}: could not identify 'from'/'by' "
                f"clauses in: {hop['raw'][:150]}",
                what="This Received header does not follow the conventional "
                     "'from ... by ...' structure.",
                why="Malformed routing headers can indicate a hand-crafted "
                    "or spoofed header, though some legitimate systems also "
                    "produce non-standard formats.",
                check="Compare this hop against the surrounding hops for consistency."))

        if hop["ip_address"] and hop["ip_classification"] == "Invalid":
            indicators.append(_indicator(
                "invalid_received_ip", "MEDIUM", "Invalid IP address in Received header",
                f"Hop {hop['hop_number']} contains an unparsable IP-like value.",
                what="A value that looked like an IP address did not parse as one.",
                why="This can indicate a malformed or deliberately obfuscated header.",
                check="Inspect the raw Received header for this hop directly."))

        if hop["ip_classification"] == "Private" and hop["hop_number"] == 1:
            indicators.append(_indicator(
                "private_ip_unexpected", "LOW", "Private IP address in originating hop",
                f"Hop {hop['hop_number']} reports a private IP address "
                f"({hop['ip_address']}) as the originating server.",
                what="The first hop's sending IP is a private (RFC 1918/ULA) address.",
                why="This is normal for mail originating inside an internal "
                    "network, but unusual for mail claiming to come from the "
                    "public internet.",
                check="Verify whether the claimed origin is expected to be internal."))

        if hop["timestamp_str"] and hop["timestamp"] is None:
            indicators.append(_indicator(
                "invalid_hop_timestamp", "LOW", "Unparsable timestamp in Received header",
                f"Hop {hop['hop_number']} timestamp '{hop['timestamp_str']}' could not be parsed.",
                what="The date/time at the end of this Received header is not "
                     "in a standard format.",
                why="This can be a sign of a hand-edited or synthetic header.",
                check="Review the raw header text for this hop."))
    return indicators


# ---------------------------------------------------------------------------
# Date / timestamp indicators
# ---------------------------------------------------------------------------

def check_dates(basic: dict, hops: list) -> list:
    indicators = []
    date_str = basic.get("date")
    date_dt = utils.safe_parse_date(date_str) if date_str else None
    now = utils.utc_now()

    if date_str and date_dt is None:
        indicators.append(_indicator(
            "invalid_date_format", "LOW", "Invalid Date header format",
            f"The Date header ('{date_str}') could not be parsed.",
            what="The Date header is not in a standard RFC 2822 format.",
            why="Malformed date headers are occasionally seen in "
                "non-standard mail tools, including spam tools.",
            check="Compare with the timestamps in the Received chain."))
    elif date_dt:
        if date_dt > now + FUTURE_TOLERANCE:
            indicators.append(_indicator(
                "future_timestamp", "MEDIUM", "Date header is in the future",
                f"The Date header ({date_dt.isoformat()}) is after the "
                f"current time ({now.isoformat()}).",
                what="The message claims to have been sent in the future.",
                why="This can indicate a misconfigured sending system or a "
                    "deliberately falsified header.",
                check="Compare with the Received chain timestamps for consistency."))
        elif now - date_dt > OLD_THRESHOLD:
            indicators.append(_indicator(
                "extremely_old_timestamp", "LOW", "Date header is extremely old",
                f"The Date header ({date_dt.isoformat()}) is more than "
                f"{OLD_THRESHOLD.days} days in the past.",
                what="The message claims a very old send date.",
                why="This is usually harmless (e.g. a resent or archived "
                    "message) but is worth noting.",
                check="Check if this message was resent or replayed."))

    hop_timestamps = [(h["hop_number"], h["timestamp"]) for h in hops if h["timestamp"]]
    for i in range(1, len(hop_timestamps)):
        prev_num, prev_ts = hop_timestamps[i - 1]
        cur_num, cur_ts = hop_timestamps[i]
        if cur_ts < prev_ts - HOP_TIME_TOLERANCE:
            indicators.append(_indicator(
                "timestamp_inconsistency", "MEDIUM", "Timestamp inconsistency in Received chain",
                f"Hop {cur_num} timestamp ({cur_ts.isoformat()}) is earlier than "
                f"hop {prev_num} timestamp ({prev_ts.isoformat()}) by more than "
                f"{HOP_TIME_TOLERANCE}.",
                what="A later hop in the delivery chain has an earlier "
                     "timestamp than an earlier hop.",
                why="Mail hops should generally move forward in time; a "
                    "reversal can indicate a forged or reordered Received header.",
                check="Review the full Received chain in order and look for "
                      "an inserted or fabricated hop."))
            break  # one summary indicator is enough to avoid noise

    if date_dt and hop_timestamps:
        first_hop_ts = hop_timestamps[0][1]
        if abs((date_dt - first_hop_ts).total_seconds()) > DATE_VS_ROUTING_TOLERANCE.total_seconds():
            indicators.append(_indicator(
                "date_routing_inconsistency", "MEDIUM",
                "Timestamp inconsistency between message Date and Received headers",
                f"The Date header ({date_dt.isoformat()}) differs from the "
                f"earliest Received hop ({first_hop_ts.isoformat()}) by more "
                f"than {DATE_VS_ROUTING_TOLERANCE}.",
                what="The claimed send date does not line up with when the "
                     "message actually entered the mail routing chain.",
                why="A large gap can indicate a falsified Date header or a "
                    "message that was held/replayed.",
                check="Compare both timestamps and consider the timezone "
                      "of each when reviewing."))

    return indicators


# ---------------------------------------------------------------------------
# Header anomalies
# ---------------------------------------------------------------------------

def check_header_anomalies(parsed: dict) -> list:
    indicators = []

    for header in parsed.get("missing_common_headers", []):
        indicators.append(_indicator(
            "missing_common_header", "LOW", f"Missing common header: {header}",
            f"The header '{header}' was not found in the analyzed headers.",
            what=f"'{header}' is normally present in a standards-compliant email.",
            why="Its absence is a minor irregularity that can also occur with "
                "certain automated or malformed mail tools.",
            check="Consider this together with other anomalies rather than alone."))

    for dup in parsed.get("duplicate_headers", []):
        indicators.append(_indicator(
            "duplicate_header", "LOW", f"Duplicate {dup['header']} header",
            f"The header '{dup['header']}' appears {dup['count']} times.",
            what="A header that is normally unique appears more than once.",
            why="Duplicate headers can be used to confuse mail clients about "
                "which value is authoritative, or can simply result from "
                "relay misconfiguration.",
            check="Inspect all instances of this header in the raw headers section."))

    for mismatch in parsed.get("bracket_mismatches", []):
        indicators.append(_indicator(
            "malformed_header", "MEDIUM", f"Malformed {mismatch['header']} header",
            f"'{mismatch['header']}' has unbalanced angle brackets: {mismatch['value']}",
            what="The header value has a '<' without a matching '>' (or vice versa).",
            why="This kind of malformation can indicate a hand-edited or "
                "tool-generated forged header.",
            check="Inspect the raw header value directly."))

    for line in parsed.get("malformed_lines", []):
        indicators.append(_indicator(
            "malformed_header_line", "MEDIUM", "Malformed header line",
            f"Line {line['line_number']} does not look like a valid header "
            f"or continuation: {line['content']}",
            what="A line in the header block does not match the expected "
                 "'Name: value' or folded-continuation format.",
            why="This can indicate injected content or a corrupted/forged header block.",
            check="Review the raw headers around this line closely."))

    for long_header in parsed.get("long_headers", []):
        indicators.append(_indicator(
            "extremely_long_header", "LOW", f"Extremely long {long_header['header']} header",
            f"'{long_header['header']}' is {long_header['length']} characters long.",
            what="This header value is far longer than typical.",
            why="Unusually long header values are sometimes used to hide "
                "content or exploit poorly written mail parsers.",
            check="Review the full value in the raw headers section."))

    for enc in parsed.get("suspicious_encoded_headers", []):
        indicators.append(_indicator(
            "suspicious_encoded_header", "MEDIUM",
            f"Suspicious encoded value in {enc['header']} header",
            f"'{enc['header']}' contains an encoded-word that is "
            f"{'unusually long' if enc['encoded_length'] > 300 else 'malformed'}.",
            what="The header uses MIME encoded-word syntax (=?charset?B/Q?...?=) "
                 "that is either very long or does not decode cleanly.",
            why="Encoded words are legitimate for non-ASCII text, but can also "
                "be used to obscure header content from casual review.",
            check="Decode the value manually and inspect its contents."))

    return indicators


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def generate_indicators(parsed: dict, auth: dict, hops: list) -> list:
    indicators = []
    indicators.extend(check_authentication(auth))
    indicators.extend(check_sender_identity(parsed["basic"], auth))
    indicators.extend(check_display_name_impersonation(parsed["basic"]))
    indicators.extend(check_domain_mismatch(parsed["basic"]))
    indicators.extend(check_message_id(parsed["basic"]))
    indicators.extend(check_domain_heuristics(parsed["basic"]))
    indicators.extend(check_ip_and_routing(hops))
    indicators.extend(check_dates(parsed["basic"], hops))
    indicators.extend(check_header_anomalies(parsed))
    return indicators
