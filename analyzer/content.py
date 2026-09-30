"""Offline, rule-based analysis of the *message body*: links and
urgency-style wording.

This module never fetches a URL over the network -- it only parses the
text of the message as supplied. That is a hard requirement of the
project (see README "Privacy"/"Security"): MailShield must never visit a
link automatically.

It complements ``analyzer.indicators`` (which only looks at headers) to
cover a real gap: a scam email can have a perfectly clean header (e.g. a
compromised-but-legitimate sending account) while the *body* contains a
fake/mismatched link or urgent, high-pressure wording. Grammar/spelling
quality scoring is deliberately NOT attempted here -- that reliably
requires NLP/ML, which is out of scope for this offline tool.
"""

from __future__ import annotations

import re
from email import message_from_string
from email.policy import compat32
from html.parser import HTMLParser

from . import utils

BARE_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
DOMAIN_LIKE_RE = re.compile(
    r"(?:https?://)?(?:www\.)?([a-z0-9][a-z0-9\-]{0,62}(?:\.[a-z0-9][a-z0-9\-]{0,62})+)",
    re.IGNORECASE)

URGENCY_PHRASES = (
    "verify your account", "account will be suspended",
    "account has been suspended", "account has been locked",
    "click here immediately", "act now", "urgent action required",
    "confirm your identity", "unusual sign-in activity",
    "your account will be locked", "within 24 hours", "within 12 hours",
    "limited time", "failure to act", "update your billing",
    "restricted access", "avoid suspension", "verify your identity",
    "immediate action required", "security alert",
)
URGENCY_MATCH_THRESHOLD = 2  # require 2+ distinct phrases to reduce noise

# Rarer, more specific phrases than URGENCY_PHRASES -- these show up in
# everyday legitimate mail far less often, so a single match is enough
# to warrant a (MEDIUM, not HIGH) flag rather than requiring a threshold.
FINANCIAL_PRIZE_PHRASES = (
    "you have been selected", "claim your prize", "claim your award",
    "claim your donation", "processing fee", "wire transfer",
    "lottery winner", "inheritance", "beneficiary of", "gift card",
    "donation award", "cash prize", "you have won", "unclaimed funds",
)

CREDENTIAL_REQUEST_PHRASES = (
    "enter your password", "confirm your password", "provide your pin",
    "social security number", "card number and cvv", "login credentials",
    "enter your ssn", "provide your login", "confirm your card details",
    "enter your card details", "verify your password",
    "provide the requested information", "log in to your account and",
    "update your payment information",
)

# Threatening/extortion language impersonating law enforcement or a legal
# authority. Rare and aggressive enough in legitimate mail that a single
# match is a strong signal on its own.
LEGAL_THREAT_PHRASES = (
    "arrest warrant", "sex offender", "child pornography",
    "cyberpornography", "pedophilia", "attorney general",
    "legal proceedings", "cybercrime investigators",
    "sexual assault charge", "criminal charges against you",
    "law enforcement action", "nearest police station",
)

# Unsolicited job/recruitment offer language -- MEDIUM on its own since
# legitimate recruiters do use some of this wording, but combined with a
# mismatched contact address (see check_contact_email_mismatch) it's a
# strong signal.
JOB_SCAM_PHRASES = (
    "work from home position", "weekly paid job", "part-time job",
    "no experience required", "job opportunity information",
    "flexible working hours from home", "hiring immediately",
)


_indicator = utils.build_indicator


class _AnchorExtractor(HTMLParser):
    """Collects (href, visible_text) pairs for every <a> tag."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.anchors = []
        self._current_href = None
        self._current_text = []
        self._depth = 0

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = dict(attrs).get("href")
            self._current_href = href
            self._current_text = []
            self._depth += 1

    def handle_data(self, data):
        if self._depth > 0:
            self._current_text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._depth > 0:
            self._depth -= 1
            text = "".join(self._current_text).strip()
            if self._current_href:
                self.anchors.append((self._current_href, text))
            self._current_href = None
            self._current_text = []


class _TextExtractor(HTMLParser):
    """Strips tags down to plain visible text, for keyword scanning."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.chunks = []

    def handle_data(self, data):
        self.chunks.append(data)

    def get_text(self):
        return " ".join(self.chunks)


def extract_message_body(raw_text: str) -> dict:
    """Parse the full raw message (headers + body) and return decoded
    plain-text and HTML parts. Returns ``{"plain": None, "html": None}``
    if there is no body (e.g. a headers-only paste)."""
    try:
        msg = message_from_string(raw_text or "", policy=compat32)
    except Exception:
        return {"plain": None, "html": None}

    plain_text = None
    html_text = None

    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        content_type = part.get_content_type()
        if part.is_multipart():
            continue
        if content_type not in ("text/plain", "text/html"):
            continue
        try:
            payload = part.get_payload(decode=True)
        except Exception:
            continue
        if payload is None:
            continue
        charset = part.get_content_charset() or "utf-8"
        try:
            text = payload.decode(charset, errors="replace")
        except (LookupError, TypeError):
            text = payload.decode("utf-8", errors="replace")

        if not text.strip():
            continue  # an empty part is not a body worth analyzing

        if content_type == "text/plain" and plain_text is None:
            plain_text = text
        elif content_type == "text/html" and html_text is None:
            html_text = text

    return {"plain": plain_text, "html": html_text}


def extract_links(plain_text: str, html_text: str) -> list:
    """Return a de-duplicated list of {href, display_text} link dicts.

    Bare URLs are only scanned for in *visible* text (tags/attributes
    stripped), so an anchor's href attribute or its own URL-shaped
    display text is never double-counted as a second, separate link.
    """
    links = []
    seen_hrefs = set()
    consumed_texts = set()

    if html_text:
        extractor = _AnchorExtractor()
        try:
            extractor.feed(html_text)
        except Exception:
            pass
        for href, text in extractor.anchors:
            if href in seen_hrefs:
                continue
            seen_hrefs.add(href)
            links.append({"href": href, "display_text": text or None})
            if text:
                consumed_texts.add(text.strip())

    visible_parts = []
    if plain_text:
        visible_parts.append(plain_text)
    if html_text:
        stripper = _TextExtractor()
        try:
            stripper.feed(html_text)
            visible_parts.append(stripper.get_text())
        except Exception:
            pass

    combined_text = " ".join(visible_parts)
    for match in BARE_URL_RE.findall(combined_text):
        if match in seen_hrefs or match in consumed_texts:
            continue
        seen_hrefs.add(match)
        links.append({"href": match, "display_text": None})

    return links


def _domain_from_display_text(display_text: str):
    if not display_text:
        return None
    match = DOMAIN_LIKE_RE.search(display_text.strip())
    return match.group(1).lower().rstrip(".") if match else None


def check_link_mismatches(links: list) -> list:
    indicators = []
    for link in links:
        display_domain = _domain_from_display_text(link.get("display_text"))
        if not display_domain:
            continue
        href_domain = utils.extract_url_hostname(link["href"])
        if href_domain and not utils.domains_match(display_domain, href_domain) \
                and display_domain not in href_domain and href_domain not in display_domain:
            indicators.append(_indicator(
                "link_text_href_mismatch", "HIGH",
                "Link text does not match its destination",
                f"A link displays '{link['display_text'].strip()[:80]}' "
                f"(looks like '{display_domain}') but actually points to "
                f"'{href_domain}'.",
                what="The clickable text of a link names one domain, but "
                     "the link's real destination is a different domain.",
                why="This is one of the most reliable phishing techniques: "
                    "showing a trusted-looking address while routing clicks "
                    "elsewhere.",
                check="Never click the link. Independently navigate to the "
                      "organization's known website instead."))
    return indicators


def check_link_domains(links: list) -> list:
    indicators = []
    checked_domains = set()
    for link in links:
        hostname = utils.extract_url_hostname(link["href"])
        if not hostname or hostname in checked_domains:
            continue
        checked_domains.add(hostname)

        if utils.is_ip_literal_host(hostname):
            indicators.append(_indicator(
                "link_ip_url", "HIGH", "Link points to a raw IP address",
                f"A link's destination host is the IP address '{hostname}' "
                f"rather than a domain name.",
                what="The link does not use a domain name at all.",
                why="Legitimate organizations essentially never link "
                    "directly to a bare IP address; this is common in "
                    "phishing and malware delivery.",
                check="Do not visit this link."))
            continue  # an IP host has no domain to run brand checks against

        if utils.is_url_shortener(hostname):
            indicators.append(_indicator(
                "link_shortener", "MEDIUM", "Link uses a URL-shortening service",
                f"A link points through the shortening service '{hostname}', "
                f"which hides its real destination.",
                what="The visible link goes through a URL shortener.",
                why="Shorteners are legitimate in general use, but they also "
                    "let attackers hide a malicious destination behind an "
                    "innocuous-looking short link.",
                check="Do not click; use a link-preview/unshortening tool "
                      "first if you need to know the real destination."))

        brand = utils.detect_lookalike_domain(hostname)
        if brand:
            indicators.append(_indicator(
                "link_lookalike_domain", "HIGH", "Link domain resembles a known brand",
                f"Link domain '{hostname}' resembles the brand '{brand}' "
                f"through character substitution, but is not that brand's domain.",
                what="Character substitution makes this link's domain "
                     "visually resemble a well-known brand.",
                why="Lookalike link domains are a classic phishing technique.",
                check="Compare character-by-character with the brand's real domain."))
        else:
            brand = utils.detect_brand_impersonation(hostname)
            if brand:
                indicators.append(_indicator(
                    "link_brand_impersonation", "HIGH",
                    "Link domain contains a well-known brand name",
                    f"Link domain '{hostname}' contains the brand name "
                    f"'{brand}' but is not that brand's own domain.",
                    what="The brand name appears in the link's domain, but "
                         "in a position that is not the brand's real domain.",
                    why="Embedding a trusted brand name in an unrelated "
                        "domain is a common phishing tactic.",
                    check="Compare with the brand's real, known domain before clicking."))

        keyword = utils.suspicious_keyword_in_domain(hostname)
        if keyword:
            indicators.append(_indicator(
                "link_suspicious_keyword", "LOW", "Suspicious keyword in link domain",
                f"Link domain '{hostname}' contains the keyword '{keyword}'.",
                what=f"The link's domain includes the word '{keyword}'.",
                why="This keyword alone is common in legitimate domains too, "
                    "but is worth reviewing alongside other indicators.",
                check="Look at who actually controls this domain before clicking."))

    return indicators


def _visible_text(plain_text: str, html_text: str) -> str:
    """Plain-text body plus HTML body with tags stripped, joined into one
    lowercase-able string for keyword scanning."""
    text_parts = []
    if plain_text:
        text_parts.append(plain_text)
    if html_text:
        extractor = _TextExtractor()
        try:
            extractor.feed(html_text)
            text_parts.append(extractor.get_text())
        except Exception:
            pass
    return " ".join(text_parts)


def check_urgency_language(plain_text: str, html_text: str) -> list:
    combined = _visible_text(plain_text, html_text).lower()
    if not combined.strip():
        return []

    matched = [phrase for phrase in URGENCY_PHRASES if phrase in combined]
    if len(matched) < URGENCY_MATCH_THRESHOLD:
        return []

    return [_indicator(
        "urgency_language", "MEDIUM", "Urgency/pressure language detected in message body",
        f"The message body contains {len(matched)} phrases commonly used "
        f"to create urgency: {', '.join(matched[:5])}"
        f"{'...' if len(matched) > 5 else ''}.",
        what="The wording repeatedly pushes the reader to act immediately.",
        why="Creating time pressure is a common social-engineering tactic "
            "to short-circuit careful review, though legitimate notices "
            "sometimes use similar language too.",
        check="Slow down. Independently verify the request before acting, "
              "especially before clicking links or providing information.")]


def check_financial_prize_language(plain_text: str, html_text: str) -> list:
    combined = _visible_text(plain_text, html_text).lower()
    if not combined.strip():
        return []

    matched = [phrase for phrase in FINANCIAL_PRIZE_PHRASES if phrase in combined]
    if not matched:
        return []

    return [_indicator(
        "financial_prize_language", "MEDIUM",
        "Prize, donation, or financial-request language detected",
        f"The message body contains phrases commonly used in prize/donation/"
        f"financial-request scams: {', '.join(matched[:5])}"
        f"{'...' if len(matched) > 5 else ''}.",
        what="The wording references an unexpected prize, donation "
             "request, inheritance, or financial transaction.",
        why="Unsolicited prize claims and financial requests are a common "
            "scam theme, though legitimate charities and promotions do "
            "also use similar language, so this alone is not conclusive.",
        check="Verify independently through the organization's official "
              "website before donating, claiming a prize, or sending "
              "anything.")]


def check_credential_request_language(plain_text: str, html_text: str) -> list:
    combined = _visible_text(plain_text, html_text).lower()
    if not combined.strip():
        return []

    matched = [phrase for phrase in CREDENTIAL_REQUEST_PHRASES if phrase in combined]
    if not matched:
        return []

    return [_indicator(
        "credential_request_language", "HIGH",
        "Message explicitly asks for a password or sensitive credential",
        f"The message body asks for sensitive information: {', '.join(matched)}.",
        what="The message asks the reader to type or send a password, "
             "PIN, card number, or similarly sensitive credential.",
        why="Legitimate organizations essentially never ask you to send "
            "or re-type a password or PIN by email; this is one of the "
            "strongest phishing signals available in body text.",
        check="Never send this information by email. Contact the "
              "organization directly through a known, trusted channel.")]


def check_legal_threat_language(plain_text: str, html_text: str) -> list:
    combined = _visible_text(plain_text, html_text).lower()
    if not combined.strip():
        return []

    matched = [phrase for phrase in LEGAL_THREAT_PHRASES if phrase in combined]
    if not matched:
        return []

    return [_indicator(
        "legal_threat_language", "HIGH",
        "Threatening legal/law-enforcement language detected",
        f"The message body contains language threatening legal or "
        f"criminal consequences: {', '.join(matched[:5])}"
        f"{'...' if len(matched) > 5 else ''}.",
        what="The message claims you are under investigation or facing "
             "criminal charges and threatens arrest, prosecution, or "
             "public exposure.",
        why="This is a well-known extortion/sextortion scam pattern: "
            "fabricated legal threats designed to frighten the recipient "
            "into paying or replying before thinking it through. Real law "
            "enforcement does not conduct investigations or demand "
            "payment over email.",
        check="Do not reply or pay anything. Report the message; do not "
              "engage with the sender.")]


def check_job_scam_language(plain_text: str, html_text: str) -> list:
    combined = _visible_text(plain_text, html_text).lower()
    if not combined.strip():
        return []

    matched = [phrase for phrase in JOB_SCAM_PHRASES if phrase in combined]
    if not matched:
        return []

    return [_indicator(
        "job_scam_language", "MEDIUM",
        "Unsolicited job/recruitment offer language detected",
        f"The message body contains phrasing common in job-offer scams: "
        f"{', '.join(matched[:5])}{'...' if len(matched) > 5 else ''}.",
        what="The message offers an unsolicited job, often vague, "
             "work-from-home, and unusually well-paid for the effort described.",
        why="Job-offer scams are commonly used for advance-fee fraud or "
            "to recruit unwitting money mules, though legitimate remote "
            "job postings do exist and use similar wording.",
        check="Research the company independently; never pay money or "
              "share financial details to accept a job offer.")]


def check_contact_email_mismatch(ocr_text: str, sender_address: str) -> list:
    """Flags a message that instructs the reader to contact a different
    email address than the one it was apparently sent from -- a common
    scam pattern (an official-looking or compromised address is used as
    the lure, while the real point of contact is a separate address)."""
    if not sender_address or not ocr_text:
        return []
    match = re.search(
        r"(?:contact|reply(?:\s+e-?mail)?|email)\D{0,25}?([\w.+\-]+@[\w\-]+\.[\w.\-]+)",
        ocr_text, re.IGNORECASE)
    if not match:
        return []
    contact_address = match.group(1)
    if contact_address.lower() == sender_address.lower():
        return []
    return [_indicator(
        "contact_email_mismatch", "HIGH",
        "Message directs you to a different contact email than the sender",
        f"The message appears to come from '{sender_address}' but "
        f"instructs you to contact a different address, '{contact_address}'.",
        what="The apparent sender and the address you're told to actually "
             "reply to or contact are different.",
        why="This is a common scam pattern: an official-looking or "
            "compromised sender address is used as the lure, while the "
            "real point of contact is a separate, often generic, address.",
        check="Be cautious of any message that asks you to contact a "
              "different address than the one it was sent from.")]


def check_link_obfuscation(links: list) -> list:
    indicators = []
    seen = set()
    for link in links:
        href = link["href"]
        if href in seen:
            continue
        seen.add(href)

        if utils.has_userinfo_trick(href):
            indicators.append(_indicator(
                "link_userinfo_trick", "HIGH",
                "Link uses a deceptive '@' before the real destination",
                f"Link '{href}' contains an '@' before its actual host -- "
                f"a technique that makes the link appear to go to one "
                f"domain while it actually goes to another.",
                what="Everything before the '@' in a URL is just a "
                     "username; the browser navigates to whatever host "
                     "comes after it.",
                why="This is a classic URL-obfuscation trick: a link like "
                    "http://paypal.com@evil.example/ visually looks like "
                    "it goes to paypal.com but actually goes to evil.example.",
                check="Do not click. The real destination is whatever "
                      "comes immediately after the '@' symbol."))

        hostname = utils.extract_url_hostname(href)
        if hostname and utils.is_punycode_domain(hostname):
            indicators.append(_indicator(
                "link_punycode_domain", "MEDIUM",
                "Link domain uses encoded international characters",
                f"Link domain '{hostname}' uses punycode (xn--) encoding, "
                f"which can visually imitate a trusted domain using "
                f"look-alike international characters.",
                what="The domain contains punycode-encoded characters.",
                why="Punycode lets attackers register domains that "
                    "*display* as nearly identical to a trusted brand "
                    "using characters from other alphabets.",
                check="Treat this domain with extra caution and verify it "
                      "independently before trusting any link to it."))
    return indicators


def extract_attachment_filenames(raw_text: str) -> list:
    """Return the declared filename of every attachment part. Only ever
    reads MIME metadata (Content-Disposition / filename) -- never
    decodes or opens the attachment's actual content."""
    try:
        msg = message_from_string(raw_text or "", policy=compat32)
    except Exception:
        return []

    filenames = []
    parts = msg.walk() if msg.is_multipart() else [msg]
    for part in parts:
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = (part.get("Content-Disposition") or "").lower()
        if filename or "attachment" in disposition:
            filenames.append(filename or "(unnamed attachment)")
    return filenames


def check_attachments(filenames: list) -> list:
    indicators = []
    for filename in filenames:
        warning = utils.classify_attachment_filename(filename)
        if not warning:
            continue
        indicators.append(_indicator(
            "suspicious_attachment", "HIGH", "Suspicious attachment filename",
            f"Attachment '{filename}': {warning}.",
            what="The attachment's declared filename suggests it may be "
                 "an executable or script, or is disguised with a double "
                 "extension.",
            why="Executable/script attachments are a common malware "
                "delivery method; a double extension (e.g. "
                "'invoice.pdf.exe') is a classic disguise trick.",
            check="Do not open this attachment. MailShield only inspects "
                  "the declared filename -- it never opens, decodes, or "
                  "scans attachment contents."))
    return indicators


def generate_content_indicators(raw_text: str, from_address: str = None) -> dict:
    """Run all body/link/attachment checks. Returns a dict with the
    indicators found plus a summary of what was parsed, for display in
    the UI. ``from_address`` (just the address, not the display name) is
    optional and enables the contact-email-mismatch check."""
    body = extract_message_body(raw_text)
    has_body = bool(body["plain"] or body["html"])
    links = extract_links(body["plain"], body["html"]) if has_body else []
    attachment_filenames = extract_attachment_filenames(raw_text)
    visible_text = _visible_text(body["plain"], body["html"])

    indicators = []
    indicators.extend(check_link_mismatches(links))
    indicators.extend(check_link_domains(links))
    indicators.extend(check_link_obfuscation(links))
    indicators.extend(check_urgency_language(body["plain"], body["html"]))
    indicators.extend(check_financial_prize_language(body["plain"], body["html"]))
    indicators.extend(check_credential_request_language(body["plain"], body["html"]))
    indicators.extend(check_legal_threat_language(body["plain"], body["html"]))
    indicators.extend(check_job_scam_language(body["plain"], body["html"]))
    indicators.extend(check_contact_email_mismatch(visible_text, from_address))
    indicators.extend(check_attachments(attachment_filenames))

    link_summary = []
    for link in links:
        hostname = utils.extract_url_hostname(link["href"])
        notes = []
        if utils.is_ip_literal_host(hostname):
            notes.append("IP address")
        if utils.is_url_shortener(hostname):
            notes.append("URL shortener")
        if utils.has_userinfo_trick(link["href"]):
            notes.append("'@' obfuscation")
        if utils.is_punycode_domain(hostname):
            notes.append("punycode")
        link_summary.append({
            "href": link["href"],
            "display_text": link["display_text"],
            "domain": hostname,
            "classification": ", ".join(notes) or None,
        })

    return {
        "has_body": has_body,
        "links": link_summary,
        "attachments": attachment_filenames,
        "indicators": indicators,
    }
