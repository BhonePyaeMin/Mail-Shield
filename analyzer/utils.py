"""Shared helper functions for domain, IP, and date handling.

Kept dependency-free (standard library only) so the analyzer can run
completely offline.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

# RFC 5737 / RFC 3849 documentation ranges. Python's ipaddress module does
# not label these as a distinct category, so we check them explicitly --
# this matters because sample/test data (and many textbook examples) use
# these ranges and they should never be mistaken for a real attacker IP.
_DOC_NETS_V4 = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("233.252.0.0/24"),
]
_DOC_NETS_V6 = [ipaddress.ip_network("2001:db8::/32")]

_KNOWN_BRANDS = (
    "paypal", "microsoft", "google", "apple", "amazon", "facebook",
    "instagram", "netflix", "ebay", "bankofamerica", "wellsfargo",
    "chase", "americanexpress", "dropbox", "linkedin", "twitter",
)

_SUSPICIOUS_KEYWORDS = (
    "login", "secure", "security", "verify", "verification", "account",
    "update", "signin", "confirm", "banking", "billing", "support",
    "recovery", "unlock",
)

# Common leetspeak / homoglyph substitutions used in lookalike domains.
_LEET_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
})


def extract_domain(address: str) -> str:
    """Return the lowercase domain part of an email address, or ''."""
    if not address:
        return ""
    match = re.search(r"@([A-Za-z0-9.\-]+)", address)
    return match.group(1).lower().rstrip(".") if match else ""


def domains_match(domain_a: str, domain_b: str) -> bool:
    """Case-insensitive comparison, tolerant of missing values."""
    if not domain_a or not domain_b:
        return True  # cannot compare -> don't flag a mismatch
    return domain_a.strip().lower() == domain_b.strip().lower()


def classify_ip(ip_str: str) -> str:
    """Classify an IP address string into a human-readable category."""
    if not ip_str:
        return "Invalid"
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return "Invalid"

    doc_nets = _DOC_NETS_V4 if ip.version == 4 else _DOC_NETS_V6
    if any(ip in net for net in doc_nets):
        return "Documentation"
    if ip.is_loopback:
        return "Loopback"
    if ip.is_multicast:
        return "Multicast"
    if ip.is_private:
        return "Private"
    if ip.is_reserved:
        return "Reserved"
    if ip.is_global:
        return "Public"
    return "Reserved"


def safe_parse_date(date_str: str):
    """Parse an RFC 2822 date header value. Returns a datetime or None."""
    if not date_str:
        return None
    try:
        dt = parsedate_to_datetime(date_str)
    except (TypeError, ValueError, IndexError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def count_subdomain_labels(domain: str) -> int:
    """Number of labels in a domain, e.g. a.b.example.com -> 4."""
    if not domain:
        return 0
    return len([label for label in domain.split(".") if label])


def has_excessive_subdomains(domain: str, threshold: int = 4) -> bool:
    return count_subdomain_labels(domain) > threshold


def suspicious_keyword_in_domain(domain: str):
    """Return the first suspicious keyword found in a domain, or None."""
    if not domain:
        return None
    lowered = domain.lower()
    for keyword in _SUSPICIOUS_KEYWORDS:
        if keyword in lowered:
            return keyword
    return None


def detect_lookalike_domain(domain: str):
    """Conservative lookalike-brand heuristic based on character
    substitution (leetspeak, doubled letters), e.g. 'micr0soft.example'.

    Distinct from :func:`detect_brand_impersonation`, which catches the
    literal brand name embedded in a domain that isn't its own.
    Returns the matched brand name, or None.
    """
    if not domain:
        return None
    registrable = domain.lower().split(".")[0] if "." in domain else domain.lower()
    normalized = registrable.translate(_LEET_MAP)
    normalized = normalized.replace("rn", "m").replace("vv", "w")
    for brand in _KNOWN_BRANDS:
        if brand in normalized and brand not in registrable:
            return brand
        if brand == registrable:
            return None
    return None


def detect_brand_impersonation(domain: str):
    """A known brand name appears literally in the domain, in a position
    unlikely to be that brand's own registrable domain.

    Uses a simple "last two labels" stand-in for the registrable domain
    (a known simplification: it does not understand multi-part public
    suffixes like ``.co.uk``, which is an accepted trade-off to keep this
    check dependency-free). Catches two common attacker patterns:
    the brand name embedded in a single label (``paypal-secure-verify.net``)
    and the brand used as a decoy label ahead of the real domain
    (``paypal.com.verify-account.tk``).
    """
    if not domain:
        return None
    labels = [label for label in domain.lower().split(".") if label]
    if len(labels) < 2:
        return None
    registrable_guess = ".".join(labels[-2:])
    for brand in _KNOWN_BRANDS:
        if labels[-2] == brand:
            continue  # likely the brand's own registrable domain
        if brand in registrable_guess or any(brand in label for label in labels[:-2]):
            return brand
    return None


def detect_display_name_brand_impersonation(display_name: str, domain: str):
    """The human-readable From display name claims to be a well-known
    brand, but the actual sending address domain is unrelated to that
    brand. Extremely common in real-world phishing/BEC: attackers send
    from a free webmail account (which passes SPF/DKIM/DMARC perfectly
    for itself) but set the display name to impersonate a trusted brand,
    since most mail clients show the display name far more prominently
    than the address underneath it.
    """
    if not display_name or not domain:
        return None
    lowered_name = display_name.lower()
    domain_lower = domain.lower()
    for brand in _KNOWN_BRANDS:
        if re.search(rf"\b{re.escape(brand)}\b", lowered_name) and brand not in domain_lower:
            return brand
    return None


URL_SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
}


_VALID_HOSTNAME_RE = re.compile(r"^[a-z0-9.\-:\[\]]+$")


def extract_url_hostname(url: str):
    """Return the lowercase hostname of a URL, or None if unparsable or
    if the input doesn't actually look like a URL/host at all."""
    if not url:
        return None
    import urllib.parse
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else f"//{url}")
        hostname = (parsed.hostname or "").lower()
    except ValueError:
        return None
    if not hostname or not _VALID_HOSTNAME_RE.match(hostname):
        return None
    return hostname


def is_url_shortener(hostname: str) -> bool:
    return bool(hostname) and hostname.lower() in URL_SHORTENER_DOMAINS


def is_ip_literal_host(hostname: str) -> bool:
    if not hostname:
        return False
    return classify_ip(hostname) != "Invalid"


def build_indicator(code, severity, title, description, what="", why="", check=""):
    """Shared indicator-dict shape used by ``indicators``, ``content``,
    and ``ocr`` -- see any of those modules' docstrings for the field
    meanings. Centralized here now that three modules build the same
    shape, to avoid three copies drifting apart."""
    return {
        "code": code,
        "severity": severity,
        "title": title,
        "description": description,
        "what": what,
        "why": why,
        "check": check,
    }


def has_userinfo_trick(url: str) -> bool:
    """Detects the classic ``http://trusted.com@evil.example/`` trick:
    everything before an unescaped ``@`` in a URL is just a username, so
    the browser navigates to whatever host comes *after* it -- but a
    casual glance reads the part before the ``@`` as the destination."""
    if not url or "@" not in url:
        return False
    import urllib.parse
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else f"//{url}")
    except ValueError:
        return False
    return bool(parsed.username) or "@" in (parsed.netloc or "")


def is_punycode_domain(hostname: str) -> bool:
    """Punycode (``xn--``) labels can render as look-alike international
    characters in a mail client, imitating a trusted domain."""
    if not hostname:
        return False
    return any(label.startswith("xn--") for label in hostname.split("."))


_DANGEROUS_ATTACHMENT_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".wsh", ".msi", ".jar", ".ps1", ".hta", ".cpl",
}


def classify_attachment_filename(filename: str):
    """Return a warning string if a declared attachment filename looks
    dangerous, else None. Only ever inspects the filename/extension the
    message *claims* -- never opens, decodes, or scans the attachment's
    actual content."""
    if not filename:
        return None
    lowered = filename.lower().strip()
    labels = lowered.split(".")
    if len(labels) < 2:
        return None
    ext = f".{labels[-1]}"
    if ext not in _DANGEROUS_ATTACHMENT_EXTENSIONS:
        return None
    if len(labels) >= 3:
        return f"double extension ending in {ext} (disguised as .{labels[-2]})"
    return f"executable/script extension ({ext})"


IPV4_RE = re.compile(r"(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}"
                      r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])(?![0-9])")
IPV6_RE = re.compile(r"(?<![0-9a-fA-F:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F:]{1,4}(?![0-9a-fA-F:])")


def find_ips(text: str):
    """Return all plausible IPv4/IPv6 address strings found in text."""
    if not text:
        return []
    found = []
    for match in IPV4_RE.findall(text):
        found.append(match)
    for match in IPV6_RE.findall(text):
        if match.count(":") >= 2:
            found.append(match)
    return found
