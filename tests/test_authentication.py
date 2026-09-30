from analyzer import authentication, parser

BASE = (
    "From: a@example.com\n"
    "To: b@example.com\n"
    "Subject: t\n"
    "Date: Tue, 30 Sep 2026 09:00:00 +0000\n"
    "Message-ID: <1@example.com>\n"
)


def _parsed_with_auth(auth_value):
    text = BASE + f"Authentication-Results: mx.example.com; {auth_value}\n"
    return parser.parse_headers(text)


def test_spf_pass():
    auth = authentication.analyze_authentication(_parsed_with_auth("spf=pass"))
    assert auth["spf"] == "pass"


def test_spf_fail():
    auth = authentication.analyze_authentication(_parsed_with_auth("spf=fail"))
    assert auth["spf"] == "fail"


def test_spf_none():
    auth = authentication.analyze_authentication(_parsed_with_auth("spf=none"))
    assert auth["spf"] == "none"


def test_dkim_pass():
    auth = authentication.analyze_authentication(_parsed_with_auth("dkim=pass"))
    assert auth["dkim"] == "pass"


def test_dkim_fail():
    auth = authentication.analyze_authentication(_parsed_with_auth("dkim=fail"))
    assert auth["dkim"] == "fail"


def test_dmarc_pass():
    auth = authentication.analyze_authentication(_parsed_with_auth("dmarc=pass"))
    assert auth["dmarc"] == "pass"


def test_dmarc_fail():
    auth = authentication.analyze_authentication(_parsed_with_auth("dmarc=fail"))
    assert auth["dmarc"] == "fail"


def test_dkim_signature_domain_and_selector():
    text = BASE + (
        "DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=selector1; "
        "h=from:to:subject;\n"
    )
    parsed = parser.parse_headers(text)
    auth = authentication.analyze_authentication(parsed)
    assert auth["dkim_signing_domain"] == "example.com"
    assert auth["dkim_selector"] == "selector1"


def test_received_spf_fallback_when_no_auth_results():
    text = BASE + "Received-SPF: pass (mx.example.com: sender authorized)\n"
    parsed = parser.parse_headers(text)
    auth = authentication.analyze_authentication(parsed)
    assert auth["spf"] == "pass"


def test_conflicting_spf_results_detected():
    text = BASE + (
        "Authentication-Results: a.example.com; spf=pass\n"
        "Authentication-Results: b.example.com; spf=fail\n"
    )
    parsed = parser.parse_headers(text)
    auth = authentication.analyze_authentication(parsed)
    mechanisms = [c["mechanism"] for c in auth["conflicts"]]
    assert "SPF" in mechanisms
