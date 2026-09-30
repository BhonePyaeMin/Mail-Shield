from analyzer import content, utils

PLAIN_HEADERS = (
    "From: a@example.com\n"
    "To: b@example.com\n"
    "Subject: hi\n"
    "Date: Tue, 30 Sep 2026 09:00:00 +0000\n"
    "Message-ID: <1@example.com>\n"
    "Content-Type: text/plain; charset=\"UTF-8\"\n"
)

HTML_HEADERS = (
    "From: a@example.com\n"
    "To: b@example.com\n"
    "Subject: hi\n"
    "Date: Tue, 30 Sep 2026 09:00:00 +0000\n"
    "Message-ID: <1@example.com>\n"
    "Content-Type: text/html; charset=\"UTF-8\"\n"
)


def test_extract_message_body_plain_text():
    raw = PLAIN_HEADERS + "\nHello, visit https://example.com/account for details.\n"
    body = content.extract_message_body(raw)
    assert body["plain"] is not None
    assert "example.com/account" in body["plain"]
    assert body["html"] is None


def test_extract_message_body_no_body_returns_none():
    raw = PLAIN_HEADERS
    body = content.extract_message_body(raw)
    assert body["plain"] is None
    assert body["html"] is None


def test_extract_links_from_bare_url():
    links = content.extract_links("Visit https://example.com/path now.", None)
    assert any(l["href"] == "https://example.com/path" for l in links)


def test_extract_links_from_html_anchor():
    html = '<a href="http://evil.example/steal">https://paypal.com/verify</a>'
    links = content.extract_links(None, html)
    assert len(links) == 1
    assert links[0]["href"] == "http://evil.example/steal"
    assert links[0]["display_text"] == "https://paypal.com/verify"


def test_link_text_href_mismatch_detected():
    html = '<a href="http://evil.example/steal">https://paypal.com/verify</a>'
    links = content.extract_links(None, html)
    indicators = content.check_link_mismatches(links)
    assert any(i["code"] == "link_text_href_mismatch" for i in indicators)


def test_link_text_href_match_not_flagged():
    html = '<a href="https://example.com/account">https://example.com/account</a>'
    links = content.extract_links(None, html)
    indicators = content.check_link_mismatches(links)
    assert indicators == []


def test_link_ip_url_detected():
    links = [{"href": "http://203.0.113.55/login", "display_text": None}]
    indicators = content.check_link_domains(links)
    assert any(i["code"] == "link_ip_url" for i in indicators)


def test_link_shortener_detected():
    links = [{"href": "http://bit.ly/abc123", "display_text": None}]
    indicators = content.check_link_domains(links)
    assert any(i["code"] == "link_shortener" for i in indicators)


def test_link_brand_impersonation_detected():
    links = [{"href": "http://secure-paypal-login.example/verify", "display_text": None}]
    indicators = content.check_link_domains(links)
    assert any(i["code"] == "link_brand_impersonation" for i in indicators)


def test_urgency_language_requires_multiple_phrases():
    weak = "Please act now, that's all."
    assert content.check_urgency_language(weak, None) == []

    strong = ("Your account will be suspended. Act now to avoid suspension "
              "and confirm your identity within 24 hours.")
    result = content.check_urgency_language(strong, None)
    assert len(result) == 1
    assert result[0]["code"] == "urgency_language"


def test_generate_content_indicators_no_body():
    result = content.generate_content_indicators(PLAIN_HEADERS)
    assert result["has_body"] is False
    assert result["links"] == []
    assert result["indicators"] == []


def test_generate_content_indicators_full_phishing_example():
    raw = HTML_HEADERS + (
        "\n<html><body>"
        "<p>Your account will be suspended. Act now to avoid suspension.</p>"
        '<p><a href="http://secure-paypal-login.example/verify">'
        "https://paypal.com/verify</a></p>"
        "</body></html>\n"
    )
    result = content.generate_content_indicators(raw)
    assert result["has_body"] is True
    codes = [i["code"] for i in result["indicators"]]
    assert "link_text_href_mismatch" in codes


def test_extract_url_hostname():
    assert utils.extract_url_hostname("https://Example.COM/path") == "example.com"
    assert utils.extract_url_hostname("not a url") is None


def test_detect_brand_impersonation_single_label():
    assert utils.detect_brand_impersonation("secure-paypal-login.example") == "paypal"
    assert utils.detect_brand_impersonation("paypal.com") is None


def test_detect_brand_impersonation_decoy_subdomain():
    assert utils.detect_brand_impersonation("paypal.com.verify-account.tk") == "paypal"
    assert utils.detect_brand_impersonation("mail.paypal.com") is None


def test_userinfo_trick_detected():
    links = [{"href": "http://paypal.com@evil.example/login", "display_text": None}]
    indicators = content.check_link_obfuscation(links)
    assert any(i["code"] == "link_userinfo_trick" for i in indicators)


def test_userinfo_trick_not_flagged_for_normal_url():
    links = [{"href": "https://example.com/path?query=value", "display_text": None}]
    indicators = content.check_link_obfuscation(links)
    assert indicators == []


def test_punycode_domain_detected():
    links = [{"href": "http://xn--pypal-4ve.com/login", "display_text": None}]
    indicators = content.check_link_obfuscation(links)
    assert any(i["code"] == "link_punycode_domain" for i in indicators)


def test_financial_prize_language_single_match_is_enough():
    result = content.check_financial_prize_language(
        "Congratulations, you have been selected to claim your prize today.", None)
    assert len(result) == 1
    assert result[0]["code"] == "financial_prize_language"


def test_financial_prize_language_not_flagged_for_normal_text():
    assert content.check_financial_prize_language("Thanks for joining the call.", None) == []


def test_credential_request_language_detected():
    result = content.check_credential_request_language(
        "Please enter your password and social security number to continue.", None)
    assert len(result) == 1
    assert result[0]["code"] == "credential_request_language"
    assert result[0]["severity"] == "HIGH"


def test_credential_request_language_not_flagged_for_normal_text():
    assert content.check_credential_request_language("Please review the attached notes.", None) == []


def test_extract_attachment_filenames():
    raw = (
        "From: a@example.com\nTo: b@example.com\nSubject: t\n"
        "Date: Tue, 30 Sep 2026 09:00:00 +0000\nMessage-ID: <1@example.com>\n"
        "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"BOUND\"\n"
        "\n--BOUND\nContent-Type: text/plain\n\nSee attached.\n"
        "--BOUND\nContent-Type: application/octet-stream\n"
        "Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\n\n"
        "ZmFrZSBiaW5hcnkgZGF0YQ==\n--BOUND--\n"
    )
    filenames = content.extract_attachment_filenames(raw)
    assert "invoice.pdf.exe" in filenames


def test_check_attachments_flags_double_extension():
    indicators = content.check_attachments(["invoice.pdf.exe"])
    assert len(indicators) == 1
    assert indicators[0]["code"] == "suspicious_attachment"
    assert "double extension" in indicators[0]["description"]


def test_check_attachments_ignores_safe_filename():
    assert content.check_attachments(["invoice.pdf", "photo.jpg"]) == []


def test_classify_attachment_filename():
    assert utils.classify_attachment_filename("invoice.exe") is not None
    assert utils.classify_attachment_filename("invoice.pdf.exe") is not None
    assert utils.classify_attachment_filename("invoice.pdf") is None
    assert utils.classify_attachment_filename(None) is None
