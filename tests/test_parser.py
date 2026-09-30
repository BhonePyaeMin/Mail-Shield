import pytest

from analyzer import parser

VALID_HEADERS = (
    "From: Alice <alice@example.com>\n"
    "To: bob@example.com\n"
    "Subject: Test\n"
    "Date: Tue, 30 Sep 2026 09:00:00 +0000\n"
    "Message-ID: <123@example.com>\n"
)


def test_parse_valid_headers():
    parsed = parser.parse_headers(VALID_HEADERS)
    assert parsed["basic"]["from"] == "Alice <alice@example.com>"
    assert parsed["basic"]["subject"] == "Test"
    assert parsed["missing_common_headers"] == []


def test_parse_missing_headers():
    text = "From: alice@example.com\nTo: bob@example.com\n"
    parsed = parser.parse_headers(text)
    assert "Subject" in parsed["missing_common_headers"]
    assert "Date" in parsed["missing_common_headers"]
    assert "Message-ID" in parsed["missing_common_headers"]


def test_parse_duplicate_headers():
    text = VALID_HEADERS + "Reply-To: x@example.com\nReply-To: y@example.com\n"
    parsed = parser.parse_headers(text)
    dup_names = [d["header"] for d in parsed["duplicate_headers"]]
    assert "Reply-To" in dup_names


def test_parse_malformed_line():
    text = VALID_HEADERS + "this is not a header line at all\n"
    parsed = parser.parse_headers(text)
    assert len(parsed["malformed_lines"]) >= 1


def test_parse_bracket_mismatch():
    text = VALID_HEADERS + "Reply-To: verify@example.net>\n"
    parsed = parser.parse_headers(text)
    headers_with_mismatch = [b["header"] for b in parsed["bracket_mismatches"]]
    assert "Reply-To" in headers_with_mismatch


def test_parse_empty_input_raises():
    with pytest.raises(parser.HeaderParseError):
        parser.parse_headers("")


def test_parse_whitespace_only_raises():
    with pytest.raises(parser.HeaderParseError):
        parser.parse_headers("   \n  \n")


def test_parse_size_limit_exceeded():
    huge = "From: a@example.com\n" + ("X-Pad: " + "a" * 100 + "\n") * 20000
    with pytest.raises(parser.HeaderParseError):
        parser.parse_headers(huge)


def test_received_headers_extracted():
    text = (
        VALID_HEADERS
        + "Received: from mail.example.net (mail.example.net [203.0.113.10])\n"
        + "    by mx.example.com with ESMTP; Tue, 30 Sep 2026 08:59:00 +0000\n"
    )
    parsed = parser.parse_headers(text)
    assert len(parsed["received_raw"]) == 1
    assert "203.0.113.10" in parsed["received_raw"][0]
