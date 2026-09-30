from analyzer import indicators, risk_engine
from analyzer.authentication import analyze_authentication
from analyzer.parser import parse_headers
from analyzer.routing import parse_received_chain


def test_no_indicators_is_low_risk():
    score = risk_engine.calculate_score([])
    assert score == 0
    assert risk_engine.risk_level(score) == "LOW"


def test_summarize_floors_risk_level_to_high_for_a_single_high_indicator():
    """A single specific, strong finding (e.g. an explicit credential
    request or a legal-threat/extortion scam) should never read as
    merely LOW/MODERATE just because few other indicators co-occurred --
    this matters most for image-based analysis, which has structurally
    fewer simultaneous signals available than full header analysis."""
    lone_high = [{"code": "credential_request_language", "severity": "HIGH"}]
    summary = risk_engine.summarize(lone_high)
    assert summary["score"] == 20
    assert summary["risk_level"] == "HIGH"


def test_summarize_floors_risk_level_to_moderate_for_a_single_medium_indicator():
    lone_medium = [{"code": "job_scam_language", "severity": "MEDIUM"}]
    summary = risk_engine.summarize(lone_medium)
    assert summary["score"] == 10
    assert summary["risk_level"] == "MODERATE"


def test_summarize_never_lowers_a_score_driven_high_risk_level():
    many_low = [{"code": "missing_common_header", "severity": "LOW"}] * 10
    summary = risk_engine.summarize(many_low)
    assert summary["risk_level"] == risk_engine.risk_level(summary["score"])


def test_several_indicators_is_high_risk():
    sample = [{"code": "spf_fail"}, {"code": "dkim_fail"}, {"code": "dmarc_fail"}]
    score = risk_engine.calculate_score(sample)
    assert score == 60
    assert risk_engine.risk_level(score) == "HIGH"


def test_many_indicators_is_critical_and_capped_at_100():
    sample = [
        {"code": "spf_fail"}, {"code": "dkim_fail"}, {"code": "dmarc_fail"},
        {"code": "reply_to_mismatch"}, {"code": "lookalike_domain"},
        {"code": "conflicting_auth_results"},
    ]
    score = risk_engine.calculate_score(sample)
    assert score >= 70
    assert risk_engine.risk_level(score) == "CRITICAL"

    huge = [{"code": "dmarc_fail"}] * 10
    assert risk_engine.calculate_score(huge) == 100


def test_risk_level_thresholds():
    assert risk_engine.risk_level(0) == "LOW"
    assert risk_engine.risk_level(19) == "LOW"
    assert risk_engine.risk_level(20) == "MODERATE"
    assert risk_engine.risk_level(39) == "MODERATE"
    assert risk_engine.risk_level(40) == "HIGH"
    assert risk_engine.risk_level(69) == "HIGH"
    assert risk_engine.risk_level(70) == "CRITICAL"
    assert risk_engine.risk_level(100) == "CRITICAL"


def test_domain_mismatch_produces_indicator_and_nonzero_score():
    text = (
        "From: user@example.com\n"
        "To: victim@example.com\n"
        "Subject: t\n"
        "Date: Tue, 30 Sep 2026 09:00:00 +0000\n"
        "Message-ID: <1@example.com>\n"
        "Reply-To: attacker@example.net\n"
    )
    parsed = parse_headers(text)
    auth = analyze_authentication(parsed)
    hops = parse_received_chain(parsed["received_raw"])
    indicator_list = indicators.generate_indicators(parsed, auth, hops)

    codes = [i["code"] for i in indicator_list]
    assert "reply_to_mismatch" in codes

    score = risk_engine.calculate_score(indicator_list)
    assert score > 0


def test_display_name_brand_impersonation_via_generic_webmail():
    """A scam sent through a fully legitimate, properly authenticated
    free webmail account: SPF/DKIM/DMARC all genuinely pass, and every
    domain-alignment check passes too (From/Reply-To/Return-Path/DKIM d=
    are all gmail.com). Only the display name gives it away."""
    text = (
        "From: Microsoft Account Team <totally.real.person99@gmail.com>\n"
        "Reply-To: Microsoft Account Team <totally.real.person99@gmail.com>\n"
        "To: victim@example.com\n"
        "Subject: Your Microsoft account has unusual sign-in activity\n"
        "Date: Tue, 30 Sep 2026 09:00:00 +0000\n"
        "Message-ID: <abc123@mail.gmail.com>\n"
        "Authentication-Results: mx.example.com; spf=pass; dkim=pass "
        "header.d=gmail.com; dmarc=pass\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=gmail.com; s=20230601;\n"
    )
    parsed = parse_headers(text)
    auth = analyze_authentication(parsed)
    hops = parse_received_chain(parsed["received_raw"])
    indicator_list = indicators.generate_indicators(parsed, auth, hops)

    codes = [i["code"] for i in indicator_list]
    assert "display_name_brand_impersonation" in codes
    assert "reply_to_mismatch" not in codes  # both addresses are gmail.com
    assert "dkim_domain_mismatch" not in codes  # d=gmail.com matches From domain
