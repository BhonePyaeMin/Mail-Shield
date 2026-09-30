from io import BytesIO

from analyzer import ocr


def test_guess_sender_name_and_email():
    text = ("Weekly Paid Job\n\nAisha S. Mansour <Aisha.Mansour@bot.go.tz>\n"
             "To\n\nBody text here.")
    name, address = ocr.guess_sender(text)
    assert name == "Aisha S. Mansour"
    assert address == "Aisha.Mansour@bot.go.tz"


def test_guess_sender_bare_email_fallback():
    text = "SUMMONS\n\nSome scary text.\n\nReply e-mail webafpat@gmail.com\n\nMore text."
    name, address = ocr.guess_sender(text)
    assert address == "webafpat@gmail.com"


def test_guess_sender_none_when_no_email_present():
    name, address = ocr.guess_sender("Just some random text with no email address at all.")
    assert name is None
    assert address is None


def test_guess_subject():
    text = "From: a@example.com\nSubject: Urgent account notice\nBody text"
    assert ocr.guess_subject(text) == "Urgent account notice"


def test_guess_subject_none_when_absent():
    assert ocr.guess_subject("No subject line here at all.") is None


def test_sender_domain_indicators_display_name_impersonation():
    indicators = ocr._sender_domain_indicators("Microsoft Support", "gmail.com")
    codes = [i["code"] for i in indicators]
    assert "display_name_brand_impersonation" in codes


def test_sender_domain_indicators_lookalike():
    indicators = ocr._sender_domain_indicators(None, "micr0soft-updates.example")
    codes = [i["code"] for i in indicators]
    assert "lookalike_domain" in codes


def test_sender_domain_indicators_clean_domain():
    assert ocr._sender_domain_indicators("Jane Doe", "example.com") == []


def test_analyze_image_rejects_oversized_input():
    huge = b"0" * (ocr.MAX_IMAGE_BYTES + 1)
    try:
        ocr.analyze_image(huge)
        assert False, "expected OCRError"
    except ocr.OCRError:
        pass


def test_analyze_image_rejects_unreadable_bytes():
    try:
        ocr.analyze_image(b"not a real image")
        assert False, "expected OCRError"
    except ocr.OCRError:
        pass


def _render_text_image(text: str, size=(900, 100), font_size=28) -> bytes:
    """Renders text at a size/font large enough for Tesseract to read
    reliably across environments (small default bitmap fonts OCR poorly)."""
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("RGB", size, color="white")
    draw = ImageDraw.Draw(img)
    font = ImageFont.load_default(size=font_size)
    draw.text((20, 20), text, fill="black", font=font)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_analyze_image_end_to_end_credential_request():
    """Lightweight integration test confirming the whole OCR pipeline --
    image bytes in, indicator out -- actually runs against the real
    Tesseract engine."""
    image_bytes = _render_text_image(
        "Please enter your password and confirm your login now.")
    result = ocr.analyze_image(image_bytes)
    codes = [i["code"] for i in result["indicators"]]
    assert "credential_request_language" in codes
    assert result["risk_level"] in ("HIGH", "CRITICAL")


def test_analyze_image_rejects_blank_image():
    from PIL import Image
    img = Image.new("RGB", (200, 100), color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    try:
        ocr.analyze_image(buf.getvalue())
        assert False, "expected OCRError for an image with no readable text"
    except ocr.OCRError:
        pass
