import re

import pytest

from app import app as flask_app

SAMPLE_HEADERS = (
    "From: a@example.com\n"
    "To: b@example.com\n"
    "Subject: hi\n"
    "Date: Tue, 30 Sep 2026 09:00:00 +0000\n"
    "Message-ID: <1@example.com>\n"
)


@pytest.fixture
def client():
    flask_app.config.update(TESTING=True)
    with flask_app.test_client() as test_client:
        yield test_client


def _extract_csrf_token(html):
    match = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert match, "csrf token not found in rendered page"
    return match.group(1)


def test_index_get(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"MAILSHIELD" in resp.data


def test_analyze_form_valid_submission(client):
    index_resp = client.get("/")
    token = _extract_csrf_token(index_resp.get_data(as_text=True))

    resp = client.post("/analyze", data={"csrf_token": token, "headers": SAMPLE_HEADERS})
    assert resp.status_code == 200
    assert b"SUSPICION SCORE" in resp.data


def test_analyze_form_rejects_bad_csrf(client):
    client.get("/")  # establish a session
    resp = client.post("/analyze", data={"csrf_token": "not-the-real-token",
                                          "headers": SAMPLE_HEADERS})
    assert resp.status_code == 400


def test_analyze_form_rejects_empty_headers(client):
    index_resp = client.get("/")
    token = _extract_csrf_token(index_resp.get_data(as_text=True))
    resp = client.post("/analyze", data={"csrf_token": token, "headers": ""})
    assert resp.status_code == 400


def test_api_analyze_json(client):
    resp = client.post("/api/analyze", json={"headers": SAMPLE_HEADERS})
    assert resp.status_code == 200
    data = resp.get_json()
    assert "score" in data
    assert "risk_level" in data
    assert set(data["authentication"].keys()) == {"spf", "dkim", "dmarc"}
    assert isinstance(data["indicators"], list)


def test_api_analyze_requires_json_content_type(client):
    resp = client.post("/api/analyze", data="headers=not-json")
    assert resp.status_code == 415


def test_api_analyze_rejects_empty_headers(client):
    resp = client.post("/api/analyze", json={"headers": ""})
    assert resp.status_code == 400


def test_get_sample_safe(client):
    resp = client.get("/sample/safe")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "example.com" in data["content"]


def test_get_sample_unknown_returns_404(client):
    resp = client.get("/sample/does-not-exist")
    assert resp.status_code == 404


def _synthetic_scam_image_bytes():
    import io
    from PIL import Image, ImageDraw, ImageFont
    img = Image.new("RGB", (900, 100), color="white")
    draw = ImageDraw.Draw(img)
    font = ImageFont.load_default(size=28)
    draw.text((20, 20), "Please enter your password and confirm your login now.",
              fill="black", font=font)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_analyze_form_routes_image_upload_to_ocr_path(client):
    import io
    index_resp = client.get("/")
    token = _extract_csrf_token(index_resp.get_data(as_text=True))

    resp = client.post("/analyze", data={
        "csrf_token": token, "headers": "",
        "file": (io.BytesIO(_synthetic_scam_image_bytes()), "screenshot.png"),
    }, content_type="multipart/form-data")

    assert resp.status_code == 200
    assert b"IMAGE SCAN (OCR)" in resp.data
    assert b"credential_request_language" not in resp.data  # code itself isn't rendered
    assert b"password or sensitive credential" in resp.data
