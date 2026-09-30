"""MailShield -- Email Header Analyzer.

A local, offline-first Flask application. See README.md for details.

Run with:  python app.py
Binds to 127.0.0.1 only, by design -- this tool is not meant to be
exposed to a network.
"""

from __future__ import annotations

import json
import os
import secrets
from datetime import datetime, timezone
from io import BytesIO

from flask import (Flask, jsonify, render_template, request, send_file,
                    session)
from werkzeug.exceptions import RequestEntityTooLarge

from analyzer import HeaderParseError, analyze_headers
from analyzer import ocr as image_ocr

MAX_TEXT_UPLOAD_BYTES = 1 * 1024 * 1024  # 1 MB -- raw headers / .eml / .txt
# The Flask-wide cap must cover the larger of the two upload paths (image
# screenshots, which are naturally heavier than plain text).
MAX_CONTENT_LENGTH = image_ocr.MAX_IMAGE_BYTES
ALLOWED_UPLOAD_EXTENSIONS = {".eml", ".txt"}
ALLOWED_IMAGE_EXTENSIONS = image_ocr.ALLOWED_IMAGE_EXTENSIONS
SAMPLE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")
SAMPLE_FILES = {
    "safe": "safe_email.txt",
    "phishing": "phishing_email.txt",
    "spoofed": "spoofed_email.txt",
}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
# A fresh random secret key each process start is sufficient here: this
# app has no user accounts and no data that needs to survive a restart.
# It only signs the CSRF token used to protect the analyze form.
app.config["SECRET_KEY"] = secrets.token_hex(32)


# ---------------------------------------------------------------------------
# CSRF protection (lightweight, no extra dependency)
# ---------------------------------------------------------------------------

def get_csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf(submitted_token: str) -> bool:
    expected = session.get("csrf_token")
    return bool(expected) and bool(submitted_token) and secrets.compare_digest(expected, submitted_token)


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": get_csrf_token()}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_uploaded_file(file_storage) -> str:
    filename = file_storage.filename or ""
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        raise HeaderParseError(
            f"Unsupported file type '{ext or 'unknown'}'. Only .eml and .txt "
            "files are accepted.")

    data = file_storage.read(MAX_TEXT_UPLOAD_BYTES + 1)
    if len(data) > MAX_TEXT_UPLOAD_BYTES:
        raise HeaderParseError("Uploaded file exceeds the 1 MB size limit.")

    return data.decode("utf-8", errors="replace")


def _get_input_headers(form, files) -> str:
    uploaded = files.get("file")
    if uploaded and uploaded.filename:
        return _read_uploaded_file(uploaded)
    return form.get("headers", "")


def _uploaded_file_kind(files) -> str:
    """Returns 'image', 'text', or None based on the uploaded file's
    extension (None means no file was uploaded -- fall back to the
    pasted-text field)."""
    uploaded = files.get("file")
    if not uploaded or not uploaded.filename:
        return None
    ext = os.path.splitext(uploaded.filename)[1].lower()
    if ext in ALLOWED_IMAGE_EXTENSIONS:
        return "image"
    return "text"


def _generate_txt_report(analysis: dict) -> str:
    lines = []
    lines.append("MAILSHIELD ANALYSIS REPORT")
    lines.append("=" * 60)
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}")
    lines.append(f"Suspicion Score: {analysis['score']} / 100")
    lines.append(f"Risk Level: {analysis['risk_level']}")
    lines.append("")
    lines.append("AUTHENTICATION")
    lines.append("-" * 60)
    auth = analysis["authentication"]
    lines.append(f"SPF:   {auth['spf'].upper()}")
    lines.append(f"DKIM:  {auth['dkim'].upper()}")
    lines.append(f"DMARC: {auth['dmarc'].upper()}")
    lines.append("")
    lines.append("SENDER")
    lines.append("-" * 60)
    basic = analysis["basic"]
    lines.append(f"From:        {basic.get('from') or '(none)'}")
    lines.append(f"Reply-To:    {basic.get('reply_to') or '(none)'}")
    lines.append(f"Return-Path: {basic.get('return_path') or '(none)'}")
    lines.append("")
    lines.append("ROUTING")
    lines.append("-" * 60)
    lines.append(f"Total Received Hops: {analysis['total_hops']}")
    for hop in analysis["hops"]:
        lines.append(f"  Hop {hop['hop_number']}: from={hop['from_host']} "
                      f"ip={hop['ip_address']} ({hop['ip_classification']}) "
                      f"by={hop['by_host']}")
    lines.append("")
    lines.append("INDICATORS")
    lines.append("-" * 60)
    if analysis["indicators"]:
        for indicator in analysis["indicators"]:
            lines.append(f"[{indicator['severity']}] {indicator['title']}")
            lines.append(f"  {indicator['description']}")
    else:
        lines.append("No major suspicious indicators were detected in the "
                      "analyzed headers.")
        lines.append("This does not guarantee that the email or its contents are safe.")
    lines.append("")
    lines.append("TECHNICAL DETAILS")
    lines.append("-" * 60)
    lines.append(f"Message-ID: {basic.get('message_id') or '(none)'}")
    lines.append(f"Date: {basic.get('date') or '(none)'}")
    lines.append(f"Subject: {basic.get('subject') or '(none)'}")
    lines.append("")
    content = analysis["content_analysis"]
    lines.append("LINKS FOUND IN BODY")
    lines.append("-" * 60)
    if content["links"]:
        for link in content["links"]:
            label = f"  {link['href']}"
            if link["domain"]:
                label += f"  [{link['domain']}]"
            if link["classification"]:
                label += f"  ({link['classification']})"
            lines.append(label)
    else:
        lines.append("  No links found (or no message body was supplied).")
    lines.append("")
    lines.append("ATTACHMENTS (metadata only -- never opened)")
    lines.append("-" * 60)
    if content["attachments"]:
        for filename in content["attachments"]:
            lines.append(f"  {filename}")
    else:
        lines.append("  None found.")
    lines.append("")
    lines.append("DISCLAIMER")
    lines.append("-" * 60)
    lines.append("Header analysis cannot guarantee that an email is safe. Review "
                  "all findings and use independent judgment before trusting a message.")
    return "\n".join(lines) + "\n"


def _analysis_to_api_dict(analysis: dict) -> dict:
    return {
        "score": analysis["score"],
        "risk_level": analysis["risk_level"],
        "authentication": {
            "spf": analysis["authentication"]["spf"],
            "dkim": analysis["authentication"]["dkim"],
            "dmarc": analysis["authentication"]["dmarc"],
        },
        "sender": {
            "from": analysis["basic"].get("from"),
            "reply_to": analysis["basic"].get("reply_to"),
            "return_path": analysis["basic"].get("return_path"),
        },
        "domain_analysis": analysis["domain_analysis"],
        "total_hops": analysis["total_hops"],
        "content_analysis": analysis["content_analysis"],
        "indicators": [
            {
                "severity": i["severity"],
                "title": i["title"],
                "description": i["description"],
            }
            for i in analysis["indicators"]
        ],
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", samples=SAMPLE_FILES)


@app.route("/analyze", methods=["POST"])
def analyze():
    if not validate_csrf(request.form.get("csrf_token", "")):
        return render_template(
            "error.html",
            message="Your session expired or the form was submitted "
                    "incorrectly. Please try again."), 400

    if _uploaded_file_kind(request.files) == "image":
        return _analyze_image_upload(request.files["file"])

    try:
        raw_headers = _get_input_headers(request.form, request.files)
        analysis = analyze_headers(raw_headers)
    except HeaderParseError as exc:
        return render_template(
            "error.html",
            message="Unable to analyze the supplied headers.",
            detail=str(exc)), 400
    except RequestEntityTooLarge:
        return render_template(
            "error.html",
            message="The uploaded content exceeds the 1 MB size limit."), 413

    # Only ever display/export the header portion -- an uploaded .eml's
    # body must never resurface in the UI, the raw-headers panel, or the
    # export hidden field.
    return render_template("results.html", analysis=analysis,
                            raw_headers=analysis["raw_header_text"])


def _analyze_image_upload(file_storage):
    if not image_ocr.OCR_AVAILABLE:
        return render_template(
            "error.html",
            message="Image scanning isn't available on this installation.",
            detail="The OCR engine (Tesseract) or its Python bindings "
                   "(pytesseract/Pillow) are not installed. See README.md "
                   "for setup instructions."), 503

    data = file_storage.read(image_ocr.MAX_IMAGE_BYTES + 1)
    try:
        result = image_ocr.analyze_image(data)
    except image_ocr.OCRError as exc:
        return render_template(
            "error.html",
            message="Unable to analyze the supplied image.",
            detail=str(exc)), 400
    except RequestEntityTooLarge:
        return render_template(
            "error.html",
            message="The uploaded image exceeds the 5 MB size limit."), 413

    return render_template("results_image.html", result=result)


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    if not request.is_json:
        return jsonify({"error": "Request must have Content-Type: application/json"}), 415

    payload = request.get_json(silent=True) or {}
    raw_headers = payload.get("headers", "")

    try:
        analysis = analyze_headers(raw_headers)
    except HeaderParseError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(_analysis_to_api_dict(analysis))


@app.route("/sample/<name>", methods=["GET"])
def get_sample(name):
    filename = SAMPLE_FILES.get(name)
    if not filename:
        return jsonify({"error": "Unknown sample"}), 404
    path = os.path.join(SAMPLE_DIR, filename)
    with open(path, "r", encoding="utf-8") as handle:
        content = handle.read()
    return jsonify({"content": content})


@app.route("/export/<fmt>", methods=["POST"])
def export_report(fmt):
    if not validate_csrf(request.form.get("csrf_token", "")):
        return render_template(
            "error.html",
            message="Your session expired or the form was submitted "
                    "incorrectly. Please try again."), 400

    raw_headers = request.form.get("headers", "")
    try:
        analysis = analyze_headers(raw_headers)
    except HeaderParseError as exc:
        return render_template(
            "error.html",
            message="Unable to analyze the supplied headers.",
            detail=str(exc)), 400

    if fmt == "txt":
        content = _generate_txt_report(analysis)
        mimetype = "text/plain"
        download_name = "mailshield_report.txt"
    elif fmt == "json":
        content = json.dumps(_analysis_to_api_dict(analysis), indent=2)
        mimetype = "application/json"
        download_name = "mailshield_report.json"
    else:
        return render_template("error.html", message="Unknown export format."), 400

    buffer = BytesIO(content.encode("utf-8"))
    return send_file(buffer, mimetype=mimetype, as_attachment=True,
                      download_name=download_name)


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(413)
def handle_too_large(_exc):
    return render_template(
        "error.html",
        message="The submitted content exceeds the 1 MB size limit."), 413


@app.errorhandler(404)
def handle_not_found(_exc):
    return render_template("error.html", message="Page not found."), 404


@app.errorhandler(500)
def handle_server_error(_exc):
    # Never leak stack traces to the user.
    return render_template(
        "error.html",
        message="An unexpected error occurred while processing your request."), 500


if __name__ == "__main__":
    debug_mode = os.environ.get("MAILSHIELD_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=5000, debug=debug_mode)
