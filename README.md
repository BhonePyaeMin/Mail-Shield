# MailShield -- Email Header Analyzer

MailShield is a lightweight, local, offline-first cybersecurity tool that
analyzes raw email headers and surfaces indicators commonly associated with
spoofing, phishing, and authentication anomalies. It is designed as a
classroom/project-friendly demonstration of how much can be learned from
headers alone, without ever touching the message body, attachments, or any
external service.

## Why email headers matter

Every email carries a trail of metadata added by mail servers, mail clients,
and (sometimes) attackers: `From`, `Reply-To`, `Return-Path`, the `Received`
chain each server adds as the message hops toward its destination, and
authentication results (SPF, DKIM, DMARC) recorded by receiving mail servers.
Careful analysis of these headers can reveal:

- A sender address that doesn't match where replies or bounces actually go
- A message that failed SPF/DKIM/DMARC authentication
- Domains crafted to look like a trusted brand (lookalike domains)
- Inconsistent or fabricated routing/timestamp information
- Malformed or duplicated headers that hint at a hand-crafted message

None of this *proves* an email is malicious or safe on its own -- but it
gives an analyst a fast, structured starting point for an investigation.

## Features

- Paste raw headers or upload a `.eml`/`.txt` file (1 MB limit)
- Robust header parsing built on Python's standard `email` module
- SPF / DKIM / DMARC result extraction (as *reported* by the headers --
  no live DNS lookups, no cryptographic verification)
- Sender identity checks: From vs. Reply-To vs. Return-Path vs. DKIM `d=`
- Domain heuristics: excessive subdomains, lookalike-brand detection
  (character substitution) and brand-impersonation detection (a brand
  name embedded in an unrelated domain) -- all conservative, offline,
  no external lookups
- **Body/link analysis** (`analyzer/content.py`): parses the message body
  (if present) to catch scams whose *headers* look clean but whose body
  doesn't -- link display-text-vs-destination mismatches (e.g. text reads
  "paypal.com" but the link goes elsewhere), raw-IP-address links,
  URL-shortener links, lookalike/impersonated brand domains in links,
  the `user@host` URL-obfuscation trick, punycode/IDN domains, a
  conservative urgency-language scan, prize/donation/financial-request
  wording, and explicit credential-request wording ("enter your
  password", etc.). Static parsing only -- **no link is ever fetched or
  visited automatically**
- **Attachment filename check**: flags dangerous extensions (`.exe`,
  `.js`, `.vbs`, ...) and double-extension disguises (`invoice.pdf.exe`)
  by inspecting only the declared MIME filename/Content-Disposition --
  attachment *contents* are never opened, decoded, or scanned
- **Display-name impersonation check**: catches a scam sent through a
  fully legitimate, properly-authenticated mailbox (e.g. a free Gmail
  account) where every header-alignment check passes -- flags when the
  human-readable From name claims a known brand but the address domain
  has nothing to do with it
- **Legal-threat / extortion language**, **unsolicited job-offer language**,
  and **contact-email mismatch** (the message appears to come from one
  address but tells you to reply to a different one) -- covers scam
  categories (sextortion/law-enforcement impersonation, job/recruitment
  fraud) distinct from the phishing-style checks above
- **Image scan (OCR)**: upload a screenshot of an email
  (`.png`/`.jpg`/`.webp`/`.gif`/`.bmp`, 5 MB limit) and MailShield runs it
  through a local OCR engine (Tesseract, via `pytesseract`) to recognize
  the text, then applies the same phrase/link heuristics used for pasted
  message bodies. The image is never uploaded anywhere -- OCR runs
  entirely on your machine. This is a *more limited* analysis than
  pasted headers: a screenshot never shows SPF/DKIM/DMARC results, the
  Received chain, or a link's real underlying destination (only its
  visible display text), so those checks cannot run on an image. See
  "Image scanning setup" below.
- IP address extraction and classification (Public / Private / Loopback /
  Reserved / Documentation / Multicast / Invalid)
- Full `Received:` chain parsing into a chronological "Mail Routing" view
- Date/timestamp consistency checks across the Date header and routing chain
- Header anomaly detection: missing/duplicate headers, malformed lines,
  unbalanced brackets, oversized values, suspicious encoded words,
  conflicting authentication results
- Transparent, configurable "Suspicion Score" (0-100) and risk level
  (LOW / MODERATE / HIGH / CRITICAL) -- weights live in one place:
  [analyzer/risk_engine.py](analyzer/risk_engine.py)
- A "What happened? / Why does it matter? / What should you check?"
  explanation panel for every indicator
- Dark cybersecurity-dashboard UI, plain HTML/CSS/JS (no frontend framework)
- Three built-in sample emails (safe, suspicious, spoofed) for instant demos
- JSON API at `POST /api/analyze` for programmatic use
- Export findings as a `.txt` or `.json` report
- Runs entirely offline; binds to `127.0.0.1` only

## Installation

Requires Python 3.11+.

```bash
python -m venv .venv
```

Activate the virtual environment:

```bash
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Windows (cmd.exe)
.venv\Scripts\activate.bat

# macOS / Linux
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python app.py
```

Then open **http://127.0.0.1:5000** in your browser.

### Image scanning setup (optional)

Header/text analysis works with just the steps above. To also scan
screenshots of emails, the Tesseract OCR engine must be installed
separately (it's a system binary, not a pip package):

```bash
# Windows (winget)
winget install --id UB-Mannheim.TesseractOCR -e

# macOS (Homebrew)
brew install tesseract

# Debian/Ubuntu
sudo apt install tesseract-ocr
```

`pytesseract`/`Pillow` (already in `requirements.txt`) talk to that
engine locally -- no image data ever leaves your machine. If Tesseract
isn't installed, every other feature still works; uploading an image
just shows a friendly "not available" message instead of a crash.

## Usage

1. Open the app in your browser.
2. Paste raw email headers into the text box, upload a `.eml`/`.txt`
   file, upload a **screenshot of an email** (`.png`/`.jpg`/`.webp`/
   `.gif`/`.bmp`), or click **Load Sample** to try one of the three
   built-in examples.
3. Click **Analyze Headers**.
4. Review the Suspicion Score, authentication results, and the list of
   indicators -- each one expands to show *what happened*, *why it
   matters*, and *what to check next*.
5. Click **Export Report** to save the findings as a `.txt` or `.json` file
   (header/text analysis only -- image scans aren't exportable yet).

### API

```
POST /api/analyze
Content-Type: application/json

{"headers": "From: example@example.com\n..."}
```

Returns a JSON object with `score`, `risk_level`, `authentication`,
`sender`, `domain_analysis`, `content_analysis` (links found in the body,
if any), and a list of `indicators`.

## Security

- The Flask development server binds to `127.0.0.1` only, by default.
- Core analysis is 100% offline: no DNS lookups, no IP/domain reputation
  services, no outbound network requests of any kind.
- The app never sends email, executes attachments, or opens URLs.
- Uploaded files are validated by extension (`.eml`/`.txt`, 1 MB max, or
  an image type for OCR, 5 MB max), processed in memory, and never
  written to disk. An uploaded image is never fetched, forwarded, or
  sent to any external service -- OCR runs locally via Tesseract only.
- The body is parsed only for the static text/link checks described
  above (`analyzer/content.py`) -- never displayed in full, never saved,
  and never used to fetch/visit any link. The "Raw Headers" panel and
  exported reports only ever show the header portion, never the body.
- Jinja2 auto-escaping is used throughout, so header/body content is
  never rendered as raw, executable HTML in the results page.
- The analyze/export forms are protected by a per-session CSRF token.
- Errors are shown as friendly messages; stack traces are never exposed
  to the browser.

## Limitations

**Header and body analysis together still cannot guarantee that an email
is malicious or safe.** SPF/DKIM/DMARC results are reported exactly as
the headers present them -- MailShield does not perform live DNS lookups
or cryptographic signature verification, and does not check IP/domain
reputation. The body/link checks are static text/HTML parsing against a
small, conservative brand/keyword list -- they do not fetch or preview
links, do not render HTML, and deliberately do not attempt grammar or
writing-quality scoring (that reliably requires NLP/ML, which is out of
scope for this offline tool). A well-crafted scam using a brand outside
the built-in list, or a mismatch technique not covered by these rules,
will not be caught. Every indicator is a signal worth reviewing, not a
verdict. Always corroborate
findings with independent verification before taking action on a message.

**Image scans are more limited still.** OCR accuracy depends on image
quality/resolution -- blurry or oddly-cropped screenshots produce
incomplete or garbled text, and clean-looking synthetic test images with
tiny/plain fonts can OCR poorly too. The guessed sender name/address and
subject are best-effort regex extraction, not a reliable parse -- there
is no structured "From:" header to read, just whatever text OCR
recognized. SPF/DKIM/DMARC, the Received chain, and link
text-vs-destination mismatches cannot be checked at all from an image,
since a screenshot never exposes that information.

## Project structure

```
mailshield/
├── app.py                  # Flask routes, CSRF, export/report generation
├── requirements.txt
├── analyzer/
│   ├── parser.py            # Raw header parsing + line-level anomaly checks
│   ├── authentication.py     # SPF/DKIM/DMARC extraction
│   ├── routing.py           # Received: chain parsing
│   ├── indicators.py        # All header-based indicator/heuristic detection
│   ├── content.py           # Body/link analysis (mismatches, IP/shortener links, urgency wording)
│   ├── ocr.py               # Image-screenshot analysis (local OCR + text heuristics)
│   ├── risk_engine.py       # Configurable scoring + risk level
│   └── utils.py             # Domain/IP/date/URL helpers
├── templates/               # Jinja2 templates (dark dashboard UI)
├── static/                  # CSS + vanilla JS
├── samples/                 # Three demo emails (safe/phishing/spoofed), each with a body
└── tests/                   # pytest suite
```

## Running tests

```bash
pytest
```
