# ARGUS PhishRadar

**Visual phishing detection engine** that combines:

- YOLO UI object detection
- DOM intelligence
- CLIP brand recognition
- layout fingerprinting
- annotated screenshots
- HTML and JSON reporting

ARGUS PhishRadar does not rely only on URL reputation or blacklists. It inspects how a page **looks** and how it is **structured** to identify phishing login pages, credential harvesting flows and brand impersonation.

## Features

- Live webpage screenshot acquisition with Playwright
- Detection of phishing-oriented UI elements with a custom YOLO model
- DOM extraction of forms, inputs, scripts and links
- CLIP-based brand recognition
- brand/domain mismatch analysis
- layout fingerprinting for phishing-kit clustering
- annotated screenshots
- HTML dashboard and JSON reports
- DOM-aware false-positive reduction

## YOLO Model Classes

The included custom model detects 21 phishing-related classes:

- `login_form`
- `username_field`
- `password_field`
- `login_button`
- `forgot_password_link`
- `remember_me_checkbox`
- `logo_facebook`
- `logo_google`
- `logo_microsoft`
- `logo_paypal`
- `logo_amazon`
- `logo_apple`
- `logo_netflix`
- `logo_instagram`
- `logo_twitter`
- `logo_linkedin`
- `security_alert`
- `fake_certificate`
- `suspicious_banner`
- `captcha`
- `2fa_field`

## Repository Layout

```text
argus-phishradar/
├── argus_phishradar.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
├── models/
│   └── best.pt
└── output/
```

## Installation

Clone the repository:

```bash
git clone https://github.com/YOURUSER/argus-phishradar.git
cd argus-phishradar
```

Install dependencies:

```bash
pip install -r requirements.txt
python -m playwright install chromium
```

The scanner expects the model at:

```text
models/best.pt
```

You can also provide a custom model path with `--yolo-model`.

## Basic Usage

```bash
python argus_phishradar.py --url "https://example.com"
```

## Recommended Deep Scan

```bash
python argus_phishradar.py --url "https://example.com" --clip --filter-anomalous-boxes --save-layout-json --no-headless --wait 3.5 --open
```

## Real Examples

Legitimate site:

```bash
python argus_phishradar.py --url "https://www.redhotcyber.com" --clip --filter-anomalous-boxes --save-layout-json --no-headless --wait 3.5
```

Suspicious Microsoft-like phishing page:

```bash
python argus_phishradar.py --url "http://www.busanopen.org/office/msgvoice/source/Login.php" --clip --filter-anomalous-boxes --save-layout-json --no-headless --wait 3.5
```

Facebook-like phishing page on free hosting:

```bash
python argus_phishradar.py --url "https://facebooklogin12732771.github.io/facebook_/index.html" --clip --filter-anomalous-boxes --save-layout-json --no-headless --wait 3.5
```

## Useful Options

Show all CLI options:

```bash
python argus_phishradar.py --help
```

Compare a suspicious page with a reference page:

```bash
python argus_phishradar.py --url "https://suspicious-site.com" --ref-url "https://legitimate-site.com" --clip --save-layout-json --no-headless
```

Force a second login step:

```bash
python argus_phishradar.py --url "https://target.com" --step2-email test@example.com --clip --no-headless
```

## Output

ARGUS PhishRadar generates:

- JSON report
- HTML dashboard
- original screenshot
- annotated screenshot
- optional layout fingerprint JSON

Default output directory:

```text
output/
```

## GitHub Description

Use this as the short repository description:

> Visual phishing detection engine combining YOLO UI detection, DOM intelligence, layout fingerprinting and brand recognition.

## Suggested GitHub Topics

- phishing
- cybersecurity
- osint
- yolo
- computer-vision
- threat-intelligence
- dom-analysis
- security-tools

## Disclaimer

This project is intended for defensive security research, phishing detection, training and authorized analysis only.

The author is not responsible for misuse.
