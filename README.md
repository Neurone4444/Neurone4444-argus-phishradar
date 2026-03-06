# ARGUS PhishRadar

# Visual phishing detection engine for detecting phishing pages and correlating related phishing campaigns that combines:

- YOLO UI object detection
- DOM intelligence
- CLIP brand recognition
- layout fingerprinting
- annotated screenshots
- HTML and JSON reporting

- ## Example Detection
![ARGUS Detection](https://github.com/user-attachments/assets/0ca03e8a-4092-49ea-ac60-0788f9695b21)

ARGUS PhishRadar does not rely only on URL reputation or blacklists. It inspects how a page **looks** and how it is **structured** to identify phishing login pages, credential harvesting flows, brand impersonation and correlate related phishing campaigns.

## Visual Detection (YOLO)

Annotated login page showing detected phishing UI elements such as login fields, buttons and password inputs.

![Annotated Login Detection](https://github.com/user-attachments/assets/9d59e313-3945-410c-93e9-517109da025b)


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

## Phishing Campaign Correlation

ARGUS PhishRadar can help identify phishing campaigns that reuse the same phishing kit or infrastructure.

The scanner extracts structural fingerprints including:

- layout fingerprint (relative positions of login elements)
- visual palette
- perceptual screenshot hash
- detected UI components
- brand impersonation signals
- reused UI structures across domains

These signals allow analysts to cluster phishing pages that likely originate from the same phishing kit or campaign infrastructure.

The optional `layout_fingerprint.json` output can be used to compare multiple scans and identify structural similarities across different domains.
## Final Analysis Report

ARGUS generates a full HTML report combining visual detection, DOM intelligence and risk scoring.

![Phishing Analysis Report](https://github.com/user-attachments/assets/52143ab3-225b-4b1c-ac47-d69215cb4f33)

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


git clone https://github.com/Neurone4444/Neurone4444-argus-phishradar.git
cd Neurone4444-argus-phishradar

Yolo Model:


Install dependencies:

pip install -r requirements.txt
python -m playwright install chromium


## YOLO Model

ARGUS PhishRadar uses a custom YOLO model trained to detect phishing UI components.

The model download is handled automatically by the scanner.

If `models/best.pt` is not found, the script will automatically download the model from the GitHub Releases section on first run.

The model will be saved to:

models/best.pt

You can also provide a custom model manually:

python argus_phishradar.py --url "https://example.com" --yolo-model path/to/model.pt

## Basic Usage

python argus_phishradar.py --url "https://example.com"


## Recommended Deep Scan

python argus_phishradar.py --url "https://example.com" --clip --filter-anomalous-boxes --save-layout-json --no-headless --wait 3.5 --open


## Real Examples

Legitimate site:

python argus_phishradar.py --url "https://www.redhotcyber.com" --clip --filter-anomalous-boxes --save-layout-json --no-headless --wait 3.5


Suspicious Microsoft-like phishing page:


python argus_phishradar.py --url "http://www.busanopen.org/office/msgvoice/source/Login.php" --clip --filter-anomalous-boxes --save-layout-json --no-headless --wait 3.5
```

Facebook-like phishing page on free hosting:

python argus_phishradar.py --url "https://facebooklogin12732771.github.io/facebook_/index.html" --clip --filter-anomalous-boxes --save-layout-json --no-headless --wait 3.5


## Useful Options

Show all CLI options:

python argus_phishradar.py --help


Compare a suspicious page with a reference page:


python argus_phishradar.py --url "https://suspicious-site.com" --ref-url "https://legitimate-site.com" --clip --save-layout-json --no-headless
```

Force a second login step:


python argus_phishradar.py --url "https://target.com" --step2-email test@example.com --clip --no-headless


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
