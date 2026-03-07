# ARGUS PhishRadar

Visual phishing detection and campaign intelligence engine.

ARGUS PhishRadar is a security research tool designed to analyze suspicious webpages, detect phishing login interfaces, and correlate related phishing infrastructure across multiple domains.

The engine combines visual analysis, DOM intelligence and infrastructure correlation to help security analysts identify credential harvesting pages and uncover related phishing campaigns.


<img width="940" height="620" alt="sdsaadsasdasdasad" src="https://github.com/user-attachments/assets/95870195-d063-443e-b64a-840b84d108e4" />

---

# Core Capabilities

ARGUS integrates several analysis layers:

## Visual phishing detection
- Custom YOLO model trained to detect phishing-oriented UI elements
- Detection of login forms, password fields, 2FA prompts and security banners
- Annotated screenshots highlighting suspicious UI components

## DOM intelligence
- Extraction of forms, inputs, scripts and links
- Identification of credential harvesting flows
- Detection of suspicious form actions and hidden inputs

## Brand impersonation detection
- CLIP-based brand recognition
- Brand/domain mismatch analysis
- Detection of common impersonation targets (Microsoft, Google, PayPal, etc.)

## Layout fingerprinting
- Structural fingerprint based on UI element positioning
- Detection of reused phishing kits across domains
- Clustering of visually similar phishing pages

## OCR-assisted semantic validation (optional)
- OCR can extract text from detected UI elements
- Helps reduce visual false positives
- Allows semantic validation of detected login fields

## Phishing campaign discovery
- Automated typosquat domain generation
- Detection of plausible phishing domains targeting a brand
- HTTP probing of candidate domains

## Infrastructure intelligence
- Resolution of discovered domains
- IP clustering of related phishing infrastructure
- Campaign graph generation for visual investigation




# Example Detection

ARGUS performs analysis without relying only on URL reputation lists or blocklists.

Instead it evaluates:

- visual structure of the page
- DOM layout and credential inputs
- brand impersonation signals
- infrastructure relationships

This allows detection of previously unseen phishing pages.

<img width="1569" height="914" alt="afsdfdffsdfsfdsfdfdf" src="https://github.com/user-attachments/assets/5ac154cb-c1ee-4044-9b2b-03840504dcbd" />

<img width="1607" height="815" alt="fsdfdsffsdfsfd" src="https://github.com/user-attachments/assets/6bb237ad-36ef-41dc-afa4-37054a242f4c" />


---

# Visual Detection (YOLO)

The custom YOLO model detects phishing-oriented UI elements including:

- login forms
- username fields
- password inputs
- authentication buttons
- brand logos
- CAPTCHA elements
- 2FA prompts
- security warning banners

Detected elements are rendered on annotated screenshots to assist investigation.

<img width="1383" height="817" alt="sfdfadsfsfsdsfsdfdsf" src="https://github.com/user-attachments/assets/d3e400ab-2554-4504-952a-f9f0b681544d" />

---

# Phishing Campaign Correlation

ARGUS can identify infrastructure reuse across phishing domains.

Signals used for correlation include:

- layout fingerprints
- perceptual screenshot hashes
- visual palette similarity
- detected UI elements
- favicon fingerprints
- hosting infrastructure clustering

These signals allow analysts to group domains likely belonging to the same phishing kit or campaign.

---

# Campaign Discovery Engine

ARGUS includes a campaign discovery module capable of identifying suspicious domains targeting a brand.

The engine performs:

1. typosquat generation  
2. domain probing  
3. live host identification  
4. infrastructure clustering  

Suspicious domains can be automatically analyzed with the visual engine.

<img width="1678" height="962" alt="dsfdfssdfsdfsdfsfsdfdsdsf" src="https://github.com/user-attachments/assets/51faca0b-4f44-46f3-b28b-6c7e397f5bab" />


<img width="1609" height="799" alt="ghdhdhdhdhdhdhdhdhdgdgh" src="https://github.com/user-attachments/assets/5383d1c9-0cc7-4329-8ed3-caf4c98c6c04" />

---

# Example Workflow

Example campaign discovery targeting Microsoft:

python argus_phishradar.py --campaign-intel microsoft

# Example phishing page analysis:

python argus_phishradar.py --url "http://example-phishing-site.com"

#  Deep visual analysis:

python argus_phishradar.py --url "http://example-phishing-site.com" --clip --filter-anomalous-boxes --save-layout-json --no-headless --wait 3

# Repository Layout

argus-phishradar/
├── argus_phishradar.py
├── argus_argus_phishradar.py
├── argus_layout_cluster.py
├── requirements.txt
├── README.md
├── models/
│   └── best.pt
└── output/

#  Installation

Clone the repository:
git clone https://github.com/Neurone4444/Neurone4444-argus-phishradar.git
cd Neurone4444-argus-phishradar

Install dependencies:
pip install -r requirements.txt
python -m playwright install chromium

#  Optional OCR Support

ARGUS can use OCR to extract text from detected UI elements and reduce visual false positives.

Install OCR support:
pip install pytesseract

#  Install Tesseract

Windows:

Download and install Tesseract OCR and add it to the system PATH.

Verify installation:
tesseract --version
If OCR is not installed, ARGUS still works normally but OCR-assisted validation will be unavailable.

#  YOLO Model

ARGUS uses a custom YOLO model trained to detect phishing-related UI components.

If the model is missing, download it from the release page:
https://github.com/Neurone4444/Neurone4444-argus-phishradar/releases/download/v1.0/best.pt
Place it in:
models/best.pt
Or provide a custom model path:
python argus_phishradar.py --url "https://example.com" --yolo-model path/to/model.pt

#  Campaign Discovery Commands

Search for domains potentially impersonating a brand:
python argus_phishradar.py --campaign-intel microsoft

Show only reachable domains:
python argus_phishradar.py --campaign-intel microsoft --live-only

Automatically analyze suspicious domains:
python argus_phishradar.py --campaign-intel microsoft --live-only --auto-analyze

Open generated reports automatically:
python argus_phishradar.py --campaign-intel microsoft --live-only --auto-analyze --open-reports

#  Example Campaign Searches

python argus_phishradar.py --campaign-intel microsoft
python argus_phishradar.py --campaign-intel google
python argus_phishradar.py --campaign-intel paypal
python argus_phishradar.py --campaign-intel netflix

#  Output

ARGUS generates:

HTML analysis dashboard

JSON report

original screenshot

annotated screenshot

layout fingerprint JSON

campaign infrastructure graph

Default output directory:

output/

#  Disclaimer

This project is intended for:

cybersecurity research

phishing detection

training

authorized security analysis

Campaign discovery identifies suspicious infrastructure but does not automatically prove phishing activity.

The author is not responsible for misuse of this software.
