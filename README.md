# ARGUS PhishRadar 
Visual phishing detection and campaign intelligence engine.

**Keywords:** phishing detection, threat intelligence, OSINT, phishing infrastructure discovery, brand abuse detection, certificate transparency monitoring

ARGUS PhishRadar is a security research tool designed to analyze suspicious webpages, detect credential-harvesting interfaces, and pivot from a single phishing page to broader phishing infrastructure.

The engine combines visual analysis, DOM intelligence, brand impersonation detection, campaign feature clustering, and infrastructure correlation to help analysts investigate phishing activity and uncover related domains, reused kits, and campaign patterns.

ARGUS is built for investigative workflows where a single suspicious URL can lead to the discovery of a wider phishing ecosystem.

Unlike tools that rely only on static blocklists or domain reputation, ARGUS evaluates the page itself: its visual structure, credential collection behavior, impersonated brand signals, and shared campaign artifacts.

<img width="940" height="620" alt="sdsaadsasdasdasad" src="https://github.com/user-attachments/assets/95870195-d063-443e-b64a-840b84d108e4" />

---

# Core Capabilities

ARGUS is designed as a multi-layer phishing investigation engine, where each analysis layer contributes evidence for both single-page triage and broader campaign discovery.

ARGUS integrates multiple analysis layers to evaluate suspicious webpages and identify phishing activity.

## DOM intelligence

ARGUS extracts structural information directly from the page DOM to identify potential credential-harvesting behavior.

The analysis includes:

- form extraction
- input field analysis
- script inspection
- link collection
- form action inspection

This helps identify suspicious submission endpoints, hidden credential collection behavior, and phishing-oriented page structure.


## Brand impersonation detection


ARGUS attempts to identify brand impersonation by combining visual signals and domain analysis.

The system supports:

- CLIP-based brand recognition
- brand/domain mismatch analysis
- detection of common impersonation targets

Typical impersonation targets include widely abused brands such as Microsoft, Google, PayPal, Apple, and other major online services.

## Layout fingerprinting

ARGUS builds a structural fingerprint of the analyzed page based on the position and type of detected UI elements.

The fingerprint captures page layout rather than page text, making it useful for identifying reused phishing templates.

This enables:

- detection of reused phishing kits
- clustering of visually similar phishing pages
- comparison of page structure across domains

Layout fingerprints help analysts identify phishing campaigns reusing the same template or interface pattern.

Because phishing kits often reuse interface structure, layout patterns, DOM structure, and other shared artifacts even when text, domains, or assets change, ARGUS can correlate visually or structurally related phishing pages across otherwise different hosts.

## OCR-assisted semantic validation (optional)

OCR can be used to extract text from detected UI elements and reduce visual false positives.

When enabled, OCR allows ARGUS to:

- extract text from login fields and interface elements
- validate detected UI components
- improve semantic understanding of page content

OCR is optional and ARGUS can operate normally without it.


## Phishing campaign discovery

ARGUS includes a campaign discovery module that identifies suspicious domains targeting a specific brand.

The discovery engine performs:

- typosquat domain generation
- discovery of domains from Certificate Transparency logs
- discovery of domains observed in public scanning platforms
- HTTP probing of candidate domains

Suspicious domains can then be automatically analyzed using the visual detection engine.


# Example Detection

ARGUS does not depend exclusively on reputation feeds, allowlists, or blocklists.

Instead, it evaluates suspicious webpages using multiple layers of evidence, including visual phishing signals, credential-oriented DOM behavior, brand impersonation indicators, and cross-domain infrastructure relationships.

This allows ARGUS to surface suspicious phishing pages and related infrastructure even when they have not yet been classified by traditional detection sources.

Instead of relying only on whether a domain is already known, ARGUS evaluates signals such as:

- visual page structure
- DOM layout and credential inputs
- form submission behavior
- brand impersonation indicators
- infrastructure relationships between domains
- shared layout or campaign artifacts

This makes ARGUS useful for identifying previously unseen phishing pages, suspicious brand-abuse domains, and related infrastructure before they appear in traditional reputation sources.

<img width="1569" height="914" alt="afsdfdffsdfsfdsfdfdf" src="https://github.com/user-attachments/assets/5ac154cb-c1ee-4044-9b2b-03840504dcbd" />

<img width="1607" height="815" alt="fsdfdsffsdfsfd" src="https://github.com/user-attachments/assets/6bb237ad-36ef-41dc-afa4-37054a242f4c" />


---

# Visual Detection (YOLO)

The custom YOLO model used by ARGUS is trained to detect phishing-related interface components.

The visual detection layer is intended to support phishing analysis at the page level, helping analysts identify authentication-oriented interfaces, reused phishing layouts, and suspicious credential collection patterns directly from rendered webpages.

Detected elements include:

- login forms
- username fields
- password inputs
- authentication buttons
- brand logos
- CAPTCHA elements
- two-factor authentication prompts
- security warning banners

Detected components are rendered directly on annotated screenshots to assist manual investigation.

<img width="1383" height="817" alt="sfdfadsfsfsdsfsdfdsf" src="https://github.com/user-attachments/assets/d3e400ab-2554-4504-952a-f9f0b681544d" />

---

# Phishing Campaign Correlation

ARGUS can identify infrastructure reuse across multiple phishing domains.

The correlation engine analyzes several signals:

layout fingerprints

perceptual screenshot hashes

visual palette similarity

detected UI components

favicon fingerprints

hosting infrastructure clustering

By combining these signals, ARGUS can group domains that are likely part of the same phishing kit or campaign.
---

# Campaign Discovery Engine

ARGUS includes a campaign discovery module capable of identifying suspicious domains targeting a brand.

The engine performs several discovery steps:

typosquat domain generation

domain probing

live host identification

infrastructure clustering

Domains identified during discovery can be automatically analyzed with the visual phishing detection engine.
<img width="1678" height="962" alt="dsfdfssdfsdfsdfsfsdfdsdsf" src="https://github.com/user-attachments/assets/51faca0b-4f44-46f3-b28b-6c7e397f5bab" />


<img width="1609" height="799" alt="ghdhdhdhdhdhdhdhdhdgdgh" src="https://github.com/user-attachments/assets/5383d1c9-0cc7-4329-8ed3-caf4c98c6c04" />

---

# Example Workflow

Example campaign discovery targeting Microsoft:

python argus_phishradar.py --campaign-intel microsoft

# Example phishing page analysis:

python argus_phishradar.py --url "http://example-phishing-site.com"

#  Batch analysis of multiple URLs

Multiple targets can be analyzed using a shell loop
Windows (CMD):
for %d in (https://example.com https://.com http://www.example.org) do python argus_phishradar.py --url "%d"

Linux / macOS:
for d in https://example.com https://example2.com http://www.example.org; do
python argus_phishradar.py --url "$d"
done

#  Deep visual analysis:

python argus_phishradar.py --url "http://example-phishing-site.com" --clip --filter-anomalous-boxes --save-layout-json --no-headless --wait 3

### Campaign Intelligence

ARGUS can automatically discover phishing infrastructure related to a brand.

Sources used for discovery include:

Certificate Transparency logs (crt.sh)

urlscan.io public scan data

dynamically generated typosquat domains

RDAP domain age information

Discovered domains are ranked using a phishing likelihood score while known official assets and partner domains are filtered out.

Example:

python argus_phishradar.py --campaign-intel paypal --live-only


<img width="1279" height="790" alt="fadsfffdsfdssdfsfdsf" src="https://github.com/user-attachments/assets/6fd63ddc-774f-439d-8017-cfbaa235c6d8" />

<img width="1476" height="806" alt="hfhjfjfjfjfjfjfjhfjj" src="https://github.com/user-attachments/assets/6e040c51-4b65-4755-ae5f-f51596cccf95" />

### Dynamic Candidate Ranking

Domains discovered through CT logs and urlscan are ranked using multiple signals:

brand presence within the domain

phishing-related keywords (login, verify, secure, account, password)

suspicious top-level domains

domain age (recent registrations increase risk score)

typo patterns and structural anomalies

Official assets and known partner domains are automatically excluded from the candidate list.

Example output:

[ARGUS] Top dynamic candidates

paypal-login-secure.info | score=68 | reasons: brand exact, phishing tokens, suspicious tld
secure-paypal-account.net | score=61 | reasons: brand exact, phishing tokens
verify-paypal-login.top | score=58 | reasons: brand exact, suspicious tld

[ARGUS] Top dynamic candidates

paypal-login-secure.info | score=68 | reasons: brand exact, phishing tokens, suspicious tld
secure-paypal-account.net | score=61 | reasons: brand exact, phishing tokens
verify-paypal-login.top | score=58 | reasons: brand exact, suspicious tld

Discover phishing infrastructure for a brand:

python argus_phishradar.py --campaign-intel microsoft

Example:

python argus_phishradar.py --campaign-intel paypal --live-only

# Repository Layout

argus-phishradar/
├── argus_phishradar.py
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

training and education

authorized security analysis

Campaign discovery identifies suspicious infrastructure but does not automatically prove phishing activity.

The author is not responsible for misuse of this software.


