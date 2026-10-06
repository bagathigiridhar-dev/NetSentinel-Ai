# NetSentinel AI

> **AI-Powered Vendor-Agnostic Network Security Compliance & Risk Assessment Engine**

NetSentinel AI ingests raw network device configuration files, automatically detects device vendors, normalizes vendor-specific syntax into a standardized **Security Baseline Model**, audits configurations against major industry cybersecurity compliance frameworks (**CIS, NIST SP 800-53, DISA STIG, ISO/IEC 27001**), calculates severity-weighted security metrics and risk scores, supports on-the-fly dynamic rule learning with token similarity matching, and generates executive-ready PDF compliance reports.

---

## 🌟 Key Features

* **Multi-Vendor Auto-Detection**: Automatically identifies configurations from Cisco IOS, Juniper JunOS, Fortinet FortiOS, Palo Alto PAN-OS, Arista EOS, SONiC, and generic devices.
* **Device Metadata Extraction**: Discovers hostname, firmware/software versions, hardware specs, serial numbers, and interfaces.
* **Vendor-Agnostic Normalization Engine**: Translates vendor commands into a unified Security Baseline Model covering administrative access, encryption, authentication, audit logging, NTP, SNMP, AAA, and firewall controls.
* **Multi-Framework Compliance Auditing**:
  * **CIS Benchmarks** (Center for Internet Security)
  * **NIST SP 800-53** (National Institute of Standards and Technology)
  * **DISA STIG** (Defense Information Systems Agency)
  * **ISO/IEC 27001** (Information Security Management)
* **Severity-Weighted Risk Scoring**: Calculates overall security score (0–100%), compliance percentage, risk points, and threat level (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `MINIMAL`).
* **Cross-Framework Cross-Tabulation**: Simultaneously benchmarks a device configuration against all supported standards.
* **Dynamic AI Learning & Training Engine**: Allows security teams to teach the engine custom command patterns (`/train`) with Jaccard token-similarity matching (`threshold >= 0.75`).
* **Automated PDF Compliance Reports**: Generates professional multi-page executive security audit reports using ReportLab.
* **Cyberpunk Security Dashboard**: Modern, responsive SPA interface for configuration uploading, live score ring metrics, control breakdown, and one-click PDF downloads.

---

## 📁 Project Structure

```text
NetSentinel-AI/
├── .env.example                     # Environment variables template
├── .gitignore                       # Git ignore configuration
├── README.md                        # Project documentation & quickstart guide
├── requirements.txt                 # Python dependencies
├── run.py                           # Root application runner
│
├── backend/
│   ├── app/
│   │   ├── __init__.py              # App package initializer
│   │   ├── main.py                  # FastAPI factory & router mounting
│   │   ├── config.py                # Centralized environment & directory configuration
│   │   │
│   │   ├── api/                     # Modular API Route Controllers
│   │   │   ├── __init__.py
│   │   │   ├── routes_analyze.py    # POST /analyze, POST /report
│   │   │   ├── routes_learning.py   # POST /train, GET /learned, GET /learning/stats
│   │   │   └── routes_system.py     # GET /, GET /health, GET /model
│   │   │
│   │   ├── core/                    # Core Domain Engines
│   │   │   ├── __init__.py
│   │   │   ├── vendor_detector.py   # Multi-vendor identification engine
│   │   │   ├── normalizer.py        # Configuration normalization & parameter extraction
│   │   │   ├── compliance_engine.py # Standards evaluation & summary builders
│   │   │   └── risk_engine.py       # Severity weighting & security score calculations
│   │   │
│   │   ├── rules/                   # Compliance Standards & Knowledge Base
│   │   │   ├── __init__.py
│   │   │   ├── compliance_rules.py  # CIS, NIST, STIG, ISO rule definitions
│   │   │   └── learned_rules.py     # Dynamic learning engine & similarity matcher
│   │   │
│   │   └── services/                # Specialized Application Services
│   │       ├── __init__.py
│   │       └── report_generator.py  # ReportLab PDF generator service
│   │
│   ├── data/                        # Persistent JSON storage
│   │   └── learned_mappings.json    # Learned command mappings database
│   │
│   ├── main.py                      # Backward-compatible entrypoint shim
│   └── requirements.txt             # Backend dependencies
│
├── frontend/
│   └── index.html                   # Cyberpunk / Security Dashboard SPA
│
├── sample_configs/                  # Test network device configurations
│   ├── cisco_router.txt
│   ├── learn.txt
│   ├── paloalto_test.txt
│   └── unknown_device.txt
│
├── tests/                           # Comprehensive Pytest Test Suite
│   ├── __init__.py
│   ├── conftest.py                  # Pytest fixtures & TestClient setup
│   ├── test_vendor_detection.py     # Vendor detection test suite
│   ├── test_normalization.py        # Parameter extraction & normalizer tests
│   ├── test_compliance.py           # Framework evaluation tests
│   ├── test_risk_scoring.py         # Risk & security score tests
│   ├── test_learning.py             # Dynamic training & similarity tests
│   ├── test_report_generator.py     # PDF generation tests
│   └── test_api_endpoints.py        # FastAPI integration tests
│
├── docs/                            # Architectural Documentation
│   └── architecture.md              # Deep-dive architecture reference
│
└── reports/                         # Output folder for generated PDF reports (.gitignored)
```

---

## 🚀 Quick Start

### 1. Prerequisites
* Python 3.10+ (tested on Python 3.13)
* Any modern web browser (Chrome, Edge, Firefox, Safari)

### 2. Setup Virtual Environment & Install Dependencies

```bash
# Clone or navigate to the project directory
cd NetSentinel-AI

# Create virtual environment
python -m venv backend/venv

# Activate virtual environment
# On Windows (PowerShell/CMD):
backend\venv\Scripts\activate
# On Linux / macOS:
source backend/venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Environment (Optional)

Copy the `.env.example` template:
```bash
cp .env.example .env
```

Available environment variables:
* `HOST`: Server bind address (default: `127.0.0.1`)
* `PORT`: Server port (default: `8000`)
* `DEBUG`: Debug mode toggle (default: `false`)
* `RELOAD`: Auto-reload on code change (default: `true`)
* `CORS_ORIGINS`: Allowed origins (default: `*`)

### 4. Start the Application

You can start the backend server using the root runner:
```bash
python run.py
```

Or directly via Uvicorn:
```bash
python -m uvicorn backend.app.main:app --reload --host 127.0.0.1 --port 8000
```

The API will be live at:
* **API Home**: `http://127.0.0.1:8000/`
* **Interactive Docs (Swagger UI)**: `http://127.0.0.1:8000/docs`
* **Alternative Docs (ReDoc)**: `http://127.0.0.1:8000/redoc`

### 5. Launch the Frontend

Open `frontend/index.html` directly in your browser or serve it using any static server:
```bash
# Python simple HTTP server (optional):
python -m http.server 3000 --directory frontend
```
Then visit `http://127.0.0.1:3000` in your browser.

---

## 📡 API Reference

### System & Health Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Service health status and welcome message |
| `GET` | `/health` | Application status, version, and knowledge base stats |
| `GET` | `/model` | Standardized Security Baseline Model definitions & categories |

### Analysis Endpoints

| Method | Endpoint | Request Body | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/analyze` | `file: UploadFile`<br>`framework: str (default="CIS")` | Runs multi-stage analysis pipeline and returns full JSON analysis |
| `POST` | `/report` | `file: UploadFile`<br>`framework: str (default="CIS")` | Runs analysis and returns downloadable PDF executive report |

### Dynamic Learning Endpoints

| Method | Endpoint | Request Body / Parameters | Description |
| :--- | :--- | :--- | :--- |
| `POST` | `/train` | `command: str`<br>`category: str`<br>`parameter: str`<br>`value: str`<br>`severity: str (optional)` | Registers a new vendor command syntax mapping |
| `GET` | `/learned` | *None* | Retrieves all active learned mappings |
| `GET` | `/learning/stats` | *None* | Returns category & parameter learning distribution |

---

## 🧪 Running Automated Tests

Run the full pytest test suite across unit, domain, and API integration tests:

```bash
# Run all tests
pytest

# Run tests with verbose output
pytest -v

# Run with test coverage (optional)
pytest --cov=backend/app tests/
```

All 27 automated tests cover:
- Multi-vendor detection rules
- Value conversion & device metadata extraction
- Normalization & Security Baseline Model parameter generation
- Compliance evaluation against CIS, NIST, STIG, ISO 27001
- Risk scoring & severity weighting math
- Dynamic rule learning & token Jaccard similarity matching
- PDF report generation and binary validity
- Full FastAPI HTTP endpoint responses and multipart uploads

---

## 🛡️ Security & Best Practices

* **No Hardcoded Secrets**: Secrets and configurations are isolated via `.env` / `backend/app/config.py`.
* **Zero Host-Dependent Paths**: All file and report paths are resolved dynamically using `pathlib.Path`.
* **Safe Error Handling**: Decodes inputs defensively with error fallback handling.
* **Defensive Rule Matching**: Exact matches are prioritized before falling back to token-similarity scoring with high threshold (0.75).
* **Git Cleanliness**: Generated PDF reports (`reports/*.pdf`), python caches (`__pycache__`), and virtual environments (`.venv`, `venv`) are strictly excluded via `.gitignore`.
