# NetSentinel AI — Architectural Reference

## Overview

NetSentinel AI is designed around a decoupled, domain-driven architecture that separates configuration normalization, compliance assessment, risk computation, dynamic learning, and reporting into isolated, testable modules.

---

## Architecture Diagram

```text
[ Network Config (.txt) ]
          │
          ▼
   [ Vendor Detector ]
          │
          ├─► Detected Vendor (Cisco, Juniper, Fortinet, Palo Alto, Arista, SONiC, Unknown)
          │
          ▼
   [ Metadata Extractor ]
          │
          ├─► Hostname, Model, Version, Serial, Interfaces
          │
          ▼
   [ Normalization Engine ] ◄─── [ Dynamic Learned Rules (Jaccard Similarity >= 0.75) ]
          │
          ├─► Security Baseline Model (Standardized Parameters & Controls)
          │
          ▼
   [ Compliance Evaluator ] ◄─── [ Compliance Standards (CIS, NIST, STIG, ISO 27001) ]
          │
          ├─► Control Statuses (PASS / FAIL / UNKNOWN)
          │
          ▼
   [ Risk & Scoring Engine ]
          │
          ├─► Severity Weighting (CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0)
          ├─► Overall Security Score (0–100%)
          ├─► Cross-Framework Summary
          │
          ├───► [ FastAPI JSON Response ]
          └───► [ ReportLab PDF Generator Service ]
```

---

## Module Breakdown

### 1. `backend/app/config.py`
Centralizes all runtime configuration:
* Environment variable loading (`HOST`, `PORT`, `DEBUG`, `RELOAD`, `CORS_ORIGINS`).
* Dynamic path resolution relative to project root (`BASE_DIR`, `DATA_DIR`, `REPORTS_DIR`).

### 2. `backend/app/core/vendor_detector.py`
Inspects raw configuration patterns to identify network vendors based on characteristic command syntax, banner markers, and hierarchy keywords.

### 3. `backend/app/core/normalizer.py`
Translates vendor-specific syntax into vendor-neutral parameter values:
* Converts strings to Python primitives (`bool`, `int`, `float`, `str`).
* Extracts device identification metadata.
* Matches built-in security patterns across administrative access, encryption, authentication, audit logging, NTP, SNMP, AAA, and access control.
* Integrates dynamic learned mappings for unrecognized commands.
* Tracks unrecognized commands in the `unknown_configuration_queue` for administrator training.

### 4. `backend/app/rules/compliance_rules.py`
Declarative standards catalog mapping compliance requirements to expected Security Baseline Model parameters across:
* **CIS** (Center for Internet Security)
* **NIST** (SP 800-53 Access Control, Audit, Configuration Management)
* **STIG** (DISA Security Technical Implementation Guide)
* **ISO** (ISO/IEC 27001 Controls A.05, A.08, A.08-LOG, A.08-NET, A.08-CRYPT)

### 5. `backend/app/rules/learned_rules.py`
Provides on-the-fly learning capabilities:
* Persists custom syntax mappings to `backend/data/learned_mappings.json`.
* Implements token-level Jaccard similarity (`command_similarity`) with whitespace and case normalization.
* Employs a strict similarity threshold (`>= 0.75`) to avoid false positive classification.

### 6. `backend/app/core/risk_engine.py`
Calculates severity-weighted compliance metrics:
* Weights: `CRITICAL` (10), `HIGH` (7), `MEDIUM` (4), `LOW` (1), `INFO` (0).
* Security Score: Weighted percentage of passing controls (`(weighted_pass / weighted_total) * 100`).
* Threat Level: Assigned hierarchically based on the highest failing severity.

### 7. `backend/app/services/report_generator.py`
Constructs multi-page executive security audit reports using ReportLab Platypus:
* Styled cover headers with timestamping and device information.
* Executive summary table with security score and risk level.
* Hardware & device identification specs.
* Detailed control findings table with severity and remediation advice.
* Cross-framework evaluation summary matrix.
* Risk metrics and failed control counts.
* Unknown command training queue.
* AI learning utilization statistics.

### 8. `backend/app/api/`
Modular FastAPI APIRouters:
* `routes_system.py`: `/`, `/health`, `/model`
* `routes_learning.py`: `/train`, `/learned`, `/learning/stats`
* `routes_analyze.py`: `/analyze`, `/report`
