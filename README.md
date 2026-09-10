# RISBDC PII Masking Engine

An automated Personally Identifiable Information (PII) redaction and masking pipeline designed for the **Rhode Island Small Business Development Center (RISBDC)** AI integration project.

---

### Overview

Security and client data privacy are non-negotiable priorities for the RISBDC project. RISBDC strictly prohibits sharing any client PII externally. Powered by **Microsoft Presidio** and custom NLP recognizers, this module automatically detects, redacts, and masks sensitive information across multi-format CRM exports, documents, and transcripts before any context is passed downstream to AI models or vector databases.

---

### Security & Policy Context

* **Non-Negotiable PII Redaction:** External sharing of unmasked PII is strictly prohibited.
* **Internal Data Protocols:** Even for internal brainstorming or tool use, unmasked client data requires signed data release forms and strict access controls.
* **Zero-Trust AI Input:** Raw datasets pulled from specialized SBDC CRMs must be stripped of PII prior to vector embedding, automated note generation, or draft response generation.

---

### Key Features & Capabilities

* **Presidio & Custom Recognizers:** Detects standard PII along with custom SBDC/RI entities:
  * **SBDC & Legal:** SBA Loan Numbers, Client IDs, EINs, SSNs.
  * **Location-Specific:** Rhode Island City Names, Street Addresses, PO Boxes, ZIP Codes.
  * **Standard PII:** Full Names, Phone Numbers, Emails, Credit Cards, URLs, IP Addresses, Dates.
* **Multi-Format Document Support:** Automatically batch-processes `.csv`, `.xlsx`/`.xls`, `.json`, `.txt`, `.pdf`, `.docx`, `.xml`, and `.md`.
* **Smart Redaction Handling:** 
  * Replaces text with standardized tokens (e.g., `[PERSON]`, `[SBA_LOAN_NUMBER]`).
  * Applies **visual black-box masking** (██████████) for PDF documents.
  * Retains document structure/formatting for `.docx` files.
* **Audit & Analytics Reporting:** Generates an end-of-run terminal report detailing total PII detected, entity breakdown percentages, and file processing status.

---

### Tech Stack & Dependencies

* **Language:** Python 3.x
* **Core PII Engine:** `presidio-analyzer`, `presidio-anonymizer`
* **NLP Model:** `spacy` (`en_core_web_lg`)
* **Data & File Handlers:** `pandas`, `python-docx`, `PyPDF2`, `openpyxl`, `xlrd`

---

### Setup & Usage

This repository contains two implementations:

* **[Standalone Script (`script/`)]:** For running local batch masking directly from your IDE or command line.
* **[FastAPI Web Service (`api/`)]:** For deploying the masking engine as an interactive web app and REST API.

For detailed setup and run instructions, refer to the guides inside each respective folder.

### Data Flow & File Output

```text
masking/
├── crm_masker.py                <-- Main Masking Script
├── clients.csv                  <-- Raw Input
── Masked_Output/                <-- Folder containing all masked outputs (Auto-Generated)
    └── masked_crm_example.csv   <-- Masked Output (Auto-Generated)
