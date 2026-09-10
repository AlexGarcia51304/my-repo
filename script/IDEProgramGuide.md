# RISBDC PII Masking Prototype Guide (Version 8)

________________________________________________________________________________________________________________________________________________________________

## Overview

This prototype automatically detects and masks Personally Identifiable Information (PII) from client documents, notes, CRM exports, and other supported files using Microsoft Presidio and custom RISBDC recognizers.  
The primary objective is to ensure that sensitive client information is removed before any AI processing occurs, in line with RISBDC data security requirements.
Examples of information that may be masked include:

- Names
- Email Addresses
- Phone Numbers
- Street Addresses
- PO Boxes
- ZIP Codes
- Credit Card Numbers
- Social Security Numbers (SSNs)
- Employer Identification Numbers (EINs)
- SBA Loan Numbers
- Client IDs
- Rhode Island City Names
- URLs
- IP Addresses
- Dates
- Other PII recognized by Microsoft Presidio

Many different file types can be masked. These file types that are supported in this masking program are:

- Comma Separated Values (.csv)
- Excel (.xlsx & .xls)
- JSON (.json)
- Text (.txt)
- PDF (.pdf)
- Microsoft Word (.docx)
- XML (.xml)
- Markdown (.md)

________________________________________________________________________________________________________________________________________________________________

## 1. Save the Script

The folder I have my files stored in is called ‘masking,’ but yours may differ.  
Save the script file as **crm_masker.py** and place it in a project folder:

**masking/**  
**├── crm_masker.py**		← contains the program that masks all PII  
**├── presets.json**		← (optional) defines custom filter presets/groups  
**└── crm_example.csv**	← an example csv file, the name of the file may differ depending on what you titled it (can be many different file types, this is just an example)

After running the program, a second file will appear automatically:

**masking/**  
**├── crm_masker.py**  
**├── presets.json**  
**├── crm_example.csv**  
**└── Masked_Output/**	← this is generated when you run the script, storing all masked files in one location  
**    └── masked_crm_example.csv**	← the name of your masked file(s), which is based on what the original file is named  
**    └── masking_log.txt**	← a text file that contains the report that is also printed in the terminal

________________________________________________________________________________________________________________________________________________________________

## 2. Opening the Project

Open the folder in any Python IDE (Visual Studios Code, Zed, PyCharm, etc.)  
Example: File → Open Folder → masking

Make sure the directory of the terminal is **masking %**, or whatever the name of the folder you have the files in is called.

________________________________________________________________________________________________________________________________________________________________

## 3. Install Dependencies

Run these two commands in the terminal one at a time:

**Step 1 — Install Python packages:**

**pip install pandas presidio-analyzer presidio-anonymizer spacy openai python-dotenv python-docx PyPDF2 openpyxl xlrd PyMuPDF**

**Step 2 — Install the spaCy language model:**

**python -m spacy download en_core_web_lg**

________________________________________________________________________________________________________________________________________________________________

## 4. Running the Program using your CRM Data

This helps guide you on how to mask your supported files and run the program:

1. Upload your supported file(s) into the same folder you have the crm_masker.py program.

Example of what the folder’s contents might look like:

**masking/**  
**├── crm_masker.py**  
**├── presets.json**  
**├── notes.txt**  
**├── application.pdf**  
**├── inquiries.xlsx**  
**├── customer_data.json**  
**├── client_report.docx**  
**├── config.xml**  
**├── README.md**  
**└── clients.csv**

2. Run the program again using **`python crm_masker.py`** in the terminal.

3. Choosing what gets masked (optional):

   1. By default, the program masks every type of PII it finds. You can narrow this down using a filter preset:
      1. **`python crm_masker.py --preset financial`** — only mask financial identifiers (SSNs, credit cards, EINs, SBA loan numbers)
      2. **`python crm_masker.py --preset contact`** — only mask contact info (phone numbers, addresses, locations, ZIP codes, emails)
      3. **`python crm_masker.py --preset identity`** — only mask names and client IDs
      4. **`python crm_masker.py --list-presets`** — see all available presets and what each one masks
   2. If no **`--preset`** is given, it defaults to **all** (masks everything, same as before).
   3. To add your own custom presets, create a **presets.json** file in the same folder as **crm_masker.py**
   4. Example:
      1. `{ "my_preset": ["PERSON", "PHONE_NUMBER"] }`
   5. Then run **`python crm_masker.py --preset my_preset`**. If you want to keep this config file somewhere else or under a different name, use **`--presets-file path/to/your_file.json`**

4. All supported files you added will each be put into separate masked versions of their original, visible in your folder. They will each begin with: **masked_**. An example of that is that **clients.csv** will turn into **masked_clients.csv**. It will appear in the folder like this:

**masking/**  
**├── crm_masker.py**  
**├── presets.json**  
**├── notes.txt**  
**├── application.pdf**  
**├── inquiries.xlsx**  
**├── customer_data.json**  
**├── client_report.docx**  
**├── config.xml**  
**├── README.md**  
**├── clients.csv**  
**└── Masked_Output/**  
**    ├── masked_notes.txt**  
**    ├── masked_application.pdf**  
**    ├── masked_inquiries.xlsx**  
**    ├── masked_customer_data.json**  
**    ├── masked_client_report.docx**  
**    ├── masked_config.xml**  
**    ├── masked_README.md**  
**    └── masked_clients.csv**  
**    └── masking_log.txt**

**Important things to note:**

- PDF files are masked with black boxes. This is because using the normal Microsoft Presidio masking cannot return as a pdf. Example:
  - John Smith is now masked as a numbered tag like `<PERSON_1>`. The same value gets the same tag every time it appears in that file (e.g. if "John Smith" is mentioned three times, all three become `<PERSON_1>`), while a different person becomes `<PERSON_2>`. This keeps different people, addresses, etc. distinguishable from each other in the masked output, instead of collapsing everyone into one generic `<PERSON>` tag.
  - For PDFs only, “John Smith” gets masked as ██████████
- `.xls` files after being masked are returned as `.xlsx`.

These are due to restrictions in the pandas software.

Also…

- Microsoft Word (.docx) files are saved as masked .docx files while preserving the document's original formatting where possible. PII is also masked inside tables, nested tables, headers, footers, first-page headers/footers, and even-page headers/footers.
- Every worksheet in Excel workbooks is processed automatically if in the masking folder.

________________________________________________________________________________________________________________________________________________________________

## 5. What Happens Automatically

When the program runs:

1. Every supported file in the project folder is identified.
2. Previously generated files beginning with `"masked_"` are skipped.
3. Microsoft Presidio scans the files for PII.
4. Custom recognizers scan for:
   1. Rhode Island city names
   2. Street addresses
   3. PO Boxes
   4. ZIP Codes
   5. EINs
   6. SBA Loan Numbers
   7. Client IDs
5. Overlapping PII detections are resolved before masking.
6. Only entity types included in the active filter preset are masked (default preset is `"all,"` which masks everything).
7. Sensitive information is masked.
8. A masked version of each supported file is generated inside the **Masked_Output** folder.
9. PII counts are recorded for each individual file.
10. Each successfully processed file receives a Low, Medium, or High risk level.
11. Processing time is recorded for each file.
12. A total PII detection report is displayed.
13. A file processing summary is displayed.
14. A **masking_log.txt** report is automatically created inside the **Masked_Output** folder.

________________________________________________________________________________________________________________________________________________________________

## 6. PII Detection Report

After processing, the program generates a report showing:

- Total PII detected
- Total PII masked
- Counts by entity type
- Percentage represented by each entity type

**File Risk Levels:**  
Each successfully processed file is assigned a risk level based on the PII detected within that file.

- HIGH:
  - Contains a US SSN or credit card number
  - OR contains 30 or more total PII detections
- MEDIUM:
  - Contains 10–29 PII detections
- LOW:
  - Contains fewer than 10 PII detections

These risk levels are intended to help prioritize manual review and should not be interpreted as a guarantee that a file is safe.

**Processing Time:**  
Processing Time is now recorded in two ways:

- By individual file: **Processing Time: 1.24 seconds**
- OR all files combined: **Total Runtime: 8.72 seconds**

Example of what appears in the terminal:

**RISBDC PII Masking Report**  
**========================================**

**Generated: 2026-08-17 15:55:49.509582**

**Filter Preset: all**

**Successful Files: 1**  
**Unsupported Files: 0**  
**Failed Files: 0**

**Total Runtime: 0.71 seconds**

**Total PII Masked: 48**

**Per File Summary**  
**-------------------------**

**sample_text.txt**  
**   CLIENT_ID: 5**  
**   PERSON: 5**  
**   PHONE_NUMBER: 5**  
**   EMAIL_ADDRESS: 5**  
**   US_ADDRESS: 5**  
**   LOCATION: 5**  
**   ZIP_CODE: 5**  
**   EIN: 5**  
**   SBA_LOAN_NUMBER: 5**  
**   US_SSN: 2**  
**   CREDIT_CARD: 1**  
**Risk Level: HIGH**

**Masking Log:**  
After processing, the program automatically creates:

**Masked_Output/masking_log.txt**

The log contains:

- Date and time the masking session was generated
- Number of successful files
- Number of unsupported files
- Number of failed files
- Total processing time
- Total PII masked
- PII counts for each processed file
- Risk level for each processed file

________________________________________________________________________________________________________________________________________________________________

## 7. Important Notes

Human Review is RECOMMENDED:

Microsoft Presidio is extremely effective at identifying PII, but it is far from perfect.  
Occasionally:

- Some PII may not be detected
- Some values may be classified as a different entity type
- Complex notes may require manual review

**Current Project Purpose:**

This prototype demonstrates:

- Automated PII masking
- Secure CRM data sanitization
- A foundation for future RISBDC integrations with CRM systems and OpenAI-powered knowledge management tools
