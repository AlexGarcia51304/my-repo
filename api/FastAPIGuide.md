# FastAPI Version of the RISBDC PII Masking Prototype Guide

## Installation

Install the required dependencies:

```bash
pip install fastapi uvicorn python-multipart python-docx PyPDF2 pymupdf pandas presidio-analyzer openpyxl xlrd
```

---

## Running the Application

Start the FastAPI server:

```bash
uvicorn crm_masker_api:app --reload
```

> **Note:** `crm_masker_api` is the name of the Python file containing the FastAPI application. Replace it with your filename if it is different.

Once the server starts, open the automatically generated API documentation in your browser:

```text
http://localhost:8000/docs
```

---

## Live Reloading

FastAPI automatically reloads the application whenever the source code changes.

Simply:

1. Save the file (`Cmd + S` on macOS or `Ctrl + S` on Windows/Linux).
2. Refresh the browser.

Your changes will be reflected immediately without restarting the server.

---

# Using the Web Application

Access the application at:

```text
http://localhost:8000/docs
```

The interactive Swagger UI provides several endpoints for masking files and generating PII reports.

## General Usage

For every endpoint:

1. Expand the endpoint by clicking the arrow on the right.
2. Click **Try it out**.
3. Provide any required input (such as uploading a file).
4. Click **Execute**.
5. Review the generated response.

If you need to clear your inputs before executing, click **Reset**.

> **Tip:** After you're finished using an endpoint, click **Cancel** to exit editing mode.

## Supported File Types

Most endpoints require uploading one of the supported file types. 

The FastAPI application supports the following file formats:

- CSV (`.csv`)
- Excel (`.xlsx`, `.xls`)
- JSON (`.json`)
- Text (`.txt`)
- PDF (`.pdf`)
- Microsoft Word (`.docx`)
- XML (`.xml`)
- Markdown (`.md`)

---

# Available Endpoints

## GET /

### Purpose

Checks whether the web application is running correctly.

### How to Use

1. Expand **GET /**.
2. Click **Try it out**.
3. Click **Execute**.

### Expected Response

The response body should display:

```json
{
  "status": "ok"
}
```

A successful response confirms that the API is running properly.

---

## GET / preset

### Purpose

Lists every available filter preset and which entity types each one masks. "all" (the default) masks everything; other presets narrow it down. For example, "financial" only masks SSNs, credit cards, EINs, and SBA loan numbers.

### How to Use

1. Open it up, click "Try Out", then "Execute"
2. The Response Body will show each preset name next to the entity types it covers
3. Use these names in the "preset" field on the other endpoints below

## POST /mask

### Purpose

Masks all PII from any uploaded file, as long as it is a supported file type. Each unique value gets its own numbered tag (e.g. "John Smith" becomes <PERSON_1>) that stays consistent everywhere that value appears in the file, so different people, addresses, etc. remain distinguishable from each other in the masked output.

### How to Use

1. Expand **POST /mask**.
2. Click **Try it out**.
3. Select a supported file using **Choose File**.
4. Under "preset," you can optionally type the name of a filter preset (see GET /presets for options) to only mask certain types of PII. Leave it as "all" to mask everything, same as before.
5. Click **Execute**.

### Result

Under **Response Body**, a **Download File** link will appear.

Downloading the file provides a masked copy of the uploaded document with detected PII replaced.

---

## POST /mask/report

### Purpose

Masks the uploaded file **and** generates a detailed PII detection report.

### How to Use

1. Expand **POST /mask/report**.
2. Click **Try it out**.
3. Upload a supported file.
4. Click **Execute**.

### Result

The response includes a downloadable ZIP archive containing:

- The masked version of the uploaded file
- A JSON PII report

The PII report includes:

- Total PII detected
- Total PII masked
- Counts by entity type
- Percentage represented by each entity type
- Which filter preset was used

---

## POST /report

### Purpose

Generates a PII detection report without returning a masked file.

### How to Use

1. Expand **POST /report**.
2. Click **Try it out**.
3. Upload a supported file.
4. Click **Execute**.

### Result

The response body contains a JSON report including:

- Total PII detected
- Total PII masked
- Counts by entity type
- Percentage represented by each entity type
- Which filter preset was used

To save the report, click **Download** in the lower-right corner of the Response Body.
