# PDF Forensic Analyzer

## Overview

This application performs a multi-layered forensic analysis on uploaded PDF documents to detect potential alterations, inconsistencies, or suspicious characteristics. It is designed to provide insights even when no prior version of the PDF is available for comparison and without prior knowledge of any signers. The analysis combines technical scrutiny of the PDF's structure and metadata with AI-powered content review.

The application is built with Python and Streamlit, providing an interactive web interface for users to upload PDFs and view analysis results.

## Core Logic: Multi-Layered Analysis

The analysis is divided into two main layers, each examining different facets of the PDF:

### Layer 1: Technical & Structural Analysis

This layer focuses on the technical and structural aspects of the PDF file itself. It uses libraries like `pikepdf` and `pyHanko` to perform the following checks:

1.  **PDF Parsing & Basic Information**:
    *   Attempts to open and parse the PDF using `pikepdf`.
    *   Extracts basic file information like name and size.

2.  **Structural Integrity Check**:
    *   Utilizes `pdf.check()` from `pikepdf` (which leverages `qpdf`'s checking capabilities) to identify low-level structural issues or syntax errors within the PDF. This can reveal if the PDF is malformed.

3.  **Incremental Updates (Save History)**:
    *   Determines if the PDF has been saved with incremental updates. PDFs can be saved by appending changes, which creates a revision history within the file. The presence of objects with generation numbers greater than 0 (accessed via `obj.objgen[1]`) indicates such a history, which can sometimes suggest modifications after the initial creation.

4.  **Digital Signature Validation**:
    *   Leverages `pyHanko` to detect and analyze any digital signatures embedded in the PDF.
    *   **Detection**: Checks if the PDF contains any signature fields.
    *   **Integrity**: For each signature found, it validates its cryptographic integrity (i.e., if the signed content has been tampered with since signing).
    *   **Signer Information**: Extracts details from the signer's certificate, such as Common Name, full distinguished name, issuer information, and the signing time (if available in the signature).
    *   **Coverage**: Reports if the signature covers the entire document or only parts of it.
    *   **Status**: Provides a summary status for each signature (e.g., "Not Signed," "Signed - Integrity OK, Trust Unverified," "Signed - Integrity Failed"). Full trust validation typically requires a pre-configured trust anchor/store, so the primary focus here is on cryptographic integrity.

5.  **Metadata Extraction**:
    *   Extracts standard metadata from the PDF's Document Information Directory (`pdf.docinfo`) using `pikepdf`. This includes fields like `CreationDate`, `ModDate`, `Creator`, `Producer`.
    *   Attempts to parse PDF-specific date formats into a standard ISO format.
    *   Checks for the presence of XMP (Extensible Metadata Platform) metadata, which can store richer metadata.
    *   Discrepancies (e.g., `ModDate` significantly later than `CreationDate` without a clear history of incremental updates) can be points of interest.

### Layer 2: LLM-Powered Content Anomaly Detection

This layer focuses on the semantic content of the PDF, using a Large Language Model (LLM) to identify potential anomalies in the text.

1.  **Text Extraction**:
    *   The textual content of the PDF is extracted using the `MarkItDown` library, which converts PDF content to Markdown format.

2.  **LLM Analysis (Forensic Document Analyst)**:
    *   The extracted text is then submitted to an LLM (e.g., Grok 3, via the x.ai API endpoint).
    *   The LLM is prompted to act as a "forensic document analyst." Its task is to review the text for:
        *   Internal inconsistencies or contradictions.
        *   Suspicious statements, claims, or unusual language.
        *   Abrupt or unexplained changes in tone, style, or terminology.
        *   Hints of unusual formatting or structure (based on the Markdown representation).
        *   Potential misinformation or deceptive language patterns.
    *   The LLM is instructed to return its findings in a structured JSON format, including:
        *   `overall_assessment`: A brief summary of its findings.
        *   `detected_anomalies`: A list of specific anomalies, each detailed with a `type`, `description`, and a relevant `excerpt` from the text.
        *   `confidence_score`: A numerical score (0.0 to 1.0) indicating the LLM's confidence in its assessment.

## Technologies Used

*   **Python**: Core programming language.
*   **Streamlit**: For creating the interactive web user interface.
*   **Pikepdf**: A Python library for reading, manipulating, and writing PDF files, built on the QPDF C++ library. Used for opening PDFs, structural checks, metadata extraction, and incremental update detection.
*   **pyHanko**: A Python SDK for digitally signing PDF documents and validating signatures. Used for the digital signature analysis.
*   **MarkItDown**: A Python library for converting various document formats (including PDF) to Markdown. Used for text extraction.
*   **Requests**: For making HTTP requests to the LLM API.
*   **LLM API (e.g., Grok 3 via x.ai)**: For the content anomaly detection.

## Code Structure (`app.py`)

The main application logic is contained within `app.py`.

*   **Imports & Setup**: Imports necessary libraries and performs initial Streamlit page configuration.
*   **Sidebar Configuration**: Code for setting up the sidebar inputs (API key, reference hash).
*   **Helper Functions**: 
    *   `format_bytes(size)`: Formats file sizes into human-readable units.
*   **`run_first_layer(pdf_bytes: bytes, reference_hash: str | None = None) -> dict`**:
    *   Takes the PDF content as bytes and an optional reference hash.
    *   Performs all Layer 1 analyses (structural check, hash comparison if reference is given, incremental update detection, signature validation, metadata extraction).
    *   Returns a dictionary containing the results of these checks.
*   **`run_second_layer(pdf_bytes: bytes) -> dict`**:
    *   Takes the PDF content as bytes.
    *   Extracts text using `MarkItDown`.
    *   Constructs a prompt for the LLM and sends the extracted text for analysis.
    *   Parses the LLM's JSON response.
    *   Returns a dictionary containing the LLM's analysis (overall assessment, detected anomalies, confidence score, and any errors).
*   **`main()` Function**:
    *   Sets up the main Streamlit interface (title, file uploader).
    *   Handles the PDF file upload.
    *   Once a file is uploaded, it calls `run_first_layer` and `run_second_layer` to perform the analyses.
    *   Displays the results from both layers in a structured and user-friendly manner using Streamlit components (e.g., `st.json`, `st.write`, `st.expander`).
    *   Provides an option to download the combined analysis results as a JSON report.

## File Structure

*   `app.py`: The main Streamlit application script.
*   `requirements.txt`: Lists the Python dependencies required for the project.
*   `Procfile`: (Heroku specific) Declares the process types for a Heroku application (e.g., `web: streamlit run app.py`).
*   `runtime.txt`: (Heroku specific) Specifies the Python runtime version to be used on Heroku.
*   `Aptfile`: (Heroku specific) Lists system-level packages (APT packages) to be installed on Heroku, often for dependencies of Python libraries (e.g., `qpdf` might be listed here if not bundled sufficiently by `pikepdf` wheels for Heroku's environment).
*   `README.md`: This file.

## Setup and Running the Application

1.  **Clone the Repository** (if applicable):
    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```

2.  **Create a Virtual Environment** (recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set Up API Key**: 
    The application requires an API key for the LLM service (e.g., Grok via x.ai).
    *   You can set it as an environment variable named `GROK_API_KEY` (or `XAI_API_KEY` as checked in the code).
    *   Alternatively, you can enter the API key directly in the application's sidebar.

5.  **Run the Application**:
    ```bash
    streamlit run app.py
    ```
    This will start the Streamlit development server, and you can access the application in your web browser (usually at `http://localhost:8501`).

## How to Use

1.  Open the application in your web browser.
2.  **Upload a PDF file** using the file uploader.
3.  **Optional**: Enter a SHA-256 reference hash in the sidebar if you want to compare the uploaded PDF's hash against a known value.
4.  **Enter API Key**: Provide your LLM API key in the sidebar if not set as an environment variable.
5.  The application will automatically perform Layer 1 and Layer 2 analyses.
6.  **Review the Results**: 
    *   Layer 1 results (structural integrity, incremental updates, signature analysis, metadata) will be displayed.
    *   Layer 2 results (LLM content anomaly detection) will show the overall assessment, confidence, and any detected anomalies in expandable sections.
7.  **Download Report**: You can download the complete analysis (Layers 1 and 2) as a JSON file.

## Potential Future Enhancements

*   More sophisticated XMP metadata parsing and analysis.
*   Integration with certificate revocation lists (CRLs) or OCSP for more robust signature trust validation (requires network access and potentially more complex setup).
*   Allowing users to customize LLM prompts or select different analysis models.
*   Visualizations for PDF structure or content changes (if a diff feature is ever re-introduced).
*   More granular error reporting and user guidance.
