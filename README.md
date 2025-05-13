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
    *   Handles password-protected PDFs gracefully by reporting the issue rather than crashing.
    *   Extracts basic file information like name and size.

2.  **Structural Integrity Check**:
    *   Utilizes `pdf.check()` from `pikepdf` (which leverages `qpdf`'s checking capabilities) to identify low-level structural issues or syntax errors within the PDF. This can reveal if the PDF is malformed.

3.  **Incremental Updates (Save History)**:
    *   Determines if the PDF has been saved with incremental updates. PDFs can be saved by appending changes, which creates a revision history within the file. The presence of objects with generation numbers greater than 0 (now checked via `pdf.has_incremental_updates()`) indicates such a history.

4.  **Digital Signature Validation**:
    *   Leverages `pyHanko` to detect and analyze any digital signatures embedded in the PDF.
    *   **Detection**: Checks if the PDF contains any signature fields using `PdfFileReader(pdf_stream).embedded_signatures`.
    *   **Integrity**: For each signature found, it validates its cryptographic integrity.
    *   **Signer Information**: Extracts details from the signer's certificate.
    *   **Coverage**: Reports if the signature covers the entire document.
    *   **Status**: Provides a summary status for each signature.

5.  **Metadata Extraction**:
    *   Extracts standard metadata from the PDF's Document Information Directory (`pdf.docinfo`) using `pikepdf`.
    *   Employs a robust helper function (`_safe_pdf_value_to_string`) to convert various `pikepdf` object types (including `pikepdf.String`, `pikepdf.Name`, Python native `int`, `float`, `bool`, `pikepdf.Array`, `pikepdf.Dictionary`, and generic `pikepdf.Object`) to string representations, significantly reducing `ValueError` or `AttributeError` issues during extraction.
    *   This includes fields like `CreationDate`, `ModDate`, `Creator`, `Producer`.
    *   Attempts to parse PDF-specific date formats.
    *   Checks for the presence of XMP (Extensible Metadata Platform) metadata.

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
    *   The prompt instructs the LLM to consider that the document is parsed and may have errors, and to omit such parsing errors from its findings.
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
*   **OpenAI Python SDK**: Used for interacting with LLM APIs (like x.ai's Grok) that support structured outputs, especially for `grok-3`.
*   **Pydantic**: For data validation and settings management through Python type annotations. Used here to define the expected schema for the LLM's structured JSON output.
*   **LLM API (e.g., Grok 3 via x.ai)**: For the content anomaly detection.

## Code Structure (`app.py`)

The main application logic is contained within `app.py`.

*   **Imports & Setup**: Imports necessary libraries and performs initial Streamlit page configuration.
*   **Sidebar Configuration (`sidebar_config`)**: 
    *   Sets up the sidebar, including debug information for pyHanko import statuses.
    *   Provides an input field for the Xai (Grok) API Key. The key is stored in `st.session_state.grok_api_key` and managed with a dedicated widget key for robustness.
*   **Helper Functions**: 
    *   `_safe_pdf_value_to_string(pdf_obj)`: Robustly converts various `pikepdf` objects to strings, handling potential errors gracefully.
*   **`run_first_layer(pdf_bytes: bytes, reference_hash: str | None = None) -> dict`**:
    *   Takes the PDF content as bytes and an optional reference hash.
    *   Initializes `pdf = None` and uses a `try...finally` block to ensure `pdf.close()` is called safely if the PDF was opened.
    *   Includes specific error handling for `pikepdf.PasswordError` to return a user-friendly message instead of crashing.
    *   Performs all Layer 1 analyses (structural check, hash comparison if reference is given, incremental update detection, signature validation, metadata extraction using `_safe_pdf_value_to_string`).
    *   Returns a dictionary containing the results of these checks.
*   **`run_second_layer(pdf_bytes: bytes) -> dict`**:
    *   Takes the PDF content as bytes.
    *   Checks for the presence of the Xai (Grok) API key in `st.session_state.grok_api_key`; skips analysis if not found.
    *   Extracts text using `MarkItDown`.
    *   Defines Pydantic models (`AnomalyDetail`, `ContentAnalysis`) to specify the desired JSON structure for the LLM's response.
    *   Initializes an `OpenAI` client configured for the x.ai API endpoint.
    *   Constructs a system prompt for the LLM, instructing it to act as a forensic document analyst and to be mindful of parsing errors in the extracted text.
    *   Calls the LLM (specifically `grok-3`) using `client.beta.chat.completions.parse()`, passing the Pydantic model in the `response_format` argument.
    *   The LLM's response is automatically parsed into an instance of the `ContentAnalysis` Pydantic model.
    *   Converts the Pydantic model instance to a dictionary using `.model_dump()` for consistent storage in the results.
    *   Includes robust error handling for text extraction and the LLM API call, returning structured error/skipped messages.
*   **`main()` Function**: 
    *   Sets up the main Streamlit interface (title, file uploader).
    *   Calls `sidebar_config()`.
    *   Handles the PDF file upload.
    *   Once a file is uploaded, it calls `run_first_layer` and `run_second_layer`.
    *   Displays the results from both layers, interpreting the structured dictionary responses (including 'status': 'skipped' or 'status': 'error' messages from Layer 2).
    *   Provides an option to download the combined analysis results as a JSON report.

## File Structure

*   `app.py`: The main Streamlit application script.
*   `requirements.txt`: Lists the Python dependencies required for the project.
*   `Procfile`: (Heroku specific) Declares the process types for a Heroku application.
*   `runtime.txt`: (Heroku specific) Specifies the Python runtime version.
*   `Aptfile`: (Heroku specific) Lists system-level packages (APT packages).
*   `.streamlit/config.toml`: Streamlit configuration file (e.g., for server settings like CORS, XSRF).
*   `README.md`: This file.

## Setup and Running the Application

1.  **Clone the Repository** (if applicable).
2.  **Create a Virtual Environment** (recommended).
3.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```
4.  **Set Up API Key**: 
    The application requires an API key for the LLM service (e.g., Grok via x.ai). You can enter the API key directly in the application's sidebar. The key is stored in Streamlit's session state.
5.  **Streamlit Configuration** (Optional but recommended):
    *   To avoid potential startup warnings related to server settings, create a file `.streamlit/config.toml` with the following content:
      ```toml
      [server]
      enableCORS = true
      enableXsrfProtection = true
      ```
6.  **Run the Application**:
    ```bash
    streamlit run app.py
    ```
    Access the application in your web browser (usually at `http://localhost:8501`).

## How to Use

1.  Open the application in your web browser.
2.  **Upload a PDF file**.
3.  **Enter API Key**: Provide your Xai (Grok) API key in the sidebar.
4.  The application will automatically perform Layer 1 and Layer 2 analyses.
5.  **Review the Results**.
6.  **Download Report**: You can download the complete analysis as a JSON file.

## Potential Future Enhancements

*   More sophisticated XMP metadata parsing and analysis.
*   Integration with certificate revocation lists (CRLs) or OCSP for more robust signature trust validation.
*   Allowing users to customize LLM prompts or select different analysis models.
*   Visualizations for PDF structure.
*   More granular error reporting and user guidance.
