# ---------------------------------------------
# app.py  (Streamlit Web App for PDF Integrity)
# ---------------------------------------------
"""
PDF Integrity Checker — two‑layer tamper detection
=================================================

**Layer 1 – Cryptographic / structural**
  • SHA‑256 mismatch vs optional reference hash  
  • Incremental‑save detection (pikepdf)  
  • Digital‑signature validation (pyHanko)  

**Layer 2 – Semantic diff**  
The earliest and latest PDF revisions are converted to Markdown with
**Microsoft MarkItDown**, then a *single* Grok 3 call returns
`{"altered": true|false}`.

Changes in this version
-----------------------
* Adds a **sidebar API‑key field** (`Grok 3 API key`) stored in
  `st.session_state` for the current browser session – no need for an
  environment variable on Heroku.
* Provides an **LLM‑ready description** (`tool_description`) that users can
  copy‑paste when they need to tell another LLM what this app does.

Deployment reminder (Heroku)
----------------------------
```
web: streamlit run app.py --server.port=$PORT --server.enableCORS=false
```

`requirements.txt` additions remain identical to the previous version.
"""

import hashlib
import io
import json
import os
from pathlib import Path
from datetime import datetime

import pikepdf
import requests
import streamlit as st
from markitdown import MarkItDown

# Lazy import of pyHanko (optional dependency)
try:
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign import validation
    from pyhanko.sign.validation import SignatureCoverageLevel, ValidatedSuccessfully, ValidationInfo
    from pyhanko.sign.general import SignedData
except ImportError:
    validate_pdf_signature = None

# Suppress Boto3 warning if not used directly but is a deep dependency of markitdown
try:
    import boto3
    from botocore.exceptions import NoCredentialsError, PartialCredentialsError
except ImportError:
    pass # Boto3 not installed, or markitdown variant without S3 used

# ------------------------------------------------------------------
# Sidebar — runtime configuration
# ------------------------------------------------------------------

def sidebar_config():
    st.sidebar.header("⚙️ Configuration")
    api_key = st.sidebar.text_input(
        "Grok 3 API key (x.ai)",
        type="password",
        key="xai_key",
        placeholder="sk‑...",
    )
    reference_hash = st.sidebar.text_input("Known good SHA‑256 (optional)")

    # Store key in session_state for easy access downstream.
    if api_key:
        st.session_state["XAI_API_KEY"] = api_key
    return reference_hash

# ------------------------------------------------------------------
# Helper — First layer: cryptographic / structural integrity
# ------------------------------------------------------------------

def run_first_layer(pdf_bytes: bytes, reference_hash: str | None = None) -> dict:
    results: dict[str, str] = {}

    # 0 — PDF Structural Integrity Check (pikepdf.check())
    try:
        pdf = pikepdf.open(io.BytesIO(pdf_bytes))
        structural_issues = pdf.check()
        results['structural_integrity'] = {
            'issues_found': len(structural_issues) > 0,
            'details': structural_issues if structural_issues else "No structural issues found."
        }
    except Exception as e:
        results['structural_integrity'] = {
            'issues_found': True,
            'details': f"Error during structural check: {str(e)}"
        }

    # 1 — File hash (if reference is provided)
    current_hash = hashlib.sha256(pdf_bytes).hexdigest()
    if reference_hash:
        results["hash_mismatch"] = "Positive" if current_hash != reference_hash.lower() else "Negative"
    else:
        results["hash_mismatch"] = "N/A (no reference)"

    # 2 — Incremental revision check
    has_incremental_updates = False
    try:
        for obj in pdf.objects:
            if obj.objgen[1] > 0:
                has_incremental_updates = True
                break
    except Exception as e:
        results['incremental_updates_check_error'] = str(e)
    results["has_incremental_updates"] = "Positive" if has_incremental_updates else "Negative"

    # 3 — Digital Signature Validation (using pyHanko)
    signature_analysis = []
    try:
        reader = PdfFileReader(io.BytesIO(pdf_bytes))
        if not reader.embedded_signatures:
            signature_analysis.append({"status": "Not Signed"})
        else:
            for sig_field_name, sig in reader.embedded_signatures.items():
                sig_details = {"field_name": sig_field_name, "status": "Processing"}
                try:
                    val_info: ValidationInfo = validation.validate_pdf_signature(sig)
                    sig_details['status_code'] = val_info.status.name if val_info.status else "Unknown"
                    sig_details['integrity_ok'] = val_info.intact
                    sig_details['covers_entire_document'] = val_info.coverage == SignatureCoverageLevel.ENTIRE_DOCUMENT
                    sig_details['summary'] = str(val_info.summary()) # Human-readable summary
                    sig_details['is_valid'] = isinstance(val_info, ValidatedSuccessfully)

                    if val_info.signer_cert:
                        sig_details['signer_common_name'] = val_info.signer_cert.subject.get_common_name()
                        sig_details['signer_info'] = val_info.signer_cert.subject.rfc4514_string()
                        sig_details['issuer_info'] = val_info.signer_cert.issuer.rfc4514_string()
                    else:
                        sig_details['signer_common_name'] = "N/A (No signer certificate)"

                    if val_info.signing_time:
                        sig_details['signing_time'] = val_info.signing_time.isoformat()
                    else:
                        sig_details['signing_time'] = "N/A (No signing time in signature)"
                    
                    if not val_info.intact:
                        sig_details['status'] = "Signed - Integrity Failed"
                    elif val_info.intact and not val_info.trusted:
                        sig_details['status'] = "Signed - Integrity OK, Trust Unverified"
                    elif val_info.intact and val_info.trusted:
                        sig_details['status'] = "Signed - Integrity OK, Trusted"
                    else:
                        sig_details['status'] = f"Signed - {val_info.status.name if val_info.status else 'Validation Issues'}"

                except Exception as e_val:
                    sig_details['status'] = "Signed - Error During Validation"
                    sig_details['validation_error'] = str(e_val)
                signature_analysis.append(sig_details)
    except Exception as e_reader:
        signature_analysis.append({"status": "Error reading signatures", "error": str(e_reader)})
    results['signature_analysis'] = signature_analysis

    # 4 — Metadata Extraction
    metadata = {}
    try:
        docinfo = pdf.docinfo
        for key, value in docinfo.items():
            if isinstance(value, pikepdf.String) and value.startswith('D:'):
                try:
                    date_str = str(value)[2:] # Remove 'D:'
                    if 'Z' in date_str: date_str = date_str.replace('Z', '')
                    if '+' in date_str: date_str = date_str.split('+')[0]
                    if '-' in date_str: date_str = date_str.split('-')[0] 
                    date_str_core = date_str[:14]
                    dt_obj = datetime.strptime(date_str_core, "%Y%m%d%H%M%S")
                    metadata[str(key)] = dt_obj.isoformat()
                except ValueError:
                    metadata[str(key)] = str(value) 
            else:
                metadata[str(key)] = str(value)
        results['docinfo_metadata'] = metadata
    except Exception as e_meta:
        results['docinfo_metadata_error'] = str(e_meta)
    
    try:
        if pdf.xmp_metadata:
            results['xmp_metadata_present'] = True
        else:
            results['xmp_metadata_present'] = False
    except Exception as e_xmp:
        results['xmp_metadata_check_error'] = str(e_xmp)
        results['xmp_metadata_present'] = 'Error checking'

    pdf.close() 
    return results

# ------------------------------------------------------------------
# Helper — Second layer: LLM-based content anomaly detection
# ------------------------------------------------------------------

def run_second_layer(pdf_bytes: bytes) -> dict:
    """Analyze PDF text content for anomalies using an LLM."""
    md = MarkItDown()
    results = {}

    try:
        # 1. Extract text content using MarkItDown
        # Ensure MarkItDown().convert_stream expects bytes for the stream
        # If it expects a file-like object with read(), use io.BytesIO
        pdf_stream = io.BytesIO(pdf_bytes)
        extracted_text = md.convert_stream(pdf_stream)
        results['text_extraction_successful'] = True
        if not extracted_text.strip():
            results['text_extraction_successful'] = False
            results['llm_analysis'] = {
                'overall_assessment': 'No text extracted from PDF.',
                'detected_anomalies': [],
                'confidence_score': 0.0,
                'error': 'No text content could be extracted for LLM analysis.'
            }
            return results
    except Exception as e:
        results['text_extraction_successful'] = False
        results['llm_analysis'] = {
            'overall_assessment': 'Error during text extraction.',
            'detected_anomalies': [],
            'confidence_score': 0.0,
            'error': f"Failed to extract text: {str(e)}"
        }
        return results

    # 2. LLM Analysis
    api_key = st.session_state.get("XAI_API_KEY") or os.getenv("GROK_API_KEY")
    if not api_key:
        results['llm_analysis'] = {
            'overall_assessment': 'API Key missing.',
            'detected_anomalies': [],
            'confidence_score': 0.0,
            'error': 'Provide an x.ai API key in the sidebar for content analysis.'
        }
        return results

    system_prompt = (
        "You are a forensic document analyst. Your task is to review the provided text content "
        "extracted from a PDF document and identify any potential anomalies, inconsistencies, or "
        "red flags that might suggest the document has been altered, contains misleading information, "
        "or exhibits unusual characteristics. Provide your findings in a structured JSON format. "
        "The JSON should include a main key 'content_analysis' which is an object. This object should contain:"
        "- 'overall_assessment': A brief summary (e.g., 'No significant anomalies detected', 'Minor inconsistencies noted', 'Potential red flags identified')."
        "- 'detected_anomalies': A list of objects, where each object describes a specific anomaly found. Each anomaly object should have:"
        "    - 'type': A category for the anomaly (e.g., 'Inconsistency', 'Suspicious Language', 'Abrupt Tone Shift', 'Unusual Formatting/Structure Hint', 'Potential Misinformation')."
        "    - 'description': A detailed explanation of the anomaly."
        "    - 'excerpt': A relevant snippet from the text where the anomaly was observed (if applicable)."
        "- 'confidence_score': A numerical score from 0.0 to 1.0 indicating your confidence in the assessment, where 1.0 is high confidence."
        "If no anomalies are found, 'detected_anomalies' should be an empty list and 'overall_assessment' should reflect this."
    )

    payload = {
        "model": "grok-3", # Or your preferred model
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": extracted_text},
        ],
        "temperature": 0.2, # Low temperature for more factual/less creative analysis
        "max_tokens": 1500, # Adjust as needed
        "response_format": {"type": "json_object"} # Request JSON output if API supports it
    }

    try:
        resp = requests.post(
            "https://api.x.ai/v1/chat/completions", # Ensure this is the correct endpoint
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=payload,
            timeout=120, # Increased timeout for potentially longer analysis
        )
        resp.raise_for_status()
        llm_response_json = resp.json()
        
        # Expecting the LLM to return JSON directly in the 'content' of the message
        # or as the top-level response if response_format is well-supported by the model/API
        if llm_response_json.get("choices") and llm_response_json["choices"][0].get("message"): 
            content_str = llm_response_json["choices"][0]["message"].get("content")
            if content_str:
                try:
                    # The content itself should be the JSON string we asked for
                    parsed_content = json.loads(content_str)
                    # Ensure it has the 'content_analysis' key we specified in the prompt
                    if 'content_analysis' in parsed_content:
                        results['llm_analysis'] = parsed_content['content_analysis']
                    else:
                        # Fallback if the LLM didn't structure it with 'content_analysis' as the root
                        results['llm_analysis'] = {
                            'overall_assessment': 'LLM response format unexpected.',
                            'detected_anomalies': [],
                            'confidence_score': 0.0,
                            'raw_response': parsed_content,
                            'error': 'LLM did not return the expected JSON structure with content_analysis key.'
                        }
                except json.JSONDecodeError as json_e:
                    results['llm_analysis'] = {
                        'overall_assessment': 'LLM response not valid JSON.',
                        'detected_anomalies': [],
                        'confidence_score': 0.0,
                        'raw_response': content_str,
                        'error': f"Failed to parse LLM JSON response: {str(json_e)}"
                    }
            else:
                 results['llm_analysis'] = {
                    'overall_assessment': 'LLM returned empty content.',
                    'detected_anomalies': [],
                    'confidence_score': 0.0, 
                    'error': 'LLM response content was empty.'
                }
        else:
            results['llm_analysis'] = {
                'overall_assessment': 'LLM response structure unexpected.',
                'detected_anomalies': [],
                'confidence_score': 0.0, 
                'raw_response': llm_response_json, 
                'error': 'LLM response did not contain expected choices or message structure.'
            }

    except requests.exceptions.RequestException as req_e:
        results['llm_analysis'] = {
            'overall_assessment': 'API Request Error.',
            'detected_anomalies': [],
            'confidence_score': 0.0,
            'error': f"Error calling LLM API: {str(req_e)}"
        }
    except Exception as e:
        results['llm_analysis'] = {
            'overall_assessment': 'LLM Analysis Error.',
            'detected_anomalies': [],
            'confidence_score': 0.0,
            'error': f"An unexpected error occurred during LLM analysis: {str(e)}"
        }
    return results

# ------------------------------------------------------------------
# Tool‑description string (for other LLMs)
# ------------------------------------------------------------------

tool_description = """PDF Integrity Checker — Two‑Layer Tamper Detection Tool\n\nInput: A PDF file.\nProcess:\n  1. Layer 1 — cryptographic/structural checks: SHA‑256 hash compare,\n     incremental‑save detection, digital‑signature validation.\n  2. Layer 2 — semantic diff: earliest vs latest revision converted to\n     Markdown with Microsoft MarkItDown, analysed by Grok 3 for material\n     content changes.\nOutput: JSON report\n  {\n    \"layer1\": { ... Positive/Negative flags ... },\n    \"layer2\": {\n        \"changes_detected\": Positive|Negative,\n        \"grok_response\": (raw)\n    }\n  }\nPositive => indications the PDF WAS altered;\nNegative => no evidence of tampering detected.\n"""

# ------------------------------------------------------------------
# Streamlit UI
# ------------------------------------------------------------------

def main():
    st.set_page_config(page_title="PDF Integrity Checker", page_icon="🔍")
    st.title("🔍 PDF Integrity Checker (2‑Layer)")
    st.markdown("Upload a PDF and get **Positive / Negative** flags for any indication that it has been tampered with.")

    reference_hash = sidebar_config()

    st.sidebar.markdown("### 📄 Tool description for LLMs")
    st.sidebar.code(tool_description)

    uploaded = st.file_uploader("Choose a PDF", type="pdf")
    if not uploaded:
        return

    pdf_bytes = uploaded.read()

    # ---------- Layer 1 ----------
    st.subheader("🔒 Layer 1 — Cryptographic / Structural")
    l1 = run_first_layer(pdf_bytes, reference_hash or None)
    for k, v in l1.items():
        if k == "layer1_overall":
            st.markdown(f"**Overall:** **{v}**")
        else:
            st.write(f"{k.replace('_', ' ').title()}: {v}")

    # ---------- Layer 2 ----------
    st.subheader("🕵️ Layer 2 — LLM Content Anomaly Detection")
    l2 = run_second_layer(pdf_bytes)
    if 'llm_analysis' in l2:
        llm_results = l2['llm_analysis']
        st.write(f"**Overall Assessment:** {llm_results.get('overall_assessment', 'N/A')}")
        st.write(f"**Confidence Score:** {llm_results.get('confidence_score', 'N/A')}")
        
        if llm_results.get('error'):
            st.error(f"LLM Analysis Error: {llm_results['error']}")
        
        anomalies = llm_results.get('detected_anomalies', [])
        if anomalies:
            st.write("**Detected Anomalies/Observations:**")
            for anomaly in anomalies:
                with st.expander(f"{anomaly.get('type', 'Anomaly')}: {anomaly.get('description', '')[:50]}..."):
                    st.json(anomaly)
        elif not llm_results.get('error'):
            st.success("No specific content anomalies reported by LLM based on the extracted text.")
        
        if 'raw_response' in llm_results:
            with st.expander("Raw LLM Response (for debugging)"):
                st.json(llm_results['raw_response'])
    else:
        st.warning("LLM Analysis results not found in Layer 2 output.")

    # ---------- JSON report download ----------
    report = {"layer1": l1, "layer2": l2}
    st.download_button(
        label="Download JSON report",
        data=json.dumps(report, indent=2),
        file_name="integrity_report.json",
        mime="application/json",
    )


if __name__ == "__main__":
    main()
