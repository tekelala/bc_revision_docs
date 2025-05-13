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
    st.sidebar.title("⚙️ Configuration")
    st.session_state.XAI_API_KEY = st.sidebar.text_input(
        "Grok API Key (x.ai)",
        type="password",
        value=st.session_state.get("XAI_API_KEY") or os.getenv("GROK_API_KEY") or "",
        help="API key for x.ai's Grok model, used for Layer 2 content analysis."
    )
    return None

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
        # pdf.docinfo attempts to access pdf.trailer["/Info"]
        # We should check if /Info exists and is a dictionary first
        info_obj = pdf.trailer.get('/Info')
        if isinstance(info_obj, pikepdf.Dictionary):
            docinfo = pdf.docinfo # Safe to access now
            for key, value in docinfo.items():
                # Dates like /CreationDate (D:20230401123045Z) need parsing
                if isinstance(value, pikepdf.String) and value.startswith('D:'):
                    try:
                        # Simplified parsing, PDF date format can be complex
                        # D:YYYYMMDDHHMMSSOHH'mm'
                        # Example: D:20240115103000-05'00'
                        date_str = str(value)[2:] # Remove 'D:'
                        # Remove timezone offset for simplicity if present, as strptime struggles with 'Z' or HH'mm'
                        if 'Z' in date_str: date_str = date_str.replace('Z', '')
                        if '+' in date_str: date_str = date_str.split('+')[0]
                        # Correctly handle '-' which might be part of date or TZ separator for negative offsets
                        # Only split by '-' if it's followed by digits and likely a TZ offset
                        if '-' in date_str and len(date_str.split('-')[-1]) <= 4 and date_str.split('-')[-1].isdigit():
                             date_str = date_str.split('-')[0]
                        else: # if '-' is part of date, don't split or handle carefully
                            # This simplified parser might still struggle with complex date strings with internal hyphens
                            pass 
                        # Ensure we only take the YYYYMMDDHHMMSS part
                        date_str_core = date_str[:14]
                        dt_obj = datetime.strptime(date_str_core, "%Y%m%d%H%M%S")
                        metadata[str(key)] = dt_obj.isoformat()
                    except ValueError:
                        metadata[str(key)] = str(value) # Store as string if parsing fails
                else:
                    metadata[str(key)] = str(value)
            results['docinfo_metadata'] = metadata
        else:
            results['docinfo_metadata'] = "Not found or not a dictionary."
    except Exception as e_meta:
        results['docinfo_metadata_error'] = str(e_meta)
    
    try:
        # XMP metadata is typically in pdf.Root.Metadata (a stream)
        xmp_stream = pdf.Root.get('/Metadata')
        if isinstance(xmp_stream, pikepdf.Stream):
            results['xmp_metadata_present'] = True
            # To get content: xmp_content = xmp_stream.read_bytes().decode('utf-8', errors='replace')
            # For now, just indicate presence.
        else:
            results['xmp_metadata_present'] = False
    except Exception as e_xmp:
        results['xmp_metadata_check_error'] = str(e_xmp)
        results['xmp_metadata_present'] = 'Error checking'

    pdf.close() # Close the pikepdf object
    return results

# ------------------------------------------------------------------
# Helper — Second layer: LLM-based content anomaly detection
# ------------------------------------------------------------------

from pydantic import BaseModel, Field
from openai import OpenAI

class AnomalyDetail(BaseModel):
    type: str = Field(description="Category for the anomaly (e.g., 'Inconsistency', 'Suspicious Language', 'Abrupt Tone Shift', 'Unusual Formatting/Structure Hint', 'Potential Misinformation')")
    description: str = Field(description="Detailed explanation of the anomaly.")
    excerpt: Optional[str] = Field(None, description="Relevant snippet from the text where the anomaly was observed (if applicable).")

class ContentAnalysis(BaseModel):
    overall_assessment: str = Field(description="Brief summary of findings (e.g., 'No significant anomalies detected', 'Minor inconsistencies noted', 'Potential red flags identified').")
    detected_anomalies: List[AnomalyDetail] = Field(description="List of specific anomalies found. Empty if none.")
    confidence_score: float = Field(description="Numerical score from 0.0 to 1.0 indicating confidence in the assessment.", ge=0.0, le=1.0)

def run_second_layer(pdf_bytes: bytes) -> dict:
    """Analyze PDF text content for anomalies using an LLM."""
    results = {
        "llm_analysis": None,
        "llm_analysis_error": None
    }
    api_key = st.session_state.get("XAI_API_KEY")

    if not api_key:
        results['llm_analysis_error'] = "API key not configured. Skipping LLM analysis."
        return results

    try:
        md = MarkItDown(enable_plugins=False)
        with io.BytesIO(pdf_bytes) as pdf_stream:
            # convert_stream returns a DocumentConverterResult object
            conversion_result = md.convert_stream(pdf_stream)
            # The actual text is in the .text_content attribute
            extracted_text = conversion_result.text_content 

        if not extracted_text or not extracted_text.strip():
            results['llm_analysis_error'] = "Extracted text is empty. Skipping LLM analysis."
            return results

    except Exception as e_text_extract:
        st.error(f"Error during text extraction: {e_text_extract}")
        results['llm_analysis_error'] = f"Failed to extract text: {e_text_extract}"
        return results

    # Simplified system prompt for structured output
    system_prompt = (
        "You are a forensic document analyst. Analyze the provided text extracted from a PDF document. "
        "Identify any anomalies such as internal inconsistencies, suspicious language or claims, "
        "abrupt changes in tone or style, unusual formatting hints (based on this text), "
        "or potential misinformation. Provide your analysis according to the defined schema."
    )

    client = OpenAI(
        api_key=api_key,
        base_url="https://api.x.ai/v1", # Ensure this is the correct base URL for x.ai Grok
    )

    raw_response_for_debug = None

    try:
        completion = client.beta.chat.completions.parse(
            model="grok-3", # Using grok-3 as it supports structured outputs
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": extracted_text},
            ],
            response_format=ContentAnalysis, # Pass the Pydantic model here
            temperature=0.2,
            max_tokens=2000, 
            timeout=180,
        )
        
        # The response is already a Pydantic model instance
        if completion.choices and completion.choices[0].message and completion.choices[0].message.parsed:
            llm_analysis_data = completion.choices[0].message.parsed
            # Convert Pydantic model to dict for consistent storage/display in results
            results['llm_analysis'] = llm_analysis_data.model_dump() 
        else:
            results['llm_analysis_error'] = "LLM response was empty or not structured as expected."
            # Attempt to get raw response if possible for debugging
            try: raw_response_for_debug = completion.model_dump_json(indent=2) 
            except: pass

    except Exception as e_llm: # Catching broader exceptions from the OpenAI SDK call
        st.error(f"Error during LLM analysis: {e_llm}")
        results['llm_analysis_error'] = f"LLM analysis failed: {e_llm}"
        # Attempt to get raw response if it's an API error with a response body
        if hasattr(e_llm, 'response') and hasattr(e_llm.response, 'text'):
            raw_response_for_debug = e_llm.response.text[:2000]
        elif hasattr(e_llm, 'message'):
             raw_response_for_debug = str(e_llm.message)[:2000]
        else:
            raw_response_for_debug = str(e_llm)[:2000]
    
    if raw_response_for_debug and results['llm_analysis_error']:
        results['raw_llm_response_for_debug'] = raw_response_for_debug

    return results
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
