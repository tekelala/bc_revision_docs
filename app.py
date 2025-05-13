import hashlib
import io
import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Union, Dict

import pikepdf
import requests
import streamlit as st
from markitdown import MarkItDown

# Lazy import of pyHanko (optional dependency)
pyhanko_reader_module = None
pyhanko_validation_module = None
pyhanko_sign_general_module = None
PyHankoValidationContext = None # Explicitly for ValidationContext

try:
    from pyhanko.pdf_utils import reader as pyhanko_reader_module
    from pyhanko.sign import validation as pyhanko_validation_module
    from pyhanko.sign import general as pyhanko_sign_general_module
    from pyhanko_certvalidator import ValidationContext as PyHankoValidationContext
except ImportError:
    # If any import fails, modules will remain None, caught by checks before use
    pass # Modules will remain None, status checked before use

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
    st.sidebar.markdown("---")

    # Debug Information Section
    st.sidebar.subheader("🐞 Debug Information")
    # Display critical session state variables for debugging
    # Convert boolean and None to string for display, or show placeholder
    pyhanko_reader_imported = str(st.session_state.get('pyhanko_reader_module_imported', 'Not Set'))
    pyhanko_validation_imported = str(st.session_state.get('pyhanko_validation_module_imported', 'Not Set'))
    pyhanko_certvalidator_vc_imported = str(st.session_state.get('pyhanko_certvalidator_vc_module_imported', 'Not Set'))

    st.sidebar.text(f"pyhanko.pdf_utils.reader: {pyhanko_reader_imported}")
    st.sidebar.text(f"pyhanko.sign.validation: {pyhanko_validation_imported}")
    st.sidebar.text(f"pyhanko_certvalidator.ValidationContext: {pyhanko_certvalidator_vc_imported}")
    st.sidebar.markdown("---")

    st.sidebar.subheader("🔑 API Keys")

    # Initialize the session state variable for the Grok API key if it doesn't exist
    if 'grok_api_key' not in st.session_state:
        st.session_state.grok_api_key = ""

    # Use a unique key for the text input widget itself
    api_key_input_from_widget = st.sidebar.text_input(
        "Enter Xai (Grok) API Key",
        value=st.session_state.grok_api_key,  # Pre-fill with the current session state value
        type="password",
        key="grok_api_key_input_widget"  # Unique key for this specific widget
    )

    # If the value entered in the widget is different from our stored session state value,
    # it means the user has changed it. Update st.session_state.grok_api_key.
    if api_key_input_from_widget != st.session_state.grok_api_key:
        st.session_state.grok_api_key = api_key_input_from_widget
        # Optionally, provide feedback or st.rerun() if immediate effect is critical,
        # but for API keys, the next analysis run will pick it up naturally.
        # st.sidebar.success("API Key updated!") # Example feedback
        # st.experimental_rerun() # If you need the app to immediately reflect the new key

    st.sidebar.markdown("---")
    # About section or other sidebar items can go here
    st.sidebar.markdown("**About**")
    st.sidebar.info(
        "This tool performs a two-layer analysis of PDF documents to check for signs of tampering or anomalies. "
        "It is intended for informational purposes and does not constitute legal or expert advice."
    )
    return None

# Helper function to safely convert pikepdf objects to strings
def _safe_pdf_value_to_string(pdf_obj):
    # pikepdf.String and pikepdf.Name are specific types.
    # For numbers and booleans, pikepdf often uses native Python int, float, bool.
    if isinstance(pdf_obj, (pikepdf.String, pikepdf.Name, int, float, bool)):
        try:
            return str(pdf_obj)
        except ValueError:
            return f"[ValueError on str({type(pdf_obj).__name__})]"
        except Exception as e_str_simple:
            return f"[Error on str({type(pdf_obj).__name__}): {type(e_str_simple).__name__}]"
    elif isinstance(pdf_obj, pikepdf.Array):
        return [_safe_pdf_value_to_string(item) for item in pdf_obj] # Recursive
    elif isinstance(pdf_obj, pikepdf.Dictionary):
        objgen_str = ""
        if hasattr(pdf_obj, 'objgen') and isinstance(pdf_obj.objgen, tuple) and len(pdf_obj.objgen) == 2:
            objgen_str = f" (obj={pdf_obj.objgen[0]}/{pdf_obj.objgen[1]})"
        return f"PDFDictionary{objgen_str} (Keys: {[_safe_pdf_value_to_string(k) for k in pdf_obj.keys()]})"
    elif isinstance(pdf_obj, pikepdf.Object): # Generic, unresolved object
        obj_details = []
        if hasattr(pdf_obj, 'objgen') and isinstance(pdf_obj.objgen, (tuple, list)) and len(pdf_obj.objgen) == 2:
            obj_details.append(f"obj={pdf_obj.objgen[0]}/{pdf_obj.objgen[1]}")
        
        pdf_type_display = "[Type N/A]"
        try:
            if hasattr(pdf_obj, 'get') and callable(pdf_obj.get) and hasattr(pdf_obj, 'keys') and callable(pdf_obj.keys):
                type_name_obj = pdf_obj.get('/Type')
                if type_name_obj:
                    pdf_type_display = f"pdf_type=/{_safe_pdf_value_to_string(type_name_obj)}" # Recursive for type name string
        except Exception:
            pass 
        
        if pdf_type_display != "[Type N/A]":
             obj_details.append(pdf_type_display)
        
        # Try a direct str() as a last resort for the object itself, but protected
        obj_str_fallback = ""
        try:
            obj_str_fallback = str(pdf_obj)
        except ValueError:
            obj_str_fallback = "[ValueError on str(Object)]"
        except Exception:
            obj_str_fallback = "[Error on str(Object)]"
        if len(obj_details) == 0 and obj_str_fallback: # If no other details, use the stringified object if available
             obj_details.append(f"RawValue='{obj_str_fallback}'")

        return f"Unresolved PDFObject ({', '.join(obj_details) if obj_details else 'Info N/A'})"
    elif pdf_obj is None:
        return "null_obj (NoneType)"
    else: 
        try:
            val_str = str(pdf_obj)
        except ValueError:
            val_str = f"[ValueError on str(value of type {type(pdf_obj).__name__})]"
        except Exception as e_str_val:
            val_str = f"[Error on str(value of type {type(pdf_obj).__name__}): {type(e_str_val).__name__}]"
        return f"OtherType (Type: {type(pdf_obj).__name__}, Value: {val_str})"


# ------------------------------------------------------------------
# Helper — First layer: cryptographic / structural integrity
# ------------------------------------------------------------------

def run_first_layer(pdf_bytes: bytes, reference_hash: str | None = None) -> dict:
    # Initialize main results dictionary
    results = {
        'structural_integrity': {'issues_found': False, 'details': []},
        'hash_mismatch': "N/A (no reference)", # Placeholder
        'incremental_updates': "Unknown",
        'signature_analysis': [],
        'docinfo_metadata': {},
        'xmp_metadata_present': False,
        'summary_anomalies': [], # For high-level anomaly summaries
        'status_summary': "Analysis Pending" # General status
    }
    metadata_error_details = None # To store any specific errors from metadata extraction

    pdf = None  # Initialize pdf to None

    try:
        # Attempt to open the PDF
        try:
            pdf = pikepdf.open(io.BytesIO(pdf_bytes))
            results['status_summary'] = "PDF Opened Successfully"
        except pikepdf.PasswordError:
            results['structural_integrity']['issues_found'] = True
            results['structural_integrity']['details'].append("PDF is password protected and cannot be opened without a password.")
            results['summary_anomalies'].append("PDF is password protected.")
            results['status_summary'] = "Error: PDF Password Protected"
            return results # Return early, 'finally' will still execute
        except Exception as e_open:
            results['structural_integrity']['issues_found'] = True
            results['structural_integrity']['details'].append(f"Failed to open or parse PDF: {type(e_open).__name__} - {str(e_open)}")
            results['summary_anomalies'].append("Failed to open or parse PDF.")
            results['status_summary'] = "Error: PDF Parsing Failed"
            return results # Return early, 'finally' will still execute

        # If we reached here, PDF is open. Proceed with analysis.

        # 1. Structural Integrity Check (pikepdf.check())
        try:
            check_results = pdf.check()
            if check_results:
                results['structural_integrity']['issues_found'] = True
                results['structural_integrity']['details'].extend(check_results)
                results['summary_anomalies'].append("Structural integrity warnings found.")
        except Exception as e_check: # Catch potential errors during .check()
            results['structural_integrity']['issues_found'] = True
            results['structural_integrity']['details'].append(f"Error during PDF structural check: {str(e_check)}")
            results['summary_anomalies'].append("Error during PDF structural check.")

        # 2. Hash Check (Placeholder - requires reference)
        # results['hash_mismatch'] = calculate_and_compare_hash(pdf_bytes, reference_hash)

        # 3. Incremental Updates (Save History)
        try:
            if hasattr(pdf, 'has_incremental_updates') and pdf.has_incremental_updates():
                results['incremental_updates'] = "Positive (Indicates changes may have been saved incrementally)"
                results['summary_anomalies'].append("PDF has incremental updates (revisions).")
            else:
                results['incremental_updates'] = "Negative"
        except Exception as e_inc_update: # Catch potential errors during .has_incremental_updates()
            results['incremental_updates'] = f"Error checking incremental updates: {str(e_inc_update)}"

        # 4. Digital Signature Analysis (pyHanko)
        # ... (existing signature analysis logic, which should be robust with its own try-except)
        # Ensure this block uses the 'pdf' variable correctly.
        try:
            # Convert pdf_bytes to a stream for pyHanko
            pdf_stream_for_pyhanko = io.BytesIO(pdf_bytes)
            r = pyhanko_reader_module.PdfFileReader(pdf_stream_for_pyhanko)

            if not r.embedded_signatures:
                results['signature_analysis'].append({'status': 'Digital Signature: Not Signed (No signatures found in PDF via embedded_signatures)'})
            else:
                # ... (rest of your existing pyHanko signature validation logic) ...
                # This part might involve complex pyHanko calls and should be within this try
                # For example:
                # vc = ValidationContext.load_default_certs() # Or your custom context
                # for signature in r.embedded_signatures:
                #     status = validate_pdf_signature(signature, vc)
                #     results['signature_analysis'].append(summarize_validation_status(status))
                # The above is a simplified placeholder, adapt with your actual pyhanko logic
                # For now, as a placeholder if you have complex logic not shown recently:
                results['signature_analysis'].append({'status': f'Signatures found ({len(r.embedded_signatures)}), detailed validation pending full pyHanko integration.'})

        except Exception as e_sign:
            results['signature_analysis'].append({'status': f'Digital Signature: Error during analysis - {type(e_sign).__name__}: {str(e_sign)}'})
            results['summary_anomalies'].append("Error during digital signature analysis.")


        # 5. Metadata Extraction (DocInfo and XMP)
        metadata_extraction_successful = False
        try:
            # DocInfo (PDF Information Dictionary)
            if hasattr(pdf, 'trailer') and pdf.trailer is not None and '/Info' in pdf.trailer:
                info_object = pdf.trailer.get('/Info')
                if info_object is not None:
                    if isinstance(info_object, pikepdf.Dictionary):
                        for key, value in info_object.items():
                            key_str = _safe_pdf_value_to_string(key)
                            if isinstance(value, pikepdf.String) and str(value).startswith('D:'):
                                try:
                                    date_str_val = str(value)[2:]
                                    results['docinfo_metadata'][key_str] = f"PDFDate({date_str_val})"
                                except Exception as e_date_parse:
                                    results['docinfo_metadata'][key_str] = f"RawPDFStringDate('{_safe_pdf_value_to_string(value)}', ParseAttemptError: {str(e_date_parse)})"
                            else:
                                results['docinfo_metadata'][key_str] = _safe_pdf_value_to_string(value)
                    elif isinstance(info_object, pikepdf.Object):
                        metadata_error_details = f"DocInfo: /Info entry is a generic PDF Object, not a Dictionary. Details: {_safe_pdf_value_to_string(info_object)}"
                        results['docinfo_metadata']['/Info_raw_type'] = _safe_pdf_value_to_string(type(info_object))
                    else:
                        metadata_error_details = f"DocInfo: /Info entry is of unexpected type: {_safe_pdf_value_to_string(type(info_object))}. Value: {_safe_pdf_value_to_string(info_object)}"
                else:
                    metadata_error_details = "DocInfo: /Info entry is null or unresolvable."
            else:
                results['docinfo_metadata']['status'] = "DocInfo: /Info dictionary not found in PDF trailer."

            # XMP Metadata
            if hasattr(pdf, 'Root') and pdf.Root is not None and '/Metadata' in pdf.Root:
                metadata_stream_obj = pdf.Root.get('/Metadata')
                if metadata_stream_obj is not None and isinstance(metadata_stream_obj, pikepdf.Stream):
                    results['xmp_metadata_present'] = True
                elif metadata_stream_obj is not None:
                    results['docinfo_metadata']['XMP_status'] = f"XMP: /Metadata entry found but is not a Stream (Type: {_safe_pdf_value_to_string(type(metadata_stream_obj).__name__)})."
            metadata_extraction_successful = True # Mark as attempted/successful path
        except AttributeError as ae:
            metadata_error_details = f"Metadata Error: AttributeError accessing PDF components ({str(ae)})."
        except Exception as e_meta:
            current_metadata_error_str = f"Metadata Error (InnerTry): ({type(e_meta).__name__} - {str(e_meta)})."
            if metadata_error_details:
                metadata_error_details += " Additional: " + current_metadata_error_str
            else:
                metadata_error_details = current_metadata_error_str
        
        if metadata_error_details:
            # If there was an error, store it distinctly. 'status' might be used for 'not found'
            results['docinfo_metadata']['error_details'] = metadata_error_details
            results['summary_anomalies'].append("Errors encountered during metadata extraction.")
        elif not results['docinfo_metadata'] and not metadata_extraction_successful:
            # If no data and not explicitly successful, and no specific error captured above for docinfo itself
            results['docinfo_metadata']['status'] = "No DocInfo data extracted or extraction process issue."

        results['status_summary'] = "Layer 1 Analysis Completed"

    finally:
        if pdf:  # Check if pdf was successfully assigned
            pdf.close()
    
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

def run_second_layer(pdf_bytes: bytes) -> Union[ContentAnalysis, Dict[str, str]]:
    """Analyze PDF text content for anomalies using an LLM."""
    
    grok_api_key = st.session_state.get('grok_api_key')
    if not grok_api_key:
        return {
            "status": "skipped", 
            "reason": "Layer 2 (Content Analysis) skipped: Xai API key not provided.",
            "overall_assessment": "Not performed",
            "detected_anomalies": [],
            "confidence_score": 0.0
        }

    try:
        md = MarkItDown(enable_plugins=False)
        with io.BytesIO(pdf_bytes) as pdf_stream:
            # convert_stream returns a DocumentConverterResult object
            conversion_result = md.convert_stream(pdf_stream)
            # The actual text is in the .text_content attribute
            extracted_text = conversion_result.text_content 

        if not extracted_text or not extracted_text.strip():
            return {
                "status": "skipped", 
                "reason": "Layer 2 (Content Analysis) skipped: Extracted text is empty.",
                "overall_assessment": "Not performed",
                "detected_anomalies": [],
                "confidence_score": 0.0
            }

    except Exception as e_text_extract:
        st.error(f"Error during text extraction: {e_text_extract}")
        return {
            "status": "error", 
            "reason": f"Failed to extract text: {e_text_extract}",
            "overall_assessment": "Not performed",
            "detected_anomalies": [],
            "confidence_score": 0.0
        }

    # Simplified system prompt for structured output
    system_prompt = (
        "You are a forensic document analyst. Analyze the provided text extracted from a PDF document. Take into account than the "
         "document is being parsed so there may be some errors in the text, omit those cases in the findings."
        "Identify any anomalies such as internal inconsistencies, suspicious language or claims, "
        "abrupt changes in tone or style, unusual formatting hints (based on this text), "
        "or potential misinformation. Provide your analysis according to the defined schema."
    )

    client = OpenAI(
        api_key=grok_api_key,
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
            return llm_analysis_data.model_dump() 
        else:
            return {
                "status": "error", 
                "reason": "LLM response was empty or not structured as expected.",
                "overall_assessment": "Not performed",
                "detected_anomalies": [],
                "confidence_score": 0.0
            }
            # Attempt to get raw response if possible for debugging
            try: raw_response_for_debug = completion.model_dump_json(indent=2) 
            except: pass

    except Exception as e_llm: # Catching broader exceptions from the OpenAI SDK call
        st.error(f"Error during LLM analysis: {e_llm}")
        return {
            "status": "error", 
            "reason": f"LLM analysis failed: {e_llm}",
            "overall_assessment": "Not performed",
            "detected_anomalies": [],
            "confidence_score": 0.0
        }
        # Attempt to get raw response if it's an API error with a response body
        if hasattr(e_llm, 'response') and hasattr(e_llm.response, 'text'):
            raw_response_for_debug = e_llm.response.text[:2000]
        elif hasattr(e_llm, 'message'):
             raw_response_for_debug = str(e_llm.message)[:2000]
        else:
            raw_response_for_debug = str(e_llm)[:2000]
    
    if raw_response_for_debug:
        return {
            "status": "error", 
            "reason": "LLM analysis failed.",
            "overall_assessment": "Not performed",
            "detected_anomalies": [],
            "confidence_score": 0.0,
            "raw_llm_response_for_debug": raw_response_for_debug
        }

# ------------------------------------------------------------------
# Streamlit UI
# ------------------------------------------------------------------

def main():
    st.set_page_config(page_title="PDF Integrity Checker", page_icon="🔍")
    st.title("🔍 PDF Integrity Checker (2‑Layer)")
    st.markdown("Upload a PDF and get **Positive / Negative** flags for any indication that it has been tampered with.")

    sidebar_config()

    uploaded = st.file_uploader("Choose a PDF", type="pdf")
    if not uploaded:
        return

    pdf_bytes = uploaded.read()

    # ---------- Layer 1 ----------
    st.subheader("🔒 Layer 1 — Cryptographic / Structural")
    l1 = run_first_layer(pdf_bytes)
    for k, v in l1.items():
        if k == "layer1_overall":
            st.markdown(f"**Overall:** **{v}**")
        else:
            st.write(f"{k.replace('_', ' ').title()}: {v}")

    # ---------- Layer 2 ----------
    st.subheader("🕵️ Layer 2 — LLM Content Anomaly Detection")
    l2_results = run_second_layer(pdf_bytes)

    if isinstance(l2_results, dict) and 'status' in l2_results:
        if l2_results['status'] == 'skipped':
            st.warning(l2_results.get('reason', 'Layer 2 skipped for an unknown reason.'))
        elif l2_results['status'] == 'error':
            st.error(l2_results.get('reason', 'Layer 2 encountered an error.'))
            if 'raw_llm_response_for_debug' in l2_results:
                with st.expander("Raw LLM Response (for debugging)"):
                    # Attempt to pretty-print if it's JSON, otherwise show as string
                    try:
                        debug_info = json.loads(l2_results['raw_llm_response_for_debug'])
                        st.json(debug_info)
                    except (json.JSONDecodeError, TypeError):
                        st.text(l2_results['raw_llm_response_for_debug'])
        else: # Should not happen if status is 'skipped' or 'error', but as a fallback
            st.info(f"Layer 2 status: {l2_results['status']}. Details: {l2_results.get('reason', 'No details')}")
    elif isinstance(l2_results, dict): # Assumed successful analysis (ContentAnalysis.model_dump())
        st.write(f"**Overall Assessment:** {l2_results.get('overall_assessment', 'N/A')}")
        st.write(f"**Confidence Score:** {l2_results.get('confidence_score', 'N/A')}")
        
        anomalies = l2_results.get('detected_anomalies', [])
        if anomalies:
            st.write("**Detected Anomalies/Observations:**")
            for anomaly in anomalies: # anomaly is a dict here
                # Ensure anomaly is a dict before using .get, for robustness
                anomaly_type = anomaly.get('type', 'Unknown Type') if isinstance(anomaly, dict) else "Invalid Anomaly Format"
                with st.expander(f"Anomaly: {anomaly_type}"):
                    st.json(anomaly)
        else:
            st.success("No specific content anomalies reported by LLM based on the extracted text.")
        # No raw_response or raw_llm_response_for_debug expected here for a clean success
    else:
        # This case should ideally not be reached if run_second_layer always returns a dict
        st.error("Layer 2 analysis returned an unexpected data type.")

    st.markdown("***")
    st.markdown("Disclaimer: This tool provides an automated analysis and does not constitute legal or expert advice. Always verify findings with qualified professionals.")

    # ---------- JSON report download ----------
    report = {"layer1": l1, "layer2": l2_results}
    st.download_button(
        label="Download JSON report",
        data=json.dumps(report, indent=2),
        file_name="integrity_report.json",
        mime="application/json",
    )


if __name__ == "__main__":
    main()
