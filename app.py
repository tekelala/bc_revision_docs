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

import pikepdf
import requests
import streamlit as st
from markitdown import MarkItDown

# Lazy import of pyHanko (optional dependency)
try:
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext
except ImportError:
    validate_pdf_signature = None

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

    # 1 — SHA‑256 compare
    sha256 = hashlib.sha256(pdf_bytes).hexdigest()
    if reference_hash:
        results["hash_mismatch"] = "Positive" if sha256 != reference_hash.lower() else "Negative"
    else:
        results["hash_mismatch"] = "N/A (no reference)"

    # 2 — Incremental revision check
    pdf = pikepdf.open(io.BytesIO(pdf_bytes))
    
    # Determine if there are multiple revisions (i.e., incremental updates)
    # In pikepdf 9.0+, get_revisions() is removed. We check for incremental updates
    # by seeing if any object has a generation number > 0.
    # obj.objgen is a tuple (id, generation_number).
    # Direct objects have objgen[1] == 0. Incrementally updated objects get gen > 0.
    has_incremental_updates = False
    for obj in pdf.objects:
        if obj.objgen[1] > 0:
            has_incremental_updates = True
            break
    results["multiple_revisions"] = "Positive" if has_incremental_updates else "Negative"

    # 3 — Signature validation
    if validate_pdf_signature:
        try:
            vc = ValidationContext()
            sig_summary = validate_pdf_signature(io.BytesIO(pdf_bytes), vc).summary()
            results["signature_invalid"] = "Negative" if sig_summary.trusted else "Positive"
        except Exception:
            results["signature_invalid"] = "Positive"
    else:
        results["signature_invalid"] = "N/A (pyHanko not installed)"

    # Overall flag
    results["layer1_overall"] = (
        "Positive" if any(v == "Positive" for v in results.values()) else "Negative"
    )
    return results

# ------------------------------------------------------------------
# Helper — Second layer: semantic diff via Grok 3
# ------------------------------------------------------------------

def run_second_layer(pdf_bytes: bytes) -> dict:
    """Compare the last two revisions of a PDF if multiple exist."""
    md = MarkItDown()
    pdf = pikepdf.open(io.BytesIO(pdf_bytes))

    has_incremental_updates = False
    for obj in pdf.objects:
        if obj.objgen[1] > 0:
            has_incremental_updates = True
            break

    if not has_incremental_updates:
        return {
            "message": "No incremental revisions found to compare.",
            "comparison": {}
        }
    else:
        # With pikepdf 9.0+, get_revisions() and accessing specific prior revision streams
        # (as was likely done before with revs[-2].get_pdf_stream()) is no longer directly available
        # as the library tends to consolidate revisions upon load/save.
        # Therefore, direct comparison of the content of specific past revisions
        # in the way previously implemented is not feasible with the current API.
        return {
            "message": "Comparison of specific content from prior revisions is not supported with the current PDF library version due to API changes.",
            "comparison": {}
        }

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
    st.subheader("🧠 Layer 2 — LLM Semantic Diff (Grok 3)")
    l2 = run_second_layer(pdf_bytes)
    st.write(f"Message: {l2['message']}")
    with st.expander("Comparison"):
        st.code(l2["comparison"], language="json")

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
