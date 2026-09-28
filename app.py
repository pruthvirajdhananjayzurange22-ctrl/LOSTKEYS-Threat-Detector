import streamlit as st
import os
import pandas as pd
from modules.engine import ThreatEngine
from modules.reporter import generate_html_report, generate_json_report
from modules.hasher import defang_string

# -----------------------------------------------------------------------------
# Page Config & Custom Styling
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="LOSTKEYS Threat Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Cyber Defensive Theme CSS
st.markdown("""
<style>
    /* Dark Cyber Theme Background */
    .stApp {
        background-color: #0A192F;
        color: #8892B0;
        font-family: 'Inter', 'Segoe UI', sans-serif;
    }
    
    /* Header Card Styling */
    .header-card {
        background: linear-gradient(135deg, #112240 0%, #0A192F 100%);
        border: 1px solid #233554;
        border-left: 6px solid #64FFDA;
        border-radius: 10px;
        padding: 24px;
        margin-bottom: 25px;
        box-shadow: 0 10px 30px -15px rgba(2,12,27,0.7);
    }
    .header-title {
        color: #CCD6F6;
        font-size: 28px;
        font-weight: 700;
        letter-spacing: 0.5px;
        margin-bottom: 6px;
    }
    .header-subtitle {
        color: #64FFDA;
        font-size: 15px;
        font-weight: 500;
    }
    .header-meta {
        color: #8892B0;
        font-size: 13px;
        margin-top: 8px;
    }

    /* Metric Card Styling */
    .metric-container {
        background: #112240;
        border: 1px solid #233554;
        border-radius: 8px;
        padding: 16px;
        text-align: center;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    .metric-lbl {
        color: #8892B0;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .metric-val-hash {
        color: #64FFDA;
        font-family: 'Courier New', monospace;
        font-size: 13px;
        font-weight: bold;
        word-break: break-all;
        margin-top: 6px;
    }

    /* Severity Badges */
    .badge-CRITICAL {
        background-color: #FF2A4B;
        color: #FFFFFF;
        font-weight: 800;
        padding: 8px 20px;
        border-radius: 20px;
        font-size: 20px;
        display: inline-block;
        box-shadow: 0 0 15px rgba(255, 42, 75, 0.4);
    }
    .badge-HIGH {
        background-color: #FF8C00;
        color: #FFFFFF;
        font-weight: 800;
        padding: 8px 20px;
        border-radius: 20px;
        font-size: 20px;
        display: inline-block;
        box-shadow: 0 0 15px rgba(255, 140, 0, 0.4);
    }
    .badge-MEDIUM {
        background-color: #FFD700;
        color: #112240;
        font-weight: 800;
        padding: 8px 20px;
        border-radius: 20px;
        font-size: 20px;
        display: inline-block;
    }
    .badge-LOW {
        background-color: #00E676;
        color: #0A192F;
        font-weight: 800;
        padding: 8px 20px;
        border-radius: 20px;
        font-size: 20px;
        display: inline-block;
    }

    /* Correlation Alert Banner */
    .correlation-alert {
        background: rgba(255, 42, 75, 0.12);
        border: 1px solid #FF2A4B;
        border-radius: 8px;
        padding: 16px;
        color: #FF2A4B;
        font-weight: 600;
        margin-top: 15px;
        margin-bottom: 20px;
    }

    /* Tab & Dataframe overrides */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        background-color: #112240;
        padding: 6px;
        border-radius: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        color: #8892B0;
        border-radius: 6px;
        padding: 8px 16px;
    }
    .stTabs [aria-selected="true"] {
        background-color: #233554 !important;
        color: #64FFDA !important;
    }
</style>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# Initialize Core Detection Engine
# -----------------------------------------------------------------------------
@st.cache_resource
def get_engine():
    return ThreatEngine()

engine = get_engine()

# -----------------------------------------------------------------------------
# Header Component
# -----------------------------------------------------------------------------
st.markdown("""
<div class="header-card">
    <div class="header-title">🛡️ LOSTKEYS Threat Detector</div>
    <div class="header-subtitle">Defensive Malware Analysis & IOC Detection Engine</div>
    <div class="header-meta">
        <strong>Case Study:</strong> 2025 COLDRIVER / Star Blizzard ClickFix Attack Chain Analysis | 
        <strong>Mode:</strong> 100% Static & Offline Defensive Triage
    </div>
</div>
""", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# Sidebar: Sample Loader & Options
# -----------------------------------------------------------------------------
st.sidebar.title("🎮 Analysis Controls")
st.sidebar.markdown("---")

from pathlib import Path

st.sidebar.subheader("📁 Test Sample Quick-Load")
sample_dir = Path(__file__).resolve().parent / "tests" / "samples"

sample_choice = st.sidebar.selectbox(
    "Select Pre-packaged Synthetic Sample:",
    ["[Manual Input / File Upload]", "sample_full_attack.log", "sample_clickfix.ps1", "sample_recon.vbs", "sample_benign.txt"]
)

# Sidebar Threat Intel reference
st.sidebar.markdown("---")
st.sidebar.subheader("ℹ️ Documented GTIG IoCs")
st.sidebar.markdown("""
- **Actor:** COLDRIVER / Star Blizzard
- **Campaign:** ClickFix & LOSTKEYS
- **C2 Domain:** `cloudmediaportal[.]com`
- **C2 IP:** `165.227.148[.]68`
- **Target Hash:** `28a0596b9c...`
""")

# -----------------------------------------------------------------------------
# Input Handling (Dual Input Options: File Upload OR Clipboard/Raw Text)
# -----------------------------------------------------------------------------
content_to_analyze = ""
sample_filename = "triage_input.txt"

col_input1, col_input2 = st.columns([1, 1])

if sample_choice != "[Manual Input / File Upload]":
    target_path = sample_dir / sample_choice
    if target_path.exists():
        with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
            content_to_analyze = f.read()
        sample_filename = sample_choice
        st.info(f"Loaded sample: `{sample_choice}` for defensive triage.")

if not content_to_analyze:
    with col_input1:
        st.subheader("📄 Dual Input Option A: Upload File")
        uploaded_file = st.file_uploader(
            "Upload suspicious log or script sample (.ps1, .vbs, .txt, .log)",
            type=["ps1", "vbs", "txt", "log", "bin", "js"]
        )
        if uploaded_file is not None:
            content_to_analyze = uploaded_file.read().decode('utf-8', errors='ignore')
            sample_filename = uploaded_file.name

    with col_input2:
        st.subheader("📋 Dual Input Option B: Raw Text / Clipboard")
        raw_text = st.text_area(
            "Paste raw PowerShell command, ClickFix lure script, or log snippet here:",
            height=140,
            placeholder="powershell -w hidden -enc ..."
        )
        if raw_text and not uploaded_file:
            content_to_analyze = raw_text
            sample_filename = "clipboard_snippet.txt"

# -----------------------------------------------------------------------------
# Execute Analysis & Render Dashboard
# -----------------------------------------------------------------------------
if content_to_analyze.strip():
    results = engine.analyze(content_to_analyze, filename=sample_filename)

    st.markdown("---")
    
    # Key Metrics Cards Row
    m_col1, m_col2, m_col3, m_col4 = st.columns([1.5, 1, 1, 1])
    
    with m_col1:
        st.markdown(f"""
        <div class="metric-container">
            <div class="metric-lbl">SHA-256 Checksum</div>
            <div class="metric-val-hash">{results['sha256']}</div>
        </div>
        """, unsafe_allow_html=True)
        
    with m_col2:
        st.markdown(f"""
        <div class="metric-container">
            <div class="metric-lbl">Shannon Entropy</div>
            <div style="font-size: 22px; font-weight: bold; color: #64FFDA; margin-top: 4px;">
                {results['entropy']} <span style="font-size: 12px; color: #8892B0;">/ 8.0</span>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
    with m_col3:
        st.markdown(f"""
        <div class="metric-container">
            <div class="metric-lbl">Calculated Threat Score</div>
            <div style="font-size: 22px; font-weight: bold; color: #FFD700; margin-top: 4px;">
                {results['score']} PTS
            </div>
        </div>
        """, unsafe_allow_html=True)

    with m_col4:
        st.markdown(f"""
        <div class="metric-container">
            <div class="metric-lbl">Risk Rating</div>
            <div style="margin-top: 4px;">
                <span class="badge-{results['risk_level']}">{results['risk_level']}</span>
            </div>
        </div>
        """, unsafe_allow_html=True)

    # Check for Correlation Alert
    has_correlation = any(s.get("rule") == "Multi_Signal_Correlation_Bonus" for s in results['signals'])
    if has_correlation:
        st.markdown("""
        <div class="correlation-alert">
            🚨 <strong>CRITICAL ATTACK CHAIN CORRELATION DETECTED:</strong><br>
            This artifact exhibits simultaneous ClickFix PowerShell script obfuscation combined with host/network reconnaissance commands! This behavior strongly aligns with COLDRIVER LOSTKEYS Stage-1 stager deployment.
        </div>
        """, unsafe_allow_html=True)

    # -------------------------------------------------------------------------
    # Dashboard Tabs Navigation
    # -------------------------------------------------------------------------
    tab_summary, tab_mitre, tab_signals, tab_decoded, tab_raw, tab_export = st.tabs([
        "📊 Risk Overview",
        "🎯 MITRE ATT&CK Mapping",
        "🔍 Signal & IOC Breakdown",
        "🔓 Payload De-obfuscator",
        "📄 Raw Artifact Viewer",
        "📥 Export Reports"
    ])

    # Tab 1: Risk Overview
    with tab_summary:
        st.subheader("Analysis Summary & Detection Engine Mode")
        st.caption(f"Engine Operating Mode: **{results['engine_mode']}**")

        c1, c2 = st.columns([1, 1])
        with c1:
            st.markdown("### Risk Level Scale")
            st.markdown("""
            - **0 – 29 PTS:** 🟢 **LOW** (Clean log or benign admin script)
            - **30 – 59 PTS:** 🟡 **MEDIUM** (Suspicious scripting or minor recon commands)
            - **60 – 79 PTS:** 🟠 **HIGH** (Known IoC match or multiple suspicious script flags)
            - **80+ PTS:** 🔴 **CRITICAL** (Confirmed COLDRIVER ClickFix attack chain / LOSTKEYS malware)
            """)

        with c2:
            st.markdown("### Summary Statistics")
            st.metric("Total Triggered Threat Signals", len(results['signals']))
            st.metric("Matched GTIG 2025 Threat Indicators (IOCs)", len(results['matched_iocs']))
            st.metric("Mapped MITRE ATT&CK Techniques", len(results['mitre_mappings']))

    # Tab 2: MITRE ATT&CK Mapping
    with tab_mitre:
        st.subheader("🎯 MITRE ATT&CK Matrix Mapping")
        if results['mitre_mappings']:
            df_mitre = pd.DataFrame(results['mitre_mappings'])
            df_mitre = df_mitre[['id', 'name', 'tactic', 'description']]
            df_mitre.columns = ['Technique ID', 'Technique Name', 'ATT&CK Tactic', 'Technique Description']
            st.dataframe(df_mitre, use_container_width=True, hide_index=True)
        else:
            st.info("No MITRE ATT&CK techniques triggered for this sample.")

    # Tab 3: Signal & IOC Breakdown
    with tab_signals:
        col_sig, col_ioc = st.columns([1, 1])
        with col_sig:
            st.subheader("⚡ Triggered Detection Signals")
            for sig in results['signals']:
                with st.expander(f"[{sig['category']}] {sig['rule']} (+{sig['points']} pts)"):
                    st.write(f"**Evidence:** {sig['evidence']}")

        with col_ioc:
            st.subheader("🎯 Matched Threat Indicators (IOCs)")
            if results['matched_iocs']:
                for ioc in results['matched_iocs']:
                    st.warning(f"**[{ioc['type']}]** `{ioc['value']}`\n\n_{ioc['description']}_")
            else:
                st.success("No documented GTIG IOC hashes, domains, or IPs matched.")

    # Tab 4: Payload De-obfuscator
    with tab_decoded:
        st.subheader("🔓 Base64 Payload Extraction & De-obfuscation")
        if results['decoded_payloads']:
            st.success(f"Successfully extracted and decoded {len(results['decoded_payloads'])} Base64 payload block(s):")
            for idx, dp in enumerate(results['decoded_payloads'], 1):
                st.markdown(f"**Payload #{idx} (Encoded sample snippet: `{dp['encoded_sample']}`)**")
                st.code(dp['decoded_text'], language="powershell")
        else:
            st.info("No encoded Base64 script payloads detected in the analyzed sample.")

    # Tab 5: Raw Artifact Viewer
    with tab_raw:
        st.subheader("📄 Raw Analyzed Content")
        st.code(content_to_analyze, language="text")

    # Tab 6: Export & Reports
    with tab_export:
        st.subheader("📥 Export Investigation Artifacts")
        st.write("Generate and download comprehensive defensive threat reports for viva and SIEM integration.")

        html_report = generate_html_report(results)
        json_report = generate_json_report(results)

        exp_col1, exp_col2 = st.columns(2)
        with exp_col1:
            st.download_button(
                label="📄 Download HTML Investigation Report",
                data=html_report,
                file_name=f"LOSTKEYS_Report_{results['filename']}.html",
                mime="text/html"
            )

        with exp_col2:
            st.download_button(
                label="⚙️ Download JSON SIEM Artifact",
                data=json_report,
                file_name=f"LOSTKEYS_SIEM_{results['filename']}.json",
                mime="application/json"
            )

else:
    st.info("👈 Please select a pre-packaged sample from the sidebar, upload a log file, or paste raw text to begin defensive triage.")
