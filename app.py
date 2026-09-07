from __future__ import annotations

import tempfile
from pathlib import Path

import streamlit as st
from core.analyzer import analyze_pcap

st.set_page_config(page_title="SecureMailScope", layout="wide")
st.title("SecureMailScope")
st.caption("v0.1 - evidence-first cryptographic posture assessment for email PCAPs")
uploaded = st.file_uploader("Upload PCAP / PCAPNG", type=["pcap", "pcapng", "cap"])
if uploaded:
    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(uploaded.name).suffix) as temp:
        temp.write(uploaded.getbuffer()); pcap_path = Path(temp.name)
    try:
        with st.spinner("Extracting TShark evidence..."): result = analyze_pcap(pcap_path)
        st.success(f"Analysis complete using {result.tshark_version}")
        a,b,c,d = st.columns(4)
        a.metric("Relevant packets", result.packet_count); b.metric("Sessions", len(result.sessions))
        c.metric("High / Critical", result.high_risk_count); d.metric("Protocols", ", ".join(result.protocols) or "None")
        st.subheader("Canonical sessions"); st.dataframe(result.session_table, use_container_width=True)
        st.subheader("Findings"); st.dataframe(result.findings, use_container_width=True) if result.findings else st.info("No v0.1 findings.")
        st.subheader("Canonical JSON"); st.json(result.as_dict())
    except Exception as error: st.error(str(error))
    finally: pcap_path.unlink(missing_ok=True)
