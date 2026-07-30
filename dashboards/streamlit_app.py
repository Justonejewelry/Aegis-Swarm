"""Lightweight Streamlit SOC / executive dashboard for AEGIS Swarm.

Run:  streamlit run dashboards/streamlit_app.py
Requires the API to be up on localhost:8080 (or set AEGIS_API_URL).
"""
from __future__ import annotations

import os
from typing import Any

import httpx
import streamlit as st

API = os.getenv("AEGIS_API_URL", "http://localhost:8080")

st.set_page_config(page_title="AEGIS Swarm", page_icon="🛡️", layout="wide")
st.title("🛡️ AEGIS Swarm — SOC Dashboard")
st.caption("Authorized cyber defense · engagement-scoped findings & risk")


@st.cache_data(ttl=15)
def fetch_json(path: str) -> Any:
    with httpx.Client(timeout=10) as client:
        r = client.get(f"{API}{path}")
        r.raise_for_status()
        return r.json()


try:
    health = fetch_json("/health")
    agents = fetch_json("/agents")
except Exception as e:
    st.error(f"Cannot reach AEGIS API at {API}: {e}")
    st.stop()

col1, col2, col3 = st.columns(3)
col1.metric("Status", health.get("status", "?").upper())
col2.metric("Agents registered", health.get("agents", 0))
col3.metric("Version", health.get("version", "?"))

st.subheader("Agent catalog (sample)")
st.dataframe(agents[:20], use_container_width=True)

st.subheader("Engagement report")
eng_id = st.text_input("Engagement UUID", placeholder="paste engagement_id from /engagements")
if eng_id:
    try:
        data = fetch_json(f"/engagements/{eng_id}")
        findings = data.get("findings", [])
        st.write(f"**{data['engagement']['name']}** — {data['engagement']['status']} · {data['finding_count']} findings")
        if findings:
            st.dataframe(findings, use_container_width=True)
            st.link_button("Open HTML executive report", f"{API}/engagements/{eng_id}/report")
        else:
            st.info("No findings yet for this engagement.")
        graph = fetch_json(f"/engagements/{eng_id}/graph")
        st.write(f"Graph: {len(graph.get('nodes', []))} nodes · {len(graph.get('edges', []))} edges")
    except Exception as e:
        st.warning(str(e))

st.markdown("---")
st.caption("AEGIS Swarm · defensive / purple-team only · no unauthorized exploitation")
