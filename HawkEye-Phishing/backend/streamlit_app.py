# streamlit_app.py
import streamlit as st
import requests
import json
from typing import List

# ✅ MUST be the first Streamlit command
st.set_page_config(page_title="HawkEye – Streamlit Tester", layout="wide")

# Sidebar configuration
st.sidebar.header("Configuration")
BACKEND_BASE = st.sidebar.text_input("Backend base URL", value="http://localhost:5000")
st.sidebar.markdown("Make sure your backend is running (python app.py)")

# Utility functions
def call_analyze_url(url: str):
    try:
        r = requests.post(f"{BACKEND_BASE}/analyze/url", json={"url": url}, timeout=8)
        return r.status_code, r.json() if r.status_code == 200 else r.text
    except Exception as e:
        return None, {"error": str(e)}

def call_analyze_batch(urls: List[str]):
    try:
        r = requests.post(f"{BACKEND_BASE}/analyze/url/batch", json={"urls": urls}, timeout=12)
        return r.status_code, r.json() if r.status_code == 200 else r.text
    except Exception as e:
        return None, {"error": str(e)}

def call_analyze_text(text: str):
    try:
        r = requests.post(f"{BACKEND_BASE}/analyze/text", json={"text": text}, timeout=12)
        return r.status_code, r.json() if r.status_code == 200 else r.text
    except Exception as e:
        return None, {"error": str(e)}

def color_for_label(label: str):
    if label == "malicious":
        return "🔴"
    elif label == "suspicious":
        return "🟡"
    elif label == "benign":
        return "🟢"
    return "⚪"

# App title
st.title("🦅 HawkEye — Phishing Analyzer (Streamlit Test UI)")
st.markdown("Quick UI to test your backend endpoints: `/analyze/url`, `/analyze/url/batch`, `/analyze/text`")

# --- Tabs for different functionalities ---
tab1, tab2, tab3, tab4 = st.tabs(["Single URL", "Batch URLs", "Text Extractor", "Health Check"])

# -------------------- Tab 1: Single URL --------------------
with tab1:
    st.subheader("Analyze a Single URL")
    sample_urls = [
        "https://bit.ly/3", 
        "http://192.168.0.1/login", 
        "http://xn--example-9d0a.com/abc", 
        "https://example.com/very/long/" + "a"*180
    ]
    st.write("**Sample URLs** (click to fill input):")
    for s in sample_urls:
        if st.button(s):
            st.session_state["single_url_input"] = s

    url_input = st.text_input("Enter URL to analyze", value=st.session_state.get("single_url_input", ""))

    if st.button("Analyze URL"):
        if not url_input.strip():
            st.warning("Please enter a URL.")
        else:
            status, payload = call_analyze_url(url_input.strip())
            if status == 200:
                label = payload.get("label", "unknown")
                st.markdown(f"### Result: {color_for_label(label)} **{label.upper()}**")
                st.markdown(f"**Score:** {payload.get('score')}  |  **Confidence:** {payload.get('confidence')}")
                st.markdown("**Reasons:**")
                st.write(payload.get("reasons", []))
                st.markdown("**Full Response:**")
                st.json(payload)
            else:
                st.error(f"Request failed: {payload}")

# -------------------- Tab 2: Batch URLs --------------------
with tab2:
    st.subheader("Analyze a Batch of URLs")
    batch_input = st.text_area("Enter one URL per line", value="https://bit.ly/3\nhttp://192.168.0.1/login\nhttps://example.com")

    if st.button("Analyze Batch"):
        urls = [u.strip() for u in batch_input.splitlines() if u.strip()]
        if not urls:
            st.warning("Provide at least one URL.")
        else:
            status, payload = call_analyze_batch(urls)
            if status == 200:
                results = payload.get("results", [])
                for r in results:
                    label = r.get("label", "unknown")
                    st.markdown(f"- {color_for_label(label)} **{r.get('input_url')}** — *{label}* (score {r.get('score')})")
                    with st.expander("Details"):
                        st.write("Resolved URL:", r.get("resolved_url"))
                        st.write("Resolved via expand:", r.get("resolved_via_expand"))
                        st.write("Reasons:", r.get("reasons", []))
                        st.write("PhishTank:", r.get("phishtank", {}))
            else:
                st.error(f"Request failed: {payload}")

# -------------------- Tab 3: Text Extractor --------------------
with tab3:
    st.subheader("Paste Text (URLs will be auto-detected & analyzed)")
    text_sample = "Hi — check this short link https://bit.ly/3 and also http://192.168.0.1/login"
    text_input = st.text_area("Paste any text, email, or message:", value=text_sample, height=180)

    if st.button("Extract & Analyze URLs"):
        status, payload = call_analyze_text(text_input)
        if status == 200:
            urls = payload.get("urls", [])
            if urls:
                st.markdown(f"**Extracted URLs ({len(urls)}):**")
                st.write(urls)
            results = payload.get("results", [])
            for r in results:
                label = r.get("label", "unknown")
                st.markdown(f"- {color_for_label(label)} **{r.get('input_url')}** — *{label}* (score {r.get('score')})")
                with st.expander("Full details"):
                    st.json(r)
        else:
            st.error(f"Request failed: {payload}")

# -------------------- Tab 4: Health Check --------------------
with tab4:
    st.subheader("Backend Health Check")
    if st.button("Ping /healthz"):
        try:
            r = requests.get(f"{BACKEND_BASE}/healthz", timeout=4)
            st.write("Status Code:", r.status_code)
            st.json(r.json())
        except Exception as e:
            st.error(f"Health check failed: {e}")

st.markdown("---")
st.info("💡 Tip: Run your backend first with `python app.py` before launching this Streamlit UI.")
