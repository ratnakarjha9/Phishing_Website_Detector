import streamlit as st
import prediction
import pandas as pd

# Page Configuration
st.set_page_config(page_title="Phishing URL Detector", layout="centered")

st.title("Phishing URL Detector")
st.markdown("Enter a URL below to evaluate its structural and network features for potential security risks.")

# Sidebar for Sample URLs
st.sidebar.header("Test Scenarios")
sample_urls = {
    "Custom Input": "",
    "Safe Bank Website": "https://www.chase.com",
    "Classic Phishing Typosquat": "https://www.paypaI.com-update-billing.xyz/login",
    "IP Address Link (Risky)": "http://192.168.1.55/secure/verify"
}
selected_sample = st.sidebar.selectbox("Select a sample URL:", list(sample_urls.keys()))
default_url = sample_urls[selected_sample]

# Input Area
with st.form("prediction_form"):
    url = st.text_input("Target URL", value=default_url, placeholder="https://www.example.com")
    submit_button = st.form_submit_button("Analyze")

# Extraction & Prediction Logic
if submit_button:
    if url:
        if not url.startswith("http"):
            url = "http://" + url

        with st.spinner("Analyzing features..."):
            try:
                result, probability, features_df = prediction.predict_url(url)
                confidence = max(probability)

                st.markdown("---")
                st.subheader("Analysis Results")

                col1, col2 = st.columns(2)
                with col1:
                    st.metric(label="Verdict", value=result)
                with col2:
                    st.metric(label="Confidence", value=f"{confidence:.2%}")

                st.progress(float(confidence))

                # Highlight Key Threat Indicators
                st.subheader("Threat Indicators")
                
                feat_dict = features_df.iloc[0].to_dict()
                flags = []
                
                if feat_dict.get("UsingIP") == -1: flags.append("IP Address used instead of Domain Name")
                if feat_dict.get("Symbol@") == -1: flags.append("Contains '@' symbol")
                if feat_dict.get("PrefixSuffix-") == -1: flags.append("Hyphenated Domain Name")
                if feat_dict.get("HTTPS") == -1: flags.append("No valid HTTPS encryption")
                if feat_dict.get("DomainRegLen") == -1: flags.append("Domain registered recently (< 1 year)")

                if flags:
                    for flag in flags:
                        st.markdown(f"- **Flag**: {flag}")
                else:
                    st.markdown("- **Status**: No critical structural flags detected.")

                # Expandable detailed metrics
                st.write("")
                with st.expander("View Feature Data"):
                    st.dataframe(features_df.T.rename(columns={0: "Value"}), use_container_width=True)

            except Exception as e:
                st.error(f"Analysis failed. The website might be unreachable. Error: {e}")
    else:
        st.info("Please enter a URL to check.")