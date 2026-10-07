# 🛡️ Phishing Website Detector

A machine learning web application that analyzes URLs and predicts whether they are legitimate or malicious phishing websites. Built with Python, Scikit-Learn, and Streamlit.

## 🚀 Live Demo
https://phishingwebsitedetector-afl5tujf3xbtgjb5chnz3c.streamlit.app/

## 📋 Overview
Phishing attacks trick users into revealing sensitive information by impersonating trustworthy entities. This project utilizes a **Random Forest Classifier** trained on 30 specific structural and network-based features to detect deceptive URLs in real-time. 

## ✨ Features
- **Real-Time URL Analysis:** Extracts live features from a target URL including DNS records, WHOIS domain age, and HTML structural tags.
- **Threat Indicators:** Automatically flags critical security risks (e.g., IP addresses in URLs, hyphenated domains, lack of HTTPS).
- **Confidence Scoring:** Displays the exact probability score of the Random Forest model's prediction.
- **Interactive Dashboard:** Minimalist, professional interface built with Streamlit.

## 🗂️ Project Structure
    Phishing_Website_Detector/
    ├── app.py                  # Streamlit dashboard and user interface
    ├── prediction.py           # Model loading and prediction pipeline
    ├── featureExtraction.py    # URL parsing and 30-feature extraction logic
    ├── requirements.txt        # Python package dependencies
    └── models/
        └── random_forest.pkl   # Pre-trained Random Forest classifier

## 🛠️ Technologies Used
- **Frontend:** Streamlit
- **Machine Learning:** Scikit-Learn (Random Forest)
- **Data Manipulation:** Pandas
- **Web Scraping & Network:** Requests, BeautifulSoup4, python-whois

## 💻 Local Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/ratnakarjha9/Phishing_Website_Detector.git](https://github.com/ratnakarjha9/Phishing_Website_Detector.git)
   cd Phishing_Website_Detector
