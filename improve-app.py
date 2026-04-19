import streamlit as st
import pandas as pd
import sqlite3
import joblib
import os
import re
import hashlib
import requests
import plotly.express as px
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# ---------------- CONFIG ----------------
st.set_page_config(page_title="SOC Platform", layout="wide")

# ---------------- DB ----------------
conn = sqlite3.connect("soc.db", check_same_thread=False)
c = conn.cursor()

c.execute("CREATE TABLE IF NOT EXISTS alerts(username TEXT, message TEXT, risk REAL, status TEXT)")
conn.commit()

# ---------------- CLEAN ----------------
def clean_text(text):
    text = text.lower()
    text = re.sub(r"http\S+", " link ", text)
    text = re.sub(r"[^a-z\s]", "", text)
    return text

# ---------------- LOAD MODEL ----------------
@st.cache_resource
def load_model():
    if os.path.exists("model.pkl") and os.path.exists("vectorizer.pkl"):
        return joblib.load("model.pkl"), joblib.load("vectorizer.pkl")

    data = pd.read_csv("sms.tsv", sep="\t", names=["label", "message"])
    data["label"] = data["label"].map({"ham": 0, "spam": 1})
    data["message"] = data["message"].apply(clean_text)

    vectorizer = TfidfVectorizer(stop_words="english")
    X = vectorizer.fit_transform(data["message"])
    y = data["label"]

    model = MultinomialNB()
    model.fit(X, y)

    joblib.dump(model, "model.pkl")
    joblib.dump(vectorizer, "vectorizer.pkl")

    return model, vectorizer

model, vectorizer = load_model()

# ---------------- VIRUSTOTAL ----------------
def scan_url(url):
    api_key = st.secrets["VIRUSTOTAL_API_KEY"]
    headers = {"x-apikey": api_key}

    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if response.status_code == 200:
        return "Submitted for scan"
    else:
        return "Error scanning"

# ---------------- UI ----------------
st.title("🔐 AI SOC Phishing Detection Platform")

menu = st.sidebar.radio("Menu", ["Analyze", "Trends"])

# ---------------- ANALYZE ----------------
if menu == "Analyze":
    msg = st.text_area("Enter message")

    if st.button("Analyze"):
        clean_input = clean_text(msg)
        data = vectorizer.transform([clean_input])
        prob = model.predict_proba(data)[0][1] * 100

        if prob > 70:
            status = "PHISHING"
            st.error("🔴 High Risk")
        elif prob > 40:
            status = "SUSPICIOUS"
            st.warning("🟠 Medium Risk")
        else:
            status = "SAFE"
            st.success("🟢 Safe")

        st.metric("Risk Score", f"{prob:.2f}%")

        # Extract URL
        urls = re.findall(r"(https?://\S+)", msg)

        if urls:
            st.subheader("🌐 URL Scan")
            for url in urls:
                result = scan_url(url)
                st.write(f"{url} → {result}")

        c.execute("INSERT INTO alerts VALUES (?, ?, ?, ?)",
                  ("user", msg, prob, status))
        conn.commit()

# ---------------- TRENDS ----------------
elif menu == "Trends":
    st.title("📊 Attack Trends")

    df = pd.read_sql_query("SELECT status FROM alerts", conn)

    if not df.empty:
        counts = df["status"].value_counts().reset_index()
        counts.columns = ["Status", "Count"]

        fig = px.bar(counts, x="Status", y="Count",
                     color="Status",
                     title="Attack Distribution")

        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No data yet")
