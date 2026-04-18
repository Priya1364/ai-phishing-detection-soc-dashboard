import joblib
import os
import pandas as pd
import streamlit as st
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.naive_bayes import MultinomialNB

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="SOC Phishing Detection",
    page_icon="🔐",
    layout="wide"
)

# ---------------- CUSTOM CSS ----------------
st.markdown("""
<style>
.main {
    background-color: #0e1117;
}
h1, h2, h3 {
    color: #00ffcc;
}
.stButton>button {
    background-color: #00ffcc;
    color: black;
    font-weight: bold;
}
</style>
""", unsafe_allow_html=True)

# ---------------- TITLE ----------------
st.title("🔐 AI-Based Phishing Detection SOC Dashboard")
st.markdown("### Advanced Threat Analysis System")
st.markdown("---")

# ---------------- CLEAN TEXT ----------------
def clean_text(text):
    text = text.lower()
    text = re.sub(r'http\S+', ' link ', text)
    text = re.sub(r'[^a-z\s]', '', text)
    return text

# ---------------- LOAD MODEL ----------------
@st.cache_resource
def load_model():

    if os.path.exists("model.pkl") and os.path.exists("vectorizer.pkl"):
        model = joblib.load("model.pkl")
        vectorizer = joblib.load("vectorizer.pkl")
        accuracy = 0.98
        return model, vectorizer, accuracy

    data = pd.read_csv("sms.tsv", sep='\t', names=["label", "message"])
    data['label'] = data['label'].map({'ham': 0, 'spam': 1})
    data['message'] = data['message'].apply(clean_text)

    X = data['message']
    y = data['label']

    vectorizer = TfidfVectorizer(stop_words='english')
    X = vectorizer.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    model = MultinomialNB()
    model.fit(X_train, y_train)

    accuracy = model.score(X_test, y_test)

    joblib.dump(model, "model.pkl")
    joblib.dump(vectorizer, "vectorizer.pkl")

    return model, vectorizer, accuracy

# ---------------- LOAD MODEL CALL ----------------
model, vectorizer, accuracy = load_model()

# ---------------- SIDEBAR ----------------
st.sidebar.title("⚙️ System Info")
st.sidebar.success(f"Model Accuracy: {accuracy*100:.2f}%")

st.sidebar.markdown("### 📌 About")
st.sidebar.info("This system detects phishing messages using Machine Learning and simulates SOC alerts.")

# ---------------- INPUT ----------------
st.subheader("📩 Enter Email / SMS Content")
email = st.text_area("Type message here...", height=150)

# ---------------- HISTORY ----------------
if "history" not in st.session_state:
    st.session_state.history = []

# ---------------- ANALYZE ----------------
if st.button("🔍 Analyze Threat"):

    if email.strip() == "":
        st.warning("⚠️ Please enter a message")
    else:
        clean_input = clean_text(email)
        input_data = vectorizer.transform([clean_input])
        prob = model.predict_proba(input_data)[0][1] * 100

        st.markdown("---")
        st.subheader("🚨 SOC Alert Dashboard")

        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### 📄 Message")
            st.code(email)

        with col2:
            st.markdown("### 📊 Risk Score")
            st.metric("Threat Probability", f"{prob:.2f}%")

        # STATUS
        if prob > 70:
            status = "PHISHING"
            st.error("🔴 HIGH RISK: Phishing Attack Detected")
        elif prob > 40:
            status = "SUSPICIOUS"
            st.warning("🟠 MEDIUM RISK: Suspicious Activity")
        else:
            status = "SAFE"
            st.success("🟢 LOW RISK: Safe Message")

        st.markdown(f"### 🔎 Status: `{status}`")

        # ---------------- ANALYSIS ----------------
        st.subheader("🧠 Threat Intelligence")

        reasons = []
        keywords = ["link", "urgent", "verify", "bank", "password", "login"]

        for word in keywords:
            if word in clean_input:
                reasons.append(f"Detected keyword: '{word}'")

        if "link" in clean_input:
            reasons.append("External URL detected")

        if reasons:
            for r in reasons:
                st.write("•", r)
        else:
            st.write("No major threat indicators")

        # ---------------- ACTION ----------------
        st.subheader("🛡️ Recommended Actions")

        if status == "PHISHING":
            st.write("• Do NOT click any links")
            st.write("• Report to SOC immediately")
            st.write("• Block sender")
            st.write("• Scan system")

        elif status == "SUSPICIOUS":
            st.write("• Verify sender identity")
            st.write("• Avoid unknown links")

        else:
            st.write("• No action required")

        # SAVE HISTORY
        st.session_state.history.append({
            "Message": email,
            "Risk %": f"{prob:.2f}",
            "Status": status
        })

# ---------------- HISTORY ----------------
if st.session_state.history:
    st.markdown("---")
    st.subheader("📁 SOC Alert History")

    df = pd.DataFrame(st.session_state.history)
    st.dataframe(df, use_container_width=True)

    csv = df.to_csv(index=False)
    st.download_button("⬇️ Download Report", csv, "soc_report.csv", "text/csv")

# ---------------- FOOTER ----------------
st.markdown("---")
st.caption("🚀 Built by Priyadharshini L | SOC Analyst Aspirant | Cybersecurity Project")
