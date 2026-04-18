import streamlit as st
import pandas as pd
import sqlite3
import joblib
import os
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# ---------------- DB SETUP ----------------
conn = sqlite3.connect("soc_app.db", check_same_thread=False)
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS users(
    username TEXT, password TEXT
)''')

c.execute('''CREATE TABLE IF NOT EXISTS alerts(
    username TEXT, message TEXT, risk REAL, status TEXT
)''')

conn.commit()

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
        return joblib.load("model.pkl"), joblib.load("vectorizer.pkl")

    data = pd.read_csv("sms.tsv", sep='\t', names=["label", "message"])
    data['label'] = data['label'].map({'ham': 0, 'spam': 1})
    data['message'] = data['message'].apply(clean_text)

    vectorizer = TfidfVectorizer(stop_words='english')
    X = vectorizer.fit_transform(data['message'])
    y = data['label']

    model = MultinomialNB()
    model.fit(X, y)

    joblib.dump(model, "model.pkl")
    joblib.dump(vectorizer, "vectorizer.pkl")

    return model, vectorizer

model, vectorizer = load_model()

# ---------------- SESSION ----------------
if "user" not in st.session_state:
    st.session_state.user = None

# ---------------- LOGIN PAGE ----------------
def login():
    st.title("🔐 Login / Signup")

    choice = st.radio("Select", ["Login", "Signup"])

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if choice == "Signup":
        if st.button("Create Account"):
            c.execute("INSERT INTO users VALUES (?, ?)", (username, password))
            conn.commit()
            st.success("Account created!")

    if choice == "Login":
        if st.button("Login"):
            c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
            data = c.fetchone()
            if data:
                st.session_state.user = username
                st.success("Login successful")
            else:
                st.error("Invalid credentials")

# ---------------- DASHBOARD ----------------
def dashboard():

    st.sidebar.title(f"👤 {st.session_state.user}")
    menu = st.sidebar.radio("Navigation", ["Home", "Analyze", "History", "Profile", "Logout"])

    if menu == "Home":
        st.title("🏠 SOC Dashboard")
        st.info("Welcome to Phishing Detection System")

    elif menu == "Analyze":
        st.title("🔍 Analyze Message")

        email = st.text_area("Enter message")

        if st.button("Analyze"):
            clean_input = clean_text(email)
            input_data = vectorizer.transform([clean_input])
            prob = model.predict_proba(input_data)[0][1] * 100

            if prob > 70:
                status = "PHISHING"
                st.error("🔴 High Risk")
            elif prob > 40:
                status = "SUSPICIOUS"
                st.warning("🟠 Medium Risk")
            else:
                status = "SAFE"
                st.success("🟢 Safe")

            st.write(f"Risk Score: {prob:.2f}%")

            c.execute("INSERT INTO alerts VALUES (?, ?, ?, ?)",
                      (st.session_state.user, email, prob, status))
            conn.commit()

    elif menu == "History":
        st.title("📁 Alert History")

        df = pd.read_sql_query(
            f"SELECT * FROM alerts WHERE username='{st.session_state.user}'", conn)
        st.dataframe(df)

    elif menu == "Profile":
        st.title("👤 Profile")
        st.write(f"Username: {st.session_state.user}")

    elif menu == "Logout":
        st.session_state.user = None
        st.rerun()

# ---------------- MAIN ----------------
if st.session_state.user:
    dashboard()
else:
    login()
