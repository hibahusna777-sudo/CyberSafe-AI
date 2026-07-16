import streamlit as st
import plotly.express as px
import pandas as pd
import re
import random
import string
from datetime import datetime

# ----------------------------
# PAGE CONFIG
# ----------------------------

st.set_page_config(
    page_title="CyberSafe AI",
    page_icon="🛡️",
    layout="wide"
)

# ----------------------------
# CUSTOM CSS
# ----------------------------

st.markdown("""
<style>

.main{
    background:#0E1117;
}

.block-container{
    padding-top:1.5rem;
}

div[data-testid="metric-container"]{
    background:#1E293B;
    border-radius:15px;
    padding:15px;
    border:1px solid #334155;
}

.stButton>button{
    width:100%;
    border-radius:10px;
    height:45px;
    font-weight:bold;
}

</style>
""", unsafe_allow_html=True)

# ----------------------------
# SIDEBAR
# ----------------------------

st.sidebar.title("🛡️ CyberSafe AI")

menu = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Dashboard",
        "📧 Email Scanner",
        "🌐 URL Checker",
        "🔐 Password Checker",
        "🎲 Password Generator",
        "ℹ️ About"
    ]
)

# ----------------------------
# DASHBOARD
# ----------------------------

if menu == "🏠 Dashboard":

    st.title("🛡️ CyberSafe AI")

    st.caption("AI Powered Cyber Security Assistant")

    st.markdown("---")

    c1,c2,c3,c4=st.columns(4)

    with c1:
        st.metric("Modules","4")

    with c2:
        st.metric("Threat Engine","AI")

    with c3:
        st.metric("Status","Secure")

    with c4:
        st.metric("Version","2.0")

    st.markdown("---")

    left,right=st.columns([2,1])

    with left:

        data=pd.DataFrame({

            "Module":[
                "Email Scanner",
                "URL Checker",
                "Password Checker",
                "Password Generator"
            ],

            "Health":[100,100,100,100]

        })

        fig=px.bar(

            data,

            x="Health",

            y="Module",

            orientation="h",

            text="Health",

            color="Module"

        )

        fig.update_layout(

            height=350,

            showlegend=False,

            margin=dict(l=20,r=20,t=20,b=20)

        )

        st.plotly_chart(

            fig,

            use_container_width=True

        )

    with right:

        st.success("🟢 Email Scanner Online")

        st.success("🟢 URL Checker Online")

        st.success("🟢 Password Checker Online")

        st.success("🟢 Password Generator Online")

        st.info("""
CyberSafe AI protects users by:

• Detecting phishing emails

• Checking suspicious URLs

• Evaluating password strength

• Generating secure passwords
""")
        # ==========================================================
# EMAIL SCANNER
# ==========================================================

elif menu == "📧 Email Scanner":

    st.title("📧 AI Email Phishing Scanner")

    email = st.text_area(
        "Paste Email Content",
        height=250
    )

    if st.button("🔍 Analyze Email"):

        if email.strip() == "":
            st.warning("Please paste an email first.")

        else:

            risk = 0
            reasons = []

            text = email.lower()

            suspicious_words = {
                "urgent":15,
                "verify":15,
                "password":20,
                "bank":15,
                "click":15,
                "gift":10,
                "free":10,
                "bitcoin":20,
                "login":15,
                "otp":20,
                "winner":15,
                "claim":15,
                "limited time":15,
                "update":10,
                "account":10
            }

            for word, weight in suspicious_words.items():

                if word in text:

                    risk += weight
                    reasons.append(word)

            if "http://" in text:
                risk += 20
                reasons.append("HTTP Link")

            if "https://" in text:
                risk += 5

            if "@" in text:
                risk += 5

            if risk > 100:
                risk = 100

            safety = 100 - risk

            st.progress(safety/100)

            col1,col2=st.columns(2)

            with col1:
                st.metric("Safety Score",f"{safety}/100")

            with col2:
                st.metric("Risk Score",f"{risk}/100")

            if risk >= 60:
                st.error("🚨 High Risk Phishing Email")

            elif risk >= 30:
                st.warning("⚠ Suspicious Email")

            else:
                st.success("✅ Safe Email")

            if reasons:

                st.subheader("Detection Reasons")

                for item in reasons:

                    st.write("•",item)

            else:

                st.success("No suspicious indicators found.")

            st.caption(
                f"Scan Time: {datetime.now().strftime('%d %b %Y %I:%M %p')}"
            )

# ==========================================================
# URL CHECKER
# ==========================================================

elif menu=="🌐 URL Checker":

    st.title("🌐 URL Safety Checker")

    url=st.text_input("Enter Website URL")

    if st.button("Check URL"):

        if url.strip()=="":

            st.warning("Enter a URL.")

        else:

            risk=0
            reasons=[]

            test=url.lower()

            if not test.startswith("https://"):

                risk+=25
                reasons.append("Website is not using HTTPS")

            suspicious=[
                "login",
                "verify",
                "update",
                "bank",
                "gift",
                "free",
                "bitcoin",
                "paypal",
                "account"
            ]

            for word in suspicious:

                if word in test:

                    risk+=10
                    reasons.append(word)

            if "@" in test:

                risk+=20
                reasons.append("@ symbol detected")

            if "-" in test:

                risk+=10
                reasons.append("Hyphen in domain")

            if risk>100:
                risk=100

            safety=100-risk

            st.progress(safety/100)

            col1,col2=st.columns(2)

            with col1:
                st.metric("Safety Score",f"{safety}/100")

            with col2:
                st.metric("Risk Score",f"{risk}/100")

            if risk>=60:

                st.error("🚨 Dangerous Website")

            elif risk>=30:

                st.warning("⚠ Suspicious Website")

            else:

                st.success("✅ Safe Website")

            if reasons:

                st.subheader("Detection Results")

                for item in reasons:

                    st.write("•",item)

            else:

                st.success("No suspicious indicators found.")
                # ==========================================================
# PASSWORD CHECKER
# ==========================================================

elif menu == "🔐 Password Checker":

    st.title("🔐 Password Strength Checker")

    password = st.text_input(
        "Enter Password",
        type="password"
    )

    if st.button("Check Password"):

        score = 0
        tips = []

        if len(password) >= 8:
            score += 20
        else:
            tips.append("Use at least 8 characters.")

        if re.search(r"[A-Z]", password):
            score += 20
        else:
            tips.append("Add uppercase letters.")

        if re.search(r"[a-z]", password):
            score += 20
        else:
            tips.append("Add lowercase letters.")

        if re.search(r"\d", password):
            score += 20
        else:
            tips.append("Add numbers.")

        if re.search(r"[!@#$%^&*()_+=<>?/{}|~]", password):
            score += 20
        else:
            tips.append("Add special characters.")

        st.progress(score / 100)

        st.metric("Password Score", f"{score}/100")

        if score >= 80:
            st.success("🟢 Strong Password")

        elif score >= 50:
            st.warning("🟡 Medium Password")

        else:
            st.error("🔴 Weak Password")

        if tips:

            st.subheader("Suggestions")

            for tip in tips:
                st.write("✔", tip)

# ==========================================================
# PASSWORD GENERATOR
# ==========================================================

elif menu == "🎲 Password Generator":

    st.title("🎲 Secure Password Generator")

    length = st.slider(
        "Password Length",
        8,
        32,
        16
    )

    upper = st.checkbox("Uppercase", True)
    lower = st.checkbox("Lowercase", True)
    numbers = st.checkbox("Numbers", True)
    symbols = st.checkbox("Symbols", True)

    if st.button("Generate Password"):

        chars = ""

        if upper:
            chars += string.ascii_uppercase

        if lower:
            chars += string.ascii_lowercase

        if numbers:
            chars += string.digits

        if symbols:
            chars += string.punctuation

        if chars == "":

            st.warning("Select at least one option.")

        else:

            password = "".join(
                random.choice(chars)
                for _ in range(length)
            )

            st.success("Password Generated Successfully")

            st.code(password)

# ==========================================================
# ABOUT
# ==========================================================

elif menu == "ℹ️ About":

    st.title("ℹ️ About CyberSafe AI")

    st.info("""

CyberSafe AI is a cybersecurity awareness application.

Modules Included

• Email Phishing Scanner

• URL Safety Checker

• Password Strength Checker

• Secure Password Generator

The project is developed for educational and cybersecurity awareness purposes.

""")

    st.markdown("---")

    st.subheader("Developer")

    st.success("""
👩‍💻 Husna Shabir Ahmad

Cyber Security Student

Bano Qabil 2026

Version 2.0
""")

    st.caption(
        f"Running Session : {datetime.now().strftime('%d %b %Y %I:%M %p')}"
    )