import streamlit as st
import re

from utils import (
    limit_score,
    safety_score,
    risk_label,
    scan_time,
    render_gauge
)


def render_email_scanner():

    st.markdown("""
    <div style="border-bottom:2px solid #334155;padding-bottom:12px;margin-bottom:20px;">
        <h1 style="color:white;">📧 AI Email Threat Scanner</h1>
        <p style="color:#94a3b8;">
        Analyze suspicious emails using AI-powered phishing heuristics.
        </p>
    </div>
    """, unsafe_allow_html=True)

    email_text = st.text_area(
        "Paste Email Content",
        height=250,
        placeholder="""
From: security@paypal-alert.com

Subject: Verify your account immediately

Dear Customer,

Your account has been suspended.

Click below to verify your account.

https://paypal-login-security.com

Regards,
Support Team
"""
    )

    if st.button("🔍 Scan Email", type="primary"):

        if not email_text.strip():
            st.error("Please paste an email first.")
            return

        risk = 0
        reasons = []
        recommendations = []

        email = email_text.lower()

        # -------------------------------------------------
        # Suspicious Keywords
        # -------------------------------------------------

        keywords = [
            "verify",
            "urgent",
            "login",
            "password",
            "account",
            "bank",
            "paypal",
            "bitcoin",
            "gift",
            "free",
            "update",
            "click here",
            "confirm",
            "limited time",
            "suspended",
            "security alert"
        ]

        found = []

        for word in keywords:
            if word in email:
                found.append(word)

        if found:
            risk += len(found) * 6
            reasons.append(
                "Suspicious keywords detected: " +
                ", ".join(found)
            )

            recommendations.append(
                "Never trust emails requesting urgent verification."
            )

        # -------------------------------------------------
        # URL Detection
        # -------------------------------------------------

        urls = re.findall(r'https?://[^\s]+', email)

        if urls:

            risk += 20

            reasons.append(
                f"{len(urls)} URL(s) detected inside email."
            )

            recommendations.append(
                "Inspect every link before clicking."
            )

        # -------------------------------------------------
        # Urgency Detection
        # -------------------------------------------------

        urgent_words = [
            "immediately",
            "urgent",
            "within 24 hours",
            "expire",
            "warning",
            "final notice"
        ]

        urgency = []

        for word in urgent_words:
            if word in email:
                urgency.append(word)

        if urgency:

            risk += 15

            reasons.append(
                "Urgent language used to pressure the victim."
            )

            recommendations.append(
                "Legitimate companies rarely pressure users into immediate action."
            )
                    # -------------------------------------------------
        # Attachment Detection
        # -------------------------------------------------

        attachment_extensions = [
            ".exe",
            ".zip",
            ".rar",
            ".js",
            ".scr",
            ".bat",
            ".cmd",
            ".vbs",
            ".docm",
            ".xlsm"
        ]

        attachments = []

        for ext in attachment_extensions:
            if ext in email:
                attachments.append(ext)

        if attachments:

            risk += 20

            reasons.append(
                "Potentially dangerous attachment detected: " +
                ", ".join(attachments)
            )

            recommendations.append(
                "Do not open unexpected email attachments."
            )

        # -------------------------------------------------
        # Sender Analysis
        # -------------------------------------------------

        suspicious_domains = [
            ".ru",
            ".xyz",
            ".top",
            ".tk",
            ".click",
            ".gq"
        ]

        for domain in suspicious_domains:
            if domain in email:
                risk += 15

                reasons.append(
                    f"Suspicious sender domain detected ({domain})"
                )

                recommendations.append(
                    "Verify the sender's domain before trusting the email."
                )

                break

        # -------------------------------------------------
        # Financial Scam Detection
        # -------------------------------------------------

        financial_words = [
            "bank",
            "credit card",
            "payment",
            "invoice",
            "refund",
            "wire transfer",
            "bitcoin",
            "crypto"
        ]

        finance = []

        for word in financial_words:
            if word in email:
                finance.append(word)

        if finance:

            risk += 10

            reasons.append(
                "Financial keywords detected: " +
                ", ".join(finance)
            )

            recommendations.append(
                "Never share banking information through email."
            )

        # -------------------------------------------------
        # AI Score Calculation
        # -------------------------------------------------

        risk = limit_score(risk)

        safety = safety_score(risk)

        level = risk_label(risk)

        timestamp = scan_time()

        st.markdown("## 📊 Scan Results")

        c1, c2, c3, c4 = st.columns(4)

        c1.metric("Risk Score", f"{risk}%")

        c2.metric("Safety Score", f"{safety}%")

        c3.metric("Threat Level", level)

        c4.metric("Scan Time", timestamp)
                st.markdown("---")

        left, right = st.columns([1, 2])

        with left:

            st.subheader("Safety Meter")

            fig = render_gauge(safety)

            st.plotly_chart(fig, use_container_width=True)

        with right:

            st.subheader("Detection Results")

            if reasons:

                for reason in reasons:
                    st.error(reason)

            else:

                st.success(
                    "No phishing indicators were detected."
                )

        st.markdown("---")

        st.subheader("Security Recommendations")

        if recommendations:

            shown = []

            for rec in recommendations:

                if rec not in shown:
                    shown.append(rec)
                    st.info(rec)

        else:

            st.success(
                "This email appears safe based on the current heuristic analysis."
            )

        st.markdown("---")

        if risk >= 80:

            st.error(
                "🔴 HIGH RISK: This email is highly suspicious. Do NOT click links, open attachments, or provide personal information."
            )

        elif risk >= 50:

            st.warning(
                "🟠 MEDIUM RISK: Proceed carefully. Verify the sender before taking any action."
            )

        else:

            st.success(
                "🟢 LOW RISK: No major phishing indicators were detected."
            )
