import streamlit as st
import random
import string
import math

from utils import (
    limit_score,
    safety_score,
    risk_label,
    scan_time,
    render_gauge
)


def render_password_tools():

    st.markdown("""
    <div style="border-bottom:2px solid #334155;padding-bottom:12px;margin-bottom:20px;">
        <h1 style="color:white;">🔐 Password Security Hub</h1>
        <p style="color:#94a3b8;">
        Analyze password strength and generate secure passwords.
        </p>
    </div>
    """, unsafe_allow_html=True)

    tab1, tab2 = st.tabs([
        "Password Strength Checker",
        "Password Generator"
    ])

    # ====================================================
    # PASSWORD CHECKER
    # ====================================================

    with tab1:

        password = st.text_input(
            "Enter Password",
            type="password"
        )

        if st.button("🔍 Analyze Password"):

            if not password:

                st.error("Please enter a password.")

                return

            risk = 0
            reasons = []
            recommendations = []

            length = len(password)

            # Length
            if length < 8:

                risk += 35

                reasons.append("Password is too short.")

                recommendations.append(
                    "Use at least 12 characters."
                )

            elif length < 12:

                risk += 15

                reasons.append(
                    "Password length is acceptable but could be stronger."
                )

            # Uppercase

            if not any(c.isupper() for c in password):

                risk += 10

                reasons.append(
                    "No uppercase letters."
                )

                recommendations.append(
                    "Include uppercase letters."
                )

            # Lowercase

            if not any(c.islower() for c in password):

                risk += 10

                reasons.append(
                    "No lowercase letters."
                )

                recommendations.append(
                    "Include lowercase letters."
                )

            # Numbers

            if not any(c.isdigit() for c in password):

                risk += 10

                reasons.append(
                    "No numeric characters."
                )

                recommendations.append(
                    "Include numbers."
                )

            # Symbols

            symbols = "!@#$%^&*()-_=+[]{}<>?/"

            if not any(c in symbols for c in password):

                risk += 15

                reasons.append(
                    "No special symbols."
                )

                recommendations.append(
                    "Include special characters."
                )

            # Common Passwords

            common = [
                "123456",
                "password",
                "password123",
                "qwerty",
                "admin",
                "welcome",
                "abc123"
            ]

            if password.lower() in common:

                risk = 100

                reasons.append(
                    "Very common password detected."
                )

                recommendations.append(
                    "Never use common passwords."
                )
