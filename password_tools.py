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
            # ENTROPY CALCULATION
            # ====================================================

            charset = 0

            if any(c.islower() for c in password):
                charset += 26

            if any(c.isupper() for c in password):
                charset += 26

            if any(c.isdigit() for c in password):
                charset += 10

            if any(c in symbols for c in password):
                charset += len(symbols)

            entropy = 0

            if charset > 0:
                entropy = round(length * math.log2(charset), 2)

            # ====================================================
            # CRACK TIME ESTIMATE
            # ====================================================

            if entropy < 28:
                crack_time = "Instantly"

            elif entropy < 36:
                crack_time = "Few Minutes"

            elif entropy < 60:
                crack_time = "Several Hours"

            elif entropy < 80:
                crack_time = "Several Years"

            else:
                crack_time = "Millions of Years"

            # ====================================================
            # FINAL SCORES
            # ====================================================

            risk = limit_score(risk)

            safety = safety_score(risk)

            level = risk_label(risk)

            st.markdown("## 📊 Password Analysis")

            c1, c2, c3, c4 = st.columns(4)

            c1.metric("Risk Score", f"{risk}%")

            c2.metric("Safety Score", f"{safety}%")

            c3.metric("Threat Level", level)

            c4.metric("Entropy", f"{entropy} bits")

            st.write(f"**Estimated Crack Time:** {crack_time}")

            st.markdown("---")

            left, right = st.columns([1,2])

            with left:

                fig = render_gauge(safety)

                st.plotly_chart(fig, use_container_width=True)

            with right:

                st.subheader("Security Findings")

                if reasons:

                    for item in reasons:
                        st.error(item)

                else:

                    st.success("Excellent password strength detected.")

            st.markdown("---")

            st.subheader("Recommendations")

            if recommendations:

                shown = []

                for item in recommendations:

                    if item not in shown:

                        shown.append(item)

                        st.info(item)

            else:

                st.success("No recommendations. Your password follows strong security practices.")
                    # ====================================================
    # PASSWORD GENERATOR
    # ====================================================

    with tab2:

        st.subheader("🔑 Secure Password Generator")

        length = st.slider(
            "Password Length",
            min_value=8,
            max_value=32,
            value=16
        )

        use_upper = st.checkbox("Include Uppercase Letters", value=True)
        use_lower = st.checkbox("Include Lowercase Letters", value=True)
        use_numbers = st.checkbox("Include Numbers", value=True)
        use_symbols = st.checkbox("Include Symbols", value=True)

        if st.button("🎲 Generate Password"):

            chars = ""

            if use_upper:
                chars += string.ascii_uppercase

            if use_lower:
                chars += string.ascii_lowercase

            if use_numbers:
                chars += string.digits

            if use_symbols:
                chars += "!@#$%^&*()-_=+[]{}<>?/"

            if not chars:

                st.error(
                    "Please select at least one character type."
                )

            else:

                generated = "".join(
                    random.choice(chars)
                    for _ in range(length)
                )

                st.success("Strong password generated successfully!")

                st.code(generated)

                st.info(
                    "💡 Store this password in a trusted password manager instead of writing it down."
                )

        st.markdown("---")

        st.subheader("Password Security Tips")

        st.markdown("""
- ✅ Use at least **12–16 characters**
- ✅ Combine uppercase, lowercase, numbers and symbols
- ✅ Never reuse passwords across multiple websites
- ✅ Enable Multi-Factor Authentication (MFA)
- ✅ Use a password manager for secure storage
- ✅ Change passwords immediately after any suspected breach
""")

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
