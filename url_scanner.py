import streamlit as st
import re
from urllib.parse import urlparse

from utils import (
    limit_score,
    safety_score,
    risk_label,
    scan_time,
    render_gauge
)


def render_url_scanner():

    st.markdown("""
    <div style="border-bottom:2px solid #334155;
                padding-bottom:12px;
                margin-bottom:20px;">
        <h1 style="color:white;">
            🌐 AI URL Threat Scanner
        </h1>

        <p style="color:#94a3b8;">
            Analyze websites for phishing, spoofing and malicious indicators.
        </p>

    </div>
    """, unsafe_allow_html=True)

    url = st.text_input(
        "Enter Website URL",
        placeholder="https://google.com"
    )

    if st.button("🔍 Scan URL", type="primary"):

        if not url.strip():

            st.error("Please enter a valid URL.")

            return

        target = url.strip()

        # Add protocol automatically

        if not re.match(r"^https?://", target, re.IGNORECASE):
            target = "http://" + target

        try:

            parsed = urlparse(target)

        except Exception:

            st.error("Invalid URL.")

            return

        host = parsed.netloc.lower()

        path = parsed.path.lower()

        full_url = target.lower()

        risk = 0

        reasons = []

        recommendations = []

        # ==========================================
        # HTTPS CHECK
        # ==========================================

        if parsed.scheme == "https":

            reasons.append(
                "HTTPS encryption detected."
            )

        else:

            risk += 15

            reasons.append(
                "Website uses HTTP instead of HTTPS."
            )

            recommendations.append(
                "Avoid entering passwords or payment information on HTTP websites."
            )

        # ==========================================
        # IP ADDRESS CHECK
        # ==========================================

        ip_regex = r"^(?:\d{1,3}\.){3}\d{1,3}$"

        domain = host.split(":")[0]

        if re.match(ip_regex, domain):

            risk += 35

            reasons.append(
                "Website uses an IP address instead of a domain."
            )

            recommendations.append(
                "Legitimate organizations usually use domain names."
            )

        # ==========================================
        # URL SHORTENER
        # ==========================================

        shorteners = [

            "bit.ly",

            "tinyurl.com",

            "t.co",

            "is.gd",

            "goo.gl",

            "ow.ly"

        ]

        for item in shorteners:

            if item in domain:

                risk += 20

                reasons.append(
                    f"Shortened URL detected ({item})."
                )

                recommendations.append(
                    "Expand shortened URLs before opening them."
                )

                break

        # ==========================================
        # @ SYMBOL
        # ==========================================

        if "@" in full_url:

            risk += 25

            reasons.append(
                "@ symbol detected in URL."
            )

            recommendations.append(
                "Attackers often use @ to hide the real destination."
            )
                    # ==========================================
        # SUSPICIOUS KEYWORDS
        # ==========================================

        keywords = [
            "login",
            "verify",
            "update",
            "secure",
            "account",
            "bank",
            "paypal",
            "bitcoin",
            "free",
            "gift",
            "password",
            "signin"
        ]

        matched = []

        for word in keywords:

            if word in full_url:

                matched.append(word)

        if matched:

            risk += min(len(matched) * 8, 30)

            reasons.append(
                "Suspicious keywords detected: " +
                ", ".join(matched)
            )

            recommendations.append(
                "Always verify the website before entering credentials."
            )

        # ==========================================
        # LONG URL
        # ==========================================

        if len(full_url) > 100:

            risk += 10

            reasons.append(
                f"Very long URL detected ({len(full_url)} characters)."
            )

            recommendations.append(
                "Long URLs can hide malicious content."
            )

        # ==========================================
        # TOO MANY HYPHENS
        # ==========================================

        if domain.count("-") >= 3:

            risk += 10

            reasons.append(
                "Multiple hyphens detected in domain."
            )

            recommendations.append(
                "Phishing websites often imitate brands using hyphens."
            )

        # ==========================================
        # SUBDOMAINS
        # ==========================================

        clean = domain.replace("www.", "")

        if clean.count(".") >= 3:

            risk += 10

            reasons.append(
                "Multiple subdomains detected."
            )

            recommendations.append(
                "Verify the real domain name carefully."
            )

        # ==========================================
        # NON STANDARD PORT
        # ==========================================

        try:

            if parsed.port and parsed.port not in [80, 443]:

                risk += 15

                reasons.append(
                    f"Non-standard port detected ({parsed.port})."
                )

                recommendations.append(
                    "Unexpected ports may indicate suspicious services."
                )

        except:

            pass

        # ==========================================
        # .ONION
        # ==========================================

        if ".onion" in domain:

            risk += 40

            reasons.append(
                "Tor (.onion) address detected."
            )

            recommendations.append(
                "Only access Tor services if you trust the source."
            )

        # ==========================================
        # FINAL SCORE
        # ==========================================

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

                for item in reasons:
                    st.warning(item)

            else:

                st.success(
                    "No suspicious indicators detected."
                )

        st.markdown("---")

        st.subheader("Security Recommendations")

        if recommendations:

            shown = []

            for item in recommendations:

                if item not in shown:

                    shown.append(item)

                    st.info(item)

        else:

            st.success(
                "No security recommendations. The URL appears safe."
            )

        st.markdown("---")

        if risk >= 80:

            st.error(
                "🔴 HIGH RISK: This website appears highly suspicious. Do NOT enter passwords or payment information."
            )

        elif risk >= 50:

            st.warning(
                "🟠 MEDIUM RISK: Proceed carefully and verify the website before continuing."
            )

        elif risk >= 20:

            st.info(
                "🟡 LOW RISK: Minor security concerns were detected."
            )

        else:

            st.success(
                "🟢 SAFE: No major phishing indicators were detected."
            )
