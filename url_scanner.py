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
    """
    Renders the universal cryptographic structural URL parser and risk analyzer.
    Performs precise semantic analysis against standard structural Indicators of Compromise (IoC).
    """
    st.markdown(
        """
        <div style="border-bottom: 2px solid #334155; padding-bottom: 12px; margin-bottom: 25px;">
            <h1 style="color: #f8fafc; font-weight: 700; margin-bottom: 4px;">🛡️ URL Threat Scanner</h1>
            <p style="color: #94a3b8; font-size: 16px; margin: 0;">Structural parsing engine designed to identify domain spoofing, redirection proxies, and transport layer weaknesses.</p>
        </div>
        """, 
        unsafe_allow_html=True
    )

    url_input = st.text_input(
        "Input Cryptographic / Uniform Resource Identifier (URI) Target", 
        placeholder="Example: http://secure-login-update-paypal@192.168.1.105:8080/free-gift/index.html"
    )

    if st.button("Execute Vector Parsing Scan", type="primary"):
        if not url_input.strip():
            st.error("Execution halted: Structural parse surface cannot be a null string value.")
            return

        reasons = []
        recommendations = []
        risk_points = 0
        
        # Format normalization boundary
        target_url = url_input.strip()
        if not re.match(r'^https?://', target_url, re.IGNORECASE):
            target_url = "http://" + target_url

        try:
            parsed = urlparse(target_url)
            netloc = parsed.netloc.lower()
            path = parsed.path.lower()
            full_lower = target_url.lower()
        except Exception:
            st.error("Structural Analysis Failure: Passed string cannot be parsed as a standard network resource locator.")
            return

        # 1. Transport Layer Cryptographic Verification (HTTPS/HTTP)
        if url_input.strip().lower().startswith("https://"):
            st.caption("🟢 Transport Security Layer Verified: HTTPS transport active.")
        elif url_input.strip().lower().startswith("http://"):
            reasons.append("Plaintext Protocol Active: Insecure HTTP transport profile exposed.")
            risk_points += 25
            recommendations.append("Do not transmit sensitive credential matrices across cleartext HTTP data pipes.")

        # 2. Raw Host Endpoint Verification (IP Address Detection)
        ip_pattern = r'(?:\d{1,3}\.){3}\d{1,3}'
        if re.search(ip_pattern, netloc):
            reasons.append("Structural Domain Masking: Endpoint points to raw IPv4 allocation block.")
            risk_points += 30
            recommendations.append("Raw node connections circumvent traditional authoritative DNS verification trails.")

        # 3. Redirection / Obfuscation Proxies (URL Shortener Detection)
        shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "goo.gl", "ow.ly"]
        found_shorteners = [s for s in shorteners if s in netloc]
        if found_shorteners:
            reasons.append(f"Proxy Obfuscation Token Identified: Known link compressor found ({found_shorteners[0]}).")
            risk_points += 20
            recommendations.append("Force full expansion parameters via API lookup tools before execution of redirected path endpoints.")

        # 4. Inline Authorization Hijacking (@ Symbol Detection)
        if "@" in netloc or (parsed.username and "@" in parsed.username):
            reasons.append("Inline Credential Masking Abuse: URL structure contains localized authentication symbol (@).")
            risk_points += 25
            recommendations.append("Phishing variants use inline authentication tokens to mask true malicious server origins.")

        # 5. Domain Token Segmentation (Hyphen Domain Detection)
        domain_part = netloc.split(':')[0] if ':' in netloc else netloc
        if domain_part.count("-") > 2:
            reasons.append(f"Excessive Subdomain Segmentation: Abnormal hyphen padding in base domain cluster ({domain_part.count('-')} counts).")
            risk_points += 15
            recommendations.append("Legitimate corporate spaces rarely utilize multi-hyphen layouts to register target entities.")

        # 6. Buffer Exceedance Vectors (Long URL Detection)
        if len(url_input) > 75:
            reasons.append(f"Target String Exceeds Length Heuristics: Length is {len(url_input)} characters.")
            risk_points += 15
            recommendations.append("Phishers intentionally scale URL lengths to push the malicious component past active viewport barriers.")

        # 7. Semantic Phishing Vectors (Suspicious Keywords Detection)
        keywords = ["login", "verify", "account", "paypal", "bank", "bitcoin", "free", "gift", "update", "password", "secure"]
        matched_keywords = [kw for kw in keywords if kw in full_lower]
        if matched_keywords:
            reasons.append(f"High-vulnerability keyword string collision: Identified keywords {matched_keywords}")
            risk_points += len(matched_keywords) * 10
            recommendations.append("Cross-reference host signatures directly with authentic authoritative enterprise portals.")

        # 8. Darknet Anonymizer Routing Target (.onion Detection)
        if ".onion" in netloc:
            reasons.append("Anonymized Darknet Service Mapping: Resolves into Tor Network hidden space (.onion TLD).")
            risk_points += 40
            recommendations.append("Only connect to hidden services if secure proxy paths have been audited and explicitly verified.")

        # 9. Multiple Subdomains Detection
        # Splitting domain blocks while dropping potential tracking extensions or zones
        clean_domain_str = domain_part.replace("www.", "")
        subdomain_count = clean_domain_str.count(".")
        if subdomain_count >= 3:
            reasons.append(f"Deep Subdomain Architecture: Multi-level subdomains detected ({subdomain_count} layer depths).")
            risk_points += 15
            recommendations.append("Verify the actual root tracking authority (right-most segment before TLD) to ensure authentic host paths.")

        # 10. Non-Standard Transport Ports (Port Number Detection)
        try:
            if parsed.port and parsed.port not in [80, 443]:
                reasons.append(f"Non-Standard Interface Binding: Target requests communication via arbitrary network port {parsed.port}.")
                risk_points += 20
                recommendations.append("Inspect host routing architecture to verify that open services are not hiding proxy shells.")
        except ValueError:
            reasons.append("Malformed Boundary Segment: Target includes out-of-bounds structural port formatting.")
            risk_points += 15

        # Consolidate Structural Risk Matrices
        final_risk = limit_score(risk_points)
        final_safety = safety_score(final_risk)
        threat_tier = risk_label(final_risk)
        execution_timestamp = scan_time()

        # Telemetry Display Panel
        st.markdown("### 📊 Structural Risk Diagnostics Matrix")

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Risk Score", f"{final_risk}%")
        with col2:
            st.metric("Safety Score", f"{final_safety}%")
        with col3:
            st.metric("Threat Level", threat_tier)
        with col4:
            st.metric("Scan Timestamp", execution_timestamp.split()[0])

        st.markdown("---")

        left_layout, right_layout = st.columns([1, 2])

        with left_layout:
            st.markdown("#### Safety Profile Metric")
            fig = render_gauge(final_safety)
            st.plotly_chart(fig, use_container_width=True)

        with right_layout:
            st.markdown("#### Diagnostic Findings Log")
            if not reasons:
                st.markdown(
    "✅ <span style='color:#10b981; font-weight:600;'>Zero signature threats matched during deep URL verification scans.</span>",
    unsafe_allow_html=True
)
            else:
                for reason in reasons:
                   st.markdown(
    f"❌ <span style='color:#fb923c; font-weight:500;'>{reason}</span>",
    unsafe_allow_html=True
)

        st.markdown("---")
        st.markdown("#### 🛠️ Security Infrastructure Recommendations")
        if not recommendations:
            st.markdown("🟢 Base configuration maps clean. Maintain automated perimeter detection profiles.")
        else:
            for rec in recommendations:
                st.markdown(
    f"▪️ <span style='color:#38bdf8;'>{rec}</span>",
    unsafe_allow_html=True
)
