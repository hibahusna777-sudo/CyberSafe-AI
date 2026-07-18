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

    st.title("📧 AI Email Threat Scanner")
    """
    Renders the heuristic Email Threat Assessment module within the Streamlit workspace.
    Processes textual payloads for lexical anomalies, structural indicators, and routing targets.
    """
    st.markdown(
        """
        <div style="border-bottom: 2px solid #334155; padding-bottom: 12px; margin-bottom: 25px;">
            <h1 style="color: #f8fafc; font-weight: 700; margin-bottom: 4px;">🛡️ Email Threat Scanner</h1>
            <p style="color: #94a3b8; font-size: 16px; margin: 0;">Heuristic payload scanning for malicious markers and indicators of compromise (IoC).</p>
        </div>
        """, 
        unsafe_allow_html=True
    )
    
    email_content = st.text_area(
        "Paste Email Content",
        height=250,
        placeholder="Input raw message body or email headers for defensive evaluation..."
    )
    
    if st.button("Execute Core Heuristics Scan", type="primary"):
        if not email_content.strip():
            st.warning("Analysis halted: Text payload evaluation surface cannot be null.")
            return

        reasons = []
        recommendations = []
        risk_points = 0

        # Heuristic 1: Targeted Keyword Matrix Evaluation
        keywords = [
            "urgent", "verify", "password", "bank", "click", "gift", "free", 
            "bitcoin", "login", "otp", "winner", "claim", "limited time", "update", "account"
        ]
        matched_keywords = [kw for kw in keywords if re.search(r'\b' + re.escape(kw) + r'\b', email_content, re.IGNORECASE)]
        
        if matched_keywords:
            reasons.append(f"High-risk credential harvesting/phishing flags flagged: {', '.join(matched_keywords)}")
            risk_points += len(matched_keywords) * 10
            recommendations.append("Exercise absolute caution. Do not click links matching financial, imperative, or urgency-based text constructs.")

        # Heuristic 2: Plaintext Transmission Schemes (HTTP Links)
        http_links = re.findall(r'http://[^\s]+', email_content)
        if http_links:
            reasons.append(f"Unencrypted protocol transport identified: Detected {len(http_links)} instance(s) of plaintext http:// schemas.")
            risk_points += 20
            recommendations.append("Avoid interactions with unencrypted transmission nodes (HTTP); data payload interception vector high.")

        # Heuristic 3: Encrypted Transport Verification (HTTPS Links)
        # Note: Checked as context, minor risk added if excessive to identify link-heavy phishing vectors
        https_links = re.findall(r'https://[^\s]+', email_content)
        if len(https_links) > 3:
            reasons.append(f"Elevated hyperlink frequency density: Contains {len(https_links)} explicit HTTPS references.")
            risk_points += 10
            recommendations.append("Verify structural domain alignments for explicit redirects before accessing secure HTTPS target paths.")

        # Heuristic 4: Obfuscated Redirection Nodes (Shortened URLs)
        shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"]
        found_shorteners = [s for s in shorteners if s in email_content.lower()]
        if found_shorteners:
            reasons.append(f"Network proxy redirect routing found: Alias shorteners resolved ({', '.join(found_shorteners)}).")
            risk_points += 20
            recommendations.append("Pass all obfuscated or shortened links through an expansion utility before execution.")

        # Heuristic 5: Direct Host Network Mappings (IP Addresses)
        ip_references = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', email_content)
        if ip_references:
            reasons.append(f"Bypassed DNS mapping detected: Raw IP endpoints present ({', '.join(ip_references)}).")
            risk_points += 25
            recommendations.append("Flag emails routing users directly to raw network blocks rather than certified domain namespaces.")

        # Heuristic 6: Target Harvester Identification (Email Addresses)
        emails_found = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', email_content)
        if len(emails_found) > 2:
            reasons.append(f"Data dissemination profile: Contains {len(emails_found)} cross-referenced email strings.")
            risk_points += 5

        # Heuristic 7: Case Variance Exploitation (Excessive CAPITAL LETTERS)
        words = email_content.split()
        if len(words) > 8:
            caps_words = [w for w in words if w.isupper() and len(w) > 1 and w.isalpha()]
            if (len(caps_words) / len(words)) > 0.30:
                reasons.append("Social engineering panic threshold matched: High concentration of UPPERCASE characters.")
                risk_points += 15
                recommendations.append("Do not respond to communicative pressures employing manufactured synthetic urgency profiles.")

        # Heuristic 8: Punctuation Abuse (Too many exclamation marks)
        exclamation_count = email_content.count('!')
        if exclamation_count > 3:
            reasons.append(f"Punctuation anomalies observed: Abnormal exclamation concentration ({exclamation_count} markers).")
            risk_points += 10

        # Heuristic 9: Darknet Topology Targets (.onion links)
        if ".onion" in email_content.lower():
            reasons.append("Tor network hidden-service resource locator (.onion) addressed inside structural body.")
            risk_points += 35
            recommendations.append("Treat hidden darknet addresses inside unexpected contexts as critical infiltration vector flags.")

        # Finalize Telemetry Calculations
        calc_risk = limit_score(risk_points)
        calc_safety = safety_score(calc_risk)
        label_threat = risk_label(calc_risk)
        timestamp = scan_time()

        # Render Metrics and Telemetry Panel
        st.markdown("### 📊 Scan Summary & Telemetry Matrix")
        
        m_col1, m_col2, m_col3, m_col4 = st.columns(4)
        with m_col1:
            st.metric("Calculated Risk Index", f"{calc_risk}%")
        with m_col2:
            st.metric("Calculated Safety Index", f"{calc_safety}%")
        with m_col3:
            st.metric("Assigned Threat Tier", label_threat)
        with m_col4:
            st.metric("System Timestamp", timestamp.split()[0])

        st.markdown("---")

        c_left, c_right = st.columns([1, 2])
        
        with c_left:
            st.markdown("#### Safety Profile Visualization")
            fig = render_gauge(calc_safety)
            st.plotly_chart(fig, use_container_width=True)

        with c_right:
            st.markdown("#### Heuristic Diagnostic Log")
            if not reasons:
               st.markdown(
    "✅ <span style='color:#10b981; font-weight:600;'>Zero signature threats matched during deep static analysis execution.</span>",
    unsafe_allow_html=True
)
            else:
                for reason in reasons:
                   st.markdown(
    f"❌ <span style='color:#f43f5e; font-weight:500;'>{reason}</span>",
    unsafe_allow_html=True
)

        st.markdown("---")
        st.markdown("#### 🛠️ Security Deficit Remediation Plan")
        if not recommendations:
            st.markdown("🟢 System posture healthy. Maintain standard data tracking protections.")
        else:
            for rec in recommendations:
                st.markdown(
    f"▪️ <span style='color:#38bdf8;'>{rec}</span>",
    unsafe_allow_html=True
)
