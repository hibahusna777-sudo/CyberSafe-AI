import streamlit as st
import plotly.graph_objects as go

from email_scanner import render_email_scanner
from url_scanner import render_url_scanner
from password_tools import render_password_tools

from utils import (
    apply_custom_css,
    render_header,
    render_footer
)

# -------------------------------------------------------
# PAGE CONFIG
# -------------------------------------------------------

st.set_page_config(
    page_title="CyberSafe AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

apply_custom_css()

# -------------------------------------------------------
# SIDEBAR
# -------------------------------------------------------

st.sidebar.title("🛡️ CyberSafe AI")
st.sidebar.caption("Version 0.3")

menu = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Email Threat Scanner",
        "URL Threat Scanner",
        "Password Security Hub"
    ]
)

st.sidebar.markdown("---")

st.sidebar.success("🟢 AI Engine Online")
st.sidebar.info("Threat Database Updated")
st.sidebar.write("TLS 1.3 Enabled")

# -------------------------------------------------------
# DASHBOARD
# -------------------------------------------------------

if menu == "Dashboard":

    render_header(
        "CyberSafe AI",
        "AI Powered Cyber Security Awareness Platform"
    )

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Threat Database", "4.2M")
    c2.metric("AI Engines", "14")
    c3.metric("System Status", "Secure")
    c4.metric("Response Time", "12 ms")

    st.divider()

    left, right = st.columns(2)

    with left:

        gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=18,
            title={"text": "Overall Risk"},
            gauge={
                "axis":{"range":[0,100]},
                "bar":{"color":"green"},
                "steps":[
                    {"range":[0,30],"color":"green"},
                    {"range":[30,70],"color":"orange"},
                    {"range":[70,100],"color":"red"}
                ]
            }
        ))

        st.plotly_chart(gauge,use_container_width=True)

    with right:

        pie = go.Figure(
            data=[
                go.Pie(
                    labels=[
                        "Emails",
                        "URLs",
                        "Passwords",
                        "Others"
                    ],
                    values=[
                        40,
                        30,
                        20,
                        10
                    ],
                    hole=.5
                )
            ]
        )

        st.plotly_chart(pie,use_container_width=True)

    st.divider()

    st.success("CyberSafe AI is ready to scan emails, URLs and passwords.")

# -------------------------------------------------------
# EMAIL
# -------------------------------------------------------

elif menu == "Email Threat Scanner":

    render_email_scanner()

# -------------------------------------------------------
# URL
# -------------------------------------------------------

elif menu == "URL Threat Scanner":

    render_url_scanner()

# -------------------------------------------------------
# PASSWORD
# -------------------------------------------------------

elif menu == "Password Security Hub":

    render_password_tools()

render_footer()
