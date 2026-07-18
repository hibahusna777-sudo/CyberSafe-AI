import streamlit as st
import plotly.graph_objects as go
from datetime import datetime

# ==========================================================
# APP INFORMATION
# ==========================================================
APP_NAME = "CyberSafe AI"
VERSION = "0.3"

# ==========================================================
# SCORE HELPERS
# ==========================================================
def limit_score(score):
    """Keep score between 0 and 100."""
    return max(0, min(100, score))


def safety_score(risk):
    """Convert risk score to safety score."""
    return 100 - limit_score(risk)


# ==========================================================
# RISK LABEL
# ==========================================================
def risk_label(risk):
    risk = limit_score(risk)

    if risk >= 80:
        return "Critical 🔴"
    elif risk >= 60:
        return "High 🟠"
    elif risk >= 30:
        return "Medium 🟡"
    else:
        return "Low 🟢"


# ==========================================================
# TIME
# ==========================================================
def scan_time():
    return datetime.now().strftime("%d %b %Y %I:%M %p")


# ==========================================================
# CSS
# ==========================================================
def apply_custom_css():

    st.markdown("""
    <style>

    .stApp{
        background:#0f172a;
        color:white;
    }

    section[data-testid="stSidebar"]{
        background:#111827;
    }

    .stButton>button{
        background:#0284c7;
        color:white;
        border-radius:8px;
        font-weight:bold;
    }

    .stButton>button:hover{
        background:#0369a1;
    }

    div[data-testid="metric-container"]{
        background:#1e293b;
        border:1px solid #334155;
        padding:15px;
        border-radius:10px;
    }

    </style>
    """, unsafe_allow_html=True)


# ==========================================================
# HEADER
# ==========================================================
def render_header(title, subtitle):

    st.markdown(f"""
    <div style="border-bottom:2px solid #334155;padding-bottom:12px;margin-bottom:25px;">
        <h1 style="color:white;">{title}</h1>
        <p style="color:#94a3b8;font-size:17px;">
            {subtitle}
        </p>
    </div>
    """, unsafe_allow_html=True)


# ==========================================================
# FOOTER
# ==========================================================
def render_footer():

    st.markdown("---")

    st.markdown(f"""
    <div style="text-align:center;color:gray;">
        © {datetime.now().year} CyberSafe AI v{VERSION}
    </div>
    """, unsafe_allow_html=True)


# ==========================================================
# GAUGE
# ==========================================================
def render_gauge(score):

    fig = go.Figure(go.Indicator(

        mode="gauge+number",

        value=score,

        gauge={

            "axis":{"range":[0,100]},

            "bar":{"color":"green"},

            "steps":[

                {"range":[0,30],"color":"red"},

                {"range":[30,70],"color":"orange"},

                {"range":[70,100],"color":"green"}

            ]

        }

    ))

    fig.update_layout(
        height=250,
        paper_bgcolor="rgba(0,0,0,0)",
        font={"color":"white"}
    )

    return fig
