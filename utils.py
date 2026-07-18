import streamlit as st
import plotly.graph_objects as go
from datetime import datetime

# ==========================================================
# APP INFORMATION
# ==========================================================
APP_NAME = "CyberSafe AI"
VERSION = "3.0"

# ==========================================================
# SCORE HELPERS
# ==========================================================
def limit_score(score: float) -> float:
    """
    Keeps score strictly bound between 0 and 100.
    """
    if score < 0:
        return 0
    if score > 100:
        return 100
    return score


def safety_score(risk: float) -> float:
    """
    Converts a risk score into an inverse safety score.
    """
    risk = limit_score(risk)
    return 100 - risk


# ==========================================================
# RISK LABELS
# ==========================================================
def risk_label(risk: float) -> str:
    """
    Maps numerical risk value to threat evaluation bands.
    """
    risk = limit_score(risk)

    if risk >= 80:
        return "Critical"
    elif risk >= 60:
        return "High"
    elif risk >= 30:
        return "Medium"
    return "Low"


# ==========================================================
# DATE AND TIME UTILITIES
# ==========================================================
def scan_time() -> str:
    """
    Generates a localized, clean string representation of the current execution timestamp.
    """
    return datetime.now().strftime("%d %b %Y %I:%M %p")


# ==========================================================
# UI & STYLING COMPONENT ENGINE
# ==========================================================
def apply_custom_css():
    """
    Injects custom CSS stylesheets into the Streamlit app interface.
    """
    st.markdown(
        """
        <style>
        /* CSS Overrides for Dark Industrial Blue Theme */
        .stApp {
            background-color: #0f172a;
            color: #f8fafc;
        }
        header[data-testid="stHeader"] {
            background-color: #0f172a;
        }
        div[data-testid="stSidebar"] {
            background-color: #1e293b;
            border-right: 1px solid #334155;
        }
        .stButton>button {
            background-color: #0284c7 !important;
            color: #ffffff !important;
            border-radius: 6px !important;
            border: 1px solid #0369a1 !important;
            font-weight: 600 !important;
            transition: all 0.3s ease;
        }
        .stButton>button:hover {
            background-color: #0369a1 !important;
            border-color: #38bdf8 !important;
            box-shadow: 0 0 10px rgba(56, 189, 248, 0.4);
        }
        div[data-testid="metric-container"] {
            background-color: #1e293b;
            border: 1px solid #334155;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        }
        div[data-baseweb="tab-list"] {
            background-color: #0f172a;
        }
        div[data-baseweb="tab"] {
            color: #94a3b8 !important;
        }
        div[data-baseweb="tab"][aria-selected="true"] {
            color: #38bdf8 !important;
            border-bottom-color: #38bdf8 !important;
        }
        </style>
        """,
        unsafe_allow_html=True
    )


def render_header(title: str, subtitle: str):
    """
    Renders standardized title layout banners.
    """
    st.markdown(f"""
<div style="border-bottom: 2px solid #334155; padding-bottom: 12px; margin-bottom: 25px;">
...
</div>
""", unsafe_allow_html=True)


def render_footer():
    """
    Unified application copyright and execution metadata module.
    """
    st.markdown("---")
    st.markdown(
        f"""
        <div style="text-align: center; color: #64748b; font-size: 13px; padding: 10px 0;">
            {APP_NAME} v{VERSION} © {datetime.now().year} Sandbox Operations. Local isolation mode active.
        </div>
        """,
        unsafe_allow_html=True
    )


def render_gauge(score: float) -> go.Figure:
    """
    Returns a Plotly Donut Gauge object for reporting telemetry scores.
    """
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#94a3b8"},
            'bar': {'color': "#10b981" if score >= 70 else "#fb923c" if score >= 40 else "#f43f5e"},
            'bgcolor': "#1e293b",
            'borderwidth': 1,
            'bordercolor': "#334155"
        }
    ))
    fig.update_layout(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font={'color': "#f8fafc"},
        height=200,
        margin=dict(l=10, r=10, t=30, b=10)
    )
    return fig
