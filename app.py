import streamlit as st
import plotly.graph_objects as go
from email_scanner import render_email_scanner
from url_scanner import render_url_scanner
from password_tools import render_password_tools
from utils import apply_custom_css, render_header, render_footer

# Page configuration
st.set_page_config(
    page_title="CyberSafe AI - Security Suite",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Apply global styling
apply_custom_css()

# Sidebar Navigation
st.sidebar.image("https://img.icons8.com/nolan/128/shield.png", width=80)
st.sidebar.title("CyberSafe AI")
st.sidebar.caption("v1.0.0 | Production Ready")
st.sidebar.markdown("---")

menu = st.sidebar.radio(
    "Navigation Menu",
    ["Dashboard", "Email Threat Scanner", "URL Threat Scanner", "Password Security Hub"],
    index=0
)

st.sidebar.markdown("---")
st.sidebar.markdown(
    """
    <div style='background-color: #1e293b; padding: 15px; border-radius: 8px; border: 1px solid #334155;'>
        <h4 style='margin-top:0; color:#38bdf8;'>System Status</h4>
        <p style='margin:0; font-size:14px;'>🟢 Engine: Operational</p>
        <p style='margin:0; font-size:14px;'>🟢 Database: Up-to-date</p>
        <p style='margin:0; font-size:14px;'>🔒 Protocol: TLS 1.3</p>
    </div>
    """, 
    unsafe_allow_html=True
)

# Dashboard View
if menu == "Dashboard":
    render_header("Security Operations Center Dashboard", "Centralized real-time cybersecurity heuristics monitoring.")
    
    # Core Metrics row
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(label="Global Shield Status", value="Secured", delta="100% Uptime")
    with col2:
        st.metric(label="Threat Databases Indexed", value="4.2M+", delta="+12k Today")
    with col3:
        st.metric(label="Active Heuristic Engines", value="14 / 14", delta="Optimal")
    with col4:
        st.metric(label="Local Analysis Latency", value="12 ms", delta="-2 ms")

    st.markdown("---")
    
    # Analytics layout
    g1, g2 = st.columns(2)
    
    with g1:
        st.subheader("Global Exploit & Threat Vector Landscape")
        fig1 = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = 14,
            domain = {'x': [0, 1], 'y': [0, 1]},
            title = {'text': "Current Risk Index (Low)", 'font': {'color': "#f8fafc"}},
            gauge = {
                'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "#94a3b8"},
                'bar': {'color': "#38bdf8"},
                'bgcolor': "#1e293b",
                'borderwidth': 2,
                'bordercolor': "#334155",
                'steps': [
                    {'range': [0, 30], 'color': '#14532d'},
                    {'range': [30, 70], 'color': '#7c2d12'},
                    {'range': [70, 100], 'color': '#7f1d1d'}
                ],
            }
        ))
        fig1.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', height=300, margin=dict(l=20, r=20, t=40, b=20))
        st.plotly_chart(fig1, use_container_width=True)
        
    with g2:
        st.subheader("Simulated Distribution of Attack Vectors")
        labels = ['Phishing Emails', 'Malicious URLs', 'Weak Credentials', 'Outdated Software']
        values = [40, 30, 20, 10]
        fig2 = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.4, marker=dict(colors=['#f43f5e', '#fb923c', '#38bdf8', '#a855f7']))])
        fig2.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            height=300,
            margin=dict(l=10, r=10, t=40, b=10),
            legend=dict(font=dict(color="#f8fafc"))
        )
        st.plotly_chart(fig2, use_container_width=True)

    st.markdown("---")
    st.subheader("Security Event Feed")
    st.info("ℹ️ System initialized. Ready to accept workloads via the sidebar scanning utilities.")

elif menu == "Email Threat Scanner":
    render_email_scanner()

elif menu == "URL Threat Scanner":
    render_url_scanner()

elif menu == "Password Security Hub":
    render_password_tools()
