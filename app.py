import time
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from sniffer import PacketSniffer, SCAPY_AVAILABLE
from detector import AnomalyDetector

# Set page layout and aesthetics
st.set_page_config(
    page_title="PacketVision - Network Security Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom premium dark styling using CSS injections
st.markdown("""
    <style>
        /* Main background and text */
        .stApp {
            background-color: #07080e;
            color: #e2e8f0;
        }
        /* Sidebar styling */
        section[data-testid="stSidebar"] {
            background-color: #0c0d16 !important;
            border-right: 1px solid #1e293b;
        }
        /* Custom metric card class */
        .metric-card {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 16px;
            padding: 20px;
            box-shadow: 0 4px 30px rgba(0, 0, 0, 0.4);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            margin-bottom: 15px;
        }
        .metric-label {
            font-size: 11px;
            font-weight: 700;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 1.5px;
        }
        .metric-value {
            font-size: 28px;
            font-weight: 900;
            color: #f8fafc;
            margin-top: 5px;
            font-family: 'Courier New', Courier, monospace;
        }
        .metric-value.highlight {
            color: #14b8a6;
            text-shadow: 0 0 10px rgba(20, 184, 166, 0.3);
        }
        .metric-value.alert {
            color: #f43f5e;
            text-shadow: 0 0 10px rgba(244, 63, 94, 0.3);
        }
        
        /* Custom headers */
        h1, h2, h3 {
            font-family: 'Inter', sans-serif;
            font-weight: 800 !important;
            letter-spacing: -0.5px;
        }
        
        /* Threat Log Alert styling */
        .alert-box {
            padding: 12px 16px;
            border-radius: 8px;
            margin-bottom: 10px;
            font-size: 13px;
            border-left: 5px solid;
            color: #f8fafc;
        }
        .alert-box.high {
            background-color: rgba(244, 63, 94, 0.1);
            border-left-color: #f43f5e;
        }
        .alert-box.medium {
            background-color: rgba(245, 158, 11, 0.1);
            border-left-color: #f59e0b;
        }
        
        /* Radar status blinker */
        .blinker {
            display: inline-block;
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background-color: #10b981;
            margin-right: 8px;
            animation: blink 1.5s infinite;
        }
        .blinker.inactive {
            background-color: #ef4444;
        }
        @keyframes blink {
            0% { opacity: 0.3; }
            50% { opacity: 1; }
            100% { opacity: 0.3; }
        }
    </style>
""", unsafe_allow_html=True)

# Initialize Session States
if "sniffer" not in st.session_state:
    st.session_state.sniffer = None
if "detector" not in st.session_state:
    st.session_state.detector = AnomalyDetector()
if "is_sniffing" not in st.session_state:
    st.session_state.is_sniffing = False

# Sidebar Configuration Controls
st.sidebar.title("🛡️ PacketVision")
st.sidebar.caption("Network Security Analysis Dashboard")
st.sidebar.markdown("---")

# Capture Mode Settings
st.sidebar.subheader("Configuration")
mode_option = st.sidebar.radio(
    "Sniffing Mode",
    ["Demo Mode (Simulation)", "Live Sniffing (Requires Root/Sudo)"],
    index=0 if not SCAPY_AVAILABLE else 0,
    help="Demo mode simulates realistic network traffic. Live sniffing uses Scapy to monitor physical adapters."
)

interface_list = ["default", "en0", "en1", "eth0", "lo0"]
selected_iface = st.sidebar.selectbox("Network Interface", interface_list, disabled=(mode_option == "Demo Mode (Simulation)"))

st.sidebar.markdown("---")

# Threhold Settings for Anomalies
st.sidebar.subheader("Threat Detection Thresholds")
scan_thresh = st.sidebar.slider("Port Scan Limit (ports/10s)", 5, 50, 15)
syn_thresh = st.sidebar.slider("SYN Flood Limit (packets/10s)", 10, 100, 40)

# Apply settings updates to the detector
st.session_state.detector.port_scan_threshold = scan_thresh
st.session_state.detector.syn_flood_threshold = syn_thresh

# Start/Stop Button Logic
st.sidebar.markdown("---")
if st.session_state.is_sniffing:
    stop_clicked = st.sidebar.button("🟥 STOP SNIFFER", use_container_width=True)
    if stop_clicked:
        if st.session_state.sniffer:
            st.session_state.sniffer.stop()
        st.session_state.is_sniffing = False
        st.rerun()
else:
    start_clicked = st.sidebar.button("🟢 START SNIFFER", use_container_width=True)
    if start_clicked:
        simulation = (mode_option == "Demo Mode (Simulation)")
        st.session_state.sniffer = PacketSniffer(
            interface=None if selected_iface == "default" else selected_iface,
            simulation_mode=simulation
        )
        st.session_state.sniffer.start()
        st.session_state.is_sniffing = True
        st.rerun()

# Clear Data Button
if st.sidebar.button("🧹 Clear Captured Logs", use_container_width=True):
    if st.session_state.sniffer:
        st.session_state.sniffer.stop()
    st.session_state.detector.clear_alerts()
    st.session_state.is_sniffing = False
    st.session_state.sniffer = None
    st.rerun()

# Header Status Banner
status_html = ""
if st.session_state.is_sniffing:
    status_html = f'<div style="margin-bottom: 25px;"><span class="blinker"></span><span style="font-weight: bold; color: #10b981;">TELEMETRY ACTIVE</span> (Running in {"Simulation" if st.session_state.sniffer.simulation_mode else "Live"} Mode)</div>'
else:
    status_html = '<div style="margin-bottom: 25px;"><span class="blinker inactive"></span><span style="font-weight: bold; color: #ef4444;">TELEMETRY STANDBY</span> (Start the sniffer in the sidebar)</div>'
st.markdown(status_html, unsafe_allow_html=True)

# Main Dashboard Title
st.title("Network Security Telemetry")
st.markdown("A real-time network traffic sniffer, parser, and anomaly threat analysis workspace.")

# Layout for Live Dashboard (Static components outside the loop)
if st.session_state.is_sniffing:
    # 1. Placeholders for Metric Cards
    metrics_placeholder = st.empty()
    
    # 2. Placeholders for Charts
    charts_placeholder = st.empty()
    
    # 3. Columns for Alert Logs and Packet Flow
    log_col, table_col = st.columns([1, 2])
    
    with log_col:
        st.subheader("⚠️ Threat Detection Log")
        alerts_placeholder = st.empty()
        
    with table_col:
        st.subheader("📥 Live Raw Packet Flow")
        search_ip = st.text_input("Filter by IP address (Source or Destination)", "", key="ip_filter")
        table_placeholder = st.empty()

    # Real-time Telemetry Loop
    while st.session_state.is_sniffing:
        # Fetch latest statistics
        stats = st.session_state.sniffer.get_stats()
        df = st.session_state.sniffer.get_packets_df()
        
        # Run anomaly analysis
        alerts = st.session_state.detector.analyze_packets(df, stats["bandwidth_bps"])
        
        # 1. Update Metrics
        with metrics_placeholder.container():
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-label">Packets Scanned</div>
                        <div class="metric-value">{stats["total_packets"]:,}</div>
                    </div>
                """, unsafe_allow_html=True)
            with col2:
                data_mb = stats["total_bytes"] / (1024 * 1024)
                st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-label">Total Data Captured</div>
                        <div class="metric-value">{data_mb:.2f} MB</div>
                    </div>
                """, unsafe_allow_html=True)
            with col3:
                kbps = (stats["bandwidth_bps"] * 8) / 1000.0
                st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-label">Network Bandwidth</div>
                        <div class="metric-value highlight">{kbps:.1f} Kbps</div>
                    </div>
                """, unsafe_allow_html=True)
            with col4:
                alert_count = len([a for a in alerts if a["Severity"] == "High"])
                alert_class = "alert" if alert_count > 0 else "highlight"
                st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-label">Security Alerts</div>
                        <div class="metric-value {alert_class}">{len(alerts)}</div>
                    </div>
                """, unsafe_allow_html=True)

        # 2. Update Charts
        with charts_placeholder.container():
            chart_col1, chart_col2 = st.columns([1, 1])
            with chart_col1:
                st.subheader("Protocol Distribution")
                if stats["protocol_counts"]:
                    proto_df = pd.DataFrame(list(stats["protocol_counts"].items()), columns=["Protocol", "Count"])
                    fig_proto = px.pie(
                        proto_df, 
                        values="Count", 
                        names="Protocol",
                        hole=0.4,
                        color_discrete_sequence=px.colors.sequential.Tealgrn
                    )
                    fig_proto.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font_color='#e2e8f0',
                        margin=dict(t=10, b=10, l=10, r=10),
                        height=260
                    )
                    st.plotly_chart(fig_proto, use_container_width=True)
                else:
                    st.info("Gathering protocol telemetry...")
            with chart_col2:
                st.subheader("Top Traffic Senders")
                if stats["top_senders"]:
                    sender_df = pd.DataFrame(list(stats["top_senders"].items()), columns=["IP Address", "Packet Count"])
                    fig_sender = px.bar(
                        sender_df,
                        x="Packet Count",
                        y="IP Address",
                        orientation="h",
                        color="Packet Count",
                        color_continuous_scale="teal"
                    )
                    fig_sender.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font_color='#e2e8f0',
                        margin=dict(t=10, b=10, l=10, r=10),
                        height=260,
                        coloraxis_showscale=False
                    )
                    st.plotly_chart(fig_sender, use_container_width=True)
                else:
                    st.info("Gathering IP telemetry...")

        # 3. Update Alerts
        with alerts_placeholder.container():
            if alerts:
                for alert in reversed(alerts):
                    severity_class = alert["Severity"].lower()
                    st.markdown(f"""
                        <div class="alert-box {severity_class}">
                            <strong>[{alert["Time"]}] {alert["Type"]}</strong><br/>
                            Source: {alert["Source"]} | Severity: {alert["Severity"]}<br/>
                            {alert["Description"]}
                        </div>
                    """, unsafe_allow_html=True)
            else:
                st.success("No anomalies detected in the network stream.")

        # 4. Update Table
        with table_placeholder.container():
            if not df.empty:
                display_df = df.copy()
                if search_ip:
                    display_df = display_df[
                        (display_df['Source'].str.contains(search_ip, case=False, na=False)) |
                        (display_df['Destination'].str.contains(search_ip, case=False, na=False))
                    ]
                st.dataframe(
                    display_df[["Time", "Source", "Destination", "Protocol", "Length", "Info"]].tail(50),
                    use_container_width=True,
                    height=300
                )
            else:
                st.info("Waiting for incoming network packets...")
                
        time.sleep(1)

# Standby Dashboard Layout (when not sniffing)
if not st.session_state.is_sniffing:
    st.info("The telemetry dashboard is currently on standby. Use the sidebar controls to start sniffing packets.")
    
    # Standby preview mock elements for presentation
    st.markdown("---")
    st.subheader("Sample Dashboard Overview")
    preview_col1, preview_col2 = st.columns(2)
    with preview_col1:
        st.markdown("""
            ### System Capabilities:
            *   **Real-time Analysis:** Performs wiretapping-level packet filtering and deep packet inspection.
            *   **Automated Threat Logging:** Uses a security logic layer to identify DOS flood patterns and active port scanners.
            *   **Compatibility:** Operates in a safe Simulation/Demo mode for presentations without security elevation.
        """)
    with preview_col2:
        st.markdown("""
            ### Network Layer Decoders:
            *   **Layer 2:** Ethernet, Address Resolution Protocol (ARP)
            *   **Layer 3:** IPv4, IPv6, ICMP (Ping)
            *   **Layer 4:** Transmission Control Protocol (TCP), User Datagram Protocol (UDP)
            *   **Layer 7:** Domain Name System (DNS), HTTP
        """)
