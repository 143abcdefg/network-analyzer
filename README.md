# PacketVision: Network Packet Sniffer & Anomaly Detector

**PacketVision** is a real-time network traffic sniffer, parser, and cybersecurity anomaly detection application. Built using Python, Scapy, and Streamlit, it provides a sleek, dark-themed diagnostic dashboard that visualizes active network streams, aggregates protocol statistics, and logs potential security threats like Port Scans and TCP SYN Flood attacks.

Designed specifically as an engineering portfolio project, it showcases low-level network packet decoding, multi-threaded state management, and algorithmic anomaly detection.

---

##  Key Features

*   **Multi-Layer Protocol Parsing:** Decodes Ethernet, IPv4, TCP (including flags), UDP, ICMP, DNS (queries and resolutions), and HTTP.
*   **Real-Time Analytics Dashboard:**
    *   **Telemetry Gauges:** Live bandwidth measurement (Kbps), total packet counters, and data volume tracking.
    *   **Interactive Visualizations:** Live charts displaying protocol distributions and active network conversations.
    *   **Live Packet Flow:** A searchable, filterable log of raw packets flowing through the network.
*   **Cybersecurity Intrusion Detection (IDS):**
    *   **Port Scan Detection:** Alerts if a single source IP targets more than 15 unique ports in a 10-second window.
    *   **TCP SYN Flood Detection:** Recognizes DOS attempt patterns by flag-tracking TCP packets.
    *   **Bandwidth Spike Alarm:** Highlights sudden traffic volume increases.
*   **Dual Mode Compatibility:**
    *   **Live Capture Mode:** Accesses raw network sockets on active Wi-Fi/Ethernet adapters using Scapy.
    *   **Simulation/Demo Mode:** Generates realistic, structured network traffic locally. **No root/administrator permissions (`sudo`) required**, making it perfect for rapid demos and presentations.

---

##  Technology Stack

*   **Programming Language:** Python
*   **Packet Handling Engine:** Scapy
*   **Web Dashboard Framework:** Streamlit
*   **Data Structures & Analytics:** Pandas, NumPy
*   **Data Visualization:** Plotly Express

---

## 📁 Directory Structure

```directory
network-analyzer/
├── app.py          # Streamlit UI layout, custom CSS, and reactive loop
├── sniffer.py      # PacketSniffer thread, Scapy callback, and simulator fallback
├── detector.py     # Anomaly detection logic (Port scan, SYN Flood, traffic spikes)
├── requirements.txt# Application dependencies
└── README.md       # Project documentation (this file)
```



## 🔬 Computer Engineering Concepts Implemented

*   **Asynchronous Multi-Threading:** The sniffing engine runs on a dedicated background thread, preventing network latency or blocking operations from freezing the UI thread.
*   **Thread-Safe Buffers:** Utilizes Python thread locks (`threading.Lock`) to safely read and write to the shared circular buffer of packet metrics.
*   **State Machine Anomaly Filtering:** Employs temporal grouping (10-second windows) and hash-map indexing to analyze packet counts per unique port/IP, tracking socket state transitions.
*   **Data Decoupling Model:** Decouples the low-level socket wiretapping pipeline (`sniffer.py`) from the visualization layer (`app.py`), enabling high-speed processing without UI rendering bottlenecks.
