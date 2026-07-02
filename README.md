# PacketVision: Network Packet Sniffer & Anomaly Detector

**PacketVision** is a real-time network traffic sniffer, parser, and cybersecurity anomaly detection application. Built using Python, Scapy, and Streamlit, it provides a sleek, dark-themed diagnostic dashboard that visualizes active network streams, aggregates protocol statistics, and logs potential security threats like Port Scans and TCP SYN Flood attacks.

Designed specifically as an engineering portfolio project, it showcases low-level network packet decoding, multi-threaded state management, and algorithmic anomaly detection.

---

## 🌟 Key Features

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

## 🛠️ Technology Stack

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

---

## ⚙️ Installation & Setup

### 1. Clone or Move to the Directory
Ensure all project files are located in your working folder:
```bash
cd /Users/nujuom/Downloads/network-analyzer
```

### 2. Create a Virtual Environment (Recommended)
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🚀 Running the Application

### Option A: Running in Demo/Simulation Mode (Recommended for Demos)
You do **not** need administrator privileges to run the simulator. Simply execute:
```bash
streamlit run app.py
```
This will open your default browser to `http://localhost:8501`. Toggle **Start Sniffer** in the sidebar, and you will see realistic traffic metrics, live charts, and mock threat warnings populate in real-time.

### Option B: Running in Live Capture Mode (Requires Admin/Sudo)
To capture real packets flowing through your physical Wi-Fi or Ethernet card:
1. Open a terminal and run the Streamlit app.
2. (Optional) On macOS or Linux, raw socket capture requires administrative access. You can run the dashboard with elevated privileges:
```bash
sudo streamlit run app.py
```
3. Set the Sniffing Mode to **"Live Sniffing"** in the sidebar, select your network adapter interface (e.g., `en0` on macOS), and click **Start Sniffer**.

---

## 🔬 Computer Engineering Concepts Implemented

*   **Asynchronous Multi-Threading:** The sniffing engine runs on a dedicated background thread, preventing network latency or blocking operations from freezing the UI thread.
*   **Thread-Safe Buffers:** Utilizes Python thread locks (`threading.Lock`) to safely read and write to the shared circular buffer of packet metrics.
*   **State Machine Anomaly Filtering:** Employs temporal grouping (10-second windows) and hash-map indexing to analyze packet counts per unique port/IP, tracking socket state transitions.
*   **Data Decoupling Model:** Decouples the low-level socket wiretapping pipeline (`sniffer.py`) from the visualization layer (`app.py`), enabling high-speed processing without UI rendering bottlenecks.
