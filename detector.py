import time
from collections import defaultdict

class AnomalyDetector:
    def __init__(self, port_scan_threshold=15, syn_flood_threshold=40):
        self.port_scan_threshold = port_scan_threshold
        self.syn_flood_threshold = syn_flood_threshold
        self.alerts = []
        
        # Keep track of recently alerted events to avoid spamming the same alert
        self.last_alert_time = {}

    def analyze_packets(self, packets_df, current_bandwidth_bps):
        """Analyzes recent packets for security threats and returns new alerts."""
        if packets_df.empty:
            return self.alerts

        current_time = time.time()
        new_alerts = []

        # Filter packets from the last 10 seconds for temporal analysis
        ten_seconds_ago = current_time - 10
        recent_packets = packets_df[packets_df['Timestamp'] > ten_seconds_ago]

        if not recent_packets.empty:
            # 1. Port Scan Detection
            self._detect_port_scans(recent_packets, current_time, new_alerts)
            
            # 2. SYN Flood Detection
            self._detect_syn_floods(recent_packets, current_time, new_alerts)

        # 3. Bandwidth Spike Detection (using live Bps calculation)
        self._detect_bandwidth_spikes(current_bandwidth_bps, current_time, new_alerts)

        # Append new alerts to historical alerts log (keeping last 100 alerts)
        if new_alerts:
            self.alerts.extend(new_alerts)
            self.alerts = self.alerts[-100:]  # Limit history
            
        return self.alerts

    def _detect_port_scans(self, df, current_time, new_alerts):
        # Group destination ports by source IP
        port_scan_candidates = defaultdict(set)
        for _, row in df.iterrows():
            src = row['Source']
            dst_port = row['DstPort']
            if src != "N/A" and dst_port != "N/A":
                port_scan_candidates[src].add(dst_port)

        for ip, ports in port_scan_candidates.items():
            if len(ports) >= self.port_scan_threshold:
                alert_key = f"port_scan_{ip}"
                # Rate limit alert to once every 15 seconds per IP
                if current_time - self.last_alert_time.get(alert_key, 0) > 15:
                    self.last_alert_time[alert_key] = current_time
                    new_alerts.append({
                        "Time": time.strftime("%H:%M:%S", time.localtime(current_time)),
                        "Type": "Port Scan Detected",
                        "Source": ip,
                        "Severity": "High",
                        "Description": f"Source IP scanned {len(ports)} unique ports in < 10 seconds."
                    })

    def _detect_syn_floods(self, df, current_time, new_alerts):
        # Filter for TCP SYN packets
        tcp_df = df[df['Protocol'] == 'TCP']
        if tcp_df.empty:
            return

        syn_counts = defaultdict(int)
        for _, row in tcp_df.iterrows():
            src = row['Source']
            info = str(row['Info'])
            if src != "N/A" and "Flags=[S]" in info or "[SYN]" in info:
                syn_counts[src] += 1

        for ip, count in syn_counts.items():
            if count >= self.syn_flood_threshold:
                alert_key = f"syn_flood_{ip}"
                # Rate limit alert to once every 15 seconds per IP
                if current_time - self.last_alert_time.get(alert_key, 0) > 15:
                    self.last_alert_time[alert_key] = current_time
                    new_alerts.append({
                        "Time": time.strftime("%H:%M:%S", time.localtime(current_time)),
                        "Type": "TCP SYN Flood Attack",
                        "Source": ip,
                        "Severity": "High",
                        "Description": f"Suspected flood: {count} connection requests (SYN) in < 10 seconds."
                    })

    def _detect_bandwidth_spikes(self, bps, current_time, new_alerts):
        mbps = (bps * 8) / 1_000_000.0  # Convert Bytes/sec to Megabits/sec
        threshold_mbps = 50.0  # 50 Mbps threshold for a spike (e.g. large download/DDoS)
        
        # Simulation mode has lower speeds, let's lower the spike threshold in simulation
        # For demonstration purposes, if traffic gets high, trigger it
        if mbps > threshold_mbps:
            alert_key = "bandwidth_spike"
            # Rate limit to once every 30 seconds
            if current_time - self.last_alert_time.get(alert_key, 0) > 30:
                self.last_alert_time[alert_key] = current_time
                new_alerts.append({
                    "Time": time.strftime("%H:%M:%S", time.localtime(current_time)),
                    "Type": "Bandwidth Spike",
                    "Source": "Internal Interface",
                    "Severity": "Medium",
                    "Description": f"Network traffic spike detected: {mbps:.2f} Mbps (Threshold: {threshold_mbps} Mbps)."
                })

    def clear_alerts(self):
        self.alerts.clear()
        self.last_alert_time.clear()
