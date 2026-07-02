import time
import random
import threading
from collections import Counter
import pandas as pd

# Try to import scapy for live sniffing. If it fails or is not installed, we fallback to simulation mode.
try:
    from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, DNS, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class PacketSniffer:
    def __init__(self, interface=None, simulation_mode=False):
        self.interface = interface
        self.simulation_mode = simulation_mode or not SCAPY_AVAILABLE
        self.running = False
        self.thread = None
        
        # Thread-safe packet storage and statistics
        self.lock = threading.Lock()
        self.packets = []          # List of processed packet dicts
        self.max_packets = 1000     # Circular buffer size
        
        # Metrics
        self.total_bytes = 0
        self.protocol_counts = Counter()
        self.ip_src_counts = Counter()
        self.ip_dst_counts = Counter()
        
        # Live bandwidth tracker
        self.bandwidth_history = []  # List of (timestamp, byte_count)
        self.current_bps = 0
        
        # Common lists for mock packet generation
        self.mock_ips = [
            "192.168.1.1", "192.168.1.54", "192.168.1.107", 
            "10.0.0.12", "8.8.8.8", "1.1.1.1", "172.217.16.142",
            "142.250.190.46", "204.79.197.200", "185.190.140.12"
        ]
        self.mock_domains = ["google.com", "github.com", "netflix.com", "amazon.com", "local-router.home"]

    def start(self):
        with self.lock:
            if self.running:
                return
            self.running = True
            
        # Reset counters
        self.total_bytes = 0
        self.protocol_counts.clear()
        self.ip_src_counts.clear()
        self.ip_dst_counts.clear()
        self.packets.clear()
        self.bandwidth_history.clear()
        
        if self.simulation_mode:
            print("[PacketVision] Starting in SIMULATION MODE...")
            self.thread = threading.Thread(target=self._run_simulation, daemon=True)
        else:
            print(f"[PacketVision] Starting LIVE SNIFFING on interface: {self.interface or 'default'}...")
            self.thread = threading.Thread(target=self._run_live_sniff, daemon=True)
            
        self.thread.start()

    def stop(self):
        with self.lock:
            self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None
        print("[PacketVision] Sniffing stopped.")

    def _process_packet_data(self, src_ip, dst_ip, src_port, dst_port, protocol, size, info):
        """Processes packet metrics and adds to circular buffer."""
        timestamp = time.time()
        
        with self.lock:
            # Update metrics
            self.total_bytes += size
            self.protocol_counts[protocol] += 1
            self.ip_src_counts[src_ip] += 1
            self.ip_dst_counts[dst_ip] += 1
            
            # Record byte count for bandwidth tracking
            self.bandwidth_history.append((timestamp, size))
            
            # Keep bandwidth history within last 60 seconds
            cutoff = timestamp - 60
            self.bandwidth_history = [item for item in self.bandwidth_history if item[0] > cutoff]
            
            # Append packet data
            packet_entry = {
                "Time": time.strftime("%H:%M:%S", time.localtime(timestamp)),
                "Timestamp": timestamp,
                "Source": src_ip,
                "Destination": dst_ip,
                "Protocol": protocol,
                "Length": size,
                "Info": info,
                "SrcPort": src_port,
                "DstPort": dst_port
            }
            
            self.packets.append(packet_entry)
            if len(self.packets) > self.max_packets:
                self.packets.pop(0)

    def _run_live_sniff(self):
        """Raw socket sniffer using Scapy."""
        try:
            sniff(
                iface=self.interface,
                prn=self._scapy_packet_callback,
                stop_filter=lambda x: not self.running,
                store=0
            )
        except Exception as e:
            print(f"[PacketVision] Live sniffing error: {e}. Switching to simulation mode.")
            self.simulation_mode = True
            self._run_simulation()

    def _scapy_packet_callback(self, pkt):
        """Scapy packet handler parser."""
        if not self.running:
            return
            
        size = len(pkt)
        src_ip = "N/A"
        dst_ip = "N/A"
        src_port = "N/A"
        dst_port = "N/A"
        protocol = "ETHERNET"
        info = pkt.summary()
        
        # Parse IP Layer
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            protocol = "IPv4"
            
            # Parse TCP Layer
            if pkt.haslayer(TCP):
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                protocol = "TCP"
                flags = pkt[TCP].underlayer.sprintf('%TCP.flags%') if hasattr(pkt[TCP], 'underlayer') else ""
                info = f"TCP: {src_port} -> {dst_port} Flags: [{flags}] Seq={pkt[TCP].seq}"
                
            # Parse UDP Layer
            elif pkt.haslayer(UDP):
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                protocol = "UDP"
                info = f"UDP: {src_port} -> {dst_port} Len={pkt[UDP].len}"
                
                # Parse DNS Layer inside UDP
                if pkt.haslayer(DNS):
                    protocol = "DNS"
                    if pkt[DNS].qd:
                        qname = pkt[DNS].qd.qname.decode('utf-8', errors='ignore') if isinstance(pkt[DNS].qd.qname, bytes) else pkt[DNS].qd.qname
                        info = f"DNS Query: {qname}"
                        
            # Parse ICMP Layer
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"
                info = f"ICMP Type: {pkt[ICMP].type} Code: {pkt[ICMP].code}"
                
        # Parse ARP Layer
        elif pkt.haslayer(ARP):
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            protocol = "ARP"
            op = "who-has" if pkt[ARP].op == 1 else "is-at"
            info = f"ARP: {op} {pkt[ARP].pdst} tell {pkt[ARP].psrc}"
            
        self._process_packet_data(src_ip, dst_ip, src_port, dst_port, protocol, size, info)

    def _run_simulation(self):
        """Generates mock packets for visualization and testing."""
        # Simulated scan parameters to trigger the anomaly detector
        scammer_ip = "192.168.1.205"
        scan_ports = list(range(20, 100))
        scan_index = 0
        
        while self.running:
            # Randomize standard protocols
            protocol = random.choice(["TCP", "UDP", "DNS", "ICMP", "ARP", "HTTP"])
            size = random.randint(40, 1500)
            src_ip = random.choice(self.mock_ips)
            dst_ip = random.choice([ip for ip in self.mock_ips if ip != src_ip])
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 53, 22, 8080, 123])
            
            # Occasional port scan anomaly generation (5% chance)
            if random.random() < 0.05:
                src_ip = scammer_ip
                dst_port = scan_ports[scan_index]
                scan_index = (scan_index + 1) % len(scan_ports)
                protocol = "TCP"
                info = f"TCP Connection Attempt: {src_port} -> {dst_port} [SYN]"
                size = 64
            # Standard protocols description
            elif protocol == "TCP":
                flags = random.choice(["S", "A", "FA", "PA"])
                info = f"TCP: {src_port} -> {dst_port} Flags=[{flags}] Seq={random.randint(10000, 99999)}"
            elif protocol == "UDP":
                info = f"UDP: {src_port} -> {dst_port} Len={size - 28}"
            elif protocol == "DNS":
                src_port = 53
                domain = random.choice(self.mock_domains)
                info = f"DNS Standard Query: A {domain}"
                size = random.randint(60, 120)
            elif protocol == "HTTP":
                protocol = "TCP"
                dst_port = 80
                info = f"HTTP GET /index.html HTTP/1.1"
                size = random.randint(200, 800)
            elif protocol == "ICMP":
                info = "ICMP Echo Request (Ping)"
                size = 64
            elif protocol == "ARP":
                src_ip = "192.168.1.1"
                dst_ip = "192.168.1.54"
                info = "ARP: who-has 192.168.1.54 tell 192.168.1.1"
                size = 42

            self._process_packet_data(src_ip, dst_ip, src_port, dst_port, protocol, size, info)
            
            # Dynamic sleep to simulate varying traffic rates
            time.sleep(random.uniform(0.05, 0.3))

    def get_packets_df(self):
        """Returns the packet log as a Pandas DataFrame."""
        with self.lock:
            if not self.packets:
                return pd.DataFrame(columns=["Time", "Source", "Destination", "Protocol", "Length", "Info"])
            return pd.DataFrame(self.packets.copy())

    def get_stats(self):
        """Returns aggregated metrics for dashboard gauges and charts."""
        with self.lock:
            # Calculate current Bandwidth (Bps) over the last 3 seconds
            now = time.time()
            recent_bytes = sum(size for ts, size in self.bandwidth_history if ts > (now - 3))
            current_bps = recent_bytes / 3.0
            
            return {
                "total_packets": len(self.packets),
                "total_bytes": self.total_bytes,
                "bandwidth_bps": current_bps,
                "protocol_counts": dict(self.protocol_counts),
                "top_senders": dict(self.ip_src_counts.most_common(5)),
                "top_receivers": dict(self.ip_dst_counts.most_common(5))
            }
