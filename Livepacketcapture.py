from scapy.all import sniff, ARP, DNS, TCP, IP
import pandas as pd
import time
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict
import requests

# Data structures for monitoring traffic
arp_features = []
dns_queries = defaultdict(list)
arp_counts = defaultdict(lambda: {"requests": 0, "replies": 0, "unique_dst": set(), "unique_mac": set()})
target_ip_counts = defaultdict(int)
port_scans = defaultdict(set)

# Initialize ML models
scaler = StandardScaler()
isolation_forest = IsolationForest(contamination=0.05, random_state=42)

# Feature extraction functions
def extract_arp_features(packet):
    return {
        "time": time.time(),
        "src_ip": packet.psrc,
        "dst_ip": packet.pdst,
        "src_mac": packet.hwsrc,
        "dst_mac": packet.hwdst,
        "op": packet.op,  # ARP operation: 1=request, 2=reply
    }

# Update ARP traffic statistics
def update_arp_stats(features):
    src_ip = features["src_ip"]
    arp_counts[src_ip]["unique_dst"].add(features["dst_ip"])
    arp_counts[src_ip]["unique_mac"].add(features["src_mac"])
    if features["op"] == 1:  # ARP request
        arp_counts[src_ip]["requests"] += 1
    elif features["op"] == 2:  # ARP reply
        arp_counts[src_ip]["replies"] += 1

# ARP Spoofing Detection
def process_arp_packet(packet):
    global arp_features

    if packet.haslayer(ARP):
        print("ARP packet detected.")
        features = extract_arp_features(packet)
        update_arp_stats(features)

        # Append features for ML analysis
        arp_features.append([
            features["src_ip"],
            len(arp_counts[features["src_ip"]]["unique_dst"]),
            len(arp_counts[features["src_ip"]]["unique_mac"]),
            arp_counts[features["src_ip"]]["requests"],
            arp_counts[features["src_ip"]]["replies"],
        ])

        # Run anomaly detection if enough data is collected
        if len(arp_features) > 50:
            print("Analyzing ARP traffic...")
            df = pd.DataFrame(arp_features, columns=[
                "src_ip", "unique_dst_count", "unique_mac_count", "request_count", "reply_count"
            ])
            feature_data = df[["unique_dst_count", "unique_mac_count", "request_count", "reply_count"]]
            scaled_features = scaler.fit_transform(feature_data)
            isolation_forest.fit(scaled_features)
            anomalies = isolation_forest.predict(scaled_features)
            df["anomaly"] = anomalies

            anomalous_ips = df[df["anomaly"] == -1]["src_ip"].unique()
            if len(anomalous_ips) > 0:
                print(f"[ARP Spoofing Detected] Anomalous IPs: {anomalous_ips}")

# DNS Cache Poisoning Detection
def process_dns_packet(packet):
    if packet.haslayer(DNS):
        query = packet[DNS].qd.qname.decode() if packet[DNS].qd else None
        src_ip = packet[IP].src if packet.haslayer(IP) else None
        dst_ip = packet[IP].dst if packet.haslayer(IP) else None
        answer_ips = [rr.rdata for rr in packet[DNS].an] if packet[DNS].an else []

        if query:
            dns_key = (src_ip, query)
            dns_queries[dns_key].append({
                "time": time.time(),
                "dst_ip": dst_ip,
                "answers": answer_ips,
            })

            if len(dns_queries[dns_key]) > 1:
                previous_entry = dns_queries[dns_key][-2]
                current_entry = dns_queries[dns_key][-1]
                if previous_entry["answers"] != current_entry["answers"]:
                    print(f"[DNS Cache Poisoning Detected] Query: {query}, IP: {src_ip}")
                    print(f"Inconsistent Answers: {previous_entry['answers']} vs {current_entry['answers']}")

# Port Scanning Detection
def detect_port_scanning(packet):
    if packet.haslayer(TCP):
        src_ip = packet[IP].src if packet.haslayer(IP) else None
        port = packet[TCP].dport if packet.haslayer(TCP) else None
        if src_ip and port:
            port_scans[src_ip].add(port)
            if len(port_scans[src_ip]) > 50:  # Threshold for potential scan
                print(f"[Port Scanning Detected] Source IP: {src_ip}, Ports Scanned: {len(port_scans[src_ip])}")

# DDoS Detection
def detect_ddos(packet):
    dst_ip = packet[IP].dst if packet.haslayer(IP) else None
    if dst_ip:
        target_ip_counts[dst_ip] += 1
        if target_ip_counts[dst_ip] > 100:  # Threshold for high traffic
            print(f"[DDoS Attack Detected] Target IP: {dst_ip}, Request Count: {target_ip_counts[dst_ip]}")

# Malware Traffic Detection
def detect_malware_traffic(packet):
    if packet.haslayer(IP):
        dst_ip = packet[IP].dst
        packet_length = len(packet)
        if packet_length > 1500:  # Large packets may indicate malware
            try:
                response = requests.get(f'https://ipinfo.io/{dst_ip}/json')
                data = response.json()
                if "org" not in data or "suspicious" in data.get("org", "").lower():
                    print(f"[Malware Traffic Detected] IP: {dst_ip}, Details: {data}")
            except Exception as e:
                print(f"Error fetching details for IP {dst_ip}: {e}")

# Packet Processing
def process_packet(packet):
    if packet.haslayer(ARP):
        process_arp_packet(packet)
    elif packet.haslayer(DNS):
        process_dns_packet(packet)
    elif packet.haslayer(TCP):
        detect_port_scanning(packet)
    elif packet.haslayer(IP):
        detect_ddos(packet)
        detect_malware_traffic(packet)

# Start packet sniffing
print("Starting comprehensive network monitoring...")
sniff(filter="arp or udp port 53 or tcp", prn=process_packet)
