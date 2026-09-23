"""
Packet Feature Extractor (CIC-IoT-2023 edition)
================================================
Extracts CIC-IoT-2023 style flow-level features from live packets captured
with scapy. Used by monitor.py to feed the ML model in real time.

CIC-IoT-2023's 46 features are computed per-FLOW (a flow = packets sharing
src/dst IP + port + protocol, aggregated over a short time window), not
per-packet, so this extractor buffers packets into flow buckets and emits
a feature row whenever a flow is flushed (on timeout or packet-count cap).
"""

import time
from collections import defaultdict

from scapy.layers.inet import ICMP, IP, TCP, UDP

# Well-known ports used for the protocol-indicator features
APP_PORT_MAP = {
    80: "HTTP", 8080: "HTTP", 443: "HTTPS", 53: "DNS", 23: "Telnet",
    25: "SMTP", 22: "SSH", 194: "IRC", 6667: "IRC", 67: "DHCP", 68: "DHCP",
}

# The 46 CIC-IoT-2023 feature names, in the order train_ids_model.py expects
FEATURE_NAMES = [
    "flow_duration", "Header_Length", "Protocol Type", "Duration", "Rate",
    "Srate", "Drate", "fin_flag_number", "syn_flag_number", "rst_flag_number",
    "psh_flag_number", "ack_flag_number", "ece_flag_number", "cwr_flag_number",
    "ack_count", "syn_count", "fin_count", "urg_count", "rst_count",
    "HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC", "TCP", "UDP",
    "DHCP", "ARP", "ICMP", "IPv", "LLC", "Tot sum", "Min", "Max", "AVG",
    "Std", "Tot size", "IAT", "Number", "Magnitue", "Radius", "Covariance",
    "Variance", "Weight",
]


class CICIoTFlowFeatureExtractor:
    def __init__(self, flow_timeout=5.0, flush_after_packets=50):
        """
        Args:
            flow_timeout: seconds of inactivity before a flow is flushed
            flush_after_packets: also flush a flow once it hits this many packets
                                  (keeps long-lived flows from growing unbounded)
        """
        self.flow_timeout = flow_timeout
        self.flush_after_packets = flush_after_packets

        # flow_key -> flow state dict
        self.flows = defaultdict(self._new_flow)

    # ------------------------------------------------------------------
    @staticmethod
    def _new_flow():
        return {
            "start_time": None,
            "last_time": None,
            "packet_sizes": [],
            "iats": [],  # inter-arrival times
            "last_pkt_time": None,
            "flags": {"fin": 0, "syn": 0, "rst": 0, "psh": 0, "ack": 0, "ece": 0, "cwr": 0},
            "flag_counts": {"ack": 0, "syn": 0, "fin": 0, "urg": 0, "rst": 0},
            "protocol_hits": {k: 0 for k in
                               ("HTTP", "HTTPS", "DNS", "Telnet", "SMTP", "SSH", "IRC",
                                "TCP", "UDP", "DHCP", "ARP", "ICMP", "IPv", "LLC")},
            "header_length_total": 0,
            "protocol_type": 0,
            "ttl_values": [],
            "src_count": 0,
            "dst_count": 0,
        }

    @staticmethod
    def _flow_key(packet):
        """5-tuple flow key, direction-normalized so both sides of a
        conversation land in the same bucket."""
        if not packet.haslayer(IP):
            return None
        ip = packet[IP]
        if packet.haslayer(TCP):
            proto, sport, dport = "TCP", packet[TCP].sport, packet[TCP].dport
        elif packet.haslayer(UDP):
            proto, sport, dport = "UDP", packet[UDP].sport, packet[UDP].dport
        elif packet.haslayer(ICMP):
            proto, sport, dport = "ICMP", 0, 0
        else:
            proto, sport, dport = "OTHER", 0, 0

        endpoints = sorted([(ip.src, sport), (ip.dst, dport)])
        return (endpoints[0][0], endpoints[0][1], endpoints[1][0], endpoints[1][1], proto)

    def _app_protocol(self, packet, flow):
        ports = []
        if packet.haslayer(TCP):
            ports = [packet[TCP].sport, packet[TCP].dport]
        elif packet.haslayer(UDP):
            ports = [packet[UDP].sport, packet[UDP].dport]
        for p in ports:
            if p in APP_PORT_MAP:
                flow["protocol_hits"][APP_PORT_MAP[p]] = 1

    # ------------------------------------------------------------------
    def update(self, packet):
        """Feed one packet in. Returns a completed feature dict if this
        packet caused a flow to flush, else None."""
        if not packet.haslayer(IP):
            return None

        key = self._flow_key(packet)
        flow = self.flows[key]
        now = time.time()

        if flow["start_time"] is None:
            flow["start_time"] = now
        else:
            flow["iats"].append(now - flow["last_pkt_time"])
        flow["last_pkt_time"] = now
        flow["last_time"] = now

        pkt_len = len(packet)
        flow["packet_sizes"].append(pkt_len)
        flow["header_length_total"] += (packet[IP].ihl * 4) if hasattr(packet[IP], "ihl") else 20
        flow["ttl_values"].append(packet[IP].ttl)
        flow["protocol_type"] = packet[IP].proto

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = int(tcp.flags)
            if flags & 0x01: flow["flags"]["fin"] = 1; flow["flag_counts"]["fin"] += 1
            if flags & 0x02: flow["flags"]["syn"] = 1; flow["flag_counts"]["syn"] += 1
            if flags & 0x04: flow["flags"]["rst"] = 1; flow["flag_counts"]["rst"] += 1
            if flags & 0x08: flow["flags"]["psh"] = 1
            if flags & 0x10: flow["flags"]["ack"] = 1; flow["flag_counts"]["ack"] += 1
            if flags & 0x20: flow["flags"]["ece"] = 1; flow["flag_counts"]["urg"] += 1
            if flags & 0x40: flow["flags"]["cwr"] = 1
            flow["protocol_hits"]["TCP"] = 1
        elif packet.haslayer(UDP):
            flow["protocol_hits"]["UDP"] = 1
        elif packet.haslayer(ICMP):
            flow["protocol_hits"]["ICMP"] = 1

        flow["protocol_hits"]["IPv"] = 1
        self._app_protocol(packet, flow)

        num_packets = len(flow["packet_sizes"])
        duration = now - flow["start_time"]

        if duration >= self.flow_timeout or num_packets >= self.flush_after_packets:
            features = self._compute_features(flow)
            del self.flows[key]
            return features
        return None

    # ------------------------------------------------------------------
    def _compute_features(self, flow):
        sizes = flow["packet_sizes"] or [0]
        n = len(sizes)
        duration = max((flow["last_time"] - flow["start_time"]), 1e-6)
        mean_size = sum(sizes) / n
        variance = sum((s - mean_size) ** 2 for s in sizes) / n
        std = variance ** 0.5

        rate = n / duration
        avg_iat = (sum(flow["iats"]) / len(flow["iats"])) if flow["iats"] else 0.0

        return {
            "flow_duration": float(duration),
            "Header_Length": float(flow["header_length_total"]),
            "Protocol Type": float(flow["protocol_type"]),
            "Duration": float(sum(flow["ttl_values"]) / len(flow["ttl_values"])) if flow["ttl_values"] else 0.0,
            "Rate": float(rate),
            "Srate": float(rate),
            "Drate": 0.0,
            "fin_flag_number": int(flow["flags"]["fin"]),
            "syn_flag_number": int(flow["flags"]["syn"]),
            "rst_flag_number": int(flow["flags"]["rst"]),
            "psh_flag_number": int(flow["flags"]["psh"]),
            "ack_flag_number": int(flow["flags"]["ack"]),
            "ece_flag_number": int(flow["flags"]["ece"]),
            "cwr_flag_number": int(flow["flags"]["cwr"]),
            "ack_count": int(flow["flag_counts"]["ack"]),
            "syn_count": int(flow["flag_counts"]["syn"]),
            "fin_count": int(flow["flag_counts"]["fin"]),
            "urg_count": int(flow["flag_counts"]["urg"]),
            "rst_count": int(flow["flag_counts"]["rst"]),
            "HTTP": int(flow["protocol_hits"]["HTTP"]),
            "HTTPS": int(flow["protocol_hits"]["HTTPS"]),
            "DNS": int(flow["protocol_hits"]["DNS"]),
            "Telnet": int(flow["protocol_hits"]["Telnet"]),
            "SMTP": int(flow["protocol_hits"]["SMTP"]),
            "SSH": int(flow["protocol_hits"]["SSH"]),
            "IRC": int(flow["protocol_hits"]["IRC"]),
            "TCP": int(flow["protocol_hits"]["TCP"]),
            "UDP": int(flow["protocol_hits"]["UDP"]),
            "DHCP": int(flow["protocol_hits"]["DHCP"]),
            "ARP": int(flow["protocol_hits"]["ARP"]),
            "ICMP": int(flow["protocol_hits"]["ICMP"]),
            "IPv": int(flow["protocol_hits"]["IPv"]),
            "LLC": int(flow["protocol_hits"]["LLC"]),
            "Tot sum": float(sum(sizes)),
            "Min": float(min(sizes)),
            "Max": float(max(sizes)),
            "AVG": float(mean_size),
            "Std": float(std),
            "Tot size": float(sum(sizes)),
            "IAT": float(avg_iat),
            "Number": int(n),
            "Magnitue": float((mean_size + mean_size) ** 0.5),
            "Radius": float((2 * variance) ** 0.5),
            "Covariance": float(variance),
            "Variance": float(variance),
            "Weight": float(n * n),
        }

    # ------------------------------------------------------------------
    def flush_all(self):
        """Force-flush every open flow (e.g. on shutdown) and return their
        feature rows."""
        results = []
        for key in list(self.flows.keys()):
            flow = self.flows[key]
            if flow["packet_sizes"]:
                results.append(self._compute_features(flow))
            del self.flows[key]
        return results

    def cleanup_stale_flows(self, max_age=300):
        """Drop flows that have been idle too long without ever flushing
        (prevents unbounded memory growth on long-running captures)."""
        now = time.time()
        stale = [k for k, f in self.flows.items()
                 if f["last_time"] and (now - f["last_time"]) > max_age]
        for k in stale:
            del self.flows[k]


# Backwards-compatible alias so monitor.py's existing import keeps working
# even though the extraction strategy changed from per-packet (NSL-KDD)
# to per-flow (CIC-IoT-2023).
ImprovedPacketFeatureExtractor = CICIoTFlowFeatureExtractor
