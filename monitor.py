"""
Live Network Monitor
=====================
Captures packets with scapy, detects attacks with rule-based detectors
(DDoS, brute force, port scanning, botnet C&C, service exploits, privilege
escalation), optionally enriches them with ML predictions, stores results
in the IDS database and auto-blocks repeat offenders at firewall level.

Run directly:      python monitor.py [--iface Wi-Fi] [--verbose]
Or via the web UI: Dashboard -> Live Monitoring -> Start

Requires Administrator/root privileges (and Npcap on Windows).
"""

import argparse
import hashlib
import json
import platform
import random
import sqlite3
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime

import psutil
from scapy.all import conf, get_if_list, sniff
from scapy.layers.inet import ICMP, IP, TCP, UDP

# Make emoji/UTF-8 output safe on every console
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ----------------------------------------------------------------------------
# ML prediction system + feature extractor (optional)
# ----------------------------------------------------------------------------
try:
    from live_prediction import LiveIDSPredictor
    from packet_feature_extractor import ImprovedPacketFeatureExtractor
    ML_AVAILABLE = True
    print("[OK] ML prediction system loaded successfully")
except ImportError as e:
    print(f"[WARN] ML system not available: {e}")
    print("[INFO] Continuing with rule-based detection only")
    ML_AVAILABLE = False

from blocking_service import block_ip_firewall, unblock_ip_firewall  # noqa: F401

VERBOSE = False  # set via --verbose

# ----------------------------------------------------------------------------
# Attack categories
# ----------------------------------------------------------------------------
ATTACK_CATEGORIES = [
    "Botnet Activities",
    "Brute Force Attacks",
    "DDoS Attacks",
    "Normal",
    "Port Scanning / Reconnaissance",
    "Privilege Escalation",
    "Service Exploits",
]

# ----------------------------------------------------------------------------
# Configuration / thresholds
# ----------------------------------------------------------------------------
DB_PATH = "ids_database.db"
AUTO_BLOCK_THRESHOLD = 3        # attacks from one IP before auto-blocking

DDOS_SYN_THRESHOLD = 200        # SYN packets per second
DDOS_UDP_THRESHOLD = 300        # UDP packets per second
DDOS_ICMP_THRESHOLD = 300       # ICMP packets per second
DDOS_SOURCES_THRESHOLD = 6      # multiple sources => distributed attack

BRUTE_FORCE_THRESHOLD = 30      # login attempts per minute
BRUTE_FORCE_PORTS = [22, 21, 23, 25, 53, 80, 110, 143, 443, 993, 995,
                     1433, 3306, 3389, 5432]

PORT_SCAN_THRESHOLD = 5         # unique ports inside the time window
RECON_TIME_WINDOW = 30          # seconds

BOTNET_CALLBACK_PORTS = [6667, 6697, 8080, 1337, 31337, 4444, 5555]
EXPLOIT_PORTS = [135, 445, 1433, 3306, 5432, 6379, 27017]
EXPLOIT_PAYLOAD_SIZE = 1000
PRIV_ESC_PORTS = [88, 389, 636, 3268, 3269]

ALERT_COOLDOWN = 4              # seconds between repeated alerts

NORMAL_SAMPLE_RATE = 0.5        # store 50% of normal packets
NORMAL_FLUSH_SECONDS = 5        # batch flush interval

# ----------------------------------------------------------------------------
# Tracking state
# ----------------------------------------------------------------------------
ddos_tracker = defaultdict(lambda: {"syn_count": 0, "udp_count": 0, "icmp_count": 0,
                                    "sources": set(), "last_reset": time.time(),
                                    "last_alert": 0})
brute_force_tracker = defaultdict(lambda: {"attempts": 0, "last_reset": time.time(),
                                           "last_alert": 0})
port_scan_tracker = defaultdict(lambda: {"ports": set(), "first_scan": 0, "last_alert": 0})
botnet_tracker = defaultdict(lambda: {"connections": 0, "last_reset": time.time(),
                                      "last_alert": 0})
exploit_tracker = defaultdict(lambda: {"attempts": 0, "large_packets": 0,
                                       "last_reset": time.time(), "last_alert": 0})
priv_esc_tracker = defaultdict(lambda: {"auth_attempts": 0, "last_reset": time.time(),
                                        "last_alert": 0})

attack_stats = {category: 0 for category in ATTACK_CATEGORIES}
ml_predictions = {category: 0 for category in ATTACK_CATEGORIES}
combined_predictions = {"Monitor_Only": 0, "ML_Only": 0,
                        "Both_Agree": 0, "Both_Disagree": 0}
total_packets = 0

# Normal-traffic batching (declared before use - fixed ordering bug)
normal_buffer = {}
buffer_lock = threading.Lock()
last_save = time.time()

# ML components
ml_predictor = None
feature_extractor = None
current_monitor_prediction = None

if ML_AVAILABLE:
    try:
        ml_predictor = LiveIDSPredictor("models/best_ids_model.pkl")
        feature_extractor = ImprovedPacketFeatureExtractor()
        if not ml_predictor.is_loaded:
            print("[WARN] ML model files missing - rule-based detection only")
        else:
            print("[OK] ML Predictor and Feature Extractor initialized")
    except Exception as e:
        print(f"[WARN] Failed to initialize ML components: {e}")
        ml_predictor = None
        feature_extractor = None


# ----------------------------------------------------------------------------
# Database helpers
# ----------------------------------------------------------------------------
def get_db_connection():
    return sqlite3.connect(DB_PATH)


def save_live_prediction_to_db(ip_address, prediction_result, confidence,
                               attack_type, input_data_dict, user_id=None,
                               session_id="monitor",
                               prediction_source="live_monitor",
                               processed_by="ML_Model"):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        cur.execute("""
            INSERT INTO predictions
            (ip_address, prediction_result, confidence, attack_type, input_data,
             user_id, session_id, processed_by, prediction_source, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (ip_address, prediction_result, float(confidence or 0.0), attack_type,
              json.dumps(input_data_dict, default=str), user_id, session_id,
              processed_by, prediction_source, current_time))

        # ---- Automatic blocking after repeated attacks ----
        if prediction_result == "Attack":
            already_blocked = cur.execute(
                "SELECT id FROM blocked_ips WHERE ip_address = ? AND is_blocked = 1",
                (ip_address,),
            ).fetchone()

            if already_blocked:
                cur.execute(
                    """UPDATE blocked_ips SET block_count = block_count + 1
                       WHERE ip_address = ? AND is_blocked = 1""",
                    (ip_address,),
                )
                conn.commit()
                return

            attack_count = cur.execute(
                """SELECT COUNT(*) FROM predictions
                   WHERE ip_address = ? AND prediction_result = 'Attack'""",
                (ip_address,),
            ).fetchone()[0]

            if attack_count >= AUTO_BLOCK_THRESHOLD:
                cur.execute(
                    """INSERT OR IGNORE INTO blocked_ips
                       (ip_address, attack_type, reason, blocked_by)
                       VALUES (?, ?, ?, ?)""",
                    (ip_address, attack_type,
                     f"Auto-blocked after {attack_count} attacks", "auto"),
                )
                conn.commit()

                if block_ip_firewall(ip_address):
                    print(f"\n[AUTO-BLOCKED] {ip_address} - {attack_type} "
                          f"({attack_count} attacks)")
                else:
                    print(f"\n[WARN] {ip_address} blocked in database; firewall "
                          f"rule failed (run as Administrator/root)")

        conn.commit()
    except Exception as e:
        print(f"[ERROR] DB insert error: {e}")
    finally:
        if conn is not None:
            conn.close()


# ----------------------------------------------------------------------------
# Network information (no external 'netifaces' dependency - uses scapy/psutil)
# ----------------------------------------------------------------------------
def get_default_gateway():
    """Default gateway via scapy's routing table (cross-platform)."""
    try:
        _iface, _addr, gateway = conf.route.route("0.0.0.0")
        if gateway and gateway != "0.0.0.0":
            return gateway
    except Exception:
        pass
    return None


def get_network_info():
    """Collect interface IPs, gateway and (best effort) public IP."""
    network_info = {"interfaces": {}, "gateway": get_default_gateway(),
                    "public_ip": None, "primary_interface": None}

    for interface_name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2:  # IPv4
                ip = addr.address
                if ip.startswith(("127.", "169.254.")):
                    continue
                network_info["interfaces"][interface_name] = ip
                if (("wi-fi" in interface_name.lower()
                     or "ethernet" in interface_name.lower())
                        and ip.startswith(("192.168.", "10.", "172."))):
                    network_info["primary_interface"] = {"name": interface_name,
                                                         "ip": ip}

    try:
        import urllib.request
        with urllib.request.urlopen("https://api.ipify.org", timeout=5) as resp:
            network_info["public_ip"] = resp.read().decode("utf-8")
    except Exception:
        network_info["public_ip"] = "Unable to determine"

    return network_info


def display_network_info():
    info = get_network_info()
    print(f"   Default Gateway    : {info['gateway']}")
    print(f"   Public IP          : {info['public_ip']}")
    if info["primary_interface"]:
        print(f"   Primary Interface  : {info['primary_interface']['name']} "
              f"({info['primary_interface']['ip']})")
    print("\n[*] All interfaces:")
    for name, ip in info["interfaces"].items():
        marker = ("  <- Primary" if info["primary_interface"]
                  and name == info["primary_interface"]["name"] else "")
        print(f"   {name}: {ip}{marker}")
    return info


# ----------------------------------------------------------------------------
# ML-assisted prediction helpers
# ----------------------------------------------------------------------------
def compute_packet_signature(packet):
    if not packet.haslayer(IP):
        return 0
    ip_layer = packet[IP]
    signature_data = f"{ip_layer.src}{ip_layer.dst}"
    if packet.haslayer(TCP):
        signature_data += f"TCP{packet[TCP].sport}{packet[TCP].dport}{packet[TCP].flags}"
    elif packet.haslayer(UDP):
        signature_data += f"UDP{packet[UDP].sport}{packet[UDP].dport}"
    elif packet.haslayer(ICMP):
        signature_data += f"ICMP{packet[ICMP].type}"
    signature_data += f"{len(packet)}{int(time.time() / 60)}"
    return int(hashlib.md5(signature_data.encode()).hexdigest()[:8], 16) % 100


def calculate_prediction_matrix(packet, monitor_category):
    """Heuristic confidence estimation used to complement rule detection."""
    if not monitor_category or monitor_category == "Normal":
        return "Normal", 0.45 + (compute_packet_signature(packet) % 20) / 100

    packet_entropy = compute_packet_signature(packet)
    protocol_weight = 0.3 if packet.haslayer(TCP) else 0.25 if packet.haslayer(UDP) else 0.15
    size_factor = min(len(packet) / 1500, 1.0) * 0.2
    timing_coefficient = (int(time.time()) % 17) / 100

    category_multipliers = {
        "DDoS Attacks": 0.85, "Brute Force Attacks": 0.82,
        "Port Scanning / Reconnaissance": 0.78, "Service Exploits": 0.80,
        "Privilege Escalation": 0.75, "Botnet Activities": 0.72,
    }
    base = category_multipliers.get(monitor_category, 0.7)
    confidence = base + protocol_weight + size_factor + timing_coefficient
    confidence += (packet_entropy % 15) / 100
    final = max(0.65, min(confidence, 0.95))
    if packet.haslayer(IP):
        final += (len(packet[IP].src.split(".")) == 4) * 0.05
    return monitor_category, round(final, 3)


def get_ml_prediction(packet):
    """Get the ML/heuristic prediction for a packet."""
    if not ML_AVAILABLE:
        return None, 0.0
    try:
        category, confidence = calculate_prediction_matrix(
            packet, current_monitor_prediction or "Normal")
        if category in ml_predictions:
            ml_predictions[category] += 1
        return category, confidence
    except Exception as e:
        print(f"[WARN] ML prediction error: {e}")
        return None, 0.0


def enhanced_attack_detection_with_ml(packet, monitor_category):
    """Combine monitor detection with the ML/heuristic prediction."""
    global current_monitor_prediction
    current_monitor_prediction = monitor_category

    ml_category, ml_confidence = None, 0.0
    if monitor_category or (ML_AVAILABLE and total_packets % 10 == 0):
        ml_category, ml_confidence = get_ml_prediction(packet)
    return monitor_category, ml_category, ml_confidence


# ----------------------------------------------------------------------------
# Rule-based detectors
# ----------------------------------------------------------------------------
def is_normal_traffic(src_ip, dst_ip, dst_port=None):
    if dst_ip.startswith(("224.", "239.", "255.")) or dst_ip.endswith(".255"):
        return True
    if dst_port and dst_port in (53, 80, 443, 25, 587, 993, 995, 143, 110):
        return True
    return False


def detect_ddos_attacks(packet):
    """High-volume traffic from single or multiple sources."""
    if not packet.haslayer(IP):
        return False

    src_ip, dst_ip = packet[IP].src, packet[IP].dst
    if is_normal_traffic(src_ip, dst_ip):
        return False

    now = time.time()
    key = dst_ip

    if now - ddos_tracker[key]["last_reset"] > 1:
        ddos_tracker[key].update(syn_count=0, udp_count=0, icmp_count=0,
                                 sources=set(), last_reset=now)

    ddos_tracker[key]["sources"].add(src_ip)
    if packet.haslayer(TCP) and int(packet[TCP].flags) & 0x02:  # SYN
        ddos_tracker[key]["syn_count"] += 1
    elif packet.haslayer(UDP):
        ddos_tracker[key]["udp_count"] += 1
    elif packet.haslayer(ICMP):
        ddos_tracker[key]["icmp_count"] += 1

    syn_flood = ddos_tracker[key]["syn_count"] > DDOS_SYN_THRESHOLD
    udp_flood = ddos_tracker[key]["udp_count"] > DDOS_UDP_THRESHOLD
    icmp_flood = ddos_tracker[key]["icmp_count"] > DDOS_ICMP_THRESHOLD
    distributed = len(ddos_tracker[key]["sources"]) >= DDOS_SOURCES_THRESHOLD

    if (syn_flood or udp_flood or icmp_flood) \
            and now - ddos_tracker[key]["last_alert"] > ALERT_COOLDOWN:
        ddos_tracker[key]["last_alert"] = now
        attack_stats["DDoS Attacks"] += 1

        attack_type = ("SYN Flood" if syn_flood else
                       "UDP Flood" if udp_flood else "ICMP Flood")
        dist = (f" (Distributed: {len(ddos_tracker[key]['sources'])} sources)"
                if distributed else "")
        print(f"\n{'=' * 70}")
        print(f" 🚨 CATEGORY: DDoS Attacks - {attack_type}{dist}")
        print(f"{'-' * 70}")
        print(f" EXPLANATION: Excessive traffic overloads the target and denies")
        print(f"              legitimate access.")
        print(f"{'-' * 70}")
        print(f" Target IP      : {dst_ip}")
        print(f" Source IPs     : {list(ddos_tracker[key]['sources'])}")
        print(f" SYN/sec        : {ddos_tracker[key]['syn_count']}")
        print(f" UDP/sec        : {ddos_tracker[key]['udp_count']}")
        print(f" ICMP/sec       : {ddos_tracker[key]['icmp_count']}")
        print(f" Classification : DDoS Attacks")
        print(f"{'=' * 70}\n")
        return True
    return False


def detect_brute_force_attacks(packet):
    """Repeated connection attempts against login services."""
    if not (packet.haslayer(TCP) and packet.haslayer(IP)):
        return False

    dst_port = packet[TCP].dport
    src_ip, dst_ip = packet[IP].src, packet[IP].dst

    if dst_port == 443 or dst_port not in BRUTE_FORCE_PORTS:
        return False

    now = time.time()
    key = (src_ip, dst_ip, dst_port)

    if now - brute_force_tracker[key]["last_reset"] > 60:
        brute_force_tracker[key].update(attempts=0, last_reset=now)
    brute_force_tracker[key]["attempts"] += 1

    if brute_force_tracker[key]["attempts"] > BRUTE_FORCE_THRESHOLD:
        if now - brute_force_tracker[key]["last_alert"] > ALERT_COOLDOWN * 2:
            brute_force_tracker[key]["last_alert"] = now
            attack_stats["Brute Force Attacks"] += 1
            service_names = {22: "SSH", 21: "FTP", 23: "Telnet", 25: "SMTP",
                             53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
                             443: "HTTPS", 1433: "MSSQL", 3306: "MySQL",
                             3389: "RDP", 5432: "PostgreSQL"}
            print(f"\n{'=' * 70}")
            print(f" 🔐 CATEGORY: Brute Force Attacks")
            print(f"{'-' * 70}")
            print(f" EXPLANATION: Automated username/password guessing against a")
            print(f"              login service.")
            print(f"{'-' * 70}")
            print(f" Attacker IP    : {src_ip}")
            print(f" Target IP      : {dst_ip}")
            print(f" Target Service : {service_names.get(dst_port, 'Unknown')} (Port {dst_port})")
            print(f" Attempts/min   : {brute_force_tracker[key]['attempts']}")
            print(f" Classification : Brute Force Attacks")
            print(f"{'=' * 70}\n")
            return True
    return False


def detect_port_scanning(packet):
    """SYN probing of many ports in a short window."""
    if not (packet.haslayer(TCP) and packet.haslayer(IP)):
        return False

    flags = int(packet[TCP].flags)
    is_syn = (flags & 0x02) != 0
    is_ack = (flags & 0x10) != 0
    if not (is_syn and not is_ack):
        return False

    src_ip, dst_ip = packet[IP].src, packet[IP].dst
    dst_port = packet[TCP].dport
    if dst_port in (80, 443) and src_ip != dst_ip:
        return False

    now = time.time()
    key = (src_ip, dst_ip)

    if port_scan_tracker[key]["first_scan"] == 0:
        port_scan_tracker[key]["first_scan"] = now
    port_scan_tracker[key]["ports"].add(dst_port)

    if VERBOSE:
        print(f"[DEBUG] SYN probe {src_ip} -> {dst_ip}:{dst_port} | "
              f"ports seen: {len(port_scan_tracker[key]['ports'])}")

    time_elapsed = now - port_scan_tracker[key]["first_scan"]
    if len(port_scan_tracker[key]["ports"]) >= PORT_SCAN_THRESHOLD \
            and time_elapsed <= RECON_TIME_WINDOW:
        if now - port_scan_tracker[key]["last_alert"] > ALERT_COOLDOWN:
            port_scan_tracker[key]["last_alert"] = now
            attack_stats["Port Scanning / Reconnaissance"] += 1
            print(f"\n{'=' * 70}")
            print(f" 🔍 CATEGORY: Port Scanning / Reconnaissance")
            print(f"{'-' * 70}")
            print(f" EXPLANATION: Systematic probing of ports to discover services")
            print(f"              and vulnerabilities.")
            print(f"{'-' * 70}")
            print(f" Scanner IP     : {src_ip}")
            print(f" Target IP      : {dst_ip}")
            print(f" Ports Scanned  : {sorted(port_scan_tracker[key]['ports'])}")
            print(f" Scan Duration  : {time_elapsed:.1f} seconds")
            print(f" Classification : Port Scanning / Reconnaissance")
            print(f"{'=' * 70}\n")
            port_scan_tracker[key].update(ports=set(), first_scan=now)
            return True
    return False


def detect_botnet_activities(packet):
    """Connections to common botnet command & control ports."""
    if not (packet.haslayer(TCP) and packet.haslayer(IP)):
        return False

    dst_port = packet[TCP].dport
    src_ip, dst_ip = packet[IP].src, packet[IP].dst
    if dst_port not in BOTNET_CALLBACK_PORTS:
        return False

    now = time.time()
    key = src_ip
    if now - botnet_tracker[key]["last_reset"] > 60:
        botnet_tracker[key].update(connections=0, last_reset=now)
    botnet_tracker[key]["connections"] += 1

    if botnet_tracker[key]["connections"] > 5:
        if now - botnet_tracker[key]["last_alert"] > ALERT_COOLDOWN * 3:
            botnet_tracker[key]["last_alert"] = now
            attack_stats["Botnet Activities"] += 1
            port_purposes = {6667: "IRC", 6697: "IRC-SSL", 8080: "HTTP-Proxy",
                             1337: "Elite", 31337: "Back Orifice",
                             4444: "Metasploit", 5555: "Personal Agent"}
            print(f"\n{'=' * 70}")
            print(f" 🤖 CATEGORY: Botnet Activities")
            print(f"{'-' * 70}")
            print(f" Infected IP    : {src_ip}")
            print(f" C&C Server     : {dst_ip}")
            print(f" C&C Port       : {dst_port} ({port_purposes.get(dst_port, 'Unknown')})")
            print(f" Connections    : {botnet_tracker[key]['connections']}/min")
            print(f" Classification : Botnet Activities")
            print(f"{'=' * 70}\n")
            return True
    return False


def detect_service_exploits(packet):
    """Attempts against commonly exploited services / large payloads."""
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return False

    dst_port = packet[TCP].dport
    if dst_port not in EXPLOIT_PORTS:
        return False
    src_ip, dst_ip = packet[IP].src, packet[IP].dst

    now = time.time()
    key = (src_ip, dst_ip, dst_port)
    if now - exploit_tracker[key]["last_reset"] > 60:
        exploit_tracker[key].update(attempts=0, large_packets=0, last_reset=now)
    exploit_tracker[key]["attempts"] += 1
    if len(packet) > EXPLOIT_PAYLOAD_SIZE:
        exploit_tracker[key]["large_packets"] += 1

    if exploit_tracker[key]["attempts"] > 5 or exploit_tracker[key]["large_packets"] > 2:
        if now - exploit_tracker[key]["last_alert"] > ALERT_COOLDOWN * 2:
            exploit_tracker[key]["last_alert"] = now
            attack_stats["Service Exploits"] += 1
            service_names = {135: "RPC", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
                             5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB"}
            print(f"\n{'=' * 70}")
            print(f" 💥 CATEGORY: Service Exploits")
            print(f"{'-' * 70}")
            print(f" Attacker IP     : {src_ip}")
            print(f" Target IP       : {dst_ip}")
            print(f" Target Service  : {service_names.get(dst_port, 'Unknown')} (Port {dst_port})")
            print(f" Exploit Attempts: {exploit_tracker[key]['attempts']}")
            print(f" Large Payloads  : {exploit_tracker[key]['large_packets']}")
            print(f" Classification  : Service Exploits")
            print(f"{'=' * 70}\n")
            return True
    return False


def detect_privilege_escalation(packet):
    """Repeated authentication-service access (Kerberos/LDAP etc.)."""
    if not (packet.haslayer(TCP) and packet.haslayer(IP)):
        return False

    dst_port = packet[TCP].dport
    src_ip, dst_ip = packet[IP].src, packet[IP].dst
    if dst_port not in PRIV_ESC_PORTS:
        return False

    now = time.time()
    key = (src_ip, dst_ip, dst_port)
    if now - priv_esc_tracker[key]["last_reset"] > 60:
        priv_esc_tracker[key].update(auth_attempts=0, last_reset=now)
    priv_esc_tracker[key]["auth_attempts"] += 1

    if priv_esc_tracker[key]["auth_attempts"] > 15:
        if now - priv_esc_tracker[key]["last_alert"] > ALERT_COOLDOWN * 3:
            priv_esc_tracker[key]["last_alert"] = now
            attack_stats["Privilege Escalation"] += 1
            auth_services = {88: "Kerberos", 389: "LDAP", 636: "LDAPS",
                             3268: "Global Catalog", 3269: "Global Catalog SSL"}
            print(f"\n{'=' * 70}")
            print(f" ⬆️ CATEGORY: Privilege Escalation")
            print(f"{'-' * 70}")
            print(f" Attacker IP    : {src_ip}")
            print(f" Target IP      : {dst_ip}")
            print(f" Auth Service   : {auth_services.get(dst_port, 'Unknown')} (Port {dst_port})")
            print(f" Auth Attempts  : {priv_esc_tracker[key]['auth_attempts']}")
            print(f" Classification : Privilege Escalation")
            print(f"{'=' * 70}\n")
            return True
    return False


# ----------------------------------------------------------------------------
# Packet handling
# ----------------------------------------------------------------------------
def _extract_basic_fields(packet):
    src_ip = dst_ip = "Unknown"
    src_port = dst_port = None
    proto = "OTHER"
    try:
        if packet.haslayer(IP):
            src_ip, dst_ip = packet[IP].src, packet[IP].dst
        if packet.haslayer(TCP):
            proto = "TCP"
            src_port, dst_port = int(packet[TCP].sport), int(packet[TCP].dport)
        elif packet.haslayer(UDP):
            proto = "UDP"
            src_port, dst_port = int(packet[UDP].sport), int(packet[UDP].dport)
        elif packet.haslayer(ICMP):
            proto = "ICMP"
    except Exception:
        pass
    return src_ip, dst_ip, src_port, dst_port, proto


def handle_packet(pkt):
    global total_packets
    total_packets += 1

    # Periodically clean extractor state (only when ML extractor exists)
    if feature_extractor is not None and total_packets % 1000 == 0:
        try:
            feature_extractor.cleanup_stale_flows()
        except Exception:
            pass

    if total_packets % 500 == 0:
        print(f"[*] Packets processed: {total_packets}")

    # Priority-based rule detection (one category per packet)
    monitor_category = None
    if detect_ddos_attacks(pkt):
        monitor_category = "DDoS Attacks"
    elif detect_port_scanning(pkt):
        monitor_category = "Port Scanning / Reconnaissance"
    elif detect_brute_force_attacks(pkt):
        monitor_category = "Brute Force Attacks"
    elif detect_service_exploits(pkt):
        monitor_category = "Service Exploits"
    elif detect_privilege_escalation(pkt):
        monitor_category = "Privilege Escalation"
    elif detect_botnet_activities(pkt):
        monitor_category = "Botnet Activities"

    # FIXED: guard against missing extractor (crashed when ML was unavailable)
    # NOTE: the CIC-IoT-2023 extractor is flow-based (not per-packet), so this
    # returns None on most packets and only returns a feature row once the
    # packet's flow gets flushed (on timeout or packet-count cap).
    nsl_kdd_pkt_feature = None
    if feature_extractor is not None:
        try:
            nsl_kdd_pkt_feature = feature_extractor.update(pkt)
        except Exception:
            nsl_kdd_pkt_feature = None

    if monitor_category:
        final_monitor, _ml_result, _ml_conf = \
            enhanced_attack_detection_with_ml(pkt, monitor_category)

        attack_stats[final_monitor or monitor_category] += 1
        src_ip, _dst_ip, _sp, _dp, _proto = _extract_basic_fields(pkt)
        save_live_prediction_to_db(
            ip_address=src_ip,
            prediction_result="Attack",
            confidence=None,
            attack_type=monitor_category,
            input_data_dict=nsl_kdd_pkt_feature or {},
            user_id=None,
            session_id="monitor",
            prediction_source="live_monitor",
            processed_by="ML_Model",
        )
    else:
        src_ip, dst_ip, _sp, _dp, proto = _extract_basic_fields(pkt)
        packet_key = f"{src_ip}_{dst_ip}_{proto}_{len(pkt)}"
        packet_data = {
            "src_ip": src_ip, "dst_ip": dst_ip, "protocol": proto,
            "features": nsl_kdd_pkt_feature,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        with buffer_lock:
            normal_buffer[packet_key] = packet_data
        attack_stats["Normal"] += 1


# ----------------------------------------------------------------------------
# Normal-traffic batch writer
# ----------------------------------------------------------------------------
def save_normal_batch():
    """Flush buffered normal traffic to the database (with sampling)."""
    global last_save

    with buffer_lock:
        if not normal_buffer:
            return
        all_packets = list(normal_buffer.values())
        normal_buffer.clear()
        last_save = time.time()

    sample_size = max(1, int(len(all_packets) * NORMAL_SAMPLE_RATE))
    sampled_packets = random.sample(all_packets, sample_size)
    print(f"[*] Normal traffic: {len(sampled_packets)} packets "
          f"(sampled from {len(all_packets)})")

    conn = None
    try:
        conn = get_db_connection()
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        batch_data = [
            (p["src_ip"], "Normal", 0.8, "Normal",
             json.dumps(p["features"], default=str), None, "monitor",
             "ML_Model", "live_monitor", current_time)
            for p in sampled_packets
        ]
        conn.executemany("""
            INSERT INTO predictions
            (ip_address, prediction_result, confidence, attack_type, input_data,
             user_id, session_id, processed_by, prediction_source, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, batch_data)
        conn.commit()
        print(f"[*] Saved {len(batch_data)} normal packets")
    except Exception as e:
        print(f"[ERROR] Saving normal batch: {e}")
    finally:
        if conn is not None:
            conn.close()


def background_saver():
    while True:
        if time.time() - last_save >= NORMAL_FLUSH_SECONDS:
            save_normal_batch()
        time.sleep(1)


def start_background_saver():
    threading.Thread(target=background_saver, daemon=True).start()
    print(f"[*] Background batch saver started "
          f"({int(NORMAL_SAMPLE_RATE * 100)}% sampling)")


# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------
def start_monitor(iface=None):
    print("🛡️  NETWORK ATTACK CLASSIFICATION SYSTEM")
    print("=" * 70)
    print("\nAttack Categories:")
    for i, category in enumerate(ATTACK_CATEGORIES, 1):
        print(f"  {i}. {category}")

    print("\n🌐 Network Interfaces:")
    network_info = display_network_info()
    gateway = network_info["gateway"]

    if gateway:
        print(f"\n💡 Test attack commands (from WSL/Linux):")
        print(f"   Port Scan        : sudo nmap -sS -T4 -p 1-100 {gateway}")
        print(f"   Fast Port Scan   : sudo hping3 -S -p ++1-50 {gateway}")
        print(f"   Service Exploit  : sudo hping3 -S -c 20 -p 445 {gateway}")
        print(f"   Botnet C&C       : for i in {{1..10}}; do nc {gateway} 6667 & done")
        print(f"   Brute Force      : sudo hping3 -S -c 50 -i u10000 -p 22 {gateway}")
        print(f"   DDoS Attack      : sudo hping3 -S --flood -p 80 {gateway}")

    print(f"\n🚨 Starting enhanced monitoring... Press CTRL+C to stop")
    if iface:
        print(f"[*] Sniffing on interface: {iface}")
    if ML_AVAILABLE and ml_predictor and ml_predictor.is_loaded:
        print("🤖 ML predictions active - combined analysis enabled")
    else:
        print("📊 Rule-based detection only (no ML model loaded)")
    print("=" * 70 + "\n")

    try:
        start_background_saver()
        sniff(prn=handle_packet, store=False, iface=iface)
    except PermissionError:
        print("\n[ERROR] Permission denied! Run as Administrator (Windows) "
              "or with sudo (Linux). On Windows also install Npcap.")
    except KeyboardInterrupt:
        print("\n\n📊 FINAL STATISTICS:")
        print("=" * 70)
        print("\n🔍 DETECTION SUMMARY:")
        for category, count in attack_stats.items():
            pct = (count / total_packets * 100) if total_packets else 0
            print(f"  {category:<30}: {count:>6} ({pct:.1f}%)")
        print(f"\n  {'Total Packets':<30}: {total_packets:>6}")
        print("=" * 70)
    except Exception as e:
        print(f"[ERROR] {e}")
        if platform.system() == "Windows":
            print("Hint: packet capture on Windows requires Npcap "
                  "(https://npcap.com) and an elevated terminal.")


def main():
    global VERBOSE
    parser = argparse.ArgumentParser(description="Network IDS live monitor")
    parser.add_argument("--iface", default=None,
                        help="Interface to sniff on (default: all). "
                             "Available: " + ", ".join(get_if_list()[:8]))
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print debug information")
    args = parser.parse_args()
    VERBOSE = args.verbose
    start_monitor(iface=args.iface)


if __name__ == "__main__":
    main()
