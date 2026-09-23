"""
Automatic IP Blocking Service
==============================
Background loop that keeps firewall rules in sync with the blocked_ips table.
Firewall rule names are unified (IDS_Block_IN_<ip> / IDS_Block_OUT_<ip>) so
blocks created by monitor.py, app.py and this service can always be removed
again - the old mixed naming (IDS_Block_<ip>) left orphaned rules behind.
"""

import os
import platform
import sqlite3
import subprocess
import time

DB_PATH = os.environ.get("IDS_DB_PATH", "ids_database.db")
CHECK_INTERVAL = int(os.environ.get("IDS_BLOCK_CHECK_INTERVAL", "3"))


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _run(cmd_list):
    """Run a command without shell=True (avoids shell injection via IPs)."""
    return subprocess.run(cmd_list, capture_output=True, text=True)


def block_ip_firewall(ip_address):
    """Block an IP at firewall level (inbound + outbound)."""
    try:
        system = platform.system()

        if system == "Windows":
            r_in = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                         f"name=IDS_Block_IN_{ip_address}", "dir=in",
                         "action=block", f"remoteip={ip_address}"])
            r_out = _run(["netsh", "advfirewall", "firewall", "add", "rule",
                          f"name=IDS_Block_OUT_{ip_address}", "dir=out",
                          "action=block", f"remoteip={ip_address}"])
            if r_in.returncode == 0 and r_out.returncode == 0:
                print(f"[OK] Blocked {ip_address} on Windows Firewall (IN+OUT)")
                return True
            print(f"[WARN] Firewall error for {ip_address}: "
                  f"IN={r_in.returncode} OUT={r_out.returncode} "
                  "(run as Administrator)")
            return False

        if system == "Linux":
            r_in = _run(["iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"])
            r_out = _run(["iptables", "-I", "OUTPUT", "-d", ip_address, "-j", "DROP"])
            if r_in.returncode == 0 and r_out.returncode == 0:
                print(f"[OK] Blocked {ip_address} with iptables (IN+OUT)")
                return True
            print(f"[WARN] iptables error for {ip_address} (need root/sudo)")
            return False

        print(f"[WARN] Firewall blocking not supported on {system}")
        return False
    except Exception as e:
        print(f"[ERROR] Firewall blocking error for {ip_address}: {e}")
        return False


def unblock_ip_firewall(ip_address):
    """Remove inbound + outbound firewall rules for an IP."""
    try:
        system = platform.system()

        if system == "Windows":
            _run(["netsh", "advfirewall", "firewall", "delete", "rule",
                  f"name=IDS_Block_IN_{ip_address}"])
            _run(["netsh", "advfirewall", "firewall", "delete", "rule",
                  f"name=IDS_Block_OUT_{ip_address}"])
            print(f"[OK] Unblocked {ip_address} from Windows Firewall")
            return True

        if system == "Linux":
            _run(["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"])
            _run(["iptables", "-D", "OUTPUT", "-d", ip_address, "-j", "DROP"])
            print(f"[OK] Unblocked {ip_address} from iptables")
            return True

        return False
    except Exception as e:
        print(f"[ERROR] Firewall unblocking error for {ip_address}: {e}")
        return False


def blocking_service_loop():
    """Continuously monitor the database and apply/remove firewall blocks."""
    print("[*] IP Blocking Service started")
    blocked_ips_cache = set()

    while True:
        conn = None
        try:
            conn = get_db_connection()

            pending_blocks = conn.execute(
                "SELECT ip_address FROM blocked_ips WHERE is_blocked = 1"
            ).fetchall()

            for row in pending_blocks:
                ip = row["ip_address"]
                if ip not in blocked_ips_cache:
                    if block_ip_firewall(ip):
                        blocked_ips_cache.add(ip)

            unblocked = conn.execute(
                """SELECT ip_address FROM blocked_ips
                   WHERE is_blocked = 0 AND unblocked_at IS NOT NULL"""
            ).fetchall()

            for row in unblocked:
                ip = row["ip_address"]
                if ip in blocked_ips_cache:
                    if unblock_ip_firewall(ip):
                        blocked_ips_cache.discard(ip)
                        conn.execute(
                            "DELETE FROM blocked_ips WHERE ip_address = ? AND is_blocked = 0",
                            (ip,),
                        )
                        conn.commit()

            conn.close()
            conn = None
            time.sleep(CHECK_INTERVAL)

        except KeyboardInterrupt:
            print("\n[*] IP Blocking Service stopped")
            break
        except Exception as e:
            print(f"[ERROR] Blocking service error: {e}")
            time.sleep(10)
        finally:
            if conn is not None:
                conn.close()


if __name__ == "__main__":
    blocking_service_loop()
