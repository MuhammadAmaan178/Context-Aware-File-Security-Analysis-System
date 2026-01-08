import datetime
import json
import os

BLOCKLIST_FILE = "blocked_ips.json"

def load_blacklist():
    if os.path.exists(BLOCKLIST_FILE):
        try:
            with open(BLOCKLIST_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_blacklist():
    with open(BLOCKLIST_FILE, "w") as f:
        json.dump(BLOCKED_IPS, f, indent=4)

BLOCKED_IPS = load_blacklist()

def is_ip_blocked(ip_address):
    """
    Lab 11: Firewall Check.
    Returns True if IP is in the blacklist.
    """
    # Reloading typically not needed every request if single worker, 
    # but for robustness in simple scripts we can just use the memory copy
    return ip_address in BLOCKED_IPS

def block_ip(ip_address, reason):
    """
    Lab 11: Automated Response.
    Adds an IP to the blocklist.
    """
    BLOCKED_IPS[ip_address] = {
        "reason": reason,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    save_blacklist() # Persist
    return True

def unblock_ip(ip_address):
    """
    For Admin Dashboard (Restoring Access).
    """
    if ip_address in BLOCKED_IPS:
        del BLOCKED_IPS[ip_address]
        save_blacklist() # Persist
        return True
    return False

def get_blocked_list():
    return BLOCKED_IPS
