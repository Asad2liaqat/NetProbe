# module1.py
# IoT Security Scanner - Module 1 (Core Engine)
# Contains: Vendor Lookup, Network Scanner, Port Scanner, Risk Engine

import socket
from scapy.all import ARP, Ether, srp, conf


# ── CONFIGURATION ──────────────────────────────────────────────────────────────

# ── KNOWN DEVICE DATABASE ──────────────────────────────────────────────────────
#
# Maps the first 3 bytes of a MAC address (OUI prefix) to a friendly name.
# Format:  "XX:XX:XX" : "Device Name"
#
# To add your own device:
#   1. Find its MAC from your scan results (e.g. "B2:68:8B:xx:xx:xx")
#   2. Take only the first 8 characters:  "B2:68:8B"
#   3. Add it below in uppercase with a descriptive name
#
# You can also call add_known_device() at runtime — see the function below.

OUI_DATABASE = {
    # ── Your network devices ───────────────────────────────────────────────
    "f8:98:b9:ee:74:b0": "Main Network Gateway",
    "BE:D9:C7": "Redmi Note 9 Pro",
    "B2:68:8B": "Google Pixel 7",
    "86:A5:D2": "Desktop PC (Intel)",
    "4C:D1:A1": "Samsung Smartphone",
    "94:E9:79": "Laptop (Testing)",
    "BC:D0:74": "TP-Link Router",
    "F8:FF:C2": "HP Electronics",
    "08:00:27": "Metasploitable Lab (Virtual)",
    # ── ADD YOUR DEVICES BELOW THIS LINE ───────────────────────────────────

}


def add_known_device(mac: str, name: str) -> None:
    """
    Registers a device in the local OUI database at runtime.
    The name will appear in all scan results and the GUI device list.

    Args:
        mac  : Full MAC address OR just the first 3 bytes.
               Both formats are accepted:
                 "B2:68:8B:1A:2B:3C"  →  stores "B2:68:8B"
                 "B2:68:8B"           →  stores "B2:68:8B"
        name : Friendly label shown in the scanner.
               e.g. "Living Room Camera", "Dad's iPhone", "Smart TV"

    Examples:
        add_known_device("2C:58:E8:AB:1F:D8", "Huawei Router")
        add_known_device("14:B2:E5",          "IP Camera (Bedroom)")
        add_known_device("74:DF:BF:03:1D:B7", "Laptop")

    Note:
        This only lasts for the current session unless you also add the
        entry directly to OUI_DATABASE above.
    """
    if not mac or not name:
        return
    prefix = mac.upper().replace("-", ":").strip()[:8]
    if len(prefix) < 8:
        print(f"  [!] add_known_device: '{mac}' is too short — need at least 3 bytes (XX:XX:XX)")
        return
    OUI_DATABASE[prefix] = name.strip()
    print(f"  [+] Known device registered: {prefix}  →  {name}")

# All ports to scan with their service names
DANGER_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    80:   "HTTP",
    443:  "HTTPS",
    445:  "SMB",
    554:  "RTSP",
    1883: "MQTT",
    3389: "RDP",
    5555: "ADB",
    5683: "CoAP",
    8080: "Alt-HTTP",
}

# Risk rules — port lists per severity
CRITICAL_PORTS = [23, 5555, 445]
HIGH_PORTS     = [21, 3389]
WEAK_PORTS     = [80, 8080, 1883, 554, 5683]


# ── VENDOR LOOKUP ──────────────────────────────────────────────────────────────

def get_vendor(mac):
    """
    Looks up the device manufacturer from the local OUI database.
    Returns 'Unknown Device' if not found.
    """
    if not mac:
        return "Unknown Device"
    prefix = mac.upper()[:8]
    return OUI_DATABASE.get(prefix, "Unknown Device")


# ── AUTO GATEWAY DETECTION ─────────────────────────────────────────────────────

def get_ip_range():
    """
    Auto-detects the default gateway using Scapy's routing table.
    Builds the /24 scan range from it automatically.
    Returns None if detection fails.
    """
    try:
        gateway = conf.route.route("0.0.0.0")[2]
        if gateway and gateway != "0.0.0.0":
            base     = '.'.join(gateway.split('.')[:3]) + '.0'
            ip_range = f"{base}/24"
            return gateway, ip_range
    except Exception:
        pass
    return None, None


# ── NETWORK SCANNER ────────────────────────────────────────────────────────────

def scan_network(ip_range):
    """
    Sends ARP broadcast to discover all active devices on the network.

    Args:
        ip_range (str): e.g. "192.168.1.0/24"

    Returns:
        list of dicts: [{'ip', 'mac', 'vendor'}]
    """
    devices = []
    try:
        packet      = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
        answered, _ = srp(packet, timeout=3, verbose=False, retry=2)

        for _, received in answered:
            mac = received.hwsrc
            devices.append({
                'ip':     received.psrc,
                'mac':    mac,
                'vendor': get_vendor(mac)
            })

    except PermissionError:
        print("[!] Run as Administrator — required for ARP scanning.")
    except Exception as e:
        print(f"[!] Scan error: {e}")

    return devices


# ── PORT SCANNER ───────────────────────────────────────────────────────────────

def scan_ports(ip):
    """
    Checks all DANGER_PORTS on a given IP using TCP connect.

    Args:
        ip (str): Target IP address.

    Returns:
        list of open port numbers (int)
    """
    open_ports = []

    for port in DANGER_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        try:
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
        except socket.error:
            pass
        finally:
            sock.close()

    return open_ports


def get_port_name(port):
    """Returns the service name for a given port number."""
    return DANGER_PORTS.get(port, "Unknown")


# ── RISK ENGINE ────────────────────────────────────────────────────────────────

def get_risk(open_ports):
    """
    Determines the risk level based on which ports are open.

    Returns:
        tuple: (risk_label, color_code)
    """
    from colorama import Fore

    if not open_ports:
        return "Safe", Fore.GREEN

    if any(p in open_ports for p in CRITICAL_PORTS):
        return "CRITICAL", Fore.RED

    if any(p in open_ports for p in HIGH_PORTS):
        return "High", Fore.LIGHTRED_EX

    if any(p in open_ports for p in WEAK_PORTS):
        return "Weak", Fore.YELLOW

    return "Safe", Fore.GREEN


# ── MASTER FUNCTION ────────────────────────────────────────────────────────────

def run_module1():
    """
    Runs the full Module 1 pipeline:
      1. Auto-detect network
      2. ARP scan all devices
      3. Port scan each device
      4. Assign risk level

    Returns:
        (gateway, ip_range, results)
        results = list of dicts ready for Module 2
    """
    gateway, ip_range = get_ip_range()

    if not ip_range:
        return None, None, []

    devices = scan_network(ip_range)

    # Check for local simulation (fake_iot.py demo device)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        if s.connect_ex(('127.0.0.1', 9999)) == 0:
            devices.append({
                'ip':     '127.0.0.1',
                'mac':    'AA:BB:CC:DD:EE:FF',
                'vendor': 'Simulated IoT Camera (Vulnerable)'
            })
        s.close()
    except Exception:
        pass

    results = []
    for device in devices:
        ip         = device['ip']
        open_ports = scan_ports(ip)
        risk, color = get_risk(open_ports)

        results.append({
            'ip':         ip,
            'mac':        device['mac'],
            'vendor':     device['vendor'],
            'open_ports': open_ports,
            'risk':       risk,
            'color':      color,
        })

    return gateway, ip_range, results