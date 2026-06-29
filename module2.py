# module2.py
# IoT Security Scanner - Module 2 (Intelligence Engine)
# Contains: MAC Vendor Lookup, Banner Grabbing, IoT Profiler, TLS Checker

import socket
import requests


# ── MAC VENDOR LOOKUP ──────────────────────────────────────────────────────────

def _is_randomised_mac(mac: str) -> bool:
    """
    Option C — Detects locally administered (randomised) MACs.

    iOS, Android 10+, and Windows 11 randomise their MAC address per
    network by setting bit 1 of the first octet.  When this bit is set
    the OUI prefix is meaningless — no database can identify the device.

    The second hex digit of the first byte will be 2, 6, A, or E when
    the MAC is randomised  (binary: xx10 pattern in the low nibble).

    Examples of randomised MACs (second digit = 2/6/A/E):
        7a:75:1d:...   86:a5:d2:...   7e:4b:24:...
        3e:dc:26:...   b2:82:02:...   fe:64:c8:...
    """
    try:
        first_byte = int(mac.replace(":", "").replace("-", "")[:2], 16)
        return bool(first_byte & 0x02)
    except Exception:
        return False


def get_mac_vendor(mac: str) -> str:
    """
    Option A — Looks up the real manufacturer from the macvendors.com API.
    Option C — Returns 'Private Device (MAC Randomised)' for randomised MACs
               instead of wasting an API call that will never resolve.

    Args:
        mac : MAC address e.g. 'AA:BB:CC:DD:EE:FF'

    Returns:
        str : Manufacturer name, 'Private Device (MAC Randomised)',
              or 'Unknown Vendor' on failure.
    """
    if not mac:
        return "Unknown Vendor"

    # Option C — detect randomised MACs before hitting the API
    if _is_randomised_mac(mac):
        return "Private Device (MAC Randomised)"

    try:
        mac_clean = mac.upper().replace("-", ":")
        url       = f"https://api.macvendors.com/{mac_clean}"
        response  = requests.get(url, timeout=3)

        if response.status_code == 200:
            return response.text.strip()
        else:
            return "Unknown Vendor"

    except requests.exceptions.ConnectionError:
        return "Offline (No Internet)"
    except requests.exceptions.Timeout:
        return "Lookup Timed Out"
    except Exception:
        return "Unknown Vendor"


def resolve_display_name(vendor_api: str, device_type: str, vendor_local: str) -> str:
    """
    Option B — Builds the best possible display name for a device using
    a priority chain so 'Unknown Device' is shown as a last resort only.

    Priority:
        1. vendor_api      — real name from MAC API  (e.g. 'TP-Link Technologies')
        2. vendor_local    — name from local OUI_DATABASE  (e.g. 'Laptop (Testing)')
        3. device_type     — port-based guess  (e.g. 'IP Camera', 'Windows PC')
        4. MAC randomised  — already labelled by get_mac_vendor
        5. 'Unknown Device' — absolute last resort

    Args:
        vendor_api   : result from get_mac_vendor()
        device_type  : result from identify_device_type()
        vendor_local : result from module1.get_vendor()  (local OUI_DATABASE)

    Returns:
        str : best available display name
    """
    UNKNOWN_LABELS = {
        "Unknown Vendor", "Unknown Device",
        "Offline (No Internet)", "Lookup Timed Out",
    }

    # 1. API gave us a real name
    if vendor_api and vendor_api not in UNKNOWN_LABELS:
        return vendor_api

    # 2. Local OUI database has a name
    if vendor_local and vendor_local not in UNKNOWN_LABELS:
        return vendor_local

    # 3. Port fingerprinting identified the device type
    if device_type and device_type != "Unknown Device":
        return device_type

    # 4. MAC was randomised — already a clean label from get_mac_vendor
    if vendor_api == "Private Device (MAC Randomised)":
        return vendor_api

    # 5. Absolute last resort
    return "Unknown Device"


# ── BANNER GRABBING ────────────────────────────────────────────────────────────

def grab_banner(ip, port=80):
    """
    Connects to a device's web interface and reads the HTTP Server header.
    This tells us what software is running (Apache, Nginx, camera firmware etc.)

    Args:
        ip   (str): Target IP address
        port (int): Port to grab banner from (default: 80)

    Returns:
        str: Server banner e.g. 'Apache/2.4.1' or 'No Banner' if not found
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))

        request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
        sock.send(request.encode())

        response = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()

        for line in response.split('\r\n'):
            if line.lower().startswith('server:'):
                return line.split(':', 1)[1].strip()

        return "No Banner"

    except (socket.timeout, ConnectionRefusedError):
        return "No Banner"
    except Exception:
        return "No Banner"


# ── TLS / SSL VERSION CHECKER ──────────────────────────────────────────────────

def check_tls(ip, port=443):
    """
    Checks if the device's HTTPS supports weak SSL/TLS versions.
    Devices using TLS 1.0 or SSL 3.0 are vulnerable to known attacks.

    Args:
        ip   (str): Target IP address
        port (int): HTTPS port (default: 443)

    Returns:
        dict: {
            'supported': True/False,
            'version':   'TLSv1.2' or 'N/A',
            'status':    'Secure' / 'Weak' / 'Not Available'
        }
    """
    import ssl

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode    = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=3) as raw_sock:
            with context.wrap_socket(raw_sock, server_hostname=ip) as tls_sock:
                version = tls_sock.version()

                weak_versions = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                status = "Weak" if version in weak_versions else "Secure"

                return {
                    'supported': True,
                    'version':   version,
                    'status':    status
                }

    except (socket.timeout, ConnectionRefusedError, OSError):
        return {'supported': False, 'version': 'N/A', 'status': 'Not Available'}
    except Exception:
        return {'supported': False, 'version': 'N/A', 'status': 'Not Available'}


# ── UPnP DEVICE FINGERPRINTING ────────────────────────────────────────────────

# Common UPnP description file paths
UPNP_PATHS = [
    '/device.xml',
    '/description.xml',
    '/rootDesc.xml',
    '/upnp/description.xml',
    '/xml/device_description.xml',
]

def get_upnp_info(ip: str) -> dict:
    """
    Queries the device's UPnP description endpoint (completely passive —
    no credentials, no exploitation).

    Many routers, smart TVs, printers, and IoT hubs expose an XML file
    at http://{ip}/device.xml that contains their exact model name,
    manufacturer, and firmware version — no login required.

    Args:
        ip (str): Target IP address

    Returns:
        dict: {
            'found':        True/False,
            'friendly_name':'TP-Link Archer C6',
            'model':        'Archer C6',
            'manufacturer': 'TP-Link',
            'model_url':    'http://...',
        }
    """
    for path in UPNP_PATHS:
        try:
            url      = f"http://{ip}{path}"
            response = requests.get(url, timeout=2)

            if response.status_code != 200:
                continue

            content = response.text

            # Parse XML tags — using simple string search to avoid
            # xml.etree dependency and handle malformed device XML
            def extract(tag):
                start = content.find(f'<{tag}>')
                end   = content.find(f'</{tag}>')
                if start != -1 and end != -1:
                    return content[start + len(tag) + 2 : end].strip()
                return ''

            friendly_name = extract('friendlyName')
            model         = extract('modelName')
            manufacturer  = extract('manufacturer')
            model_url     = extract('modelURL')

            # Only return if we actually got useful data
            if friendly_name or model or manufacturer:
                return {
                    'found':         True,
                    'friendly_name': friendly_name,
                    'model':         model,
                    'manufacturer':  manufacturer,
                    'model_url':     model_url,
                    'source_path':   path,
                }

        except requests.exceptions.ConnectionError:
            break   # device not reachable on HTTP
        except requests.exceptions.Timeout:
            continue
        except Exception:
            continue

    return {'found': False}


# ── IoT DEVICE PROFILER ────────────────────────────────────────────────────────

# Port combinations that suggest specific device types
# Note: duplicate "Router / Gateway" key removed — Python dicts keep last value only
DEVICE_PROFILES = {
    "IP Camera":        [554, 80],
    "Router / Gateway": [80, 443],
    "Smart TV":         [5555, 8080],
    "IoT Hub / Bridge": [1883, 8883],
    "Network Printer":  [9100, 80],
    "Smart Speaker":    [8080, 443],
    "Windows PC":       [445, 3389],
    "Linux Server":     [22, 80],
    "Android Device":   [5555],
    "IoT Sensor":       [5683, 1883],
}


def identify_device_type(open_ports):
    """
    Guesses device type based on open port signatures.
    Requires at least 60% of signature ports to match.
    """
    if not open_ports:
        return "Unknown Device"

    open_set         = set(open_ports)
    best_match       = "Unknown Device"
    best_match_score = 0

    for device_type, signature_ports in DEVICE_PROFILES.items():
        matches = sum(1 for p in signature_ports if p in open_set)
        total   = len(signature_ports)
        score   = matches / total

        if score >= 0.6 and matches > best_match_score:
            best_match       = device_type
            best_match_score = matches

    return best_match


# ── OS FINGERPRINTING ──────────────────────────────────────────────────────────

# TTL values reported by different operating systems in IP packets
TTL_OS_MAP = [
    (255, 128, "Cisco / Network Device"),
    (128, 128, "Windows"),
    (64,  64,  "Linux / Android / macOS"),
    (32,  32,  "Windows 9x / older"),
]

def detect_os_ttl(ip: str) -> str:
    """
    Sends a single ICMP ping and reads the TTL from the response.
    Different OSes use different default TTL values:
      255 = Cisco / network gear
      128 = Windows
       64 = Linux / Android / macOS / iOS

    Args:
        ip : target IP address

    Returns:
        str: OS guess e.g. 'Linux / Android / macOS', 'Windows', or 'Unknown'
    """
    try:
        from scapy.all import IP, ICMP, sr1
        pkt = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=False)
        if pkt and pkt.haslayer('IP'):
            ttl = pkt['IP'].ttl
            # TTL decrements each hop — round up to nearest standard value
            if ttl > 128:
                return "Cisco / Network Device"
            elif ttl > 64:
                return "Windows"
            elif ttl > 32:
                return "Linux / Android / macOS"
            else:
                return "Older / Embedded OS"
    except Exception:
        pass
    return "Unknown"


def detect_firmware_from_banner(banner: str) -> dict:
    """
    Extracts firmware/software version from an HTTP Server banner.
    e.g. 'lighttpd/1.4.35'  -> {'server': 'lighttpd', 'version': '1.4.35'}
         'Apache/2.4.51'    -> {'server': 'Apache',   'version': '2.4.51'}
         'GoAhead/3.6.5'    -> {'server': 'GoAhead',  'version': '3.6.5'}

    GoAhead is a common embedded IoT web server — version is critical for CVE lookup.

    Args:
        banner : HTTP Server header string

    Returns:
        dict: {'server': str, 'version': str, 'raw': str}
              version is '' if not found
    """
    import re

    if not banner or banner in ('No Banner', 'N/A', ''):
        return {'server': '', 'version': '', 'raw': ''}

    # Match  "ServerName/x.y.z"  or  "ServerName x.y.z"
    match = re.search(r'([A-Za-z][A-Za-z0-9\-\.]+)[/ ](\d+\.\d+[\.\d]*)', banner)
    if match:
        return {
            'server':  match.group(1),
            'version': match.group(2),
            'raw':     banner,
        }

    return {'server': banner.split('/')[0].strip(), 'version': '', 'raw': banner}


def get_nmap_os(ip: str) -> str:
    """
    Uses nmap OS detection (-O flag) to identify the operating system.
    Falls back gracefully if nmap is not installed or scan fails.

    Requires: python-nmap  (pip install python-nmap)
              nmap binary  (already installed with Scapy setup on most systems)

    Args:
        ip : target IP

    Returns:
        str: OS name e.g. 'Linux 3.x', 'Windows 10', or '' if unavailable
    """
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(ip, arguments='-O --osscan-guess -T4 --max-retries 1')
        if ip in nm.all_hosts():
            osmatch = nm[ip].get('osmatch', [])
            if osmatch:
                return osmatch[0].get('name', '')
    except ImportError:
        pass   # python-nmap not installed — TTL fallback is fine
    except Exception:
        pass
    return ''


# ── MASTER FUNCTION ────────────────────────────────────────────────────────────

def run_module2(module1_results):
    """
    Takes Module 1 results and enriches each device with intelligence data.

    Args:
        module1_results (list): Output from module1.run_module1()

    Returns:
        list of dicts — each device dict extended with:
            vendor_api  : real vendor name from MAC lookup API
            banner      : HTTP Server header (or 'N/A' / 'No Banner')
            tls         : {supported, version, status}
            device_type : guessed type from open port signatures
    """
    enriched = []

    for device in module1_results:
        ip         = device['ip']
        mac        = device['mac']
        open_ports = device['open_ports']

        print(f"  Enriching {ip}...")

        # 1. Real vendor name from MAC address API (Option C filters randomised MACs)
        vendor_api   = get_mac_vendor(mac)
        vendor_local = device.get('vendor', 'Unknown Device')   # from module1 OUI_DATABASE

        # 2. Grab HTTP banner if port 80 is open
        banner = grab_banner(ip, 80) if 80 in open_ports else "N/A"

        # 3. Check TLS if port 443 is open
        tls = check_tls(ip, 443) if 443 in open_ports else {
            'supported': False, 'version': 'N/A', 'status': 'Not Available'
        }

        # 4. UPnP fingerprinting
        upnp = {'found': False}
        if 80 in open_ports or 8080 in open_ports:
            print(f"    Probing UPnP on {ip}...")
            upnp = get_upnp_info(ip)
            if upnp['found']:
                print(f"    UPnP: {upnp.get('friendly_name') or upnp.get('model','?')}")

        # 5. OS detection — TTL first (fast), nmap if available (accurate)
        print(f"    Detecting OS on {ip}...")
        os_ttl   = detect_os_ttl(ip)
        os_nmap  = get_nmap_os(ip)
        os_guess = os_nmap if os_nmap else os_ttl

        # 6. Firmware version from HTTP banner
        firmware = detect_firmware_from_banner(banner)

        # 7. Guess device type from open ports
        device_type = identify_device_type(open_ports)
        if upnp['found']:
            fn = (upnp.get('friendly_name') or upnp.get('model') or '').lower()
            if any(k in fn for k in ['camera', 'cam', 'ipc']):
                device_type = 'IP Camera'
            elif any(k in fn for k in ['router', 'gateway', 'archer', 'tplink', 'huawei']):
                device_type = 'Router / Gateway'
            elif any(k in fn for k in ['printer', 'laserjet', 'officejet']):
                device_type = 'Network Printer'
            elif any(k in fn for k in ['tv', 'bravia', 'smart']):
                device_type = 'Smart TV'

        # 8. Upgrade vendor_api if UPnP gave us better manufacturer info
        if upnp['found'] and vendor_api in [
            "Unknown Vendor", "Unknown Device",
            "Offline (No Internet)", "Lookup Timed Out"
        ]:
            mfr = upnp.get('manufacturer', '')
            if mfr:
                vendor_api = mfr

        # 9. Option B — resolve best display name from all available sources
        display_name = resolve_display_name(vendor_api, device_type, vendor_local)

        enriched.append({
            **device,
            'vendor_api':    vendor_api,
            'vendor_local':  vendor_local,
            'display_name':  display_name,   # use this in GUI instead of vendor_api
            'banner':        banner,
            'tls':           tls,
            'device_type':   device_type,
            'upnp':          upnp,
            'os':            os_guess,
            'firmware':      firmware,
        })

    return enriched
