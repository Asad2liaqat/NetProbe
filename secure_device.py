# secure_device.py
# IoT Security Scanner — Secure Device Module
#
# Provides TWO layers of camera protection:
#
#   Layer 1 — OS Driver Lock:
#       Disables the webcam device via PowerShell PnP.
#       This stops ALL apps (VLC, browsers, Teams, OBS) from
#       opening the camera. The device disappears from Device Manager.
#
#   Layer 2 — Network Firewall Block:
#       Adds Windows Firewall rules to block RTSP/HTTP camera
#       traffic inbound AND outbound for specific IPs or all hosts.
#
# Usage (standalone):
#   python secure_device.py --lock       lock camera + block ports
#   python secure_device.py --unlock     restore camera + remove rules
#   python secure_device.py --status     check current state
#   python secure_device.py --block-ip 192.168.1.100   block one device
#
# Usage (from gui.py):
#   import secure_device
#   secure_device.lock_camera()
#   secure_device.unlock_camera()
#   status = secure_device.get_full_status()

import os
import sys
import subprocess
import json
import datetime
import argparse
from colorama import Fore, Style, init

init(autoreset=True)

# ── Constants ──────────────────────────────────────────────────────────────────

STATE_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "secure_state.json"
)

# ── Firewall rule definitions ─────────────────────────────────────────────────
# Each rule has a fixed readable name, port, protocol, and description.
# This matches the format you can manually delete with:
#   netsh advfirewall firewall delete rule name="Block Camera RTSP In"
#
# Rule naming convention:
#   "Block <ServiceName> <Protocol> <Direction>"
#   e.g. "Block Camera RTSP In", "Block Camera RTSP Out"

FIREWALL_RULES = [
    # ── Camera streaming ───────────────────────────────────────────────────────
    {"name": "Block Camera RTSP In",       "port": 554,   "proto": "TCP", "dir": "in",  "desc": "RTSP camera stream inbound"},
    {"name": "Block Camera RTSP Out",      "port": 554,   "proto": "TCP", "dir": "out", "desc": "RTSP camera stream outbound"},
    {"name": "Block Camera RTSP UDP In",   "port": 554,   "proto": "UDP", "dir": "in",  "desc": "RTSP UDP inbound"},
    {"name": "Block Camera RTSP UDP Out",  "port": 554,   "proto": "UDP", "dir": "out", "desc": "RTSP UDP outbound"},
    {"name": "Block Camera RTSP Alt In",   "port": 8554,  "proto": "TCP", "dir": "in",  "desc": "RTSP alt port inbound"},
    {"name": "Block Camera RTSP Alt Out",  "port": 8554,  "proto": "TCP", "dir": "out", "desc": "RTSP alt port outbound"},

    # ── Camera web interfaces ──────────────────────────────────────────────────
    {"name": "Block Camera HTTP In",       "port": 80,    "proto": "TCP", "dir": "in",  "desc": "Camera HTTP web UI inbound"},
    {"name": "Block Camera HTTP Out",      "port": 80,    "proto": "TCP", "dir": "out", "desc": "Camera HTTP web UI outbound"},
    {"name": "Block Camera HTTP Alt In",   "port": 8080,  "proto": "TCP", "dir": "in",  "desc": "Camera HTTP alt inbound"},
    {"name": "Block Camera HTTP Alt Out",  "port": 8080,  "proto": "TCP", "dir": "out", "desc": "Camera HTTP alt outbound"},
    {"name": "Block Camera HTTP 8888 In",  "port": 8888,  "proto": "TCP", "dir": "in",  "desc": "Camera HTTP 8888 inbound"},
    {"name": "Block Camera HTTP 8888 Out", "port": 8888,  "proto": "TCP", "dir": "out", "desc": "Camera HTTP 8888 outbound"},

    # ── Vendor-specific protocols ──────────────────────────────────────────────
    {"name": "Block Dahua Protocol In",    "port": 37777, "proto": "TCP", "dir": "in",  "desc": "Dahua camera protocol inbound"},
    {"name": "Block Dahua Protocol Out",   "port": 37777, "proto": "TCP", "dir": "out", "desc": "Dahua camera protocol outbound"},
    {"name": "Block XMEye Protocol In",    "port": 34567, "proto": "TCP", "dir": "in",  "desc": "XMEye camera protocol inbound"},
    {"name": "Block XMEye Protocol Out",   "port": 34567, "proto": "TCP", "dir": "out", "desc": "XMEye camera protocol outbound"},
    {"name": "Block Hikvision ISAPI In",   "port": 9000,  "proto": "TCP", "dir": "in",  "desc": "Hikvision ISAPI inbound"},
    {"name": "Block Hikvision ISAPI Out",  "port": 9000,  "proto": "TCP", "dir": "out", "desc": "Hikvision ISAPI outbound"},
]

# For quick port lookups (backwards compat)
CAMERA_PORTS = {r["port"]: r["desc"] for r in FIREWALL_RULES}

# PnP device classes that cover webcams / USB cameras / integrated cameras
CAMERA_PNP_CLASSES = ["Camera", "Image", "SmartCameras"]

# Audit log
AUDIT_LOG = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "audit_log.txt"
)


# ══════════════════════════════════════════════════════════════════════════════
# STATE MANAGEMENT
# ══════════════════════════════════════════════════════════════════════════════

def _load_state() -> dict:
    """Loads persisted secure state from disk."""
    default = {
        "camera_locked":     False,
        "locked_at":         None,
        "blocked_ips":       [],
        "firewall_rules":    [],
        "devices_disabled":  [],
    }
    if not os.path.exists(STATE_FILE):
        return default
    try:
        with open(STATE_FILE, "r") as f:
            saved = json.load(f)
        default.update(saved)
        return default
    except Exception:
        return default


def _save_state(state: dict) -> None:
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


def _audit(msg: str) -> None:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(AUDIT_LOG, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] [SecureDevice] {msg}\n")
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 1 — OS DRIVER LOCK  (kills VLC and all app access)
# ══════════════════════════════════════════════════════════════════════════════

def _run_powershell(cmd: str, capture: bool = True) -> tuple:
    """
    Runs a PowerShell command with admin rights assumed.
    Returns (returncode, stdout, stderr).
    """
    try:
        result = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass",
             "-WindowStyle", "Hidden", "-Command", cmd],
            capture_output=capture,
            text=True,
            timeout=15
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Timeout"
    except Exception as e:
        return -1, "", str(e)


def discover_cameras() -> list:
    """
    Returns a list of camera devices found via PowerShell PnP.
    Each entry: {'name': str, 'instance_id': str, 'status': str}
    """
    cmd = (
        "Get-PnpDevice | "
        "Where-Object { $_.Class -in @('Camera','Image','SmartCameras') } | "
        "Select-Object FriendlyName, InstanceId, Status | "
        "ConvertTo-Json -Compress"
    )
    rc, out, err = _run_powershell(cmd)
    if rc != 0 or not out:
        return []

    try:
        raw = json.loads(out)
        # PowerShell returns a dict if only one device, list if multiple
        if isinstance(raw, dict):
            raw = [raw]
        return [
            {
                "name":        d.get("FriendlyName", "Unknown Camera"),
                "instance_id": d.get("InstanceId", ""),
                "status":      d.get("Status", "Unknown"),
            }
            for d in raw if d.get("InstanceId")
        ]
    except Exception:
        return []


def _disable_camera_devices() -> tuple:
    """
    Disables all PnP camera devices via PowerShell.
    Returns (success: bool, disabled_names: list, message: str)
    """
    cameras = discover_cameras()
    if not cameras:
        # Try a broader disable by class even if discovery returned nothing
        cmd = (
            "Get-PnpDevice -Class Camera,Image -ErrorAction SilentlyContinue | "
            "Disable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue"
        )
        rc, _, err = _run_powershell(cmd)
        if rc == 0:
            return True, ["All camera devices"], "Disabled by class"
        return False, [], f"No cameras found: {err}"

    disabled = []
    errors   = []
    for cam in cameras:
        iid = cam["instance_id"].replace("'", "\\'")
        cmd = (
            f"Get-PnpDevice -InstanceId '{iid}' | "
            f"Disable-PnpDevice -Confirm:$false -ErrorAction Stop"
        )
        rc, _, err = _run_powershell(cmd)
        if rc == 0:
            disabled.append(cam["name"])
        else:
            errors.append(f"{cam['name']}: {err[:60]}")

    if disabled:
        return True, disabled, f"Disabled: {', '.join(disabled)}"
    return False, [], f"Failed: {'; '.join(errors)}"


def _enable_camera_devices() -> tuple:
    """
    Re-enables all PnP camera devices.
    Returns (success: bool, enabled_names: list, message: str)
    """
    cmd = (
        "Get-PnpDevice -Class Camera,Image -ErrorAction SilentlyContinue | "
        "Enable-PnpDevice -Confirm:$false -ErrorAction SilentlyContinue"
    )
    rc, out, err = _run_powershell(cmd)

    if rc == 0:
        cameras = discover_cameras()
        names   = [c["name"] for c in cameras] or ["Camera devices"]
        return True, names, "All camera devices re-enabled"
    return False, [], f"Enable failed: {err[:80]}"


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 2 — NETWORK FIREWALL BLOCK
# ══════════════════════════════════════════════════════════════════════════════

def _add_single_rule(rule: dict, ip: str = None) -> bool:
    """
    Adds one firewall rule from the FIREWALL_RULES table.
    If ip is provided the rule is scoped to that remote IP only.
    Rule name stays exactly as defined — readable and manually deletable.

    Manual delete:
        netsh advfirewall firewall delete rule name="Block Camera RTSP In"
    """
    name    = rule["name"]
    port    = rule["port"]
    proto   = rule["proto"]
    dir_    = rule["dir"]
    ip_part = f'remoteip="{ip}"' if ip else ""

    # Append IP suffix to name so per-IP rules don't collide with global rules
    if ip:
        name = f'{name} [{ip}]'

    cmd = (
        f'netsh advfirewall firewall add rule '
        f'name="{name}" '
        f'dir={dir_} '
        f'action=block '
        f'protocol={proto} '
        f'localport={port} '
        f'{ip_part} '
        f'enable=yes'
    )
    rc, _, _ = _run_powershell(cmd)
    return rc == 0


def _delete_single_rule(rule: dict, ip: str = None) -> bool:
    """
    Deletes one firewall rule by its exact name.
    Matches the same naming convention used in _add_single_rule.

    Equivalent manual command:
        netsh advfirewall firewall delete rule name="Block Camera RTSP In"
    """
    name = rule["name"]
    if ip:
        name = f'{name} [{ip}]'
    rc, _, _ = _run_powershell(
        f'netsh advfirewall firewall delete rule name="{name}"'
    )
    return rc == 0


def _block_all_camera_ports(ip: str = None) -> dict:
    """
    Adds all firewall rules from FIREWALL_RULES table.
    If ip is provided, rules are scoped to that IP only.

    To manually remove ALL rules this creates:
        netsh advfirewall firewall delete rule name="Block Camera RTSP In"
        netsh advfirewall firewall delete rule name="Block Camera RTSP Out"
        ... (one per rule in FIREWALL_RULES)

    Returns: {'blocked': [port list], 'failed': [port list]}
    """
    blocked_ports = set()
    failed_ports  = set()

    for rule in FIREWALL_RULES:
        ok = _add_single_rule(rule, ip=ip)
        if ok:
            blocked_ports.add(rule["port"])
        else:
            failed_ports.add(rule["port"])

    return {
        "blocked": sorted(blocked_ports),
        "failed":  sorted(failed_ports - blocked_ports),
    }


def _remove_all_firewall_rules() -> int:
    """
    Removes every firewall rule this module created.
    Iterates FIREWALL_RULES and deletes each by exact name.

    Equivalent manual commands (global rules):
        netsh advfirewall firewall delete rule name="Block Camera RTSP In"
        netsh advfirewall firewall delete rule name="Block Camera RTSP Out"
        netsh advfirewall firewall delete rule name="Block Camera RTSP UDP In"
        ... etc.

    Returns: count of rules successfully removed.
    """
    count = 0
    for rule in FIREWALL_RULES:
        # Delete global rule
        if _delete_single_rule(rule):
            count += 1

    # Also try to delete any per-IP rules from blocked_ips in state
    state = _load_state()
    for ip in state.get("blocked_ips", []):
        for rule in FIREWALL_RULES:
            if _delete_single_rule(rule, ip=ip):
                count += 1

    return count


def _remove_ip_firewall_rules(ip: str) -> int:
    """
    Removes firewall rules scoped to a specific IP.

    Equivalent manual commands:
        netsh advfirewall firewall delete rule name="Block Camera RTSP In [192.168.1.x]"
        netsh advfirewall firewall delete rule name="Block Camera RTSP Out [192.168.1.x]"
        ... etc.

    Returns: count of rules removed.
    """
    count = 0
    for rule in FIREWALL_RULES:
        if _delete_single_rule(rule, ip=ip):
            count += 1
    return count


def list_active_rules() -> list:
    """
    Returns all active firewall rules created by this module.
    Useful for the GUI blocked devices panel and status check.

    Returns: list of rule name strings currently active in Windows Firewall.
    """
    active = []
    for rule in FIREWALL_RULES:
        # Check global rule
        rc, out, _ = _run_powershell(
            f'netsh advfirewall firewall show rule name="{rule["name"]}"'
        )
        if rc == 0 and "No rules match" not in out:
            active.append(rule["name"])

    # Check per-IP rules
    state = _load_state()
    for ip in state.get("blocked_ips", []):
        for rule in FIREWALL_RULES:
            name = f'{rule["name"]} [{ip}]'
            rc, out, _ = _run_powershell(
                f'netsh advfirewall firewall show rule name="{name}"'
            )
            if rc == 0 and "No rules match" not in out:
                active.append(name)

    return active


def get_manual_delete_commands(ip: str = None) -> list:
    """
    Returns the exact netsh commands needed to manually remove all rules.
    Useful for printing to the GUI log so the user can run them manually.

    Args:
        ip: if provided, returns commands for that IP's rules only

    Returns: list of command strings
    """
    cmds = []
    for rule in FIREWALL_RULES:
        name = f'{rule["name"]} [{ip}]' if ip else rule["name"]
        cmds.append(f'netsh advfirewall firewall delete rule name="{name}"')
    return cmds


# ══════════════════════════════════════════════════════════════════════════════
# LAYER 3 — KILL ACTIVE CAMERA PROCESSES  (bonus: stops running VLC etc.)
# ══════════════════════════════════════════════════════════════════════════════

CAMERA_PROCESSES = [
    "vlc", "zoom", "teams", "skype", "obs64", "obs32",
    "chrome", "msedge", "firefox", "CameraApp",
    "WindowsCamera", "SnippingTool"
]

def kill_camera_processes(dry_run: bool = True) -> list:
    """
    Finds and optionally kills processes known to access the camera.
    dry_run=True: returns list without killing (for UI confirmation).
    dry_run=False: actually terminates them.

    Returns list of {'name': str, 'pid': int, 'killed': bool}
    """
    cmd = (
        "Get-Process | "
        "Select-Object Name, Id | "
        "ConvertTo-Json -Compress"
    )
    rc, out, _ = _run_powershell(cmd)
    if rc != 0 or not out:
        return []

    try:
        processes = json.loads(out)
        if isinstance(processes, dict):
            processes = [processes]
    except Exception:
        return []

    found = []
    for proc in processes:
        name = proc.get("Name", "").lower()
        pid  = proc.get("Id", 0)
        if any(name.startswith(cp.lower()) for cp in CAMERA_PROCESSES):
            killed = False
            if not dry_run:
                rc2, _, _ = _run_powershell(
                    f"Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue"
                )
                killed = rc2 == 0
            found.append({"name": proc["Name"], "pid": pid, "killed": killed})

    return found


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def lock_camera(kill_procs: bool = False) -> dict:
    """
    Full camera lockdown:
      1. Kills active camera processes (optional)
      2. Disables camera device driver (blocks VLC + all apps)
      3. Adds firewall rules for all camera ports

    Args:
        kill_procs: if True, also kill VLC/Teams/etc. before locking

    Returns:
        {
          'success':          bool,
          'driver_disabled':  bool,
          'driver_names':     [str],
          'ports_blocked':    [int],
          'ports_failed':     [int],
          'procs_killed':     [dict],
          'message':          str,
        }
    """
    result = {
        "success":         False,
        "driver_disabled": False,
        "driver_names":    [],
        "ports_blocked":   [],
        "ports_failed":    [],
        "procs_killed":    [],
        "message":         "",
    }

    # Step 0 — kill camera processes
    if kill_procs:
        procs = kill_camera_processes(dry_run=False)
        result["procs_killed"] = procs

    # Step 1 — disable driver (Layer 1)
    ok, names, msg = _disable_camera_devices()
    result["driver_disabled"] = ok
    result["driver_names"]    = names

    # Step 2 — firewall rules (Layer 2)
    fw = _block_all_camera_ports()
    result["ports_blocked"] = fw["blocked"]
    result["ports_failed"]  = fw["failed"]

    result["success"] = ok or bool(fw["blocked"])
    result["message"] = (
        f"Driver: {'Disabled' if ok else 'Failed'}  |  "
        f"Ports blocked: {len(fw['blocked'])}  |  "
        f"Ports failed: {len(fw['failed'])}"
    )

    # Persist state
    state = _load_state()
    state["camera_locked"]    = True
    state["locked_at"]        = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    state["devices_disabled"] = names
    state["firewall_rules"]   = fw["blocked"]   # port numbers
    _save_state(state)

    # Print manual delete commands to stdout so GUI log captures them
    print("  Manual unlock commands (run as Admin if needed):")
    for cmd in get_manual_delete_commands()[:4]:
        print(f"    {cmd}")
    print(f"  ... ({len(FIREWALL_RULES)} rules total)")

    _audit(f"Camera LOCKED — {result['message']}")
    return result


def unlock_camera() -> dict:
    """
    Full camera restore:
      1. Re-enables camera device driver
      2. Removes all firewall rules added by this module

    Returns:
        {
          'success':        bool,
          'driver_enabled': bool,
          'rules_removed':  int,
          'message':        str,
        }
    """
    result = {
        "success":        False,
        "driver_enabled": False,
        "rules_removed":  0,
        "message":        "",
    }

    # Step 1 — re-enable driver
    ok, names, msg = _enable_camera_devices()
    result["driver_enabled"] = ok

    # Step 2 — remove firewall rules
    removed = _remove_all_firewall_rules()
    result["rules_removed"] = removed

    result["success"] = ok or removed > 0
    result["message"] = (
        f"Driver: {'Re-enabled' if ok else 'Failed'}  |  "
        f"Rules removed: {removed}"
    )

    # Update state
    state = _load_state()
    state["camera_locked"]    = False
    state["locked_at"]        = None
    state["devices_disabled"] = []
    state["firewall_rules"]   = []
    _save_state(state)

    _audit(f"Camera UNLOCKED — {result['message']}")
    return result


def block_device_camera(ip: str) -> dict:
    """
    Blocks camera access from/to a specific IP only.
    Useful for locking down a single suspicious camera on the network.

    Returns:
        {'ip': str, 'ports_blocked': [int], 'ports_failed': [int]}
    """
    fw = _block_all_camera_ports(ip=ip)

    state = _load_state()
    if ip not in state["blocked_ips"]:
        state["blocked_ips"].append(ip)
    _save_state(state)

    _audit(f"Blocked camera ports for IP {ip} — ports: {fw['blocked']}")
    return {
        "ip":           ip,
        "ports_blocked": fw["blocked"],
        "ports_failed":  fw["failed"],
    }


def unblock_device_camera(ip: str) -> dict:
    """
    Removes all firewall rules for a specific IP.
    Also removes any host route block added by quick_block_rtsp.

    Equivalent manual command (fastest — removes ALL rules for that IP):
        netsh advfirewall firewall delete rule name=all remoteip=192.168.100.124

    Returns: {'ip': str, 'rules_removed': int}
    """
    removed = _remove_ip_firewall_rules(ip)

    # Also remove host route block if one was added
    _run_powershell(
        f'route delete {ip}'
    )

    state = _load_state()
    state["blocked_ips"] = [x for x in state["blocked_ips"] if x != ip]
    _save_state(state)

    _audit(f"Unblocked {ip} — {removed} firewall rules removed")

    # Print confirmation commands
    print(f"  Unblocked {ip}.")
    print(f"  If rules still appear, run manually:")
    print(f'    netsh advfirewall firewall delete rule name=all remoteip={ip}')

    return {"ip": ip, "rules_removed": removed}


# ══════════════════════════════════════════════════════════════════════════════
# RTSP URL PARSER + QUICK BLOCK
# ══════════════════════════════════════════════════════════════════════════════

def parse_rtsp_url(url: str) -> dict:
    """
    Parses an RTSP URL into its components.

    Supports formats:
        rtsp://192.168.100.124/
        rtsp://192.168.100.124:554/stream1
        rtsp://admin:password@192.168.100.124:554/live
        rtsp://192.168.100.124          (no trailing slash)

    Returns:
        {
          'valid':    bool,
          'ip':       str,
          'port':     int,
          'path':     str,
          'username': str,
          'password': str,
          'raw':      str,
          'error':    str,
        }
    """
    result = {
        "valid":    False,
        "ip":       "",
        "port":     554,
        "path":     "/",
        "username": "",
        "password": "",
        "raw":      url.strip(),
        "error":    "",
    }

    try:
        url = url.strip()

        # Strip protocol
        if "://" in url:
            proto, rest = url.split("://", 1)
            if proto.lower() not in ("rtsp", "rtsps", "http", "https"):
                result["error"] = f"Unknown protocol: {proto}"
                return result
        else:
            rest = url

        # Extract credentials if present (user:pass@host)
        if "@" in rest:
            creds, rest = rest.split("@", 1)
            if ":" in creds:
                result["username"], result["password"] = creds.split(":", 1)
            else:
                result["username"] = creds

        # Extract path
        if "/" in rest:
            host_part, path = rest.split("/", 1)
            result["path"] = "/" + path
        else:
            host_part = rest

        # Extract port
        if ":" in host_part:
            ip_str, port_str = host_part.rsplit(":", 1)
            try:
                result["port"] = int(port_str)
            except ValueError:
                result["error"] = f"Invalid port: {port_str}"
                return result
        else:
            ip_str = host_part

        # Validate IP
        parts = ip_str.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
            result["ip"]    = ip_str
            result["valid"] = True
        else:
            result["error"] = f"Invalid IP address: {ip_str}"
            return result

    except Exception as e:
        result["error"] = str(e)

    return result


def quick_block_rtsp(url: str, kill_vlc: bool = True) -> dict:
    """
    Parses an RTSP URL and immediately blocks access to that camera.

    Usage:
        result = quick_block_rtsp("rtsp://192.168.100.124/")
        result = quick_block_rtsp("rtsp://admin:pass@192.168.100.124:8554/live")

    3-step lockdown:
      1. Kill VLC and any app streaming from that IP
      2. Block all camera ports for that specific IP via Firewall
      3. Add a host route block — drops ALL packets to the IP at OS level

    To manually unblock:
        netsh advfirewall firewall delete rule name=all remoteip=192.168.100.124
        route delete 192.168.100.124

    Returns:
        {
          'success':       bool,
          'ip':            str,
          'port':          int,
          'ports_blocked': [int],
          'ports_failed':  [int],
          'procs_killed':  [dict],
          'route_blocked': bool,
          'message':       str,
          'unblock_cmd':   str,
        }
    """
    # Step 0 — Parse the URL
    parsed = parse_rtsp_url(url)
    if not parsed["valid"]:
        return {
            "success": False,
            "ip":      "",
            "message": f"Invalid RTSP URL: {parsed['error']}",
        }

    ip   = parsed["ip"]
    port = parsed["port"]

    print(f"  Parsed RTSP URL:")
    print(f"    IP       : {ip}")
    print(f"    Port     : {port}")
    print(f"    Path     : {parsed['path']}")
    if parsed["username"]:
        print(f"    Auth     : {parsed['username']}:{'*' * len(parsed['password'])}")

    result = {
        "success":       False,
        "ip":            ip,
        "port":          port,
        "ports_blocked": [],
        "ports_failed":  [],
        "procs_killed":  [],
        "route_blocked": False,
        "message":       "",
        "unblock_cmd":   (
            f'netsh advfirewall firewall delete rule name=all remoteip={ip}\n'
            f'route delete {ip}'
        ),
    }

    # Step 1 — Kill VLC and streaming apps
    if kill_vlc:
        print(f"  Step 1/3 — Killing VLC and streaming apps...")
        procs  = kill_camera_processes(dry_run=False)
        killed = [p["name"] for p in procs if p.get("killed")]
        result["procs_killed"] = procs
        if killed:
            print(f"    Killed: {', '.join(killed)}")
        else:
            print(f"    No streaming apps were running.")

    # Step 2 — Add precise RTSP firewall rules for this specific IP + port.
    # These two commands are the exact rules that kill an active VLC RTSP stream:
    #   Outbound: block TCP from us to remoteip:remoteport (stops VLC sending requests)
    #   Inbound:  block TCP from remoteip on localport     (stops camera data arriving)
    print(f"  Step 2/3 — Adding RTSP firewall rules for {ip}:{port}...")

    out_name = f"Block Camera RTSP Out [{ip}]"
    in_name  = f"Block Camera RTSP In [{ip}]"

    cmd_out = (
        f'netsh advfirewall firewall add rule '
        f'name="{out_name}" '
        f'protocol=TCP '
        f'dir=out '
        f'remoteip={ip} '
        f'remoteport={port} '
        f'action=block'
    )
    cmd_in = (
        f'netsh advfirewall firewall add rule '
        f'name="{in_name}" '
        f'protocol=TCP '
        f'dir=in '
        f'remoteip={ip} '
        f'localport={port} '
        f'action=block'
    )

    rc_out, _, err_out = _run_powershell(cmd_out)
    rc_in,  _, err_in  = _run_powershell(cmd_in)

    if rc_out == 0:
        result["ports_blocked"].append(port)
        print(f"    [OK] Outbound rule added: {out_name}")
    else:
        result["ports_failed"].append(port)
        print(f"    [!] Outbound rule failed: {err_out[:60]}")

    if rc_in == 0:
        if port not in result["ports_blocked"]:
            result["ports_blocked"].append(port)
        print(f"    [OK] Inbound rule added:  {in_name}")
    else:
        print(f"    [!] Inbound rule failed:  {err_in[:60]}")

    # Persist the rule names so unblock can find and remove them
    fw = {"blocked": result["ports_blocked"], "failed": result["ports_failed"]}

    # Step 3 — Add host route block (drops ALL packets to IP, any port)
    print(f"  Step 3/3 — Adding host route block for {ip}...")
    rc, _, err = _run_powershell(
        f'route add {ip} mask 255.255.255.255 0.0.0.0'
    )
    result["route_blocked"] = rc == 0
    if rc == 0:
        print(f"    Host route block added — all traffic to {ip} is now dropped.")
    else:
        print(f"    Route block failed (non-critical): {err[:60]}")

    # Persist state
    state = _load_state()
    if ip not in state["blocked_ips"]:
        state["blocked_ips"].append(ip)
    _save_state(state)

    result["success"] = bool(fw["blocked"]) or result["route_blocked"]
    result["message"] = (
        f"IP {ip} blocked — "
        f"{len(fw['blocked'])} firewall rules  |  "
        f"Route block: {'Yes' if result['route_blocked'] else 'No'}  |  "
        f"Processes killed: {len([p for p in result['procs_killed'] if p.get('killed')])}"
    )

    _audit(f"RTSP Quick Block — URL: {url}  IP: {ip}  {result['message']}")

    print(f"\n  To manually unblock {ip}, run:")
    print(f'    netsh advfirewall firewall delete rule name=all remoteip={ip}')
    print(f'    route delete {ip}')

    return result


def get_full_status() -> dict:
    """
    Returns current state of all locks.
    Safe to call at any time — reads state file + live device check.

    Returns:
        {
          'camera_locked':    bool,
          'locked_at':        str | None,
          'cameras_found':    [{'name', 'status'}],
          'driver_disabled':  bool,
          'blocked_ips':      [str],
          'firewall_rules':   [int],
        }
    """
    state   = _load_state()
    cameras = discover_cameras()

    # Check if driver is actually disabled right now (live check)
    driver_off = any(
        c["status"] in ("Error", "Unknown", "Disabled")
        for c in cameras
    ) if cameras else state.get("camera_locked", False)

    # Get live active rule list from Windows Firewall (not just saved state)
    try:
        active_rules = list_active_rules()
    except Exception:
        active_rules = state.get("firewall_rules", [])

    return {
        "camera_locked":   state.get("camera_locked", False),
        "locked_at":       state.get("locked_at"),
        "cameras_found":   cameras,
        "driver_disabled": driver_off,
        "blocked_ips":     state.get("blocked_ips", []),
        "firewall_rules":  active_rules,
        "rule_names":      active_rules,   # readable names for GUI display
    }


def check_admin() -> bool:
    """Returns True if current process has admin privileges."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
# CLI INTERFACE  (for standalone use)
# ══════════════════════════════════════════════════════════════════════════════

def _print_status():
    status = get_full_status()

    print(f"\n{Fore.CYAN}{'═' * 55}")
    print(f"  IoT Scanner — Secure Device Status")
    print(f"{'═' * 55}{Style.RESET_ALL}\n")

    locked = status["camera_locked"]
    color  = Fore.RED if locked else Fore.GREEN
    label  = "🔒  LOCKED" if locked else "🔓  UNLOCKED"
    print(f"  Camera Status : {color}{label}{Style.RESET_ALL}")

    if status["locked_at"]:
        print(f"  Locked at     : {status['locked_at']}")

    print(f"\n  Cameras found :")
    if status["cameras_found"]:
        for cam in status["cameras_found"]:
            st    = cam["status"]
            col   = Fore.RED if st in ("Error", "Disabled") else Fore.GREEN
            print(f"    {col}● {cam['name']}  [{st}]{Style.RESET_ALL}")
    else:
        print(f"    {Fore.YELLOW}No camera devices detected{Style.RESET_ALL}")

    print(f"\n  Firewall rules : {len(status['firewall_rules'])} active")
    for r in status.get("rule_names", [])[:6]:
        print(f"    - {r}")
    if len(status.get("rule_names", [])) > 6:
        print(f"    ... and {len(status['rule_names']) - 6} more")

    if status["blocked_ips"]:
        print(f"\n  Blocked IPs    : {', '.join(status['blocked_ips'])}")
        print(f"\n  Manual delete commands:")
        for ip in status["blocked_ips"][:1]:   # show first IP
            for cmd in get_manual_delete_commands(ip)[:3]:
                print(f"    {cmd}")
            print(f"    ... ({len(FIREWALL_RULES)} rules total per IP)")

    print()


def main():
    if not check_admin():
        print(f"{Fore.RED}[!] Must run as Administrator{Style.RESET_ALL}")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="IoT Scanner — Secure Device (Camera Lockdown)",
        epilog="Run as Administrator. Locks camera at driver + firewall level."
    )
    parser.add_argument("--lock",       action="store_true",
                        help="Lock camera (disable driver + block ports)")
    parser.add_argument("--unlock",     action="store_true",
                        help="Unlock camera (re-enable driver + remove rules)")
    parser.add_argument("--status",     action="store_true",
                        help="Show current lock status")
    parser.add_argument("--block-ip",   metavar="IP",
                        help="Block camera ports for a specific IP")
    parser.add_argument("--unblock-ip", metavar="IP",
                        help="Remove camera block for a specific IP")
    parser.add_argument("--kill-procs", action="store_true",
                        help="Also kill VLC/Teams/etc. when locking")
    args = parser.parse_args()

    if args.status or not any([
        args.lock, args.unlock, args.block_ip, args.unblock_ip
    ]):
        _print_status()
        return

    if args.lock:
        print(f"\n{Fore.YELLOW}  Locking camera...{Style.RESET_ALL}")
        result = lock_camera(kill_procs=args.kill_procs)
        if result["success"]:
            print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} {result['message']}")
            if result["driver_names"]:
                for n in result["driver_names"]:
                    print(f"       Driver disabled: {n}")
            print(f"       Ports blocked  : {result['ports_blocked']}")
        else:
            print(f"  {Fore.RED}[!!]{Style.RESET_ALL} Lock failed: {result['message']}")

    elif args.unlock:
        print(f"\n{Fore.YELLOW}  Unlocking camera...{Style.RESET_ALL}")
        result = unlock_camera()
        if result["success"]:
            print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} {result['message']}")
        else:
            print(f"  {Fore.RED}[!!]{Style.RESET_ALL} Unlock failed: {result['message']}")

    elif args.block_ip:
        print(f"\n  Blocking camera for {args.block_ip}...")
        result = block_device_camera(args.block_ip)
        print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} Blocked ports {result['ports_blocked']} for {args.block_ip}")

    elif args.unblock_ip:
        print(f"\n  Unblocking {args.unblock_ip}...")
        result = unblock_device_camera(args.unblock_ip)
        print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} Removed {result['rules_removed']} rules for {args.unblock_ip}")

    print()


if __name__ == "__main__":
    main()
