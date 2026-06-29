"""
module6.py — Storage & History Engine
IoT Device Security Scanner | Module 6

Responsibilities:
  - Persist every scan to a local SQLite database (no install required)
  - Retrieve previous scan results for comparison
  - Detect new devices, missing devices, and changed port profiles
  - Print a colour-coded change-alert table to the console

Database file: scanner_history.db  (created in project root on first run)

Tables
------
scans   : one row per scan run
devices : one row per device per scan (linked by scan_id)
"""

import sqlite3
import json
import os
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# ---------------------------------------------------------------------------
# Database path — sits next to this file
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner_history.db")


# ===========================================================================
# 1.  Schema Bootstrap
# ===========================================================================

def _get_connection() -> sqlite3.Connection:
    """Return a connection with foreign-key enforcement enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row          # access columns by name
    return conn


def init_db() -> None:
    """Create tables if they do not already exist.  Safe to call every run."""
    conn = _get_connection()
    try:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT    NOT NULL,
                gateway     TEXT    NOT NULL,
                ip_range    TEXT    NOT NULL,
                score       INTEGER NOT NULL,
                score_label TEXT    NOT NULL,
                device_count INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS devices (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                ip          TEXT    NOT NULL,
                mac         TEXT    NOT NULL,
                vendor      TEXT,
                vendor_api  TEXT,
                device_type TEXT,
                risk        TEXT    NOT NULL,
                open_ports  TEXT    NOT NULL,   -- JSON list of ints
                banner      TEXT,
                tls_version TEXT,
                tls_status  TEXT,
                verdict     TEXT                -- from module4, nullable
            );

            CREATE INDEX IF NOT EXISTS idx_devices_scan_id ON devices(scan_id);
            CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp);
        """)
        conn.commit()
        print(f"{Fore.CYAN}[Module 6]{Style.RESET_ALL} Database ready → {DB_PATH}")
    finally:
        conn.close()


# ===========================================================================
# 2.  Save Scan
# ===========================================================================

def save_scan(
    gateway: str,
    ip_range: str,
    score: int,
    score_label: str,
    devices: list,          # m2_results or m3['devices']
    m4_results: list = None # optional — adds verdict per device
) -> int:
    """
    Persist a complete scan to the database.

    Parameters
    ----------
    gateway     : e.g. '192.168.100.1'
    ip_range    : e.g. '192.168.100.0/24'
    score       : network security score 0-100
    score_label : 'Critical' / 'At Risk' / 'Good' / 'Excellent'
    devices     : list of device dicts (m2_results format)
    m4_results  : optional list of red-team results (adds verdict column)

    Returns
    -------
    scan_id : int — the new row's primary key
    """
    # Build a verdict lookup from m4 results if provided
    verdict_map = {}
    if m4_results:
        for r in m4_results:
            verdict_map[r.get('ip', '')] = r.get('verdict', None)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = _get_connection()
    try:
        cursor = conn.execute(
            """INSERT INTO scans (timestamp, gateway, ip_range, score, score_label, device_count)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (timestamp, gateway, ip_range, score, score_label, len(devices))
        )
        scan_id = cursor.lastrowid

        for dev in devices:
            tls       = dev.get('tls') or {}
            open_ports = json.dumps(dev.get('open_ports', []))
            verdict   = verdict_map.get(dev.get('ip', ''), None)

            conn.execute(
                """INSERT INTO devices
                   (scan_id, ip, mac, vendor, vendor_api, device_type,
                    risk, open_ports, banner, tls_version, tls_status, verdict)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    dev.get('ip',          'Unknown'),
                    dev.get('mac',         'Unknown'),
                    dev.get('display_name', dev.get('vendor', 'Unknown')),
                    dev.get('vendor_api',  None),
                    dev.get('device_type', None),
                    dev.get('risk',        'UNKNOWN'),
                    open_ports,
                    dev.get('banner',      None),
                    tls.get('version',     None),
                    tls.get('status',      None),
                    verdict,
                )
            )

        conn.commit()
        print(f"{Fore.GREEN}[Module 6]{Style.RESET_ALL} Scan #{scan_id} saved "
              f"({len(devices)} devices, score {score}/100, {timestamp})")
        return scan_id

    except Exception as exc:
        conn.rollback()
        print(f"{Fore.RED}[Module 6] ERROR saving scan: {exc}{Style.RESET_ALL}")
        return -1
    finally:
        conn.close()


# ===========================================================================
# 3.  Retrieve Scans
# ===========================================================================

def get_last_scan(exclude_scan_id: int = None) -> dict | None:
    """
    Return the most recent scan as a dict with a 'devices' list.

    Parameters
    ----------
    exclude_scan_id : pass the current scan_id to fetch the *previous* scan
                      (useful when you've just saved and want to compare)

    Returns None if no previous scan exists.
    """
    conn = _get_connection()
    try:
        if exclude_scan_id is not None:
            row = conn.execute(
                "SELECT * FROM scans WHERE id != ? ORDER BY id DESC LIMIT 1",
                (exclude_scan_id,)
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT 1"
            ).fetchone()

        if row is None:
            return None

        scan = dict(row)
        device_rows = conn.execute(
            "SELECT * FROM devices WHERE scan_id = ?", (scan['id'],)
        ).fetchall()

        scan['devices'] = []
        for dr in device_rows:
            d = dict(dr)
            d['open_ports'] = json.loads(d['open_ports'])   # restore list
            scan['devices'].append(d)

        return scan

    finally:
        conn.close()


def get_scan_history(limit: int = 10) -> list:
    """
    Return the last `limit` scan summaries (no device detail).
    Useful for a history table in main.py --history flag.
    """
    conn = _get_connection()
    try:
        rows = conn.execute(
            """SELECT id, timestamp, gateway, ip_range, score, score_label, device_count
               FROM scans ORDER BY id DESC LIMIT ?""",
            (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ===========================================================================
# 4.  Compare Scans
# ===========================================================================

def compare_scans(current_devices: list, previous_scan: dict) -> dict:
    """
    Diff the current device list against a previous scan.

    Parameters
    ----------
    current_devices : list of device dicts from current run (m2_results)
    previous_scan   : dict returned by get_last_scan()

    Returns
    -------
    {
        'new_devices'     : [{'ip', 'mac', 'vendor', 'risk', 'open_ports'}],
        'missing_devices' : [{'ip', 'mac', 'vendor'}],
        'changed_ports'   : [{'ip', 'vendor', 'old_ports', 'new_ports',
                               'added_ports', 'removed_ports'}],
        'risk_changes'    : [{'ip', 'vendor', 'old_risk', 'new_risk'}],
        'has_changes'     : bool
    }
    """
    prev_devices = {d['ip']: d for d in previous_scan.get('devices', [])}
    curr_devices = {d['ip']: d for d in current_devices}

    prev_ips = set(prev_devices.keys())
    curr_ips  = set(curr_devices.keys())

    # New devices — not seen in previous scan
    new_devices = []
    for ip in (curr_ips - prev_ips):
        dev = curr_devices[ip]
        new_devices.append({
            'ip':         ip,
            'mac':        dev.get('mac',        'Unknown'),
            'vendor':     dev.get('display_name', dev.get('vendor', 'Unknown')),
            'risk':       dev.get('risk',       'UNKNOWN'),
            'open_ports': dev.get('open_ports', []),
        })

    # Missing devices — were present before, now gone
    missing_devices = []
    for ip in (prev_ips - curr_ips):
        dev = prev_devices[ip]
        missing_devices.append({
            'ip':     ip,
            'mac':    dev.get('mac',    'Unknown'),
            'vendor': dev.get('display_name', dev.get('vendor', 'Unknown')),
        })

    # Changed ports — same IP, different open port set
    changed_ports = []
    risk_changes  = []
    for ip in (curr_ips & prev_ips):
        curr_dev = curr_devices[ip]
        prev_dev = prev_devices[ip]

        curr_ports = set(curr_dev.get('open_ports', []))
        prev_ports = set(prev_dev.get('open_ports', []))

        if curr_ports != prev_ports:
            changed_ports.append({
                'ip':           ip,
                'vendor':       curr_dev.get('display_name', curr_dev.get('vendor', 'Unknown')),
                'old_ports':    sorted(prev_ports),
                'new_ports':    sorted(curr_ports),
                'added_ports':  sorted(curr_ports - prev_ports),
                'removed_ports':sorted(prev_ports - curr_ports),
            })

        curr_risk = curr_dev.get('risk', 'UNKNOWN')
        prev_risk = prev_dev.get('risk', 'UNKNOWN')
        if curr_risk != prev_risk:
            risk_changes.append({
                'ip':       ip,
                'vendor':   curr_dev.get('display_name', curr_dev.get('vendor', 'Unknown')),
                'old_risk': prev_risk,
                'new_risk': curr_risk,
            })

    return {
        'new_devices':     new_devices,
        'missing_devices': missing_devices,
        'changed_ports':   changed_ports,
        'risk_changes':    risk_changes,
        'has_changes':     bool(new_devices or missing_devices or changed_ports or risk_changes),
    }


# ===========================================================================
# 5.  Display Helpers
# ===========================================================================

RISK_COLORS = {
    'CRITICAL': Fore.RED,
    'High':     Fore.LIGHTRED_EX,   # matches module1 get_risk() exactly
    'Weak':     Fore.YELLOW,
    'Safe':     Fore.GREEN,
    'UNKNOWN':  Fore.WHITE,
}


def print_change_report(diff: dict, prev_scan: dict) -> None:
    """Pretty-print a change-alert table to the console."""
    sep   = "=" * 70
    thin  = "-" * 70

    print(f"\n{Fore.CYAN}{sep}")
    print(f"  MODULE 6 — NETWORK CHANGE REPORT")
    print(f"  Compared against scan #{prev_scan['id']} — {prev_scan['timestamp']}")
    print(f"{sep}{Style.RESET_ALL}\n")

    if not diff['has_changes']:
        print(f"{Fore.GREEN}  [OK] No changes detected since last scan.{Style.RESET_ALL}\n")
        return

    # --- New Devices --------------------------------------------------------
    if diff['new_devices']:
        print(f"{Fore.YELLOW}  ⚠  NEW DEVICES DETECTED ({len(diff['new_devices'])}){Style.RESET_ALL}")
        print(f"  {thin}")
        print(f"  {'IP':<18} {'MAC':<20} {'Vendor':<22} {'Risk':<10} {'Open Ports'}")
        print(f"  {thin}")
        for dev in diff['new_devices']:
            rc    = RISK_COLORS.get(dev['risk'], Fore.WHITE)
            ports = ', '.join(str(p) for p in dev['open_ports']) or 'None'
            print(f"  {dev['ip']:<18} {dev['mac']:<20} "
                  f"{dev['vendor'][:20]:<22} "
                  f"{rc}{dev['risk']:<10}{Style.RESET_ALL} {ports}")
        print()

    # --- Missing Devices ----------------------------------------------------
    if diff['missing_devices']:
        print(f"{Fore.BLUE}  ℹ  DEVICES NO LONGER ON NETWORK ({len(diff['missing_devices'])}){Style.RESET_ALL}")
        print(f"  {thin}")
        print(f"  {'IP':<18} {'MAC':<20} {'Vendor'}")
        print(f"  {thin}")
        for dev in diff['missing_devices']:
            print(f"  {dev['ip']:<18} {dev['mac']:<20} {dev['vendor']}")
        print()

    # --- Changed Ports ------------------------------------------------------
    if diff['changed_ports']:
        print(f"{Fore.MAGENTA}  ⚡ PORT CHANGES DETECTED ({len(diff['changed_ports'])}){Style.RESET_ALL}")
        print(f"  {thin}")
        for ch in diff['changed_ports']:
            print(f"  {ch['ip']} — {ch['vendor']}")
            if ch['added_ports']:
                print(f"    {Fore.RED}+ Ports opened : {ch['added_ports']}{Style.RESET_ALL}")
            if ch['removed_ports']:
                print(f"    {Fore.GREEN}- Ports closed : {ch['removed_ports']}{Style.RESET_ALL}")
        print()

    # --- Risk Level Changes -------------------------------------------------
    if diff['risk_changes']:
        print(f"{Fore.RED}  !! RISK LEVEL CHANGES ({len(diff['risk_changes'])}){Style.RESET_ALL}")
        print(f"  {thin}")
        for rc in diff['risk_changes']:
            old_c = RISK_COLORS.get(rc['old_risk'], Fore.WHITE)
            new_c = RISK_COLORS.get(rc['new_risk'], Fore.WHITE)
            print(f"  {rc['ip']} — {rc['vendor']}")
            print(f"    {old_c}{rc['old_risk']}{Style.RESET_ALL} → "
                  f"{new_c}{rc['new_risk']}{Style.RESET_ALL}")
        print()

    print(f"{Fore.CYAN}{sep}{Style.RESET_ALL}\n")


def print_scan_history(limit: int = 10) -> None:
    """Print a table of the last N scans."""
    history = get_scan_history(limit)
    if not history:
        print(f"{Fore.YELLOW}[Module 6] No scan history found.{Style.RESET_ALL}")
        return

    sep = "=" * 75
    print(f"\n{Fore.CYAN}{sep}")
    print(f"  SCAN HISTORY  (last {len(history)} scans)")
    print(f"{sep}{Style.RESET_ALL}")
    print(f"  {'#':<5} {'Timestamp':<22} {'IP Range':<20} {'Score':<8} {'Label':<12} {'Devices'}")
    print(f"  {'-'*70}")
    for s in history:
        score_color = (Fore.RED if s['score'] < 50 else
                       Fore.YELLOW if s['score'] < 70 else Fore.GREEN)
        print(f"  {s['id']:<5} {s['timestamp']:<22} {s['ip_range']:<20} "
              f"{score_color}{s['score']:<8}{Style.RESET_ALL}"
              f"{s['score_label']:<12} {s['device_count']}")
    print()


# ===========================================================================
# 6.  Master Entry Point
# ===========================================================================

def run_module6(
    gateway: str,
    ip_range: str,
    m3: dict,
    m4_results: list = None,
    show_history: bool = False
) -> dict:
    """
    Master function — call after Module 3 (and optionally Module 4).

    Parameters
    ----------
    gateway     : gateway IP string from Module 1
    ip_range    : CIDR string from Module 1
    m3          : full m3 dict from module3.run_module3()
    m4_results  : list from module4.run_module4()  (optional)
    show_history: if True, prints the last 10 scans table

    Returns
    -------
    {
        'scan_id'  : int,
        'diff'     : compare_scans() result dict  (None on first run),
        'prev_scan': previous scan dict           (None on first run),
    }
    """
    init_db()

    devices     = m3.get('devices', [])
    score       = m3.get('score', 0)
    score_label = m3.get('score_label', 'Unknown')

    # Save current scan first
    scan_id = save_scan(
        gateway     = gateway,
        ip_range    = ip_range,
        score       = score,
        score_label = score_label,
        devices     = devices,
        m4_results  = m4_results,
    )

    # Compare against the previous scan (exclude the one we just saved)
    prev_scan = get_last_scan(exclude_scan_id=scan_id)

    diff = None
    if prev_scan:
        diff = compare_scans(devices, prev_scan)
        print_change_report(diff, prev_scan)
    else:
        print(f"{Fore.CYAN}[Module 6]{Style.RESET_ALL} First scan recorded — "
              f"no previous data to compare.\n")

    if show_history:
        print_scan_history()

    return {
        'scan_id':   scan_id,
        'diff':      diff,
        'prev_scan': prev_scan,
    }
