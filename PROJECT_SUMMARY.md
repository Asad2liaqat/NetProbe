# IoT Security Scanner — Complete Project Summary

## Overview

A professional IoT network security tool built in Python with a modern CustomTkinter GUI.
The project has two planned modes:

- **HomeGuard** — simplified home user monitor (planned)
- **NetProbe** — full offensive penetration testing tool (current implementation)

---

## Project File Structure

```
project/
├── gui.py                  ← Main GUI frontend (CustomTkinter, 3748 lines)
├── mailer.py               ← Official software email sender
├── secure_device.py        ← Device lockdown engine (3-layer)
├── dos_demo.py             ← DoS attack demo script (localhost only)
├── traffic_monitor.py      ← Live packet sniffer + attack detector
├── module1.py              ← Network scanner + port scanner + risk engine
├── module2.py              ← Intelligence engine (vendor, banner, TLS, UPnP)
├── module3.py              ← Assessment engine (scoring, CVE, recommendations)
├── module4.py              ← Red team active penetration tests
├── module5.py              ← PDF report generator
├── module6.py              ← SQLite database (scan history)
├── module7.py              ← Watch mode (auto-rescan)
├── visuals.py              ← Chart and graph generator
├── error_handler.py        ← Safe API call wrapper with retry/fallback
├── api.py                  ← Flask REST API (for Android app integration)
├── attack_simulator.py     ← Advanced attack simulation (Scapy-based)
├── requirements.txt        ← Python dependencies (updated)
├── audit_log.txt           ← Ethics consent + lockdown audit trail
├── scanner_history.db      ← SQLite scan history database
├── alert_settings.json     ← User alert preferences + verified email
├── ssid_history.json       ← WiFi name per scan ID
└── secure_state.json       ← Camera/device lock state persistence
```

---

## What Was Built — Full Breakdown

---

### 1. `gui.py` — Main GUI Frontend

**Framework:** CustomTkinter (dark theme, modern UI)

**Tabs built:**

| Tab | Purpose |
|-----|---------|
| 📊 Dashboard | Score gauge, stat cards, live scan log |
| 📡 Devices | Filterable device list with risk badges |
| 🔍 CVEs | Per-device CVE results with severity badges |
| ⚔️ Red Team | Per-device penetration test results |
| 📶 Traffic Monitor | Live packet feed + attack alerts |
| 🕑 History | Scan history table with WiFi name column |
| 📄 PDF Report | One-click PDF generation |
| 🔒 Secure Device | Device isolation and lockdown |
| 🔔 Alert Settings | Email verification + alert triggers |

**Key GUI components built:**

- `ScoreGauge` — animated half-circle arc gauge (0–100)
- `StatCard` — reusable stat display card
- `LogPanel` — colour-coded scrollable terminal output
- `DeviceRow` — device card with risk badge, IP, vendor, ports
- `EmailSetupWizard` — 2-step modal email verification wizard

**Sidebar features:**
- Navigation with active tab highlighting
- ▶ Start Scan button
- Skip Red Team toggle switch
- Auto-scan scheduler (15min / 30min / 1h / 2h / 6h) with next-scan countdown

---

### 2. Scan Pipeline (Modules 1–6)

Each scan runs this pipeline in a background thread with live stdout capture:

```
Module 1 → ARP scan + port scan + risk level
Module 2 → MAC vendor API + banner grab + TLS + UPnP + OS fingerprint
Module 3 → Network health score + CVE lookup + fix recommendations
Module 4 → Red team active tests (with ethics consent dialog)
Module 5 → PDF report generation
Module 6 → Save to SQLite + compare against previous scan
```

**Scoring system (module3.py):**

| Port | Deduction |
|------|-----------|
| Telnet (23) | -20 |
| ADB (5555) | -20 |
| FTP (21) | -15 |
| SMB (445) | -15 |
| RDP (3389) | -15 |
| MQTT (1883) | -10 |
| RTSP (554) | -10 |
| HTTP (80/8080) | -5 |
| Unknown vendor + open ports | -5 |
| Weak TLS | -10 |

Score labels: Excellent (≥90) / Good (≥70) / At Risk (≥50) / Critical (<50)

---

### 3. Features Added to `gui.py`

#### ✅ Feature 1 — CSV Export
- Export button in History tab header
- Exports all scan history + per-device detail (IP, MAC, vendor, risk, ports, TLS, red team verdict)
- Auto-opens folder after export
- File: timestamped CSV on Desktop

#### ✅ Feature 2 — Scheduled Auto-Scan
- Interval dropdown in sidebar (15min to 6h)
- Toggle switch enables/disables
- Shows "Next scan at HH:MM:SS" countdown
- Silently fires `_start_scan()` on schedule, auto-reschedules

#### ✅ Feature 3 — Device Change Detector
- Runs after every scan via `module6.compare_scans()`
- Detects: new devices, missing devices, port changes, risk escalations
- Logs colour-coded summary in dashboard
- Pops a warning dialog for new CRITICAL/High devices
- Triggers email alert for new devices

#### ✅ Feature 4 — Email + Desktop Alerts
- Alerts fire for: new devices, score drops below threshold, traffic attacks
- Desktop toast via PowerShell (Windows, zero config)
- All alert triggers toggleable (on/off per type)
- Score threshold configurable

#### ✅ WiFi SSID Detection
- Detected at scan start using `netsh` (Windows), `airport` (macOS), `nmcli`/`iwgetid` (Linux)
- Stored in `ssid_history.json` mapped to scan ID
- Shown in History tab WiFi column and Dashboard header

---

### 4. `mailer.py` — Official Software Email Sender

**Architecture:** One official Gmail account sends all alerts. Users never configure SMTP.

**How it works:**
1. Developer fills in `SENDER_EMAIL` and `SENDER_APP_PASSWORD` once in `mailer.py`
2. Users sign up with their own email — receive a 6-digit verification code
3. After verification their email is stored in `alert_settings.json`
4. All alerts sent FROM software email TO user's email

**Email templates built:**
- `send_verification_code()` — branded HTML with large 6-digit code display
- `send_welcome()` — onboarding email after signup
- `send_new_device_alert()` — table of new devices with risk badges
- `send_score_alert()` — large score display with threshold context
- `send_traffic_alert()` — attack type, source IP, detail, timestamp table
- `send_password_reset()` — reset code with expiry warning

All emails have HTML + plain text fallback. Branded dark theme matching the GUI.

**Developer setup:**
```python
SENDER_EMAIL        = "iotscanner.alerts@gmail.com"
SENDER_APP_PASSWORD = "your-16-char-app-password"
```

Test with: `python mailer.py yourpersonalemail@gmail.com`

---

### 5. Email Setup Wizard (`EmailSetupWizard` class in `gui.py`)

**Triggered:** On first launch if `email_verified = false` in `alert_settings.json`

**Cannot be skipped or closed.**

**Step 1:**
- User enters their email address only (no SMTP config)
- Software sends 6-digit code FROM official mailer
- Validation: must be valid email format

**Step 2:**
- Large entry field for 6-digit code
- 10-minute countdown timer (auto-expires)
- Back button to change email
- On correct code: email saved, wizard closes, alerts tab refreshes to "Connected" state

**After verification:**
- Alert Settings tab shows `✅ Connected yourmail@gmail.com`
- Change Email button re-runs full wizard
- Password obfuscated with XOR + base64 (never stored in plain text)

---

### 6. `secure_device.py` — Device Lockdown Engine

**3-layer protection system:**

| Layer | Method | Effect |
|-------|--------|--------|
| Layer 1 | Windows Firewall rules | Blocks all traffic to/from device IP (TCP + UDP) |
| Layer 2 | Process termination | Kills VLC, Teams, Zoom, browsers, OBS etc. |
| Layer 3 | PnP Driver disable | Disables hardware in Device Manager — no app can open it |

**Ports blocked (8 camera/IoT ports):**
554, 80, 8080, 8554, 8888, 37777 (Dahua), 34567 (XMEye), 9000 (Hikvision)

**Public API:**
```python
lock_camera(kill_procs=True)       # Full 3-layer lockdown
unlock_camera()                    # Restore everything
block_device_camera(ip)            # Network block for specific IP
unblock_device_camera(ip)          # Remove IP-specific rules
get_full_status()                  # Current lock state
kill_camera_processes(dry_run)     # Find/kill camera apps
discover_cameras()                 # List PnP camera devices
test_connection()                  # Test SMTP (used by mailer)
```

**State persistence:** `secure_state.json` — remembers lock state across restarts

**Audit logging:** Every lock/unlock written to `audit_log.txt`

---

### 7. Secure Device Tab (GUI) — Rebuilt

**What changed from camera-only to device-agnostic:**

- Description: "Isolate and contain any compromised device — routers, cameras, TVs, sensors"
- Layer 1: "Network Block — cuts all traffic to/from selected IP"
- Layer 2: "Process Kill — terminates apps connected to device"
- Layer 3: "Driver Lock — for locally connected hardware"
- Status banner: "LOCKDOWN ACTIVE — 2 device(s) isolated"
- Device dropdown: populated after scan with `IP — Vendor [RISK]` + coloured risk badge
- New panel: **Currently Blocked Devices** list with per-device Unblock button

**Action buttons:**
1. 🔒 Full Lockdown (Layers 1+2+3)
2. 🌐 Block Network (Firewall only)
3. ⚙ Kill Connections (terminate apps)
4. 🔓 Restore All Access

**Fix applied:** Correct execution order — kill apps FIRST, then block firewall,
so VLC drops its active RTSP stream before the rule is applied.

---

### 8. Traffic Monitor — Rebuilt

**`traffic_monitor.py` changes:**
- Added `_extract_packet_info()` — extracts human-readable info from every packet
- Added `_packet_callbacks` list — fires for every packet, not just attacks
- Added `_proto_counts` dict — TCP/UDP/ICMP/ARP/OTHER counters
- Added `get_proto_counts()` public function
- Added `packet_callback` parameter to `start_monitor()`
- Fixed: callbacks cleared on `stop_monitor()` so they don't accumulate on restart

**GUI Traffic tab rebuilt with:**
- **Protocol Breakdown bar** — TCP/UDP/ICMP/ARP/OTHER counts updating every 2 seconds
- **Live Packet Feed** (left panel) — every packet: `[time] src → dst PROTO :port SIZEb`
- **⏸ Pause / ▶ Resume** button — freeze feed without stopping monitor
- **Attack Alerts** (right panel) — only fires when threshold crossed, separate from feed
- Stats cards: Packets Seen / Alerts Fired / IPs Blocked / Packets per sec

**Detection signatures (unchanged):**
- SYN Flood: >200 SYN/sec per source IP
- ICMP Flood: >100 ICMP/sec per source IP
- UDP Flood: >300 UDP/sec per source IP
- Port Scan: >20 unique ports/sec per source IP
- ARP Spoofing: same IP claiming two different MACs

---

### 9. `dos_demo.py` — DoS Demo Script

**Purpose:** Trigger traffic monitor alerts for live demo.
Targets `127.0.0.1` (localhost) only. Logged to `audit_log.txt`.

**Attack modes:**
| Mode | Trigger | Method |
|------|---------|--------|
| `syn_flood` | SYN FLOOD alert | Raw TCP SYN via Scapy (fallback: connect flood) |
| `udp_flood` | UDP FLOOD alert | 512-byte UDP payloads to random ports |
| `port_scan` | PORT SCAN alert | TCP connect to ports 1-1024 via 4 threads |
| `icmp_flood` | ICMP FLOOD alert | Raw ICMP via Scapy (fallback: ping) |
| `all` | All 3 alerts | Runs all in sequence |

**Features:**
- Live progress bar with packets sent / rate / elapsed time
- `stop()` function for GUI stop button
- `callback(event, data)` system: `progress`, `done`, `error`, `phase`
- CLI and importable API

**CLI usage:**
```bash
python dos_demo.py --mode syn_flood --duration 10
python dos_demo.py --mode all
```

---

### 10. `module5.py` — PDF Bug Fix

**Problem:** `fpdf2` with Helvetica font only supports Latin-1 characters.
UPnP device names, vendor APIs, and CVE descriptions returned Unicode characters
(em dash `—`, curly quotes `'`, ellipsis `…` etc.) causing a crash.

**Fix:** Added `sanitize()` function that:
1. Maps 20 common Unicode characters to ASCII equivalents
2. Drops any remaining non-Latin-1 characters silently
3. Applied to every `cell()` and `multi_cell()` call in the report

```python
_UNICODE_MAP = {
    '\u2014': '--',   # em dash
    '\u2013': '-',    # en dash
    '\u2018': "'",    # left quote
    '\u2019': "'",    # right quote
    # ... 16 more
}
```

---

### 11. `requirements.txt` — Updated

Added two missing dependencies:
```
customtkinter   # Modern dark-theme GUI
pillow          # Image handling required by CustomTkinter
```

Full list:
```
scapy, requests, customtkinter, pillow, fpdf2, matplotlib,
networkx, colorama, tabulate, flask, python-nmap
```

---

## JSON Sidecar Files Explained

| File | Purpose | Safe to delete? |
|------|---------|----------------|
| `alert_settings.json` | Verified email + alert toggle preferences | ⚠️ Re-triggers wizard |
| `ssid_history.json` | WiFi name mapped to each scan ID | ✅ Only loses WiFi column |
| `secure_state.json` | Lock state across restarts | ✅ Recreated on next lock |
| `audit_log.txt` | Ethics consent + lockdown audit trail | Keep for examiner |
| `scanner_history.db` | All scan data (devices, scores, history) | ⚠️ Permanent data loss |

---

## What Still Needs To Be Built

### Pending from this session:
1. **DoS Demo button in GUI Traffic tab** — panel with mode selector, progress bar, Stop button
2. **Camera rating fix** — port 554 (RTSP) should be CRITICAL not Weak; compromised devices escalate to CRITICAL
3. **HomeGuard mode** — simplified home user interface (launcher screen)
4. **Login / Auth system** — `auth.py` with signup, password hash, local SQLite users DB
5. **Expanded port list for NetProbe** — 30+ ports (Modbus, BACnet, TR-069, VNC, SNMP etc.)

### Architecture planned but not started:
- Launcher screen (HomeGuard vs NetProbe chooser)
- `auth.py` — user registration, hashed passwords, local DB
- Network topology map in `visuals.py` (stub exists, never implemented)
- Android app (REST API in `api.py` is complete and ready)

---

## How to Run

```bash
# Install dependencies
pip install -r requirements.txt

# Configure official email (one-time, developer only)
# Open mailer.py and fill in SENDER_EMAIL + SENDER_APP_PASSWORD

# Run (must be Administrator on Windows for ARP scanning)
python gui.py

# Or use the bat file
run_gui.bat  (right-click → Run as administrator)
```

---

## Rating Summary

**Current rating: 7.8 / 10**

Strong points: clean module architecture, real network scanning,
professional GUI, ethics audit trail, 3-layer device lockdown,
live traffic monitoring, PDF reports, email alerts.

Gap to 9/10: unit tests missing, login system not yet built,
HomeGuard mode not started, some modules inconsistent in error handling.
