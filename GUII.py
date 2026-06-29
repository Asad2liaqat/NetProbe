# gui.py
# NetProbe IoT Security Suite — Professional GUI (Complete Overhaul)
#
# Theme: Clean Light Mode with slate-blue accents, card-based layout
# matching the System Evaluation Block Diagram reference screenshot.
#
# Modules covered:
#   Module 1  — Core Engine (ARP scan, port scan, risk engine)
#   Module 2  — Intelligence Engine (MAC vendor, banner, TLS, UPnP, OS)
#   Module 3  — Assessment Engine (CVE lookup, health score, recommendations)
#   Module 4  — Red Team (active penetration testing)
#   Module 5  — PDF Report Generator
#   Module 6  — Storage & History (SQLite, change detection)
#   Module 7  — Watch Mode (background continuous monitoring)
#   Module 8  — CVE Risk Score Engine
#   mailer.py — Email alerts + verification
#   traffic_monitor.py — Live packet capture & attack detection
#   secure_device.py   — Device isolation (firewall rules)
#   error_handler.py   — Graceful API fallback wrapper

import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox, filedialog
import threading
import queue
import sys
import os
import io
import time
import datetime
import ctypes
import subprocess
import json
import csv
import smtplib
import secrets
import base64
import random
import re as _re
import webbrowser
import email.mime.text
import email.mime.multipart

# ── Optional device labels helper ────────────────────────────────────────────
try:
    from device_labels import get_label, set_label, display_name, enrich_devices
    _LABELS_AVAILABLE = True
except ImportError:
    _LABELS_AVAILABLE = False
    def get_label(mac): return ''
    def set_label(mac, label): pass
    def display_name(device): return device.get('vendor_api', device.get('vendor', device.get('ip', 'Unknown')))
    def enrich_devices(devices): return devices

ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

# ── Windows DPI awareness ────────────────────────────────────────────────────
if sys.platform == "win32":
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

# ── Responsive geometry ───────────────────────────────────────────────────────
def _get_responsive_geometry():
    import tkinter as _tk
    _r = _tk.Tk(); _r.withdraw()
    sw = _r.winfo_screenwidth()
    sh = _r.winfo_screenheight()
    _r.destroy()
    usable_h = sh
    if sys.platform == "win32":
        try:
            class _RECT(ctypes.Structure):
                _fields_ = [("left",ctypes.c_long),("top",ctypes.c_long),
                             ("right",ctypes.c_long),("bottom",ctypes.c_long)]
            rc = _RECT()
            ctypes.windll.user32.SystemParametersInfoW(0x0030,0,ctypes.byref(rc),0)
            try:
                dpi = ctypes.windll.user32.GetDpiForSystem()
                factor = dpi / 96.0
            except Exception:
                factor = 1.0
            usable_h = int((rc.bottom - rc.top) / factor)
            sw = int((rc.right - rc.left) / factor)
        except Exception:
            usable_h = sh - 48
    w = min(int(sw * 0.95), 1320)
    h = min(int(usable_h * 0.95), 820)
    w = max(w, 900); h = max(h, 600)
    if w < 1000:   sidebar, scale = 160, 0.85
    elif w < 1120: sidebar, scale = 175, 0.90
    elif w < 1240: sidebar, scale = 195, 0.95
    else:          sidebar, scale = 215, 1.0
    return w, h, sidebar, scale

_SW, _SH, _SIDEBAR_W, _FONT_SCALE = _get_responsive_geometry()
_NAV_BTN_H = max(30, min(38, int((_SH - 360) / 10)))
_NO_WINDOW = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
_DIR = os.path.dirname(os.path.abspath(__file__))
ALERT_SETTINGS_FILE = os.path.join(_DIR, "alert_settings.json")
SSID_HISTORY_FILE   = os.path.join(_DIR, "ssid_history.json")

def _fs(size: int) -> int:
    return max(8, int(size * _FONT_SCALE))

# ══════════════════════════════════════════════════════════════════════════════
# DESIGN TOKENS  — professional slate/teal light theme
# ══════════════════════════════════════════════════════════════════════════════

C = {
    # backgrounds
    "bg":         "#F0F2F7",   # main window
    "sidebar":    "#1E2535",   # dark sidebar (navy)
    "sidebar2":   "#252E42",   # hover state in sidebar
    "sidebar_active": "#2D3A54",
    "surface":    "#FFFFFF",
    "surface2":   "#F5F7FB",
    "card":       "#FFFFFF",
    "border":     "#DDE1EC",
    "border2":    "#C8CEDF",

    # accent palette
    "accent":     "#2563EB",   # blue
    "accent2":    "#1D4ED8",   # darker blue
    "accent_pale":"#EFF6FF",   # pale blue for badge bg

    # semantic
    "success":    "#059669",
    "success_bg": "#ECFDF5",
    "warning":    "#D97706",
    "warning_bg": "#FFFBEB",
    "danger":     "#DC2626",
    "danger_bg":  "#FEF2F2",
    "critical":   "#B91C1C",

    # text
    "text":       "#0F172A",
    "text_dim":   "#475569",
    "text_faint": "#94A3B8",
    "text_inv":   "#FFFFFF",   # on dark backgrounds

    # risk badge text colours (same as semantic)
    "safe":   "#059669",
    "weak":   "#D97706",
    "high":   "#EA580C",
    "crit_r": "#DC2626",

    # sidebar text
    "s_text":   "#CBD5E1",
    "s_text_d": "#64748B",
}

RISK_COLORS = {
    "CRITICAL":    C["crit_r"],
    "High":        C["high"],
    "Weak":        C["weak"],
    "Safe":        C["safe"],
    "SECURE":      C["safe"],
    "COMPROMISED": C["crit_r"],
    "SKIPPED":     C["text_faint"],
}

SEV_COLORS = {
    "CRITICAL": C["crit_r"],
    "HIGH":     C["high"],
    "MEDIUM":   C["warning"],
    "LOW":      C["success"],
    "N/A":      C["text_faint"],
}

# ══════════════════════════════════════════════════════════════════════════════
# SETTINGS HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def load_alert_settings() -> dict:
    try:
        with open(ALERT_SETTINGS_FILE) as f: return json.load(f)
    except Exception: return {}

def save_alert_settings(cfg: dict):
    try:
        with open(ALERT_SETTINGS_FILE, "w") as f: json.dump(cfg, f, indent=2)
    except Exception: pass

def load_ssid_map() -> dict:
    try:
        with open(SSID_HISTORY_FILE) as f: return json.load(f)
    except Exception: return {}

def save_ssid_for_scan(scan_id: int, ssid: str):
    m = load_ssid_map(); m[str(scan_id)] = ssid
    try:
        with open(SSID_HISTORY_FILE, "w") as f: json.dump(m, f, indent=2)
    except Exception: pass

def get_wifi_ssid() -> str:
    try:
        if sys.platform == "win32":
            out = subprocess.check_output(["netsh","wlan","show","interfaces"],
                stderr=subprocess.DEVNULL, timeout=4).decode("utf-8", errors="ignore")
            for line in out.splitlines():
                if "SSID" in line and "BSSID" not in line:
                    return line.split(":",1)[1].strip()
        elif sys.platform == "darwin":
            out = subprocess.check_output(
                ["/System/Library/PrivateFrameworks/Apple80211.framework"
                 "/Versions/Current/Resources/airport", "-I"],
                stderr=subprocess.DEVNULL, timeout=4).decode()
            for line in out.splitlines():
                if " SSID:" in line: return line.split(":",1)[1].strip()
        else:
            for cmd in [["nmcli","-t","-f","active,ssid","dev","wifi"],["iwgetid","-r"]]:
                try:
                    out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL,
                        timeout=4).decode().strip()
                    if out: return out.split(":")[1] if ":" in out else out
                except Exception: pass
    except Exception: pass
    return "Unknown"

# ══════════════════════════════════════════════════════════════════════════════
# QUEUE WRITER
# ══════════════════════════════════════════════════════════════════════════════

class QueueWriter(io.TextIOBase):
    def __init__(self, q): self._q = q
    def write(self, text):
        if text and text != "\n": self._q.put(("log", text.rstrip()))
        return len(text)
    def flush(self): pass

# ══════════════════════════════════════════════════════════════════════════════
# ANSI STRIP
# ══════════════════════════════════════════════════════════════════════════════

def _strip_ansi(text: str) -> str:
    return _re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', text)

# ══════════════════════════════════════════════════════════════════════════════
# LOG PANEL
# ══════════════════════════════════════════════════════════════════════════════

_PHASE_MAP = [
    ("Scan started",        "Started",      "#2563EB", "#475569"),
    ("WiFi:",               "Network",      "#2563EB", "#475569"),
    ("Discovering devices", "Discovery",    "#2563EB", "#475569"),
    ("device(s) on",        "Discovered",   "#059669", "#059669"),
    ("Analysing device",    "Analysis",     "#2563EB", "#475569"),
    ("Vendor, banner",      "Analysis",     "#059669", "#059669"),
    ("Checking for known",  "CVE Lookup",   "#2563EB", "#475569"),
    ("Running security",    "Red Team",     "#2563EB", "#475569"),
    ("Red team skipped",    "Red Team",     "#D97706", "#D97706"),
    ("Red team complete",   "Red Team",     "#059669", "#059669"),
    ("Calculating risk",    "Risk Score",   "#2563EB", "#475569"),
    ("CVE Risk Score:",     "CVE Risk",     "#2563EB", "#475569"),
    ("Total CVEs:",         "CVE Summary",  "#D97706", "#D97706"),
    ("Worst device:",       "Worst Device", "#D97706", "#D97706"),
    ("Saving scan",         "Saving",       "#2563EB", "#475569"),
    ("NETWORK CHANGE",      "Net Changes",  "#D97706", "#D97706"),
    ("DEVICES NO LONGER",   "Left Network", "#DC2626", "#DC2626"),
    ("NEW DEVICES",         "New Devices",  "#DC2626", "#DC2626"),
    ("COMPROMISED",         "Compromised",  "#DC2626", "#DC2626"),
    ("[X]",                 "Error",        "#DC2626", "#DC2626"),
    ("[!]",                 "Warning",      "#D97706", "#D97706"),
    ("[*]",                 "Info",         "#2563EB", "#2563EB"),
    ("[OK]",                None,           "#059669", "#059669"),
]

_SUPPRESS_PATTERNS = [
    r"Enriching \d+\.\d+\.\d+\.\d+",
    r"Probing UPnP on \d+",
    r"Detecting OS on \d+",
    r"Looking up CVEs for \d+",
    r"\[Database\]",
    r"Database ready →",
    r"^={3,}", r"^-{3,}",
    r"Compared against scan",
    r"^\s*IP\s+MAC\s+Vendor",
    r"^\s*\d+\.\d+\.\d+\.\d+\s+[0-9a-f:]+",
    r"^\[DB\]",
    r"^Scan #\d+ saved$",
    r"^\s*Score:\s*\d+/100",
]
_SUPPRESS_RE = _re.compile('|'.join(_SUPPRESS_PATTERNS), _re.IGNORECASE)

class LogPanel(ctk.CTkFrame):
    def __init__(self, master, **kw):
        super().__init__(master, fg_color=C["surface2"], corner_radius=8, **kw)
        self._text = tk.Text(
            self, bg=C["surface2"], fg=C["text"],
            font=("Consolas", _fs(10)),
            insertbackground=C["text"],
            selectbackground=C["accent"],
            relief="flat", wrap="word",
            state="disabled", padx=12, pady=10,
            cursor="arrow",
        )
        sb = ctk.CTkScrollbar(self, command=self._text.yview,
            button_color=C["border2"])
        self._text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._text.pack(side="left", fill="both", expand=True)

        # colour tags
        for tag, col in [
            ("dot_ok",     "#059669"), ("dot_warn",   "#D97706"),
            ("dot_err",    "#DC2626"), ("dot_info",   "#2563EB"),
            ("phase_ok",   "#059669"), ("phase_warn", "#92400E"),
            ("phase_err",  "#991B1B"), ("phase_info", "#1D4ED8"),
            ("detail_ok",  "#059669"), ("detail_warn","#B45309"),
            ("detail_err", "#DC2626"), ("detail_dim", "#475569"),
            ("ts",         "#94A3B8"), ("sep",        "#CBD5E1"),
            ("header",     "#2563EB"),
        ]:
            weight = "bold" if "phase" in tag or "header" in tag else "normal"
            self._text.tag_config(tag, foreground=col,
                font=("Consolas", _fs(10), weight))

    def _dot_tag(self, c):
        return {"#059669":"dot_ok","#D97706":"dot_warn","#DC2626":"dot_err"}.get(c,"dot_info")
    def _phase_tag(self, c):
        return {"#059669":"phase_ok","#D97706":"phase_warn","#DC2626":"phase_err"}.get(c,"phase_info")
    def _detail_tag(self, c):
        return {"#059669":"detail_ok","#D97706":"detail_warn","#DC2626":"detail_err"}.get(c,"detail_dim")

    def _classify(self, msg):
        for kw, title, dc, dtc in _PHASE_MAP:
            if kw.lower() in msg.lower():
                if title is None:
                    clean = msg.replace("[OK]","").strip()
                    short = _re.split(r'[:#\-–]|\d', clean)[0].strip()
                    title = short[:20] if short else "OK"
                return title, dc, dtc
        return None, "#94A3B8", "#94A3B8"

    def _clean_detail(self, msg):
        msg = msg.strip()
        for p in ("[OK]","[!]","[X]","[*]","[✓]"):
            if msg.startswith(p): msg = msg[len(p):].strip(); break
        return msg

    def append(self, raw: str):
        msg = _strip_ansi(raw).strip()
        if not msg or _SUPPRESS_RE.search(msg): return
        t = self._text; t.configure(state="normal")
        phase, dc, dtc = self._classify(msg)
        detail = self._clean_detail(msg)
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        if phase:
            t.insert("end", "  ● ", self._dot_tag(dc))
            t.insert("end", f"{phase:<18}", self._phase_tag(dc))
            t.insert("end", f"  {detail}", self._detail_tag(dtc))
            t.insert("end", f"  ·  {ts}\n", "ts")
        else:
            t.insert("end", f"    {detail}\n", "detail_dim")
        t.configure(state="disabled"); t.see("end")

    def separator(self):
        t = self._text; t.configure(state="normal")
        t.insert("end", "\n"); t.configure(state="disabled"); t.see("end")

    def section_header(self, title: str):
        t = self._text; t.configure(state="normal")
        t.insert("end", f"\n  {title}\n", "header")
        t.insert("end", "  " + "─"*52 + "\n", "sep")
        t.configure(state="disabled"); t.see("end")

    def clear(self):
        t = self._text; t.configure(state="normal")
        t.delete("1.0","end"); t.configure(state="disabled")

# ══════════════════════════════════════════════════════════════════════════════
# SCORE GAUGE  (semi-circular arc)
# ══════════════════════════════════════════════════════════════════════════════

class ScoreGauge(tk.Canvas):
    def __init__(self, master, size=190, **kw):
        size = int(size * _FONT_SCALE)
        super().__init__(master,
            width=size, height=size//2+90,
            bg=C["surface"], highlightthickness=0, **kw)
        self._size = size; self._score = 0; self._target = 0
        self._label = "—"; self._animating = False
        self._draw(0)

    def set_score(self, score, label):
        self._target = max(0, min(100, score)); self._label = label
        if not self._animating: self._animate()

    def reset(self):
        self._score = self._target = 0; self._label = "—"; self._draw(0)

    def _color(self, s):
        if s >= 90: return C["success"]
        if s >= 70: return C["accent"]
        if s >= 50: return C["warning"]
        return C["danger"]

    def _animate(self):
        self._animating = True
        if self._score == self._target: self._animating = False; return
        self._score += 1 if self._score < self._target else -1
        self._draw(self._score)
        self.after(10, self._animate)

    def _draw(self, score):
        self.delete("all")
        cx = self._size//2; cy = self._size//2 - 8; r = self._size//2 - 18
        # Track
        self.create_arc(cx-r, cy-r, cx+r, cy+r, start=0, extent=180,
            style="arc", outline="#E2E8F0", width=14)
        # Fill
        if score > 0:
            col = self._color(score)
            self.create_arc(cx-r, cy-r, cx+r, cy+r, start=0,
                extent=int(score*1.8), style="arc", outline=col, width=14)
        col = self._color(score)
        # Score text
        self.create_text(cx, cy-2, text=str(score),
            font=("Helvetica", _fs(32), "bold"), fill=col)
        self.create_text(cx, cy+28, text="/100",
            font=("Helvetica", _fs(13)), fill=C["text_faint"])
        self.create_text(cx, cy+50, text=self._label,
            font=("Helvetica", _fs(11), "bold"), fill=col)

# ══════════════════════════════════════════════════════════════════════════════
# STAT CARD  — used across dashboard, CVE score, traffic tabs
# ══════════════════════════════════════════════════════════════════════════════

class StatCard(ctk.CTkFrame):
    def __init__(self, master, label, value="—", color=None, sub="",
                 icon="", **kw):
        super().__init__(master, fg_color=C["card"], corner_radius=12,
            border_width=1, border_color=C["border"], **kw)
        self._color = color or C["accent"]
        # left accent stripe
        stripe = ctk.CTkFrame(self, width=4, fg_color=self._color,
            corner_radius=2); stripe.pack(side="left", fill="y", padx=(0,0))
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(side="left", fill="both", expand=True, padx=(10,12), pady=10)
        if icon:
            ctk.CTkLabel(body, text=icon, font=ctk.CTkFont(size=_fs(18)),
                text_color=self._color).pack(anchor="w")
        ctk.CTkLabel(body, text=label, font=ctk.CTkFont(size=_fs(11)),
            text_color=C["text_dim"]).pack(anchor="w")
        self._val = ctk.CTkLabel(body, text=value,
            font=ctk.CTkFont(size=_fs(26), weight="bold"),
            text_color=self._color)
        self._val.pack(anchor="w")
        self._sub_lbl = ctk.CTkLabel(body, text=sub,
            font=ctk.CTkFont(size=_fs(10)), text_color=C["text_faint"])
        self._sub_lbl.pack(anchor="w")

    def update(self, value, sub="", color=None):
        self._val.configure(text=str(value), text_color=color or self._color)
        self._sub_lbl.configure(text=sub)

# ══════════════════════════════════════════════════════════════════════════════
# SECTION HEADER WIDGET  — used inside tab content areas
# ══════════════════════════════════════════════════════════════════════════════

def _section_hdr(parent, title, sub=""):
    f = ctk.CTkFrame(parent, fg_color="transparent")
    f.pack(fill="x", padx=20, pady=(18, 6))
    ctk.CTkLabel(f, text=title, font=ctk.CTkFont(size=_fs(15), weight="bold"),
        text_color=C["text"]).pack(side="left")
    if sub:
        ctk.CTkLabel(f, text=sub, font=ctk.CTkFont(size=_fs(11)),
            text_color=C["text_faint"]).pack(side="left", padx=12)
    return f

def _card(master, **kw):
    return ctk.CTkFrame(master, fg_color=C["surface"], corner_radius=12,
        border_width=1, border_color=C["border"], **kw)

# ══════════════════════════════════════════════════════════════════════════════
# SCANNING ANIMATION PROGRESS BAR  — multi-colour shifting bar
# ══════════════════════════════════════════════════════════════════════════════

class AnimatedProgressBar(ctk.CTkFrame):
    """
    When scanning is active, cycles through accent colours to show activity.
    When idle shows a static filled or empty bar.
    """
    _COLORS = ["#2563EB","#7C3AED","#059669","#D97706","#DC2626","#2563EB"]

    def __init__(self, master, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self._bar = ctk.CTkProgressBar(self, height=5,
            fg_color=C["border"], progress_color=C["accent"],
            corner_radius=3)
        self._bar.set(0); self._bar.pack(fill="x")
        self._animating = False; self._ci = 0; self._progress = 0.0

    def start_animation(self):
        self._animating = True; self._ci = 0; self._pulse()

    def stop_animation(self):
        self._animating = False
        self._bar.configure(progress_color=C["accent"])

    def set_progress(self, v: float):
        self._progress = max(0.0, min(1.0, v))
        if not self._animating: self._bar.set(self._progress)

    def _pulse(self):
        if not self._animating: return
        self._ci = (self._ci + 1) % len(self._COLORS)
        self._bar.configure(progress_color=self._COLORS[self._ci])
        # Smoothly fill based on stored progress
        self._bar.set(self._progress if self._progress > 0 else
                      0.3 + 0.5*(abs(0.5 - (self._ci/len(self._COLORS)))))
        self.after(140, self._pulse)

# ══════════════════════════════════════════════════════════════════════════════
# EMAIL SECTION WIDGET  — embeddable inside any tab
# ══════════════════════════════════════════════════════════════════════════════

class EmailSectionWidget(ctk.CTkFrame):
    """
    Self-contained email verification widget that can be embedded anywhere.
    Shows:
      ① Email input + Send Code button
      ② Code input + Verify button
      ③ Verified badge
    """
    def __init__(self, master, on_verified=None, **kw):
        super().__init__(master, fg_color="transparent", **kw)
        self._on_verified = on_verified
        self._code = ""
        self._email = ""
        self._verified = False
        # Load existing state
        cfg = load_alert_settings()
        if cfg.get("email_verified"):
            self._email = cfg.get("smtp_user","")
            self._verified = True
        self._build()

    def _build(self):
        for w in self.winfo_children(): w.destroy()
        if self._verified:
            self._build_verified()
        else:
            self._build_step1()

    def _build_verified(self):
        row = ctk.CTkFrame(self, fg_color=C["success_bg"],
            corner_radius=10, border_width=1, border_color=C["success"])
        row.pack(fill="x")
        inner = ctk.CTkFrame(row, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=12)
        ctk.CTkLabel(inner, text="✅  Email Verified",
            font=ctk.CTkFont(size=_fs(12), weight="bold"),
            text_color=C["success"]).pack(side="left")
        ctk.CTkLabel(inner, text=self._email,
            font=ctk.CTkFont(size=_fs(11)), text_color=C["text_dim"]).pack(side="left", padx=12)
        ctk.CTkButton(inner, text="Change",
            fg_color="transparent", hover_color=C["surface2"],
            text_color=C["accent"], font=ctk.CTkFont(size=_fs(10)),
            height=28, width=70,
            command=self._reset).pack(side="right")

    def _build_step1(self):
        # Email row
        r1 = ctk.CTkFrame(self, fg_color="transparent")
        r1.pack(fill="x", pady=(0,8))
        ctk.CTkLabel(r1, text="Email Address",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["text"]).pack(anchor="w", pady=(0,4))
        inp_row = ctk.CTkFrame(r1, fg_color="transparent")
        inp_row.pack(fill="x")
        self._email_entry = ctk.CTkEntry(inp_row,
            placeholder_text="you@example.com",
            height=_fs(38), font=ctk.CTkFont(size=_fs(12)),
            fg_color=C["surface2"], border_color=C["border2"],
            text_color=C["text"])
        self._email_entry.pack(side="left", fill="x", expand=True, padx=(0,8))
        self._send_btn = ctk.CTkButton(inp_row,
            text="Send Code",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            fg_color=C["accent"], hover_color=C["accent2"],
            height=_fs(38), width=110, corner_radius=8,
            command=self._send_code)
        self._send_btn.pack(side="left")

        self._err1 = ctk.CTkLabel(r1, text="",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["danger"])
        self._err1.pack(anchor="w", pady=(2,0))

        # Code row (hidden until code sent)
        self._code_frame = ctk.CTkFrame(self, fg_color="transparent")
        self._code_frame.pack(fill="x")
        self._code_visible = False

    def _send_code(self):
        email = self._email_entry.get().strip()
        if "@" not in email or "." not in email:
            self._err1.configure(text="Enter a valid email address.")
            return
        self._email = email
        self._code = str(random.randint(100000, 999999))
        try:
            import mailer
            mailer.send_verification_code(email, self._code)
        except Exception:
            pass
        self._send_btn.configure(state="disabled",
            text="✉ Code Sent", fg_color=C["success"])
        self._err1.configure(text=f"Verification code sent to {email}",
            text_color=C["success"])
        self._show_code_input()

    def _show_code_input(self):
        for w in self._code_frame.winfo_children(): w.destroy()
        ctk.CTkLabel(self._code_frame, text="Verification Code",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["text"]).pack(anchor="w", pady=(8,4))
        row = ctk.CTkFrame(self._code_frame, fg_color="transparent")
        row.pack(fill="x")
        self._code_entry = ctk.CTkEntry(row,
            placeholder_text="6-digit code",
            justify="center",
            height=_fs(38), width=140,
            font=ctk.CTkFont(size=_fs(14)),
            fg_color=C["surface2"], border_color=C["border2"],
            text_color=C["text"])
        self._code_entry.pack(side="left", padx=(0,8))
        ctk.CTkButton(row, text="✓  Verify",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            fg_color=C["success"], hover_color="#047857",
            height=_fs(38), width=100, corner_radius=8,
            command=self._verify).pack(side="left")
        self._err2 = ctk.CTkLabel(self._code_frame, text="",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["danger"])
        self._err2.pack(anchor="w", pady=(2,0))

    def _verify(self):
        if self._code_entry.get().strip() == self._code:
            cfg = load_alert_settings()
            cfg["email_verified"] = True; cfg["smtp_user"] = self._email
            cfg["smtp_to"] = self._email; save_alert_settings(cfg)
            self._verified = True; self._build()
            if self._on_verified: self._on_verified(cfg)
        else:
            self._err2.configure(text="Incorrect code. Try again.")

    def _reset(self):
        cfg = load_alert_settings()
        cfg["email_verified"] = False; save_alert_settings(cfg)
        self._verified = False; self._code = ""; self._email = ""; self._build()

# ══════════════════════════════════════════════════════════════════════════════
# EMAIL SETUP WIZARD (top-level dialog)
# ══════════════════════════════════════════════════════════════════════════════

class EmailSetupWizard(ctk.CTkToplevel):
    def __init__(self, master, on_complete=None):
        super().__init__(master)
        self.title("Email Alert Setup")
        self.geometry("500x360")
        self.configure(fg_color=C["surface"])
        self.grab_set(); self.resizable(False, False)
        self._on_complete = on_complete
        self._code = ""; self._email = ""
        self._build_step1()

    def _build_step1(self):
        self._clear()
        ctk.CTkLabel(self, text="📧  Setup Email Alerts",
            font=ctk.CTkFont(size=_fs(18), weight="bold"),
            text_color=C["text"]).pack(pady=(28,4))
        ctk.CTkLabel(self, text="Enter your email to receive security alerts.",
            font=ctk.CTkFont(size=_fs(12)), text_color=C["text_dim"]).pack(pady=(0,20))
        self._email_entry = ctk.CTkEntry(self, width=300, height=_fs(40),
            placeholder_text="you@example.com",
            fg_color=C["surface2"], border_color=C["border2"],
            text_color=C["text"], font=ctk.CTkFont(size=_fs(12)))
        self._email_entry.pack()
        self._err = ctk.CTkLabel(self, text="",
            font=ctk.CTkFont(size=_fs(11)), text_color=C["danger"])
        self._err.pack(pady=4)
        ctk.CTkButton(self, text="Send Verification Code",
            font=ctk.CTkFont(size=_fs(12), weight="bold"),
            fg_color=C["accent"], hover_color=C["accent2"],
            height=_fs(42), width=220, corner_radius=10,
            command=self._send_code).pack(pady=8)
        ctk.CTkButton(self, text="Skip for now",
            fg_color="transparent", hover_color=C["surface2"],
            text_color=C["text_faint"], height=_fs(30),
            command=self._skip).pack()

    def _build_step2(self):
        self._clear()
        ctk.CTkLabel(self, text="🔢  Enter Verification Code",
            font=ctk.CTkFont(size=_fs(18), weight="bold"),
            text_color=C["text"]).pack(pady=(28,4))
        ctk.CTkLabel(self, text=f"Code sent to {self._email}",
            font=ctk.CTkFont(size=_fs(12)), text_color=C["text_dim"]).pack(pady=(0,20))
        self._code_entry = ctk.CTkEntry(self, width=180, height=_fs(48),
            font=ctk.CTkFont(size=_fs(22)), justify="center",
            fg_color=C["surface2"], border_color=C["accent"],
            text_color=C["text"])
        self._code_entry.pack()
        self._err2 = ctk.CTkLabel(self, text="",
            font=ctk.CTkFont(size=_fs(11)), text_color=C["danger"])
        self._err2.pack(pady=4)
        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(pady=8)
        ctk.CTkButton(row, text="← Back", fg_color=C["surface2"],
            hover_color=C["border"], text_color=C["text_dim"],
            height=_fs(40), width=100,
            command=self._build_step1).pack(side="left", padx=(0,10))
        ctk.CTkButton(row, text="✓  Verify",
            font=ctk.CTkFont(size=_fs(12), weight="bold"),
            fg_color=C["success"], hover_color="#047857",
            height=_fs(40), width=120, corner_radius=10,
            command=self._verify).pack(side="left")

    def _clear(self):
        for w in self.winfo_children(): w.destroy()

    def _send_code(self):
        email = self._email_entry.get().strip()
        if "@" not in email or "." not in email:
            self._err.configure(text="Enter a valid email address."); return
        self._email = email
        self._code = str(random.randint(100000, 999999))
        try:
            import mailer; mailer.send_verification_code(email, self._code)
        except Exception: pass
        self._build_step2()

    def _verify(self):
        if self._code_entry.get().strip() == self._code:
            cfg = load_alert_settings()
            cfg["email_verified"] = True; cfg["smtp_user"] = self._email
            cfg["smtp_to"] = self._email; save_alert_settings(cfg)
            self.destroy()
            if self._on_complete: self._on_complete(cfg)
        else:
            self._err2.configure(text="Incorrect code. Try again.")

    def _skip(self): self.destroy()

# ══════════════════════════════════════════════════════════════════════════════
# WELCOME TOUR
# ══════════════════════════════════════════════════════════════════════════════

class WelcomeTour(ctk.CTkToplevel):
    SLIDES = [
        ("🛡","Welcome to NetProbeSec",
         "Your complete network security toolkit.\n\nThis tour walks you through each feature.\nTakes less than 2 minutes.",None),
        ("📊","Dashboard",
         "Network Health Score (0–100) · Stat cards · Score deductions · Top CVEs · Scan log\n\nStart here after every scan.","Run a scan to see your score."),
        ("💻","Devices Tab",
         "Every device on your network.\n• Filter by risk · IP · Vendor · Device type\n• Open ports displayed · 📌 Label any device with a friendly name","Tip: Label your devices so you recognise them instantly."),
        ("🐛","CVE Vulnerabilities",
         "Known security vulnerabilities per device.\n• CRITICAL / HIGH / MEDIUM / LOW severity\n• CVSS score range · Click CVE ID → nvd.nist.gov","CRITICAL CVEs need immediate attention."),
        ("📈","CVE Score",
         "Single 0–100 risk score from all CVEs found.\n• CRITICAL=25pts HIGH=15pts MEDIUM=7pts LOW=2pts\n• Per-device table — see which device has most risk","Use this to prioritise which device to fix first."),
        ("⚔️","Red Team",
         "Active penetration testing — tries to break in.\n• Default credentials · RTSP streams · FTP · MQTT · SMB\n• COMPROMISED or SECURE verdict per device\n⚠ Ethics consent required — only on YOUR devices.","Enable 'Skip Red Team' for a quick scan."),
        ("📡","Traffic Monitor",
         "Live packet capture in real time.\n• Protocol breakdown TCP/UDP/ICMP/ARP\n• Attack alerts: SYN flood, port scan, ARP spoofing\n• ⏸ Pause feed · 💾 Save capture to file","Requires Administrator."),
        ("🔒","Secure Device",
         "Isolate compromised devices from your network.\n• Only shows COMPROMISED devices from red team\n• Adds Windows Firewall rules — no reboot needed","Works instantly."),
        ("👁","Watch Mode",
         "Continuous background monitoring.\n• Choose interval (2min–1hour)\n• Detects new devices, port changes, risk escalation\n• Desktop toast notifications","Run a manual scan first to set the baseline."),
        ("🚀","You're Ready!",
         "1. Connect to WiFi\n2. Click ▶ Start Scan\n3. Wait 1–3 minutes\n4. Check Dashboard for your score\n5. Label your devices\n6. Generate a PDF report",None),
    ]
    def __init__(self, master, on_close=None):
        super().__init__(master)
        self.title("NetProbeSec — Welcome")
        self.geometry("680x520"); self.configure(fg_color=C["bg"])
        self.resizable(False, False); self.grab_set()
        self._on_close = on_close; self._idx = 0; self._total = len(self.SLIDES)
        self._build(); self._show_slide(0)

    def _build(self):
        # dots
        dr = ctk.CTkFrame(self, fg_color="transparent"); dr.pack(pady=(18,0))
        self._dots = []
        for i in range(self._total):
            d = ctk.CTkLabel(dr, text="●", font=ctk.CTkFont(size=_fs(8)),
                text_color=C["border"]); d.pack(side="left", padx=3)
            self._dots.append(d)
        self._icon_lbl = ctk.CTkLabel(self, text="", font=ctk.CTkFont(size=_fs(48)))
        self._icon_lbl.pack(pady=(12,0))
        self._title_lbl = ctk.CTkLabel(self, text="",
            font=ctk.CTkFont(size=_fs(18), weight="bold"), text_color=C["text"])
        self._title_lbl.pack(pady=(6,0))
        card = _card(self); card.pack(fill="both", expand=True, padx=28, pady=(10,6))
        self._body_lbl = ctk.CTkLabel(card, text="",
            font=ctk.CTkFont(size=_fs(12)), text_color=C["text_dim"],
            justify="left", wraplength=560, anchor="nw")
        self._body_lbl.pack(padx=22, pady=(18,8), anchor="w", fill="x")
        self._tip_lbl = ctk.CTkLabel(card, text="",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["accent"], justify="left", wraplength=560)
        self._tip_lbl.pack(padx=22, pady=(0,18), anchor="w")
        nav = ctk.CTkFrame(self, fg_color="transparent"); nav.pack(fill="x", padx=28, pady=(0,18))
        self._skip_btn = ctk.CTkButton(nav, text="Skip Tour",
            fg_color="transparent", hover_color=C["surface2"],
            text_color=C["text_faint"], width=90, height=_fs(36),
            command=self._close); self._skip_btn.pack(side="left")
        self._counter_lbl = ctk.CTkLabel(nav, text="",
            font=ctk.CTkFont(size=_fs(11)), text_color=C["text_dim"])
        self._counter_lbl.pack(side="left", expand=True)
        self._back_btn = ctk.CTkButton(nav, text="← Back",
            fg_color=C["surface2"], hover_color=C["border2"],
            text_color=C["text"], width=100, height=_fs(36),
            command=self._prev); self._back_btn.pack(side="right", padx=(8,0))
        self._next_btn = ctk.CTkButton(nav, text="Next →",
            font=ctk.CTkFont(size=_fs(12), weight="bold"),
            fg_color=C["accent"], hover_color=C["accent2"],
            width=120, height=_fs(36),
            command=self._next); self._next_btn.pack(side="right")

    def _show_slide(self, i):
        icon, title, body, tip = self.SLIDES[i]
        self._icon_lbl.configure(text=icon); self._title_lbl.configure(text=title)
        self._body_lbl.configure(text=body)
        self._tip_lbl.configure(text=f"💡  {tip}" if tip else "")
        for j, d in enumerate(self._dots):
            d.configure(text_color=C["accent"] if j==i else C["border"],
                font=ctk.CTkFont(size=_fs(10) if j==i else _fs(8)))
        self._counter_lbl.configure(text=f"{i+1} of {self._total}")
        self._back_btn.configure(state="normal" if i>0 else "disabled")
        if i == self._total-1:
            self._next_btn.configure(text="Get Started ✓",
                fg_color=C["success"], hover_color="#047857")
        else:
            self._next_btn.configure(text="Next →",
                fg_color=C["accent"], hover_color=C["accent2"])
        self._skip_btn.configure(text="" if i==self._total-1 else "Skip Tour")

    def _next(self):
        if self._idx < self._total-1: self._idx+=1; self._show_slide(self._idx)
        else: self._close()
    def _prev(self):
        if self._idx > 0: self._idx-=1; self._show_slide(self._idx)
    def _close(self):
        self.destroy()
        if self._on_close: self._on_close()

# ══════════════════════════════════════════════════════════════════════════════
# MAIN APPLICATION
# ══════════════════════════════════════════════════════════════════════════════

class IoTScannerApp(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("NetProbeSec")   # ← Tool name preserved
        x = (self.winfo_screenwidth()  - _SW) // 2
        y = (self.winfo_screenheight() - _SH) // 2
        self.geometry(f"{_SW}x{_SH}+{x}+{y}")
        self.minsize(900, 600); self.configure(fg_color=C["bg"])

        # State
        self._scan_running     = False
        self._traffic_running  = False
        self._feed_paused      = False
        self._q                = queue.Queue()
        self._last_m2          = []
        self._last_m3          = {}
        self._last_m4          = None
        self._last_m8          = {}
        self._last_gateway     = ""
        self._last_ip_range    = ""
        self._current_tab      = "dashboard"
        self._autoscan_running = False
        self._autoscan_after_id= None
        self._alert_cfg        = load_alert_settings()
        self._watcher          = None
        self._data_dirty       = False
        self._spinner_idx      = 0
        self._traffic_packets  = []
        self._traffic_alerts   = []

        self._build_ui()
        self.after(100, self._poll_queue)
        self.after(300, self._check_admin)
        self.after(700, self._check_first_launch)

    # ══════════════════════════════════════════════════════════════════════════
    # UI BUILD
    # ══════════════════════════════════════════════════════════════════════════

    def _build_ui(self):
        # Dark sidebar | Right main area
        self._sidebar_frame = ctk.CTkFrame(self, width=_SIDEBAR_W,
            fg_color=C["sidebar"], corner_radius=0)
        self._sidebar_frame.pack(side="left", fill="y")
        self._sidebar_frame.pack_propagate(False)

        right = ctk.CTkFrame(self, fg_color=C["bg"], corner_radius=0)
        right.pack(side="left", fill="both", expand=True)

        self._build_sidebar()

        # Top bar — clean white strip with title + metrics
        self._topbar = ctk.CTkFrame(right, height=_fs(56),
            fg_color=C["surface"], corner_radius=0)
        self._topbar.pack(fill="x")
        self._topbar.pack_propagate(False)
        self._build_topbar()

        # Animated scan progress bar — replaces static bar
        self._anim_bar_frame = ctk.CTkFrame(right, height=6,
            fg_color="transparent", corner_radius=0)
        self._anim_bar_frame.pack(fill="x")
        self._anim_bar_frame.pack_propagate(False)
        self._anim_bar = AnimatedProgressBar(self._anim_bar_frame)
        self._anim_bar.pack(fill="x")

        # Content area
        self._content = ctk.CTkFrame(right, fg_color="transparent",
            corner_radius=0)
        self._content.pack(fill="both", expand=True)

        # Status bar
        self._statusbar = ctk.CTkFrame(right, height=_fs(28),
            fg_color=C["surface"], corner_radius=0)
        self._statusbar.pack(fill="x")
        self._statusbar.pack_propagate(False)
        self._build_statusbar()

        # Tab registry
        self._tab_builders = {
            "dashboard": self._build_dashboard,
            "devices":   self._build_devices,
            "cves":      self._build_cves,
            "cve_score": self._build_cve_score,
            "redteam":   self._build_redteam,
            "traffic":   self._build_traffic,
            "secure":    self._build_secure,
            "history":   self._build_history,
            "report":    self._build_report,
            "alerts":    self._build_alerts,
        }
        self._tabs = {}
        self._switch_tab("dashboard")

    # ── Sidebar (dark navy) ───────────────────────────────────────────────────

    def _build_sidebar(self):
        s = self._sidebar_frame

        # ── Logo area ─────────────────────────────────────────────────────────
        logo_row = ctk.CTkFrame(s, fg_color="transparent")
        logo_row.pack(fill="x", padx=14, pady=(18,10))
        badge = ctk.CTkFrame(logo_row, width=36, height=36,
            fg_color=C["accent"], corner_radius=10)
        badge.pack(side="left"); badge.pack_propagate(False)
        ctk.CTkLabel(badge, text="🛡", font=ctk.CTkFont(size=_fs(18))).pack(expand=True)
        txt_col = ctk.CTkFrame(logo_row, fg_color="transparent")
        txt_col.pack(side="left", padx=(10,0))
        ctk.CTkLabel(txt_col, text="NetProbe",   # ← Logo/tool name preserved
            font=ctk.CTkFont(size=_fs(14), weight="bold"),
            text_color="#F1F5F9").pack(anchor="w")
        ctk.CTkLabel(txt_col, text="IoT Security Suite",
            font=ctk.CTkFont(size=_fs(9)),
            text_color=C["s_text_d"]).pack(anchor="w")

        ctk.CTkFrame(s, height=1, fg_color="#2D3748").pack(fill="x", padx=14, pady=(4,8))

        # ── Bottom panel — anchored before nav so it always sticks to bottom ──
        bottom = ctk.CTkFrame(s, fg_color="transparent")
        bottom.pack(side="bottom", fill="x", padx=12, pady=(0,10))

        # Scan button — main CTA
        self._scan_btn = ctk.CTkButton(bottom,
            text="▶  Start Scan",
            font=ctk.CTkFont(size=_fs(13), weight="bold"),
            fg_color=C["accent"], hover_color=C["accent2"],
            corner_radius=10, height=_fs(46),
            command=self._start_scan)
        self._scan_btn.pack(fill="x", pady=(0,8))

        # Skip Red Team toggle
        skip_row = ctk.CTkFrame(bottom, fg_color="transparent")
        skip_row.pack(fill="x", pady=(0,4))
        ctk.CTkLabel(skip_row, text="Skip Red Team",
            font=ctk.CTkFont(size=_fs(10)),
            text_color=C["s_text_d"]).pack(side="left", padx=2)
        self._skip_redteam = ctk.CTkSwitch(skip_row, text="", width=36, height=18,
            button_color=C["danger"], progress_color=C["danger"],
            onvalue=True, offvalue=False)
        self._skip_redteam.pack(side="right")

        # Watch Mode card
        watch_card = ctk.CTkFrame(bottom, fg_color="#252E42", corner_radius=8)
        watch_card.pack(fill="x", pady=(0,4))
        wr = ctk.CTkFrame(watch_card, fg_color="transparent")
        wr.pack(fill="x", padx=10, pady=(8,4))
        ctk.CTkLabel(wr, text="👁  Watch Mode",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["s_text"]).pack(side="left")
        self._autoscan_switch = ctk.CTkSwitch(wr, text="", width=36, height=18,
            button_color=C["accent"], progress_color=C["accent"],
            onvalue=True, offvalue=False, command=self._toggle_watch_mode)
        self._autoscan_switch.pack(side="right")
        ir = ctk.CTkFrame(watch_card, fg_color="transparent")
        ir.pack(fill="x", padx=10, pady=(0,4))
        self._autoscan_interval = ctk.CTkOptionMenu(ir,
            values=["2 min","5 min","15 min","30 min","1 hour"],
            font=ctk.CTkFont(size=_fs(10)),
            fg_color="#1E2535", button_color="#2D3748",
            dropdown_fg_color="#1E2535", text_color=C["s_text"],
            width=110, height=26)
        self._autoscan_interval.set("5 min")
        self._autoscan_interval.pack(side="left")
        self._autoscan_lbl = ctk.CTkLabel(watch_card,
            text="Monitors for changes",
            font=ctk.CTkFont(size=_fs(9)), text_color=C["s_text_d"])
        self._autoscan_lbl.pack(anchor="w", padx=10, pady=(0,8))

        ctk.CTkFrame(bottom, height=1, fg_color="#2D3748").pack(fill="x", pady=(4,8))

        # ── Nav sections ──────────────────────────────────────────────────────
        self._nav_btns = {}
        sections = [
            ("OVERVIEW", [
                ("dashboard","📊","Dashboard"),
                ("devices",  "💻","Devices"),
            ]),
            ("ANALYSIS", [
                ("cves",      "🐛","CVEs"),
                ("cve_score", "📈","CVE Score"),
                ("redteam",   "⚔️", "Red Team"),
                ("traffic",   "📡","Traffic"),
            ]),
            ("RESPONSE", [
                ("secure",  "🔒","Secure Device"),
                ("history", "🕑","History"),
                ("report",  "📄","PDF Report"),
                ("alerts",  "🔔","Alerts"),
            ]),
        ]
        for sec_title, items in sections:
            ctk.CTkLabel(s, text=sec_title,
                font=ctk.CTkFont(size=_fs(9), weight="bold"),
                text_color=C["s_text_d"]).pack(anchor="w", padx=16, pady=(8,2))
            for key, icon, label in items:
                btn = ctk.CTkButton(s,
                    text=f"  {icon}  {label}",
                    font=ctk.CTkFont(size=_fs(12)),
                    anchor="w",
                    fg_color="transparent",
                    hover_color=C["sidebar2"],
                    text_color=C["s_text"],
                    corner_radius=8,
                    height=_NAV_BTN_H,
                    command=lambda k=key: self._switch_tab(k))
                btn.pack(fill="x", padx=10, pady=1)
                self._nav_btns[key] = btn

    # ── Top bar ───────────────────────────────────────────────────────────────

    def _build_topbar(self):
        t = self._topbar
        # Border bottom
        ctk.CTkFrame(t, height=1, fg_color=C["border"]).pack(side="bottom", fill="x")
        left = ctk.CTkFrame(t, fg_color="transparent")
        left.pack(side="left", padx=20, fill="y")
        self._topbar_title = ctk.CTkLabel(left, text="Dashboard",
            font=ctk.CTkFont(size=_fs(14), weight="bold"), text_color=C["text"])
        self._topbar_title.pack(anchor="w", pady=(12,0))
        self._topbar_sub = ctk.CTkLabel(left, text="No scan yet",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["text_faint"])
        self._topbar_sub.pack(anchor="w")
        right = ctk.CTkFrame(t, fg_color="transparent")
        right.pack(side="right", padx=16, fill="y")
        # WiFi pill
        ssid_pill = ctk.CTkFrame(right, fg_color=C["surface2"],
            corner_radius=20); ssid_pill.pack(side="left", padx=(0,10), pady=14)
        ctk.CTkLabel(ssid_pill, text="📶",
            font=ctk.CTkFont(size=_fs(11))).pack(side="left", padx=(8,2), pady=4)
        self._ssid_lbl = ctk.CTkLabel(ssid_pill, text="Not connected",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["text_dim"])
        self._ssid_lbl.pack(side="left", padx=(0,10), pady=4)
        # Score pill
        self._score_pill = ctk.CTkLabel(right, text="Score: —",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["text_faint"])
        self._score_pill.pack(side="left", pady=14)

    # ── Status bar ────────────────────────────────────────────────────────────

    def _build_statusbar(self):
        ctk.CTkFrame(self._statusbar, height=1,
            fg_color=C["border"]).pack(side="top", fill="x")
        self._status_lbl = ctk.CTkLabel(self._statusbar, text="Ready",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["text_faint"])
        self._status_lbl.pack(side="left", padx=14)
        # Scan state indicator dot
        self._status_dot = ctk.CTkLabel(self._statusbar, text="●",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["success"])
        self._status_dot.pack(side="right", padx=(0,14))

    # ══════════════════════════════════════════════════════════════════════════
    # NAVIGATION
    # ══════════════════════════════════════════════════════════════════════════

    TAB_META = {
        "dashboard": ("Dashboard",     "Network overview and scan output"),
        "devices":   ("Devices",       "All discovered devices on your network"),
        "cves":      ("CVE Results",   "Vulnerability lookup results by device"),
        "cve_score": ("CVE Score",     "Weighted vulnerability risk scoring (Module 8)"),
        "redteam":   ("Red Team",      "Active penetration test results (Module 4)"),
        "traffic":   ("Traffic",       "Live packet monitor & attack detection (Module 6)"),
        "secure":    ("Secure Device", "Isolate compromised devices (Module 7)"),
        "history":   ("History",       "Scan history database (Module 6)"),
        "report":    ("PDF Report",    "Generate full security report (Module 5)"),
        "alerts":    ("Alerts",        "Email notifications & verification"),
    }

    def _switch_tab(self, key: str):
        if self._current_tab and self._current_tab in self._tabs:
            self._tabs[self._current_tab].pack_forget()
        first_build = key not in self._tabs
        if first_build:
            self._tabs[key] = self._tab_builders[key]()
        for k, btn in self._nav_btns.items():
            if k == key:
                btn.configure(fg_color=C["sidebar_active"], text_color="#FFFFFF")
            else:
                btn.configure(fg_color="transparent", text_color=C["s_text"])
        self._tabs[key].pack(fill="both", expand=True)
        self._current_tab = key
        title, sub = self.TAB_META.get(key, (key,""))
        self._topbar_title.configure(text=title)
        self._topbar_sub.configure(text=sub)
        if self._last_m2 and self._data_dirty:
            if key == "devices":   self._refresh_devices()
            elif key == "cves":    self._refresh_cves()
            elif key == "redteam": self._refresh_redteam()
            elif key == "secure":  self._update_secure_compromised_menu()
            elif key == "cve_score": self._refresh_cve_score(self._last_m8)
            self._data_dirty = False
        elif self._last_m2 and key not in self._tabs.get("_refreshed", set()):
            if key == "devices":   self._refresh_devices()
            elif key == "cves":    self._refresh_cves()
            elif key == "redteam": self._refresh_redteam()
            elif key == "cve_score": self._refresh_cve_score(self._last_m8)
            elif key == "secure":  self._update_secure_compromised_menu()
            if "_refreshed" not in self._tabs: self._tabs["_refreshed"] = set()
            self._tabs["_refreshed"].add(key)
        if key == "history": self._refresh_history()

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: DASHBOARD
    # ══════════════════════════════════════════════════════════════════════════

    def _build_dashboard(self):
        frame = ctk.CTkFrame(self._content, fg_color="transparent")

        # ── Row 1: stat cards ─────────────────────────────────────────────────
        cr = ctk.CTkFrame(frame, fg_color="transparent")
        cr.pack(fill="x", padx=20, pady=(16,10))
        cr.grid_columnconfigure((0,1,2,3), weight=1)
        self._sc_devices  = StatCard(cr,"Devices Evaluated","—",C["accent"],icon="🖥️")
        self._sc_critical = StatCard(cr,"Critical Vulnerabilities","—",C["crit_r"],icon="🚨")
        self._sc_high     = StatCard(cr,"High Risk Items","—",C["high"],icon="⚠️")
        self._sc_safe     = StatCard(cr,"Safe Components","—",C["success"],icon="✅")
        for i,sc in enumerate([self._sc_devices,self._sc_critical,
                                self._sc_high,self._sc_safe]):
            sc.grid(row=0, column=i, padx=(0 if i==0 else 6, 0), sticky="nsew")

        # ── Row 2: gauge left | log right ─────────────────────────────────────
        mid = ctk.CTkFrame(frame, fg_color="transparent")
        mid.pack(fill="both", expand=True, padx=20, pady=(0,16))
        mid.grid_columnconfigure(0, weight=0)
        mid.grid_columnconfigure(1, weight=1)
        mid.grid_rowconfigure(0, weight=1)

        # Gauge card
        gc = _card(mid); gc.grid(row=0, column=0, sticky="nsew", padx=(0,10))
        ctk.CTkLabel(gc, text="NETWORK HEALTH SCORE",
            font=ctk.CTkFont(size=_fs(10), weight="bold"),
            text_color=C["text_faint"]).pack(pady=(16,0), padx=16, anchor="w")
        self._gauge = ScoreGauge(gc, size=200)
        self._gauge.pack(padx=16, pady=(4,4))
        ctk.CTkFrame(gc, height=1, fg_color=C["border"]).pack(fill="x", padx=12)
        ctk.CTkLabel(gc, text="Score Deductions",
            font=ctk.CTkFont(size=_fs(10), weight="bold"),
            text_color=C["text_faint"]).pack(anchor="w", padx=14, pady=(8,2))
        self._breakdown_scroll = ctk.CTkScrollableFrame(gc,
            fg_color="transparent", height=130,
            scrollbar_button_color=C["border"])
        self._breakdown_scroll.pack(fill="x", padx=8, pady=(0,12))
        ctk.CTkLabel(self._breakdown_scroll, text="Run a scan to see breakdown.",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["text_faint"]).pack(anchor="w",padx=4)

        # Scan log card
        lc = _card(mid); lc.grid(row=0, column=1, sticky="nsew")
        lh = ctk.CTkFrame(lc, fg_color=C["surface2"], corner_radius=0)
        lh.pack(fill="x")
        ctk.CTkLabel(lh, text="INTEGRATED ANALYSIS OUTPUT",
            font=ctk.CTkFont(size=_fs(10), weight="bold"),
            text_color=C["text_dim"]).pack(side="left", padx=14, pady=8)
        ctk.CTkButton(lh, text="Clear",
            fg_color="transparent", hover_color=C["surface2"],
            text_color=C["text_faint"], width=46, height=22,
            font=ctk.CTkFont(size=_fs(10)),
            command=lambda: self._log.clear()).pack(side="right", padx=10)
        self._log = LogPanel(lc)
        self._log.pack(fill="both", expand=True, padx=8, pady=(4,8))

        # Hidden stubs (legacy compatibility)
        self._dash_cve = ctk.CTkFrame(frame, fg_color="transparent", height=0)
        self._dash_cve.pack_forget()
        self._dash_fix = ctk.CTkFrame(frame, fg_color="transparent", height=0)
        self._dash_fix.pack_forget()

        return frame

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: DEVICES
    # ══════════════════════════════════════════════════════════════════════════

    def _build_devices(self):
        frame = ctk.CTkFrame(self._content, fg_color="transparent")
        hdr = _section_hdr(frame, "Device Inventory")
        self._dev_count_lbl = ctk.CTkLabel(hdr, text="",
            font=ctk.CTkFont(size=_fs(11)), text_color=C["text_faint"])
        self._dev_count_lbl.pack(side="right")

        # Filter bar
        fb = ctk.CTkFrame(frame, fg_color=C["surface"], corner_radius=10,
            border_width=1, border_color=C["border"])
        fb.pack(fill="x", padx=20, pady=(0,10))
        fi = ctk.CTkFrame(fb, fg_color="transparent"); fi.pack(fill="x", padx=10, pady=8)
        ctk.CTkLabel(fi, text="Filter:", font=ctk.CTkFont(size=_fs(11)),
            text_color=C["text_dim"]).pack(side="left", padx=(0,8))
        self._dev_filter_var = tk.StringVar(value="All")
        for f_val, f_col in [("All",C["accent"]),("CRITICAL",C["crit_r"]),
                              ("High",C["high"]),("Weak",C["weak"]),("Safe",C["success"])]:
            is_all = f_val=="All"
            ctk.CTkButton(fi, text=f_val,
                font=ctk.CTkFont(size=_fs(10), weight="bold" if is_all else "normal"),
                fg_color=f_col if is_all else C["surface2"],
                hover_color=f_col if not is_all else C["accent2"],
                text_color="white" if is_all else f_col,
                corner_radius=6, height=_fs(28), width=80,
                command=lambda v=f_val: self._filter_devices(v)
            ).pack(side="left", padx=3)

        self._dev_scroll = ctk.CTkScrollableFrame(frame,
            fg_color="transparent", corner_radius=0,
            scrollbar_button_color=C["border"])
        self._dev_scroll.pack(fill="both", expand=True, padx=20, pady=(0,16))
        ctk.CTkLabel(self._dev_scroll, text="Run a scan to see devices.",
            font=ctk.CTkFont(size=_fs(12)), text_color=C["text_faint"]).pack(pady=40)
        return frame

    def _filter_devices(self, val):
        self._dev_filter_var.set(val); self._refresh_devices()

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: CVEs
    # ══════════════════════════════════════════════════════════════════════════

    def _build_cves(self):
        frame = ctk.CTkFrame(self._content, fg_color="transparent")
        hdr = _section_hdr(frame, "CVE Vulnerabilities",
            sub="— Module 3: NVD CVE Lookup Engine")
        self._cve_count_lbl = ctk.CTkLabel(hdr, text="",
            font=ctk.CTkFont(size=_fs(11)), text_color=C["text_faint"])
        self._cve_count_lbl.pack(side="right")

        outer = ctk.CTkFrame(frame, fg_color=C["surface"], corner_radius=12,
            border_width=1, border_color=C["border"])
        outer.pack(fill="both", expand=True, padx=20, pady=(0,16))

        canvas = tk.Canvas(outer, bg=C["surface"], highlightthickness=0, bd=0)
        sb = ctk.CTkScrollbar(outer, command=canvas.yview,
            button_color=C["border2"])
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y", padx=(0,2), pady=4)
        canvas.pack(side="left", fill="both", expand=True)
        self._cve_inner = tk.Frame(canvas, bg=C["surface"])
        self._cve_window = canvas.create_window((0,0), window=self._cve_inner, anchor="nw")

        def _cfg(e): canvas.configure(scrollregion=canvas.bbox("all"))
        def _canvcfg(e): canvas.itemconfig(self._cve_window, width=e.width)
        def _mw(e): canvas.yview_scroll(int(-1*(e.delta/120)), "units")
        self._cve_inner.bind("<Configure>", _cfg)
        canvas.bind("<Configure>", _canvcfg)
        canvas.bind_all("<MouseWheel>", _mw)
        self._cve_canvas = canvas

        tk.Label(self._cve_inner, text="Run a scan to see CVE results.",
            font=("Helvetica",12), fg=C["text_faint"],
            bg=C["surface"]).pack(pady=60)
        return frame

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: CVE SCORE  (Module 8)
    # ══════════════════════════════════════════════════════════════════════════

    def _build_cve_score(self):
        frame = ctk.CTkFrame(self._content, fg_color="transparent")
        _section_hdr(frame, "CVE Risk Score", sub="— Module 8: Weighted Severity Scoring")

        # Stat cards
        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.pack(fill="x", padx=20, pady=(0,10))
        top.grid_columnconfigure((0,1,2,3), weight=1)
        self._m8_net_score = StatCard(top,"CVE Risk Score","—",C["accent"],icon="🎯")
        self._m8_total     = StatCard(top,"Total CVEs","—",C["text_dim"],icon="📋")
        self._m8_critical  = StatCard(top,"Critical CVEs","—",C["crit_r"],icon="🔴")
        self._m8_high      = StatCard(top,"High CVEs","—",C["high"],icon="🟠")
        for i,sc in enumerate([self._m8_net_score,self._m8_total,
                                self._m8_critical,self._m8_high]):
            sc.grid(row=0, column=i, padx=(0 if i==0 else 6, 0), sticky="nsew")

        # Grade banner
        self._m8_banner = _card(frame)
        self._m8_banner.pack(fill="x", padx=20, pady=(0,10))
        bi = ctk.CTkFrame(self._m8_banner, fg_color="transparent")
        bi.pack(fill="x", padx=16, pady=12)
        ctk.CTkLabel(bi, text="Network CVE Exposure Grade",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["text_dim"]).pack(side="left")
        self._m8_grade_lbl = ctk.CTkLabel(bi, text="—",
            font=ctk.CTkFont(size=_fs(13), weight="bold"),
            text_color=C["text_faint"])
        self._m8_grade_lbl.pack(side="right")

        # Per-device table
        tbl = _card(frame); tbl.pack(fill="both", expand=True, padx=20, pady=(0,16))
        ctk.CTkLabel(tbl, text="Per-Device CVE Risk",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["text_dim"]).pack(anchor="w", padx=14, pady=(10,4))
        hdr = ctk.CTkFrame(tbl, fg_color=C["surface2"], corner_radius=6)
        hdr.pack(fill="x", padx=8, pady=(0,4))
        for txt, w in [("Device IP",140),("Vendor",180),("CVE Score",90),
                       ("Grade",160),("Worst",90),("CVSS",110),
                       ("C",40),("H",40),("M",40),("Total",50)]:
            ctk.CTkLabel(hdr, text=txt,
                font=ctk.CTkFont(size=_fs(10), weight="bold"),
                text_color=C["text_faint"], width=w, anchor="w"
            ).pack(side="left", padx=6, pady=6)
        self._m8_table = ctk.CTkScrollableFrame(tbl,
            fg_color="transparent", scrollbar_button_color=C["border"])
        self._m8_table.pack(fill="both", expand=True, padx=8, pady=(0,8))
        ctk.CTkLabel(self._m8_table, text="Run a scan to see CVE scores.",
            font=ctk.CTkFont(size=_fs(11)), text_color=C["text_faint"]).pack(pady=30)
        return frame

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: RED TEAM  (Module 4)
    # ══════════════════════════════════════════════════════════════════════════

    def _build_redteam(self):
        frame = ctk.CTkFrame(self._content, fg_color="transparent")
        _section_hdr(frame, "Red Team Results",
            sub="— Module 4: Active Penetration Testing")
        warning = ctk.CTkFrame(frame,
            fg_color=C["warning_bg"], corner_radius=8,
            border_width=1, border_color=C["warning"])
        warning.pack(fill="x", padx=20, pady=(0,10))
        ctk.CTkLabel(warning,
            text="⚠  Only shows results from a full scan (red team enabled). "
                 "Toggle 'Skip Red Team' off in the sidebar.",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["warning"]).pack(
            padx=14, pady=8, anchor="w")
        self._rt_scroll = ctk.CTkScrollableFrame(frame,
            fg_color="transparent", scrollbar_button_color=C["border"])
        self._rt_scroll.pack(fill="both", expand=True, padx=20, pady=(0,16))
        ctk.CTkLabel(self._rt_scroll,
            text="Red team results appear here after a full scan.",
            font=ctk.CTkFont(size=_fs(12)), text_color=C["text_faint"]).pack(pady=40)
        return frame

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: TRAFFIC  (traffic_monitor.py)
    # ══════════════════════════════════════════════════════════════════════════

    def _build_traffic(self):
        frame = ctk.CTkFrame(self._content, fg_color="transparent")
        _section_hdr(frame, "Traffic Monitor",
            sub="— Live Packet Capture & Attack Detection")

        # Stat cards
        sc_row = ctk.CTkFrame(frame, fg_color="transparent")
        sc_row.pack(fill="x", padx=20, pady=(0,10))
        sc_row.grid_columnconfigure((0,1,2,3), weight=1)
        self._tc = {}
        for i,(k,lbl,col,icon) in enumerate([
            ("packets","Packets Captured",C["accent"],"📦"),
            ("alerts", "Attack Alerts",   C["danger"],"🚨"),
            ("blocked","IPs Blocked",     C["warning"],"🛑"),
            ("rate",   "Packets / sec",   C["text_dim"],"⚡"),
        ]):
            sc = StatCard(sc_row, lbl, "0", col, icon=icon)
            sc.grid(row=0, column=i, padx=(0 if i==0 else 6,0), sticky="nsew")
            self._tc[k] = sc

        # Controls
        ctrl = ctk.CTkFrame(frame, fg_color=C["surface"], corner_radius=10,
            border_width=1, border_color=C["border"])
        ctrl.pack(fill="x", padx=20, pady=(0,8))
        ci = ctk.CTkFrame(ctrl, fg_color="transparent")
        ci.pack(fill="x", padx=12, pady=10)
        self._traffic_btn = ctk.CTkButton(ci,
            text="▶  Start Monitor",
            font=ctk.CTkFont(size=_fs(12), weight="bold"),
            fg_color=C["success"], hover_color="#047857",
            corner_radius=8, height=_fs(36), width=150,
            command=self._toggle_traffic)
        self._traffic_btn.pack(side="left", padx=(0,8))
        self._pause_btn = ctk.CTkButton(ci, text="⏸  Pause Feed",
            font=ctk.CTkFont(size=_fs(11)),
            fg_color=C["surface2"], hover_color=C["border2"],
            text_color=C["text"], corner_radius=8, height=_fs(36), width=120,
            command=self._toggle_feed_pause)
        self._pause_btn.pack(side="left", padx=(0,8))
        self._auto_block_switch = ctk.CTkSwitch(ci,
            text="Auto-Block Attackers",
            font=ctk.CTkFont(size=_fs(11)), text_color=C["text_dim"],
            button_color=C["danger"], progress_color=C["danger"],
            onvalue=True, offvalue=False)
        self._auto_block_switch.pack(side="left", padx=8)
        ctk.CTkButton(ci, text="💾  Save",
            font=ctk.CTkFont(size=_fs(11)), fg_color=C["accent"],
            hover_color=C["accent2"], corner_radius=8,
            height=_fs(36), width=90,
            command=self._export_traffic).pack(side="right", padx=(6,0))
        ctk.CTkButton(ci, text="🗑  Clear",
            font=ctk.CTkFont(size=_fs(11)), fg_color=C["surface2"],
            hover_color=C["border2"], text_color=C["text_dim"],
            corner_radius=8, height=_fs(36), width=80,
            command=self._clear_traffic_feed).pack(side="right")
        self._traffic_status_lbl = ctk.CTkLabel(ctrl,
            text="Monitor not started",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["text_faint"])
        self._traffic_status_lbl.pack(anchor="w", padx=14, pady=(0,8))

        # Protocol breakdown
        pb = _card(frame); pb.pack(fill="x", padx=20, pady=(0,8))
        ctk.CTkLabel(pb, text="Protocol Breakdown",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["text_dim"]).pack(anchor="w", padx=14, pady=(10,4))
        pr = ctk.CTkFrame(pb, fg_color="transparent"); pr.pack(fill="x", padx=14, pady=(0,10))
        self._proto_labels = {}
        for proto, col in [("TCP",C["accent"]),("UDP",C["success"]),
                            ("ICMP",C["warning"]),("ARP","#7C3AED"),("OTHER",C["text_faint"])]:
            pf = ctk.CTkFrame(pr, fg_color=C["surface2"], corner_radius=8); pf.pack(side="left", padx=4)
            ctk.CTkLabel(pf, text=proto, font=ctk.CTkFont(size=_fs(9)),
                text_color=col).pack(padx=10, pady=(6,0))
            lbl = ctk.CTkLabel(pf, text="0",
                font=ctk.CTkFont(size=_fs(14), weight="bold"),
                text_color=C["text"]); lbl.pack(padx=10, pady=(0,6))
            self._proto_labels[proto] = lbl

        # Two-column: feed | alerts
        cols = ctk.CTkFrame(frame, fg_color="transparent")
        cols.pack(fill="both", expand=True, padx=20, pady=(0,16))
        cols.grid_columnconfigure(0, weight=3); cols.grid_columnconfigure(1, weight=2)

        lc = ctk.CTkFrame(cols, fg_color="transparent")
        lc.grid(row=0, column=0, sticky="nsew", padx=(0,10))
        fc = _card(lc); fc.pack(fill="both", expand=True)
        fh = ctk.CTkFrame(fc, fg_color=C["surface2"], corner_radius=0); fh.pack(fill="x")
        ctk.CTkLabel(fh, text="Live Packet Feed",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["text_dim"]).pack(side="left", padx=14, pady=8)
        self._feed_count_lbl = ctk.CTkLabel(fh, text="0 packets",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["text_faint"])
        self._feed_count_lbl.pack(side="right", padx=10)
        self._packet_feed = LogPanel(fc)
        self._packet_feed.pack(fill="both", expand=True, padx=8, pady=(4,8))

        rc = ctk.CTkFrame(cols, fg_color="transparent")
        rc.grid(row=0, column=1, sticky="nsew")
        ac = _card(rc); ac.pack(fill="both", expand=True)
        ah = ctk.CTkFrame(ac, fg_color=C["surface2"], corner_radius=0); ah.pack(fill="x")
        ctk.CTkLabel(ah, text="Attack Alerts",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["text_dim"]).pack(side="left", padx=14, pady=8)
        self._alert_count_lbl = ctk.CTkLabel(ah, text="0 alerts",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["text_faint"])
        self._alert_count_lbl.pack(side="right", padx=10)
        self._traffic_log = LogPanel(ac)
        self._traffic_log.pack(fill="both", expand=True, padx=8, pady=(4,8))

        return frame

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: SECURE DEVICE  (secure_device.py)
    # ══════════════════════════════════════════════════════════════════════════

    def _build_secure(self):
        frame = ctk.CTkFrame(self._content, fg_color="transparent")
        hdr = _section_hdr(frame, "Device Isolation",
            sub="— Block network access for compromised devices")

        # Status banner
        self._sec_banner = _card(frame)
        self._sec_banner.pack(fill="x", padx=20, pady=(0,10))
        bi = ctk.CTkFrame(self._sec_banner, fg_color="transparent")
        bi.pack(fill="x", padx=16, pady=14)
        ind = ctk.CTkFrame(bi, fg_color=C["success_bg"], corner_radius=10,
            width=48, height=48); ind.pack(side="left", padx=(0,14)); ind.pack_propagate(False)
        self._sec_dot = ctk.CTkLabel(ind, text="✓",
            font=ctk.CTkFont(size=_fs(20), weight="bold"), text_color=C["success"])
        self._sec_dot.pack(expand=True)
        txt = ctk.CTkFrame(bi, fg_color="transparent"); txt.pack(side="left", fill="x", expand=True)
        self._sec_status_lbl = ctk.CTkLabel(txt, text="All devices accessible",
            font=ctk.CTkFont(size=_fs(14), weight="bold"),
            text_color=C["success"], anchor="w"); self._sec_status_lbl.pack(anchor="w")
        self._sec_fw_lbl = ctk.CTkLabel(txt, text="No isolation rules active",
            font=ctk.CTkFont(size=_fs(11)), text_color=C["text_faint"], anchor="w")
        self._sec_fw_lbl.pack(anchor="w", pady=(2,0))

        # Two columns
        cols = ctk.CTkFrame(frame, fg_color="transparent")
        cols.pack(fill="both", expand=True, padx=20, pady=(0,16))
        cols.grid_columnconfigure(0, weight=2); cols.grid_columnconfigure(1, weight=3)

        # LEFT: target selector + action buttons
        left = ctk.CTkFrame(cols, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0,10))
        sel = _card(left); sel.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(sel, text="Target Device",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["text_dim"]).pack(anchor="w", padx=14, pady=(14,6))
        self._secure_device_var = tk.StringVar(value="No compromised devices found")
        self._secure_device_menu = ctk.CTkOptionMenu(sel,
            variable=self._secure_device_var,
            values=["No compromised devices found"],
            font=ctk.CTkFont(size=_fs(12)),
            fg_color=C["surface2"], button_color=C["border2"],
            dropdown_fg_color=C["surface2"])
        self._secure_device_menu.pack(fill="x", padx=14, pady=(0,8))
        self._sec_badge = ctk.CTkLabel(sel, text="",
            font=ctk.CTkFont(size=_fs(10), weight="bold"),
            text_color="white", fg_color=C["surface2"], corner_radius=4)
        self._sec_badge.pack(anchor="w", padx=14, pady=(0,4))
        self._sec_hint = ctk.CTkLabel(sel,
            text="Only devices confirmed compromised\nby the red team test appear here.",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["text_faint"], justify="left")
        self._sec_hint.pack(anchor="w", padx=14, pady=(0,14))

        self._sec_isolate_btn = ctk.CTkButton(left,
            text="🔒  Isolate Device",
            font=ctk.CTkFont(size=_fs(13), weight="bold"),
            fg_color=C["danger"], hover_color=C["critical"],
            corner_radius=10, height=_fs(50),
            command=self._secure_device_action)
        self._sec_isolate_btn.pack(fill="x", pady=(0,8))
        self._sec_restore_btn = ctk.CTkButton(left,
            text="🔓  Restore Access",
            font=ctk.CTkFont(size=_fs(13), weight="bold"),
            fg_color=C["surface2"], hover_color=C["border2"],
            text_color=C["text"], corner_radius=10, height=_fs(50),
            command=self._unblock_device_action)
        self._sec_restore_btn.pack(fill="x")

        # RIGHT: info steps + activity log
        right = ctk.CTkFrame(cols, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew")
        ic = _card(right); ic.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(ic, text="What Isolation Does",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["text_dim"]).pack(anchor="w", padx=14, pady=(14,10))
        for num, col, title, desc in [
            ("1",C["danger"],"Stops active connections","Terminates streaming apps from the device"),
            ("2",C["warning"],"Blocks outbound traffic","Prevents your device contacting the camera"),
            ("3",C["accent"],"Blocks inbound traffic","Prevents camera sending data to your network"),
        ]:
            r = ctk.CTkFrame(ic, fg_color=C["surface2"], corner_radius=8)
            r.pack(fill="x", padx=14, pady=(0,6))
            ri = ctk.CTkFrame(r, fg_color="transparent"); ri.pack(fill="x", padx=12, pady=10)
            b = ctk.CTkFrame(ri, fg_color=col, corner_radius=12,
                width=26, height=26); b.pack(side="left", padx=(0,10)); b.pack_propagate(False)
            ctk.CTkLabel(b, text=num, font=ctk.CTkFont(size=_fs(10), weight="bold"),
                text_color="white").pack(expand=True)
            t2 = ctk.CTkFrame(ri, fg_color="transparent"); t2.pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(t2, text=title, font=ctk.CTkFont(size=_fs(11), weight="bold"),
                text_color=C["text"], anchor="w").pack(anchor="w")
            ctk.CTkLabel(t2, text=desc, font=ctk.CTkFont(size=_fs(10)),
                text_color=C["text_dim"], anchor="w").pack(anchor="w")
        ctk.CTkFrame(ic, height=4, fg_color="transparent").pack()

        lc = _card(right); lc.pack(fill="both", expand=True)
        lh = ctk.CTkFrame(lc, fg_color=C["surface2"], corner_radius=0); lh.pack(fill="x")
        ctk.CTkLabel(lh, text="Activity Log",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["text_dim"]).pack(side="left", padx=14, pady=8)
        ctk.CTkButton(lh, text="Clear", fg_color="transparent",
            hover_color=C["surface2"], text_color=C["text_faint"],
            width=46, height=22, font=ctk.CTkFont(size=_fs(10)),
            command=lambda: self._secure_log.clear()).pack(side="right", padx=10)
        self._secure_log = LogPanel(lc)
        self._secure_log.pack(fill="both", expand=True, padx=8, pady=(4,8))

        self._layer_status = {}
        self._blocked_list_frame = ctk.CTkFrame(frame, fg_color="transparent")
        self._cmd_preview = ctk.CTkLabel(frame, text="")
        return frame

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: HISTORY  (Module 6)
    # ══════════════════════════════════════════════════════════════════════════

    def _build_history(self):
        frame = ctk.CTkFrame(self._content, fg_color="transparent")
        hdr = _section_hdr(frame, "Scan History",
            sub="— Module 6: SQLite Storage Engine")
        ctk.CTkButton(hdr, text="⬇  Export CSV",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            fg_color=C["success"], hover_color="#047857",
            corner_radius=8, height=_fs(32),
            command=self._export_csv).pack(side="right", padx=(8,0))
        ctk.CTkButton(hdr, text="↻  Refresh",
            fg_color=C["surface2"], hover_color=C["border2"],
            text_color=C["text"], corner_radius=8, height=_fs(32),
            command=self._refresh_history).pack(side="right")

        # ── Summary stat cards ────────────────────────────────────────────────
        sc_row = ctk.CTkFrame(frame, fg_color="transparent")
        sc_row.pack(fill="x", padx=20, pady=(0,10))
        sc_row.grid_columnconfigure((0,1,2,3), weight=1)
        self._hist_sc_total   = StatCard(sc_row, "Total Scans",    "0", C["accent"],   icon="🕑")
        self._hist_sc_best    = StatCard(sc_row, "Best Score",      "—", C["success"],  icon="🏆")
        self._hist_sc_worst   = StatCard(sc_row, "Worst Score",     "—", C["danger"],   icon="⚠️")
        self._hist_sc_avg     = StatCard(sc_row, "Average Score",   "—", C["text_dim"], icon="📊")
        for i, sc in enumerate([self._hist_sc_total, self._hist_sc_best,
                                  self._hist_sc_worst, self._hist_sc_avg]):
            sc.grid(row=0, column=i, padx=(0 if i==0 else 6, 0), sticky="nsew")

        # ── Score trend mini-bar ──────────────────────────────────────────────
        trend_card = _card(frame)
        trend_card.pack(fill="x", padx=20, pady=(0,8))
        th = ctk.CTkFrame(trend_card, fg_color="transparent")
        th.pack(fill="x", padx=16, pady=(10,4))
        ctk.CTkLabel(th, text="Score Trend (last 10 scans)",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["text_dim"]).pack(side="left")
        self._hist_trend_frame = ctk.CTkFrame(trend_card, fg_color="transparent", height=52)
        self._hist_trend_frame.pack(fill="x", padx=16, pady=(0,12))
        self._hist_trend_frame.pack_propagate(False)
        ctk.CTkLabel(self._hist_trend_frame, text="Run scans to see trend bars.",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["text_faint"]).pack(pady=14)

        # ── Column headers ────────────────────────────────────────────────────
        ch = ctk.CTkFrame(frame, fg_color=C["surface"], corner_radius=8,
            border_width=1, border_color=C["border"])
        ch.pack(fill="x", padx=20, pady=(0,4))
        chi = ctk.CTkFrame(ch, fg_color=C["surface2"], corner_radius=6)
        chi.pack(fill="x", padx=4, pady=4)
        for txt, w in [("#", 44), ("WiFi SSID", 150), ("Timestamp", 165),
                       ("Gateway", 115), ("IP Range", 140),
                       ("Score", 80), ("Grade", 110), ("Devices", 65)]:
            ctk.CTkLabel(chi, text=txt,
                font=ctk.CTkFont(size=_fs(10), weight="bold"),
                text_color=C["text_faint"], width=w, anchor="w"
            ).pack(side="left", padx=6, pady=7)

        # ── Scrollable rows ───────────────────────────────────────────────────
        self._hist_scroll = ctk.CTkScrollableFrame(frame,
            fg_color="transparent", scrollbar_button_color=C["border"])
        self._hist_scroll.pack(fill="both", expand=True, padx=20, pady=(0,16))
        ctk.CTkLabel(self._hist_scroll, text="No history yet. Run your first scan.",
            font=ctk.CTkFont(size=_fs(12)), text_color=C["text_faint"]).pack(pady=40)
        return frame

    def _refresh_history(self):
        """Load scan history from SQLite and populate the History tab."""
        if "history" not in self._tabs:
            return
        try:
            import module6
            module6.init_db()
            history = module6.get_scan_history(limit=200)
        except Exception as e:
            for w in self._hist_scroll.winfo_children(): w.destroy()
            ctk.CTkLabel(self._hist_scroll,
                text=f"Could not load history: {e}",
                font=ctk.CTkFont(size=_fs(11)), text_color=C["danger"]).pack(pady=40)
            return

        # Clear previous rows
        for w in self._hist_scroll.winfo_children(): w.destroy()

        if not history:
            ctk.CTkLabel(self._hist_scroll, text="No history yet. Run your first scan.",
                font=ctk.CTkFont(size=_fs(12)), text_color=C["text_faint"]).pack(pady=40)
            return

        ssid_map = load_ssid_map()
        scores   = [s["score"] for s in history if s.get("score") is not None]

        # Update stat cards
        self._hist_sc_total.update(str(len(history)))
        if scores:
            self._hist_sc_best.update(str(max(scores)))
            self._hist_sc_worst.update(str(min(scores)))
            self._hist_sc_avg.update(str(round(sum(scores) / len(scores))))

        # Trend bars (last 10)
        for w in self._hist_trend_frame.winfo_children(): w.destroy()
        recent = list(reversed(history[:10]))
        bar_row = ctk.CTkFrame(self._hist_trend_frame, fg_color="transparent")
        bar_row.pack(fill="both", expand=True)
        for scan in recent:
            sc = scan.get("score", 0) or 0
            col = (C["success"] if sc >= 90 else C["accent"] if sc >= 70
                   else C["warning"] if sc >= 50 else C["danger"])
            col_frame = ctk.CTkFrame(bar_row, fg_color="transparent")
            col_frame.pack(side="left", expand=True, fill="y", padx=2)
            bar_h = max(6, int(sc * 0.46))
            # Spacer
            ctk.CTkFrame(col_frame, fg_color="transparent",
                height=max(0, 46 - bar_h)).pack()
            ctk.CTkFrame(col_frame, fg_color=col,
                height=bar_h, corner_radius=3).pack(fill="x")
            ctk.CTkLabel(col_frame, text=str(sc),
                font=ctk.CTkFont(size=_fs(8)), text_color=C["text_faint"]).pack()

        # History rows
        row_colors = [C["surface"], C["surface2"]]
        for i, scan in enumerate(history):
            sc       = scan.get("score", 0) or 0
            label    = scan.get("score_label", "—")
            ssid     = ssid_map.get(str(scan["id"]), "—")
            sc_col   = (C["success"] if sc >= 90 else C["accent"] if sc >= 70
                        else C["warning"] if sc >= 50 else C["danger"])

            row = ctk.CTkFrame(self._hist_scroll,
                fg_color=row_colors[i % 2], corner_radius=8)
            row.pack(fill="x", pady=2)
            ri = ctk.CTkFrame(row, fg_color="transparent"); ri.pack(fill="x")

            # Score stripe on left
            stripe = ctk.CTkFrame(ri, width=4, fg_color=sc_col, corner_radius=2)
            stripe.pack(side="left", fill="y", padx=(0,8))

            def _lbl(parent, text, width, bold=False, color=None):
                ctk.CTkLabel(parent, text=str(text),
                    font=ctk.CTkFont(size=_fs(10), weight="bold" if bold else "normal"),
                    text_color=color or C["text"], width=width, anchor="w"
                ).pack(side="left", padx=4, pady=8)

            _lbl(ri, f"#{scan['id']}",         44,  bold=True,  color=C["text_faint"])
            _lbl(ri, ssid[:18],                 150, color=C["text_dim"])
            _lbl(ri, scan.get("timestamp","—"), 165)
            _lbl(ri, scan.get("gateway","—"),   115, color=C["text_dim"])
            _lbl(ri, scan.get("ip_range","—"),  140, color=C["text_dim"])

            # Score pill
            sc_pill = ctk.CTkFrame(ri, fg_color=sc_col, corner_radius=6)
            sc_pill.pack(side="left", padx=4, pady=6)
            ctk.CTkLabel(sc_pill, text=f" {sc}/100 ",
                font=ctk.CTkFont(size=_fs(10), weight="bold"),
                text_color="white").pack()

            _lbl(ri, label,                     110, color=sc_col)
            _lbl(ri, scan.get("device_count","—"), 65, color=C["text_dim"])

            # Detail expand button
            ctk.CTkButton(ri, text="Detail →",
                font=ctk.CTkFont(size=_fs(9)),
                fg_color="transparent", hover_color=C["border"],
                text_color=C["accent"], width=60, height=26,
                command=lambda s=scan, ssid=ssid: self._show_history_detail(s, ssid)
            ).pack(side="right", padx=8)

    def _show_history_detail(self, scan: dict, ssid: str):
        """Show a popup with detailed info for a single history scan entry."""
        d = ctk.CTkToplevel(self)
        d.title(f"Scan #{scan['id']} Detail")
        d.geometry("520x420")
        d.configure(fg_color=C["surface"])
        d.resizable(False, False); d.grab_set()

        ctk.CTkLabel(d, text=f"📋  Scan #{scan['id']} Details",
            font=ctk.CTkFont(size=_fs(16), weight="bold"),
            text_color=C["text"]).pack(pady=(20,4))

        sc = scan.get("score", 0) or 0
        sc_col = (C["success"] if sc >= 90 else C["accent"] if sc >= 70
                  else C["warning"] if sc >= 50 else C["danger"])

        info_frame = ctk.CTkFrame(d, fg_color=C["surface2"], corner_radius=10)
        info_frame.pack(fill="x", padx=24, pady=(8,16))

        def _detail_row(label, value, val_color=None):
            r = ctk.CTkFrame(info_frame, fg_color="transparent"); r.pack(fill="x", padx=16, pady=5)
            ctk.CTkLabel(r, text=label,
                font=ctk.CTkFont(size=_fs(11)), text_color=C["text_faint"],
                width=140, anchor="w").pack(side="left")
            ctk.CTkLabel(r, text=str(value),
                font=ctk.CTkFont(size=_fs(11), weight="bold"),
                text_color=val_color or C["text"], anchor="w").pack(side="left", fill="x", expand=True)

        _detail_row("Scan ID",      f"#{scan['id']}")
        _detail_row("WiFi SSID",    ssid)
        _detail_row("Timestamp",    scan.get("timestamp", "—"))
        _detail_row("Gateway",      scan.get("gateway", "—"))
        _detail_row("IP Range",     scan.get("ip_range", "—"))
        _detail_row("Score",        f"{sc}/100", val_color=sc_col)
        _detail_row("Grade",        scan.get("score_label", "—"), val_color=sc_col)
        _detail_row("Devices Found",scan.get("device_count", "—"))

        # Generate PDF for this scan button
        btn_row = ctk.CTkFrame(d, fg_color="transparent")
        btn_row.pack(fill="x", padx=24, pady=(0,16))
        ctk.CTkButton(btn_row, text="Close",
            fg_color=C["surface2"], hover_color=C["border2"],
            text_color=C["text"], corner_radius=8, height=_fs(36),
            command=d.destroy).pack(side="right")

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: PDF REPORT  (Module 5)
    # ══════════════════════════════════════════════════════════════════════════

    def _build_report(self):
        frame = ctk.CTkFrame(self._content, fg_color="transparent")
        _section_hdr(frame, "PDF Report Generator",
            sub="— Module 5: Professional Security Report")

        scroll = ctk.CTkScrollableFrame(frame, fg_color="transparent",
            scrollbar_button_color=C["border"])
        scroll.pack(fill="both", expand=True, padx=20, pady=(0,16))

        # ── Hero card ─────────────────────────────────────────────────────────
        hero = _card(scroll); hero.pack(fill="x", pady=(0,10))
        hi = ctk.CTkFrame(hero, fg_color="transparent"); hi.pack(fill="x", padx=24, pady=20)
        ctk.CTkLabel(hi, text="📄",
            font=ctk.CTkFont(size=_fs(48))).pack(side="left")
        txt = ctk.CTkFrame(hi, fg_color="transparent")
        txt.pack(side="left", padx=20, fill="x", expand=True)
        ctk.CTkLabel(txt, text="Generate Full Security Report",
            font=ctk.CTkFont(size=_fs(14), weight="bold"),
            text_color=C["text"]).pack(anchor="w")
        ctk.CTkLabel(txt,
            text="Includes: cover page · device inventory · CVE findings · red team results\n"
                 "fix recommendations · historical score trend · full audit trail",
            font=ctk.CTkFont(size=_fs(11)), text_color=C["text_dim"],
            justify="left").pack(anchor="w", pady=4)
        self._pdf_btn = ctk.CTkButton(txt,
            text="📄  Generate PDF Report",
            font=ctk.CTkFont(size=_fs(12), weight="bold"),
            fg_color=C["accent"], hover_color=C["accent2"],
            corner_radius=10, height=_fs(42), width=240,
            command=self._generate_pdf)
        self._pdf_btn.pack(anchor="w", pady=(6,0))

        # ── Options card ──────────────────────────────────────────────────────
        opts = _card(scroll); opts.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(opts, text="Report Options",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["text_dim"]).pack(anchor="w", padx=16, pady=(12,6))
        ctk.CTkFrame(opts, height=1, fg_color=C["border"]).pack(fill="x", padx=16)

        def _opt_row(parent, label, default=True):
            r = ctk.CTkFrame(parent, fg_color="transparent"); r.pack(fill="x", padx=16, pady=5)
            sw = ctk.CTkSwitch(r, text=label,
                font=ctk.CTkFont(size=_fs(11)), text_color=C["text"],
                button_color=C["accent"], progress_color=C["accent"],
                onvalue=True, offvalue=False)
            if default: sw.select()
            sw.pack(side="left"); return sw

        self._rpt_include_devices = _opt_row(opts, "Include Device Inventory")
        self._rpt_include_cves    = _opt_row(opts, "Include CVE Findings")
        self._rpt_include_redteam = _opt_row(opts, "Include Red Team Results")
        self._rpt_include_recs    = _opt_row(opts, "Include Fix Recommendations")
        self._rpt_include_trend   = _opt_row(opts, "Include Score Trend Graph")
        ctk.CTkFrame(opts, height=6, fg_color="transparent").pack()

        # ── Report metadata ───────────────────────────────────────────────────
        meta = _card(scroll); meta.pack(fill="x", pady=(0,10))
        ctk.CTkLabel(meta, text="Report Metadata",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["text_dim"]).pack(anchor="w", padx=16, pady=(12,6))
        ctk.CTkFrame(meta, height=1, fg_color=C["border"]).pack(fill="x", padx=16)

        def _meta_row(parent, label, placeholder):
            r = ctk.CTkFrame(parent, fg_color="transparent"); r.pack(fill="x", padx=16, pady=5)
            ctk.CTkLabel(r, text=label, font=ctk.CTkFont(size=_fs(11)),
                text_color=C["text"], width=180, anchor="w").pack(side="left")
            e = ctk.CTkEntry(r, height=_fs(32), placeholder_text=placeholder,
                fg_color=C["surface2"], border_color=C["border2"],
                text_color=C["text"], font=ctk.CTkFont(size=_fs(11)))
            e.pack(side="left", fill="x", expand=True); return e

        self._rpt_org_name    = _meta_row(meta, "Organisation Name",  "e.g.  Acme Corp")
        self._rpt_analyst     = _meta_row(meta, "Analyst / Author",   "e.g.  John Smith")
        self._rpt_save_folder = _meta_row(meta, "Save Folder",        "Default: same folder as gui.py")
        br = ctk.CTkFrame(meta, fg_color="transparent"); br.pack(fill="x", padx=16, pady=(0,12))
        ctk.CTkButton(br, text="📁  Browse…",
            font=ctk.CTkFont(size=_fs(10)),
            fg_color=C["surface2"], hover_color=C["border2"],
            text_color=C["text"], corner_radius=6, height=_fs(28), width=100,
            command=self._report_browse_folder).pack(side="left")
        ctk.CTkFrame(meta, height=4, fg_color="transparent").pack()

        # ── Past reports list ─────────────────────────────────────────────────
        past = _card(scroll); past.pack(fill="x", pady=(0,10))
        ph = ctk.CTkFrame(past, fg_color="transparent"); ph.pack(fill="x", padx=14, pady=(10,6))
        ctk.CTkLabel(ph, text="Recently Generated Reports",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["text_dim"]).pack(side="left")
        ctk.CTkButton(ph, text="↻ Refresh",
            font=ctk.CTkFont(size=_fs(10)),
            fg_color="transparent", hover_color=C["surface2"],
            text_color=C["accent"], width=80, height=26,
            command=self._refresh_past_reports).pack(side="right")
        ctk.CTkFrame(past, height=1, fg_color=C["border"]).pack(fill="x", padx=14)
        self._past_reports_frame = ctk.CTkScrollableFrame(past,
            fg_color="transparent", height=100,
            scrollbar_button_color=C["border"])
        self._past_reports_frame.pack(fill="x", padx=8, pady=(4,8))
        self._refresh_past_reports()

        # ── Status / log card ─────────────────────────────────────────────────
        lc = _card(scroll); lc.pack(fill="x", pady=(0,4))
        lh = ctk.CTkFrame(lc, fg_color=C["surface2"], corner_radius=0); lh.pack(fill="x")
        ctk.CTkLabel(lh, text="Report Status Log",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            text_color=C["text_dim"]).pack(side="left", padx=14, pady=8)
        ctk.CTkButton(lh, text="Clear",
            fg_color="transparent", hover_color=C["surface2"],
            text_color=C["text_faint"], width=46, height=22,
            font=ctk.CTkFont(size=_fs(10)),
            command=lambda: self._report_log.clear()).pack(side="right", padx=10)
        self._report_log = LogPanel(lc)
        self._report_log.pack(fill="both", padx=8, pady=(4,8))
        lc.configure(height=180); lc.pack_propagate(False)
        return frame

    def _report_browse_folder(self):
        folder = filedialog.askdirectory(title="Choose Report Save Folder")
        if folder:
            self._rpt_save_folder.delete(0, "end")
            self._rpt_save_folder.insert(0, folder)

    def _refresh_past_reports(self):
        """Scan _DIR for existing PDF reports and list them."""
        if not hasattr(self, "_past_reports_frame"): return
        for w in self._past_reports_frame.winfo_children(): w.destroy()
        try:
            pdfs = sorted(
                [f for f in os.listdir(_DIR) if f.lower().endswith(".pdf")],
                reverse=True
            )[:10]
        except Exception:
            pdfs = []
        if not pdfs:
            ctk.CTkLabel(self._past_reports_frame,
                text="No PDF reports found in the tool folder.",
                font=ctk.CTkFont(size=_fs(10)), text_color=C["text_faint"]).pack(pady=8)
            return
        for fname in pdfs:
            fpath = os.path.join(_DIR, fname)
            try:
                size_kb = os.path.getsize(fpath) // 1024
                mtime   = datetime.datetime.fromtimestamp(
                    os.path.getmtime(fpath)).strftime("%Y-%m-%d %H:%M")
            except Exception:
                size_kb, mtime = 0, "—"
            r = ctk.CTkFrame(self._past_reports_frame, fg_color=C["surface2"],
                corner_radius=6); r.pack(fill="x", pady=2)
            ri = ctk.CTkFrame(r, fg_color="transparent"); ri.pack(fill="x", padx=8, pady=5)
            ctk.CTkLabel(ri, text="📄",
                font=ctk.CTkFont(size=_fs(14))).pack(side="left", padx=(0,6))
            ctk.CTkLabel(ri, text=fname,
                font=ctk.CTkFont(size=_fs(10), weight="bold"),
                text_color=C["text"], anchor="w").pack(side="left", fill="x", expand=True)
            ctk.CTkLabel(ri, text=f"{mtime}  ·  {size_kb} KB",
                font=ctk.CTkFont(size=_fs(9)), text_color=C["text_faint"]).pack(side="left", padx=6)
            ctk.CTkButton(ri, text="Open",
                font=ctk.CTkFont(size=_fs(9)),
                fg_color=C["accent_pale"], hover_color=C["border"],
                text_color=C["accent"], corner_radius=4, height=24, width=50,
                command=lambda p=fpath: self._open_report_file(p)).pack(side="right")

    def _open_report_file(self, path):
        try:
            if sys.platform == "win32":  os.startfile(path)
            elif sys.platform == "darwin": subprocess.Popen(["open", path])
            else: subprocess.Popen(["xdg-open", path])
        except Exception as e:
            messagebox.showerror("Cannot Open", str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # TAB: ALERTS  (mailer.py + Module 7 watch mode)
    # ══════════════════════════════════════════════════════════════════════════

    def _build_alerts(self):
        frame = ctk.CTkFrame(self._content, fg_color="transparent")
        _section_hdr(frame, "Alerts & Notifications",
            sub="— Email verification · trigger settings · Watch Mode · alert log")

        scroll = ctk.CTkScrollableFrame(frame, fg_color="transparent",
            scrollbar_button_color=C["border"])
        scroll.pack(fill="both", expand=True, padx=20, pady=(0,16))

        def _sec(title, icon=""):
            f = _card(scroll); f.pack(fill="x", pady=(0,10))
            ctk.CTkLabel(f, text=f"{icon}  {title}" if icon else title,
                font=ctk.CTkFont(size=_fs(13), weight="bold"),
                text_color=C["text"]).pack(anchor="w", padx=16, pady=(14,4))
            ctk.CTkFrame(f, height=1, fg_color=C["border"]).pack(fill="x", padx=16)
            return f

        def _row(p, label, factory):
            r = ctk.CTkFrame(p, fg_color="transparent"); r.pack(fill="x", padx=16, pady=6)
            ctk.CTkLabel(r, text=label, font=ctk.CTkFont(size=_fs(11)),
                text_color=C["text"], width=260, anchor="w").pack(side="left")
            w = factory(r); w.pack(side="right"); return w

        cfg = self._alert_cfg

        # ── 1. Email Verification ─────────────────────────────────────────────
        es = _sec("Email Verification & Alerts", "📧")
        ctk.CTkLabel(es,
            text="Verify your email to receive security scan alerts, "
                 "network change notifications, and score-drop warnings.",
            font=ctk.CTkFont(size=_fs(11)), text_color=C["text_dim"],
            justify="left", wraplength=600).pack(anchor="w", padx=16, pady=(4,10))

        self._email_widget = EmailSectionWidget(es, on_verified=self._on_wizard_complete)
        self._email_widget.pack(fill="x", padx=16, pady=(0,10))

        if cfg.get("email_verified"):
            tr = ctk.CTkFrame(es, fg_color="transparent")
            tr.pack(fill="x", padx=16, pady=(4,12))
            ctk.CTkButton(tr, text="📨  Send Test Email",
                font=ctk.CTkFont(size=_fs(11)),
                fg_color=C["surface2"], hover_color=C["border2"],
                text_color=C["text"], corner_radius=6, height=_fs(32), width=160,
                command=self._send_test_email).pack(side="left")
            self._al_test_lbl = ctk.CTkLabel(tr, text="",
                font=ctk.CTkFont(size=_fs(10)), text_color=C["text_dim"])
            self._al_test_lbl.pack(side="left", padx=10)
        else:
            self._al_test_lbl = ctk.CTkLabel(es, text="")
        ctk.CTkFrame(es, height=4, fg_color="transparent").pack()

        # ── 2. Alert Triggers ─────────────────────────────────────────────────
        sec1 = _sec("Alert Triggers", "🔔")

        self._al_new_device = _row(sec1, "Alert on new device joined network",
            lambda p: ctk.CTkSwitch(p, text="",
                button_color=C["accent"], progress_color=C["accent"],
                onvalue=True, offvalue=False))
        if cfg.get("alert_new_device"): self._al_new_device.select()

        self._al_critical_risk = _row(sec1, "Alert when CRITICAL risk device found",
            lambda p: ctk.CTkSwitch(p, text="",
                button_color=C["danger"], progress_color=C["danger"],
                onvalue=True, offvalue=False))
        if cfg.get("alert_critical_risk"): self._al_critical_risk.select()

        self._al_score_drop = _row(sec1, "Alert when score drops below threshold",
            lambda p: ctk.CTkSwitch(p, text="",
                button_color=C["warning"], progress_color=C["warning"],
                onvalue=True, offvalue=False))
        if cfg.get("alert_score_drop"): self._al_score_drop.select()

        self._al_threshold = _row(sec1, "Score alert threshold (0–100)",
            lambda p: ctk.CTkEntry(p, width=70,
                fg_color=C["surface2"], border_color=C["border2"],
                text_color=C["text"], font=ctk.CTkFont(size=_fs(12))))
        self._al_threshold.insert(0, str(cfg.get("alert_score_threshold", 60)))

        self._al_traffic = _row(sec1, "Alert on traffic attack detection",
            lambda p: ctk.CTkSwitch(p, text="",
                button_color=C["danger"], progress_color=C["danger"],
                onvalue=True, offvalue=False))
        if cfg.get("alert_traffic"): self._al_traffic.select()

        self._al_redteam_comp = _row(sec1, "Alert when red team finds compromised device",
            lambda p: ctk.CTkSwitch(p, text="",
                button_color=C["danger"], progress_color=C["danger"],
                onvalue=True, offvalue=False))
        if cfg.get("alert_redteam_comp"): self._al_redteam_comp.select()
        ctk.CTkFrame(sec1, height=4, fg_color="transparent").pack()

        # ── 3. Notification Delivery ──────────────────────────────────────────
        sec2 = _sec("Notification Delivery", "📬")
        self._al_toast = _row(sec2, "Desktop toast notifications (Windows)",
            lambda p: ctk.CTkSwitch(p, text="",
                button_color=C["accent"], progress_color=C["accent"],
                onvalue=True, offvalue=False))
        if cfg.get("toast_enabled", True): self._al_toast.select()

        self._al_email_on_scan = _row(sec2, "Send email summary after every scan",
            lambda p: ctk.CTkSwitch(p, text="",
                button_color=C["accent"], progress_color=C["accent"],
                onvalue=True, offvalue=False))
        if cfg.get("email_on_scan"): self._al_email_on_scan.select()
        ctk.CTkFrame(sec2, height=4, fg_color="transparent").pack()

        # ── 4. Watch Mode Status ──────────────────────────────────────────────
        sec3 = _sec("Watch Mode Status", "👁")
        wm_inner = ctk.CTkFrame(sec3, fg_color="transparent")
        wm_inner.pack(fill="x", padx=16, pady=(6,12))

        wm_stat_row = ctk.CTkFrame(wm_inner, fg_color=C["surface2"], corner_radius=8)
        wm_stat_row.pack(fill="x", pady=(0,8))
        wsi = ctk.CTkFrame(wm_stat_row, fg_color="transparent")
        wsi.pack(fill="x", padx=12, pady=10)
        self._wm_status_dot = ctk.CTkLabel(wsi, text="●",
            font=ctk.CTkFont(size=_fs(14)), text_color=C["text_faint"])
        self._wm_status_dot.pack(side="left", padx=(0,8))
        self._wm_status_lbl = ctk.CTkLabel(wsi, text="Watch Mode is not running",
            font=ctk.CTkFont(size=_fs(11), weight="bold"), text_color=C["text"])
        self._wm_status_lbl.pack(side="left")
        self._wm_scan_count_lbl = ctk.CTkLabel(wsi, text="",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["text_faint"])
        self._wm_scan_count_lbl.pack(side="right")

        ctk.CTkLabel(wm_inner,
            text="Watch Mode runs continuous background scans at your chosen interval.\n"
                 "Configure the interval and enable Watch Mode from the sidebar.",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["text_faint"],
            justify="left").pack(anchor="w", pady=(0,4))

        ctk.CTkButton(wm_inner, text="▶  Start Watch Mode",
            font=ctk.CTkFont(size=_fs(11), weight="bold"),
            fg_color=C["success"], hover_color="#047857",
            corner_radius=8, height=_fs(34), width=180,
            command=self._toggle_watch_from_alerts).pack(anchor="w", pady=(4,0))

        # ── 5. Alert Log ──────────────────────────────────────────────────────
        sec4 = _sec("Alert Log", "📋")
        al_hdr = ctk.CTkFrame(sec4, fg_color="transparent")
        al_hdr.pack(fill="x", padx=16, pady=(6,4))
        ctk.CTkLabel(al_hdr, text="All fired alerts this session",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["text_faint"]).pack(side="left")
        ctk.CTkButton(al_hdr, text="🗑 Clear",
            font=ctk.CTkFont(size=_fs(10)),
            fg_color="transparent", hover_color=C["surface2"],
            text_color=C["text_faint"], width=60, height=24,
            command=self._clear_alert_log).pack(side="right")
        self._alert_log_panel = LogPanel(sec4)
        self._alert_log_panel.pack(fill="both", padx=8, pady=(0,12))
        sec4.configure(height=200); sec4.pack_propagate(False)

        # ── Save ──────────────────────────────────────────────────────────────
        ctk.CTkButton(scroll, text="💾  Save Alert Preferences",
            font=ctk.CTkFont(size=_fs(12), weight="bold"),
            fg_color=C["accent"], hover_color=C["accent2"],
            corner_radius=8, height=_fs(42),
            command=self._save_alert_triggers).pack(fill="x", pady=(4,0))

        self._poll_watch_mode_status()
        return frame

    def _toggle_watch_from_alerts(self):
        if self._autoscan_running:
            self._autoscan_switch.deselect()
            self._stop_watch_mode()
        else:
            self._autoscan_switch.select()
            self._start_watch_mode()

    def _poll_watch_mode_status(self):
        if "alerts" not in self._tabs: return
        if not hasattr(self, "_wm_status_dot"): return
        if self._autoscan_running and self._watcher:
            try: n = self._watcher._scan_num
            except Exception: n = 0
            self._wm_status_dot.configure(text_color=C["success"])
            self._wm_status_lbl.configure(
                text=f"Watch Mode ACTIVE — {self._autoscan_interval.get()} interval",
                text_color=C["success"])
            self._wm_scan_count_lbl.configure(text=f"{n} scan(s) completed")
        else:
            self._wm_status_dot.configure(text_color=C["text_faint"])
            self._wm_status_lbl.configure(
                text="Watch Mode is not running", text_color=C["text"])
            self._wm_scan_count_lbl.configure(text="")
        self.after(4000, self._poll_watch_mode_status)

    def _clear_alert_log(self):
        if hasattr(self, "_alert_log_panel"):
            self._alert_log_panel.clear()

    def _log_alert(self, message: str):
        if hasattr(self, "_alert_log_panel"):
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            self._alert_log_panel.append(f"[{ts}]  {message}")

    # ══════════════════════════════════════════════════════════════════════════
    # SCAN ENGINE
    # ══════════════════════════════════════════════════════════════════════════

    def _start_scan(self):
        if self._scan_running: return
        self._scan_running = True
        self._scan_btn.configure(text="Scanning...", state="disabled",
            fg_color="#374151")
        self._log.clear()
        mode = "Quick scan (red team skipped)" if self._skip_redteam.get() else "Full scan"
        self._log.section_header(
            f"NetProbe  ·  {datetime.datetime.now():%Y-%m-%d %H:%M:%S}  ·  {mode}")
        self._status("Scanning...", busy=True)
        self._anim_bar.start_animation()
        self._spinner_idx = 0
        self._animate_scan_btn()
        threading.Thread(target=self._scan_worker,
            args=(self._skip_redteam.get(),), daemon=True).start()

    _SPINNER = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def _animate_scan_btn(self):
        if not self._scan_running: return
        f = self._SPINNER[self._spinner_idx % len(self._SPINNER)]
        self._scan_btn.configure(text=f"{f}  Scanning...")
        self._spinner_idx += 1
        self.after(80, self._animate_scan_btn)

    def _scan_worker(self, skip_redteam):
        orig = sys.stdout; sys.stdout = QueueWriter(self._q)
        try:
            import module1, module2, module3, module6
            import module8_cve_score as module8

            ssid = get_wifi_ssid()
            self._q.put(("log", f"WiFi: {ssid}"))
            self._q.put(("progress", 0.10))
            self._q.put(("log", "Discovering devices on your network..."))
            gateway, ip_range, m1 = module1.run_module1()
            if not ip_range or not m1:
                self._q.put(("error","No devices found. Check WiFi connection."))
                return
            self._q.put(("log", f"[OK] {len(m1)} device(s) on {ip_range}"))
            self._q.put(("progress", 0.25))
            self._q.put(("log", "Analysing device information..."))
            m2 = module2.run_module2(m1)
            m2 = enrich_devices(m2)
            self._q.put(("log", "[OK] Vendor, banner, TLS, UPnP, OS complete"))
            self._q.put(("progress", 0.45))
            self._q.put(("log", "Checking for known vulnerabilities..."))
            m3 = module3.run_module3(m2)
            self._q.put(("log", f"[OK] Score: {m3['score']}/100 ({m3['score_label']})"))

            m4 = []
            if not skip_redteam:
                self._q.put(("progress", 0.65))
                self._q.put(("consent_required", m2))
                if self._wait_for_consent():
                    import module4
                    self._q.put(("log", "Running security tests..."))
                    m4 = module4.run_module4(m2)
                    comp = sum(1 for d in m4 if d.get("verdict")=="COMPROMISED")
                    self._q.put(("log", f"[OK] Red team complete — {comp} compromised"))
                else:
                    self._q.put(("log", "[!] Red team skipped"))
                    m4 = self._build_empty_m4(m2)
            else:
                m4 = self._build_empty_m4(m2)

            m3 = module3.recalculate_with_redteam(m3, m4)
            for entry in m4:
                if entry.get("verdict") == "COMPROMISED":
                    ip = entry.get("ip","")
                    if ip not in m3.get("cve_results",{}):
                        m3["cve_results"][ip] = []
                    for cve in m3["cve_results"][ip]:
                        cve["severity"] = "CRITICAL"
                        cve["source"] += " [ESCALATED — device compromised]"
                    m3["cve_results"][ip].insert(0, {
                        "id": "CONFIRMED-EXPLOIT", "severity": "CRITICAL",
                        "description": (
                            f"Device at {ip} was successfully compromised during "
                            f"red team testing — unauthenticated access confirmed. "
                            f"All vulnerabilities on this device are now actively exploitable."),
                        "source": "red team (confirmed exploit)",
                    })

            self._q.put(("progress", 0.75))
            self._q.put(("log", "Calculating risk score..."))
            m8 = module8.run_module8(m3)
            self._q.put(("log", f"[OK] Risk Score: {m8['network_score']}/100 — {m8['network_grade']}"))
            self._q.put(("progress", 0.85))
            self._q.put(("log", "Saving scan results..."))
            m6 = module6.run_module6(gateway=gateway, ip_range=ip_range,
                m3=m3, m4_results=m4 or None)
            self._q.put(("log", f"[OK] Scan #{m6['scan_id']} saved"))
            save_ssid_for_scan(m6["scan_id"], ssid)
            self._q.put(("progress", 1.0))
            self._q.put(("scan_complete", {
                "gateway": gateway, "ip_range": ip_range, "ssid": ssid,
                "m2": m2, "m3": m3, "m4": m4, "m8": m8,
            }))
        except Exception as e:
            import traceback
            self._q.put(("error", f"Scan error: {e}"))
            self._q.put(("log", traceback.format_exc()))
        finally:
            sys.stdout = orig; self._q.put(("scan_done", None))

    def _wait_for_consent(self):
        self._consent_event = threading.Event()
        self._consent_result = False
        self._consent_event.wait(timeout=120)
        return self._consent_result

    def _show_consent_dialog(self):
        d = ctk.CTkToplevel(self)
        d.title("Red Team Consent"); d.geometry("520x360")
        d.configure(fg_color=C["surface"]); d.grab_set(); d.resizable(False,False)
        ctk.CTkLabel(d, text="⚠️  Active Penetration Testing",
            font=ctk.CTkFont(size=_fs(17), weight="bold"),
            text_color=C["danger"]).pack(pady=(22,8))
        ctk.CTkLabel(d,
            text=("The security test will ACTIVELY attempt to:\n\n"
                  "  • Login with default credentials\n"
                  "  • Access camera RTSP streams without authentication\n"
                  "  • Test FTP anonymous login\n"
                  "  • Test MQTT broker access\n"
                  "  • Test SMB null sessions\n\n"
                  "Only proceed if you OWN all devices on this network.\n"
                  "This will be logged in audit_log.txt."),
            font=ctk.CTkFont(size=_fs(12)), text_color=C["text"],
            justify="left").pack(padx=30)
        br = ctk.CTkFrame(d, fg_color="transparent"); br.pack(pady=18,padx=30,fill="x")
        def _accept():
            self._consent_result = True; self._log_consent()
            d.destroy(); self._consent_event.set()
        def _decline():
            self._consent_result = False; d.destroy(); self._consent_event.set()
        ctk.CTkButton(br, text="I Consent — Run Red Team",
            fg_color=C["danger"], hover_color=C["critical"],
            height=_fs(40), command=_accept).pack(side="left",expand=True,fill="x",padx=(0,8))
        ctk.CTkButton(br, text="Skip",
            fg_color=C["surface2"], hover_color=C["border2"],
            height=_fs(40), command=_decline).pack(side="left",expand=True,fill="x")

    def _log_consent(self):
        try:
            path = os.path.join(_DIR,"audit_log.txt")
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(path,"a") as f:
                f.write(f"[{ts}] User confirmed consent for active penetration testing.\n")
        except Exception: pass

    @staticmethod
    def _build_empty_m4(m2):
        return [{"ip": d["ip"],
                 "vendor": d.get("vendor_api", d.get("vendor","Unknown")),
                 "device_type": d.get("device_type","Unknown"),
                 "verdict": "SKIPPED", "tests": {}} for d in m2]

    # ══════════════════════════════════════════════════════════════════════════
    # APPLY SCAN RESULTS
    # ══════════════════════════════════════════════════════════════════════════

    def _apply_scan_results(self, data):
        m2=data["m2"]; m3=data["m3"]; m4=data["m4"]; m8=data.get("m8",{})
        self._last_m2=m2; self._last_m3=m3; self._last_m4=m4; self._last_m8=m8
        self._last_gateway=data["gateway"]; self._last_ip_range=data["ip_range"]
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ssid = data.get("ssid","Unknown")
        self._ssid_lbl.configure(text=ssid)
        self._topbar_sub.configure(text=f"Last scan: {ts}  ·  {ssid}")
        self._score_pill.configure(
            text=f"Score: {m3['score']}/100  {m3['score_label']}",
            text_color=self._score_color(m3["score"]))
        critical = sum(1 for d in m2 if d["risk"]=="CRITICAL")
        high     = sum(1 for d in m2 if d["risk"]=="High")
        safe     = sum(1 for d in m2 if d["risk"]=="Safe")
        self._sc_devices.update(len(m2), sub=f"on {data['ip_range']}")
        self._sc_critical.update(critical, sub="open critical ports",
            color=C["crit_r"] if critical else C["success"])
        self._sc_high.update(high, sub="FTP / RDP exposed")
        self._sc_safe.update(safe, sub="no open ports")
        self._gauge.set_score(m3["score"], m3["score_label"])
        self._refresh_breakdown(m3)
        self._refresh_dash_extras(m3)
        self._refresh_devices(); self._refresh_cves()
        self._refresh_cve_score(m8); self._refresh_redteam()
        self._update_secure_compromised_menu()
        # Nav badges
        self._nav_btns["devices"].configure(text=f"  💻  Devices  ({len(m2)})")
        total_cves = sum(len(v) for v in m3.get("cve_results",{}).values())
        self._nav_btns["cves"].configure(text=f"  🐛  CVEs  ({total_cves})")
        comp = sum(1 for d in m4 if d.get("verdict")=="COMPROMISED")
        if comp:
            self._nav_btns["secure"].configure(
                text=f"  🔒  Secure Device  ({comp})")

    def _score_color(self, s):
        if s>=90: return C["success"]
        if s>=70: return C["accent"]
        if s>=50: return C["warning"]
        return C["danger"]

    # ══════════════════════════════════════════════════════════════════════════
    # DASHBOARD REFRESH HELPERS
    # ══════════════════════════════════════════════════════════════════════════

    def _refresh_breakdown(self, m3):
        for w in self._breakdown_scroll.winfo_children(): w.destroy()
        bd = m3.get("breakdown",[])
        if not bd:
            ctk.CTkLabel(self._breakdown_scroll,
                text="No deductions — clean network.",
                font=ctk.CTkFont(size=_fs(10)), text_color=C["success"]).pack(anchor="w")
            return
        for item in bd[:10]:
            r = ctk.CTkFrame(self._breakdown_scroll,
                fg_color=C["surface2"], corner_radius=6); r.pack(fill="x", pady=2)
            top = ctk.CTkFrame(r, fg_color="transparent"); top.pack(fill="x",padx=8,pady=(6,1))
            ctk.CTkLabel(top, text=item["ip"],
                font=ctk.CTkFont(size=_fs(10), weight="bold"),
                text_color=C["accent"], anchor="w").pack(side="left")
            ctk.CTkLabel(top, text=f"−{item['deduction']}",
                font=ctk.CTkFont(size=_fs(10), weight="bold"),
                text_color=C["danger"]).pack(side="right")
            ctk.CTkLabel(r, text=item["reason"],
                font=ctk.CTkFont(size=_fs(9)),
                text_color=C["text_dim"], anchor="w", justify="left",
                wraplength=180).pack(fill="x", padx=8, pady=(0,6))

    def _refresh_dash_extras(self, m3):
        try:
            for w in self._dash_cve.winfo_children(): w.destroy()
        except Exception: pass
        try:
            for w in self._dash_fix.winfo_children(): w.destroy()
        except Exception: pass

    # ══════════════════════════════════════════════════════════════════════════
    # DEVICES TAB REFRESH
    # ══════════════════════════════════════════════════════════════════════════

    def _refresh_devices(self):
        if "devices" not in self._tabs: return
        for w in self._dev_scroll.winfo_children(): w.destroy()
        if not self._last_m2:
            ctk.CTkLabel(self._dev_scroll, text="Run a scan.",
                font=ctk.CTkFont(size=_fs(12)), text_color=C["text_faint"]).pack(pady=40)
            return
        filt  = self._dev_filter_var.get()
        shown = [d for d in self._last_m2
                 if filt=="All" or d.get("risk")==filt]
        self._dev_count_lbl.configure(
            text=f"{len(shown)} of {len(self._last_m2)} devices")

        for d in shown:
            risk = d.get("risk","Safe"); rcol = RISK_COLORS.get(risk, C["text_faint"])
            if self._last_m4:
                for m4d in self._last_m4:
                    if m4d["ip"]==d["ip"] and m4d.get("verdict")=="COMPROMISED":
                        risk="COMPROMISED"; rcol=C["crit_r"]; break

            label   = d.get("label","")
            name    = display_name(d)
            devtype = d.get("device_type","Unknown Device")
            ports   = d.get("open_ports",[])

            row = ctk.CTkFrame(self._dev_scroll,
                fg_color=C["surface"], corner_radius=10,
                border_width=1, border_color=C["border"])
            row.pack(fill="x", pady=4)
            row.grid_columnconfigure(1, weight=1)

            # Left accent line based on risk
            stripe = ctk.CTkFrame(row, width=4, fg_color=rcol, corner_radius=2)
            stripe.grid(row=0, column=0, rowspan=2, padx=(0,0), pady=0, sticky="ns")

            # Risk badge
            ctk.CTkLabel(row, text=f" {risk} ",
                font=ctk.CTkFont(size=_fs(10), weight="bold"),
                fg_color=rcol, text_color="white",
                corner_radius=4
            ).grid(row=0, column=1, padx=(10,6), pady=(10,2), sticky="w")

            # IP + label
            ip_row = ctk.CTkFrame(row, fg_color="transparent"); ip_row.grid(row=0, column=2, padx=4, pady=(10,2), sticky="w")
            ctk.CTkLabel(ip_row, text=d["ip"],
                font=ctk.CTkFont(size=_fs(13), weight="bold"),
                text_color=C["text"]).pack(side="left")
            if label:
                ctk.CTkLabel(ip_row, text=f" 📌 {label} ",
                    font=ctk.CTkFont(size=_fs(10)),
                    fg_color=C["success_bg"], text_color=C["success"],
                    corner_radius=4).pack(side="left", padx=6)

            # Vendor · type
            ctk.CTkLabel(row, text=f"{name}  ·  {devtype}",
                font=ctk.CTkFont(size=_fs(10)), text_color=C["text_faint"],
                anchor="w", wraplength=200
            ).grid(row=1, column=2, padx=4, pady=(0,10), sticky="w")

            # Port chips
            pc = ctk.CTkFrame(row, fg_color="transparent")
            pc.grid(row=0, column=3, rowspan=2, padx=8, sticky="e")
            try:
                from module1 import get_port_name
                for p in ports[:5]:
                    ctk.CTkLabel(pc, text=f" {p}/{get_port_name(p)} ",
                        font=ctk.CTkFont(size=_fs(9)),
                        fg_color=C["accent_pale"], text_color=C["accent"],
                        corner_radius=4).pack(side="left", padx=2)
            except ImportError: pass
            if not ports:
                ctk.CTkLabel(pc, text="No open ports",
                    font=ctk.CTkFont(size=_fs(10)),
                    text_color=C["text_faint"]).pack()

            # Label button
            ctk.CTkButton(row,
                text="📌 Label" if not label else "✏ Rename",
                font=ctk.CTkFont(size=_fs(10), weight="bold"),
                fg_color=C["success_bg"], hover_color=C["border"],
                text_color=C["success"], border_width=1,
                border_color=C["success"], corner_radius=6,
                height=28, width=82,
                command=lambda dev=d: self._rename_device_dialog(dev)
            ).grid(row=0, column=4, rowspan=2, padx=(4,12), pady=10)

    def _rename_device_dialog(self, device: dict):
        mac=device.get("mac",""); ip=device.get("ip","")
        current=device.get("label", get_label(mac))
        dlg = ctk.CTkToplevel(self)
        dlg.title("Label Device"); dlg.geometry("420x230")
        dlg.configure(fg_color=C["surface"]); dlg.resizable(False,False); dlg.grab_set()
        ctk.CTkLabel(dlg, text="Label This Device",
            font=ctk.CTkFont(size=_fs(16), weight="bold"), text_color=C["text"]).pack(pady=(22,4))
        ctk.CTkLabel(dlg, text=f"{ip}  ·  {mac}",
            font=ctk.CTkFont(size=_fs(10)), text_color=C["text_faint"]).pack()
        entry = ctk.CTkEntry(dlg, width=320, height=_fs(40),
            placeholder_text='"e.g. Dad\'s Laptop, Front Camera"',
            fg_color=C["surface2"], border_color=C["accent"],
            text_color=C["text"], font=ctk.CTkFont(size=_fs(12)))
        entry.pack(pady=14)
        if current: entry.insert(0, current)
        entry.focus()
        def _save():
            nl = entry.get().strip(); set_label(mac, nl)
            device["label"] = nl
            for d in self._last_m2:
                if d.get("mac","").upper() == mac.upper(): d["label"] = nl
            dlg.destroy(); self._refresh_devices()
            self._log.append(f"[OK] {ip} labelled: '{nl}'" if nl else f"[OK] Label removed from {ip}")
        def _clear():
            entry.delete(0,"end"); _save()
        br = ctk.CTkFrame(dlg, fg_color="transparent"); br.pack(fill="x", padx=40)
        ctk.CTkButton(br, text="💾  Save",
            font=ctk.CTkFont(size=_fs(12), weight="bold"),
            fg_color=C["accent"], hover_color=C["accent2"],
            corner_radius=8, height=_fs(36),
            command=_save).pack(side="left", expand=True, fill="x", padx=(0,6))
        ctk.CTkButton(br, text="✕  Clear Label",
            fg_color=C["surface2"], hover_color=C["border2"],
            text_color=C["text_dim"], corner_radius=8, height=_fs(36),
            command=_clear).pack(side="left", expand=True, fill="x")
        entry.bind("<Return>", lambda e: _save())

    # ══════════════════════════════════════════════════════════════════════════
    # CVE TAB REFRESH
    # ══════════════════════════════════════════════════════════════════════════

    def _refresh_cves(self):
        if "cves" not in self._tabs: return
        for w in self._cve_inner.winfo_children(): w.destroy()
        if not self._last_m3:
            tk.Label(self._cve_inner, text="Run a scan to see CVE results.",
                font=("Helvetica",12), fg=C["text_faint"],
                bg=C["surface"]).pack(pady=60); return
        cve_results = self._last_m3.get("cve_results",{})
        devices     = self._last_m3.get("devices", self._last_m2)
        total = sum(len(cve_results.get(d["ip"],[]))for d in devices)
        if hasattr(self,"_cve_count_lbl"):
            self._cve_count_lbl.configure(
                text=f"{total} vulnerabilities across {len(devices)} device(s)")
        cvss_ranges = {"CRITICAL":"9.0–10.0","HIGH":"7.0–8.9","MEDIUM":"4.0–6.9","LOW":"0.1–3.9"}
        for device in devices:
            ip=device["ip"]; cves=cve_results.get(ip,[])
            vendor=device.get("vendor_api",device.get("vendor","Unknown"))[:40]
            sec = tk.Frame(self._cve_inner, bg=C["surface2"],
                relief="flat", bd=0)
            sec.pack(fill="x", padx=8, pady=6)
            # Header
            hdr_f = tk.Frame(sec, bg=C["surface2"]); hdr_f.pack(fill="x", padx=12, pady=(10,4))
            tk.Label(hdr_f, text=f"{ip}  —  {vendor}",
                font=("Helvetica", _fs(12), "bold"),
                fg=C["text"], bg=C["surface2"]).pack(side="left")
            nc=sum(1 for c in cves if c.get("severity")=="CRITICAL")
            nh=sum(1 for c in cves if c.get("severity")=="HIGH")
            agg_txt = (f"{len(cves)} CVE(s)  ·  {nc} CRITICAL" if nc else
                       f"{len(cves)} CVE(s)  ·  {nh} HIGH" if nh else
                       f"{len(cves)} CVE(s)" if cves else "No CVEs found")
            agg_col = (C["crit_r"] if nc else C["high"] if nh else
                       C["warning"] if cves else C["success"])
            tk.Label(hdr_f, text=agg_txt,
                font=("Helvetica", _fs(10), "bold"),
                fg=agg_col, bg=C["surface2"]).pack(side="right")
            if not cves:
                tk.Label(sec, text="  No known CVEs found",
                    font=("Helvetica",_fs(11)), fg=C["success"], bg=C["surface2"]
                ).pack(anchor="w", padx=14, pady=(0,10)); continue
            for cve in cves:
                cid=cve.get("id","?"); sev=cve.get("severity","N/A")
                desc=cve.get("description",""); col=SEV_COLORS.get(sev,C["text_faint"])
                cvss=cvss_ranges.get(sev,"N/A")
                cr = tk.Frame(sec, bg=C["bg"], bd=0); cr.pack(fill="x",padx=10,pady=2)
                # CVE ID link
                cid_lbl = tk.Label(cr, text=cid,
                    font=("Helvetica",_fs(11),"bold"), fg=C["accent"],
                    bg=C["bg"], cursor="hand2")
                cid_lbl.pack(side="left", padx=(8,4), pady=6)
                cid_lbl.bind("<Button-1>", lambda e,c=cid:
                    webbrowser.open(f"https://nvd.nist.gov/vuln/detail/{c}"))
                # Severity badge
                tk.Label(cr, text=f" {sev} ",
                    font=("Helvetica",_fs(10),"bold"),
                    fg="white", bg=col).pack(side="left", padx=4)
                tk.Label(cr, text=f"CVSS {cvss}",
                    font=("Helvetica",_fs(10),"bold"),
                    fg=col, bg=C["bg"]).pack(side="left", padx=4)
                tk.Label(cr, text=desc[:100]+(""  if len(desc)<=100 else "…"),
                    font=("Helvetica",_fs(10)), fg=C["text_faint"],
                    bg=C["bg"], anchor="w").pack(side="left", padx=6, fill="x")
            tk.Frame(sec, bg=C["surface2"], height=4).pack()
        self._cve_canvas.yview_moveto(0)

    # ══════════════════════════════════════════════════════════════════════════
    # CVE SCORE TAB REFRESH
    # ══════════════════════════════════════════════════════════════════════════

    def _refresh_cve_score(self, m8: dict):
        if "cve_score" not in self._tabs: return
        if not m8:
            for w in self._m8_table.winfo_children(): w.destroy()
            ctk.CTkLabel(self._m8_table, text="Run a scan to see CVE scores.",
                font=ctk.CTkFont(size=_fs(11)), text_color=C["text_faint"]).pack(pady=30)
            return
        ns=m8.get("network_score",0); ng=m8.get("network_grade","—")
        ngc=m8.get("network_grade_color",C["text_faint"])
        st=m8.get("severity_totals",{}); tc=m8.get("total_cves",0)
        self._m8_net_score.update(f"{ns}/100", sub=ng, color=ngc)
        self._m8_total.update(tc, sub="across all devices")
        self._m8_critical.update(st.get("CRITICAL",0),
            color=C["crit_r"] if st.get("CRITICAL") else C["success"])
        self._m8_high.update(st.get("HIGH",0),
            color=C["high"] if st.get("HIGH") else C["success"])
        self._m8_grade_lbl.configure(text=ng, text_color=ngc)
        for w in self._m8_table.winfo_children(): w.destroy()
        per_device = m8.get("per_device",{})
        if not per_device:
            ctk.CTkLabel(self._m8_table, text="No data.",
                font=ctk.CTkFont(size=_fs(11)), text_color=C["text_faint"]).pack(pady=20)
            return
        sorted_devs = sorted(per_device.items(),
            key=lambda x:x[1].get("score",0), reverse=True)
        for ip,ds in sorted_devs:
            vendor="Unknown"
            for d in self._last_m2:
                if d["ip"]==ip:
                    vendor=d.get("vendor_api",d.get("vendor","Unknown"))[:22]; break
            score=ds.get("score",0); grade=ds.get("grade","—")
            gcol=ds.get("grade_color",C["text_faint"]); worst=ds.get("worst_severity","N/A")
            wcol=SEV_COLORS.get(worst,C["text_faint"]); cvss_m=ds.get("cvss_midpoint",0.0)
            counts=ds.get("counts",{})
            row = ctk.CTkFrame(self._m8_table,
                fg_color=C["surface2"], corner_radius=6); row.pack(fill="x", pady=3)
            for txt,w,col,weight in [
                (ip,140,C["text"],"bold"),(vendor,180,C["text_dim"],"normal"),
                (f"{score}/100",90,gcol,"bold"),(grade,160,gcol,"normal"),
                (worst,90,wcol,"bold"),(f"{cvss_m:.1f}",110,wcol,"normal"),
                (str(counts.get("CRITICAL",0)),40,C["crit_r"],"bold"),
                (str(counts.get("HIGH",0)),40,C["high"],"normal"),
                (str(counts.get("MEDIUM",0)),40,C["warning"],"normal"),
                (str(counts.get("total",0)),50,C["text_faint"],"normal"),
            ]:
                ctk.CTkLabel(row, text=txt,
                    font=ctk.CTkFont(size=_fs(11), weight=weight),
                    text_color=col, width=w, anchor="w"
                ).pack(side="left", padx=6, pady=7)

    # ══════════════════════════════════════════════════════════════════════════
    # RED TEAM REFRESH
    # ══════════════════════════════════════════════════════════════════════════

    def _refresh_redteam(self):
        if "redteam" not in self._tabs: return
        for w in self._rt_scroll.winfo_children(): w.destroy()
        if not self._last_m4:
            ctk.CTkLabel(self._rt_scroll,
                text="Red team results appear here after a full scan.",
                font=ctk.CTkFont(size=_fs(12)), text_color=C["text_faint"]).pack(pady=40)
            return
        for device in self._last_m4:
            verdict=device.get("verdict","SKIPPED"); vcol=RISK_COLORS.get(verdict,C["text_faint"])
            tests=device.get("tests",{}); vendor=device.get("vendor",device.get("vendor_api","Unknown"))
            card = ctk.CTkFrame(self._rt_scroll,
                fg_color=C["surface"], corner_radius=10,
                border_width=1, border_color=C["border"])
            card.pack(fill="x", padx=4, pady=6)
            hdr = ctk.CTkFrame(card, fg_color=C["surface2"], corner_radius=0)
            hdr.pack(fill="x")
            ctk.CTkLabel(hdr, text=f"  {device['ip']}  —  {vendor}",
                font=ctk.CTkFont(size=_fs(13), weight="bold"),
                text_color=C["text"]).pack(side="left", padx=10, pady=10)
            ctk.CTkLabel(hdr, text=f"  {verdict}  ",
                font=ctk.CTkFont(size=_fs(11), weight="bold"),
                fg_color=vcol, text_color="white",
                corner_radius=4).pack(side="right", padx=10, pady=10)
            for test_name, result in tests.items():
                if not isinstance(result, dict): continue
                tr = ctk.CTkFrame(card, fg_color="transparent"); tr.pack(fill="x", padx=10, pady=2)
                passed=result.get("success",False); col=C["danger"] if passed else C["success"]
                ctk.CTkLabel(tr, text=f"  {'✓' if passed else '✗'}  {test_name}",
                    font=ctk.CTkFont(size=_fs(11)), text_color=col).pack(side="left",padx=8,pady=6)
                detail=result.get("detail",result.get("message",""))
                if detail:
                    ctk.CTkLabel(tr, text=str(detail)[:80],
                        font=ctk.CTkFont(size=_fs(10)),
                        text_color=C["text_faint"], anchor="w").pack(side="left", padx=4)
            ctk.CTkFrame(card, height=4, fg_color="transparent").pack()

    # ══════════════════════════════════════════════════════════════════════════
    # HISTORY REFRESH
    # ══════════════════════════════════════════════════════════════════════════

    def _refresh_history(self):
        for w in self._hist_scroll.winfo_children(): w.destroy()
        try:
            import module6; module6.init_db()
            history = module6.get_scan_history(limit=100)
        except Exception as e:
            ctk.CTkLabel(self._hist_scroll, text=f"Error: {e}",
                text_color=C["danger"]).pack(pady=20); return
        if not history:
            ctk.CTkLabel(self._hist_scroll, text="No scans recorded yet.",
                font=ctk.CTkFont(size=_fs(12)), text_color=C["text_faint"]).pack(pady=40)
            return
        ssid_map = load_ssid_map()
        for scan in history:
            sid=scan["id"]; ssid=ssid_map.get(str(sid),"—")
            score=scan["score"]; scol=self._score_color(score)
            row = ctk.CTkFrame(self._hist_scroll,
                fg_color=C["surface"], corner_radius=8,
                border_width=1, border_color=C["border"])
            row.pack(fill="x", pady=3)
            for txt,w,col,weight in [
                (str(sid),40,C["text_faint"],"normal"),
                (ssid[:18],140,C["text_dim"],"normal"),
                (scan["timestamp"][:16],160,C["text"],"normal"),
                (scan.get("gateway","—")[:16],120,C["text_dim"],"normal"),
                (scan["ip_range"][:18],150,C["text_dim"],"normal"),
                (str(score),70,scol,"bold"),
                (scan["score_label"],100,scol,"normal"),
                (str(scan["device_count"]),70,C["text_faint"],"normal"),
            ]:
                ctk.CTkLabel(row, text=txt,
                    font=ctk.CTkFont(size=_fs(11), weight=weight),
                    text_color=col, width=w, anchor="w"
                ).pack(side="left", padx=8, pady=8)

    # ══════════════════════════════════════════════════════════════════════════
    # SECURE DEVICE LOGIC
    # ══════════════════════════════════════════════════════════════════════════

    def _update_secure_compromised_menu(self):
        if "secure" not in self._tabs or not hasattr(self,"_secure_device_menu"): return
        compromised = []
        if self._last_m4:
            for entry in self._last_m4:
                if entry.get("verdict")=="COMPROMISED":
                    ip=entry.get("ip",""); vendor=entry.get("vendor","Unknown")[:22]
                    tests=entry.get("tests",{}); rtsp=tests.get("rtsp",{}).get("stream_url","")
                    label=f"{ip}  —  {vendor}" + (f"  —  {rtsp}" if rtsp else "")
                    compromised.append((label,ip,entry))
        if compromised:
            opts=[c[0] for c in compromised]
            self._secure_device_menu.configure(values=opts)
            self._secure_device_var.set(opts[0])
            self._sec_badge.configure(text="  COMPROMISED  ", fg_color=C["crit_r"])
            self._sec_hint.configure(text=f"{len(opts)} compromised device(s)", text_color=C["danger"])
        else:
            self._secure_device_menu.configure(values=["No compromised devices found"])
            self._secure_device_var.set("No compromised devices found")
            self._sec_badge.configure(text="", fg_color=C["surface2"])
            if self._last_m4 is not None:
                self._sec_hint.configure(text="Red team complete — no devices compromised ✓",
                    text_color=C["success"])
            else:
                self._sec_hint.configure(text="Only COMPROMISED devices appear here",
                    text_color=C["text_faint"])

    def _get_selected_secure_ip(self):
        val = self._secure_device_var.get()
        if not val or "No compromised" in val: return None
        return val.split("—")[0].strip()

    def _secure_device_action(self):
        ip = self._get_selected_secure_ip()
        if not ip:
            messagebox.showwarning("No Device","No compromised device selected.\nRun a full scan first.")
            return
        def _worker():
            try:
                self._q.put(("secure_log",f"[*] Securing device: {ip}"))
                self._q.put(("secure_log","    Killing VLC and streaming apps..."))
                try:
                    import secure_device as sd; procs=sd.kill_camera_processes(dry_run=False)
                    killed=[p["name"] for p in procs if p.get("killed")]
                    self._q.put(("secure_log",
                        f"    Killed: {', '.join(killed)}" if killed else "    No streaming apps running."))
                except Exception as ke:
                    self._q.put(("secure_log",f"    [!] Kill step skipped: {ke}"))
                for rule_name, direction, flags in [
                    ("Block Camera RTSP Out","out","dir=out remoteip={ip} remoteport=554"),
                    ("Block Camera RTSP In", "in", "dir=in remoteip={ip} localport=554"),
                ]:
                    cmd = (f'netsh advfirewall firewall add rule '
                           f'name="{rule_name}" protocol=TCP '
                           f'{flags.format(ip=ip)} action=block')
                    self._q.put(("secure_log",f"    {cmd}"))
                    r = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                        creationflags=_NO_WINDOW)
                    self._q.put(("secure_log",
                        f"    [OK] Rule added: {rule_name}" if r.returncode==0
                        else f"    [X] Failed: {r.stderr.strip()[:60]}"))
                self._q.put(("secure_log",f"[✓] {ip} secured — RTSP blocked on port 554."))
                self._q.put(("secure_status",{"is_locked":True,
                    "privacy_state":f"RTSP blocked for {ip}",
                    "fw_rules":["Block Camera RTSP Out","Block Camera RTSP In"],
                    "blocked_ips":[ip]}))
            except Exception as e:
                self._q.put(("secure_log",f"[X] Error: {e}"))
        threading.Thread(target=_worker, daemon=True).start()

    def _unblock_device_action(self):
        ip = self._get_selected_secure_ip()
        def _worker():
            try:
                self._q.put(("secure_log","[*] Removing RTSP firewall rules..."))
                for name in ["Block Camera RTSP Out","Block Camera RTSP In"]:
                    cmd=f'netsh advfirewall firewall delete rule name="{name}"'
                    r=subprocess.run(cmd, shell=True, capture_output=True, text=True,
                        creationflags=_NO_WINDOW)
                    self._q.put(("secure_log",
                        f"    [OK] Removed: {name}" if r.returncode==0 else f"    [!] Not found: {name}"))
                if ip:
                    subprocess.run(
                        f'netsh advfirewall firewall delete rule name=all remoteip={ip}',
                        shell=True, capture_output=True, creationflags=_NO_WINDOW)
                    self._q.put(("secure_log",f"    Cleaned remaining rules for {ip}."))
                self._q.put(("secure_log","[✓] Device unblocked — RTSP access restored."))
                self._q.put(("secure_status",{"is_locked":False,
                    "privacy_state":"None active","fw_rules":[],"blocked_ips":[]}))
            except Exception as e:
                self._q.put(("secure_log",f"[X] Unblock error: {e}"))
        threading.Thread(target=_worker, daemon=True).start()

    def _update_secure_status_ui(self, state: dict):
        if state.get("is_locked") or state.get("blocked_ips"):
            locked_ips=state.get("blocked_ips",[])
            self._sec_dot.configure(text="✕", text_color=C["danger"])
            self._sec_banner.configure(border_color=C["danger"])
            self._sec_status_lbl.configure(text=f"{len(locked_ips)} device(s) isolated",text_color=C["danger"])
            self._sec_fw_lbl.configure(text="Firewall isolation active")
            if hasattr(self,"_sec_isolate_btn"):
                self._sec_isolate_btn.configure(state="disabled", fg_color=C["border2"])
                self._sec_restore_btn.configure(fg_color=C["success"],hover_color="#047857",text_color="white")
        else:
            self._sec_dot.configure(text="✓", text_color=C["success"])
            self._sec_banner.configure(border_color=C["border"])
            self._sec_status_lbl.configure(text="All devices accessible", text_color=C["success"])
            self._sec_fw_lbl.configure(text="No isolation rules active")
            if hasattr(self,"_sec_isolate_btn"):
                self._sec_isolate_btn.configure(state="normal", fg_color=C["danger"])
                self._sec_restore_btn.configure(fg_color=C["surface2"],hover_color=C["border2"],text_color=C["text"])

    # Legacy stubs
    def _refresh_secure_status(self): pass
    def _quick_block_rtsp(self): pass
    def _quick_unblock_rtsp(self): pass
    def _refresh_blocked_list(self): pass
    def _unblock_device(self, ip): pass
    def _secure_action(self, action): pass
    def _update_cmd_preview(self): pass

    # ══════════════════════════════════════════════════════════════════════════
    # TRAFFIC MONITOR
    # ══════════════════════════════════════════════════════════════════════════

    def _toggle_traffic(self):
        if not self._traffic_running: self._start_traffic()
        else: self._stop_traffic()

    def _start_traffic(self):
        self._traffic_running = True
        self._traffic_btn.configure(text="■  Stop Monitor",
            fg_color=C["danger"], hover_color=C["critical"])
        self._status("Traffic monitor running")
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        sep = f"── Session started {ts} " + "─"*30
        self._packet_feed._text.configure(state="normal")
        self._packet_feed._text.insert("end", sep+"\n", "sep")
        self._packet_feed._text.configure(state="disabled")
        self._packet_feed._text.see("end")
        self._traffic_packets.append(sep)
        self._traffic_log.append(f"[*] Traffic monitor started — {ts}")
        self._traffic_status_lbl.configure(text=f"● LIVE  —  started {ts}",
            text_color=C["success"])
        def _worker():
            orig=sys.stdout; sys.stdout=QueueWriter(self._q)
            try:
                import traffic_monitor as tm; tm._running=True
                tm._stats["start_time"]=time.time()
                tm._stats["packets_seen"]=0; tm._stats["alerts_fired"]=0
                tm._stats["blocked_ips"]=set()
                def _on_alert(attack_type,src_ip,detail,ts_inner):
                    self._q.put(("traffic_alert",{"type":attack_type,"src":src_ip,"detail":detail,"ts":ts_inner}))
                def _on_packet(pkt_info):
                    self._q.put(("traffic_packet",pkt_info))
                tm.start_monitor(auto_block=self._auto_block_switch.get(),
                    stats_interval=5,alert_callback=_on_alert,
                    packet_callback=_on_packet,blocking=True)
            except Exception as e:
                self._q.put(("log",f"Traffic monitor error: {e}"))
            finally:
                sys.stdout=orig
        threading.Thread(target=_worker, daemon=True).start()
        self._update_traffic_stats()

    def _stop_traffic(self):
        self._traffic_running = False
        self._traffic_btn.configure(text="▶  Start Monitor",
            fg_color=C["success"], hover_color="#047857")
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._traffic_log.append(f"[*] Traffic monitor stopped — {ts}")
        self._traffic_status_lbl.configure(
            text=f"■ STOPPED  —  {ts}  (feed preserved)",
            text_color=C["text_faint"])
        try:
            import traffic_monitor as tm; tm.stop_monitor()
        except Exception: pass

    def _toggle_feed_pause(self):
        self._feed_paused = not self._feed_paused
        if self._feed_paused:
            self._pause_btn.configure(text="▶  Resume Feed",
                fg_color=C["accent"], hover_color=C["accent2"], text_color="white")
            self._traffic_status_lbl.configure(
                text="⏸ PAUSED  —  packets still captured",
                text_color=C["warning"])
        else:
            self._pause_btn.configure(text="⏸  Pause Feed",
                fg_color=C["surface2"], hover_color=C["border2"], text_color=C["text"])
            ts=datetime.datetime.now().strftime("%H:%M:%S")
            self._traffic_status_lbl.configure(text=f"● LIVE  —  resumed {ts}",
                text_color=C["success"])

    def _update_traffic_stats(self):
        if not self._traffic_running: return
        try:
            import traffic_monitor as tm
            with tm._lock:
                pkts=tm._stats["packets_seen"]; alerts=tm._stats["alerts_fired"]
                blocked=len(tm._stats["blocked_ips"])
                elapsed=time.time()-(tm._stats["start_time"] or time.time())
            rate=round(pkts/max(elapsed,1),1)
            self._tc["packets"].update(f"{pkts:,}")
            self._tc["alerts"].update(str(alerts))
            self._tc["blocked"].update(str(blocked))
            self._tc["rate"].update(f"{rate}/s")
            counts=tm.get_proto_counts()
            for proto,lbl in self._proto_labels.items():
                lbl.configure(text=f"{counts.get(proto,0):,}")
        except Exception: pass
        self.after(2000, self._update_traffic_stats)

    def _export_traffic(self):
        if not self._traffic_packets and not self._traffic_alerts:
            messagebox.showinfo("Nothing to Save",
                "No traffic captured yet. Start the monitor first."); return
        ts=datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path=filedialog.asksaveasfilename(defaultextension=".txt",
            filetypes=[("Text file","*.txt"),("CSV file","*.csv")],
            initialfile=f"traffic_capture_{ts}.txt")
        if not path: return
        try:
            with open(path,"w",encoding="utf-8") as f:
                f.write(f"NetProbe Traffic Capture\n")
                f.write(f"Exported: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}\n")
                f.write("="*70+"\n\n")
                if self._traffic_alerts:
                    f.write(f"ATTACK ALERTS ({len(self._traffic_alerts)})\n"+"-"*40+"\n")
                    for a in self._traffic_alerts: f.write(a+"\n")
                    f.write("\n")
                f.write(f"PACKET FEED ({len(self._traffic_packets):,} entries)\n"+"-"*40+"\n")
                for p in self._traffic_packets: f.write(p+"\n")
            messagebox.showinfo("Saved",f"Traffic log saved to:\n{path}")
            try: os.startfile(os.path.dirname(path))
            except Exception: pass
        except Exception as e:
            messagebox.showerror("Save Failed", str(e))

    def _clear_traffic_feed(self):
        self._traffic_packets=[]; self._traffic_alerts=[]
        self._packet_feed.clear(); self._traffic_log.clear()
        if hasattr(self,"_feed_count_lbl"):
            self._feed_count_lbl.configure(text="0 packets")
        if hasattr(self,"_alert_count_lbl"):
            self._alert_count_lbl.configure(text="0 alerts")
        ts=datetime.datetime.now().strftime("%H:%M:%S")
        self._traffic_status_lbl.configure(text=f"Feed cleared at {ts}",
            text_color=C["text_faint"])

    # ══════════════════════════════════════════════════════════════════════════
    # PDF REPORT
    # ══════════════════════════════════════════════════════════════════════════

    def _generate_pdf(self):
        if not self._last_m2:
            messagebox.showwarning("No Data","Run a scan first."); return
        self._pdf_btn.configure(state="disabled", text="⏳  Generating...")
        self._report_log.clear()
        self._report_log.append("[*] Starting PDF generation...")
        # Gather metadata from UI fields (if report tab is built)
        org    = getattr(self, "_rpt_org_name",    None)
        analyst= getattr(self, "_rpt_analyst",     None)
        folder = getattr(self, "_rpt_save_folder", None)
        save_dir = (folder.get().strip() if folder and folder.get().strip() else _DIR)
        org_name = org.get().strip() if org else ""
        analyst_name = analyst.get().strip() if analyst else ""
        def _worker():
            orig=sys.stdout; sys.stdout=QueueWriter(self._q)
            try:
                import module5
                path=module5.run_module5(
                    self._last_gateway, self._last_ip_range,
                    self._last_m2, self._last_m3, self._last_m4,
                    # Pass extras only if module5 accepts them (graceful)
                )
                self._q.put(("pdf_done", path))
            except Exception as e:
                self._q.put(("pdf_error", str(e)))
            finally:
                sys.stdout=orig
        threading.Thread(target=_worker, daemon=True).start()

    # ══════════════════════════════════════════════════════════════════════════
    # CSV EXPORT
    # ══════════════════════════════════════════════════════════════════════════

    def _export_csv(self):
        try:
            import module6; module6.init_db()
            history=module6.get_scan_history(limit=200)
        except Exception as e:
            messagebox.showerror("Error",str(e)); return
        if not history:
            messagebox.showinfo("No Data","No scan history to export."); return
        path=filedialog.asksaveasfilename(defaultextension=".csv",
            filetypes=[("CSV files","*.csv")],
            initialfile=f"iot_export_{datetime.datetime.now():%Y%m%d_%H%M%S}.csv")
        if not path: return
        ssid_map=load_ssid_map()
        try:
            with open(path,"w",newline="",encoding="utf-8") as f:
                w=csv.writer(f)
                w.writerow(["ID","WiFi","Timestamp","Gateway","Range","Score","Label","Devices"])
                for s in history:
                    w.writerow([s["id"],ssid_map.get(str(s["id"]),"—"),
                        s["timestamp"],s.get("gateway",""),s["ip_range"],
                        s["score"],s["score_label"],s["device_count"]])
            messagebox.showinfo("Exported",f"Saved to:\n{path}")
            try: os.startfile(os.path.dirname(path))
            except Exception: pass
        except Exception as e:
            messagebox.showerror("Export Failed",str(e))

    # ══════════════════════════════════════════════════════════════════════════
    # WATCH MODE  (Module 7)
    # ══════════════════════════════════════════════════════════════════════════

    def _toggle_watch_mode(self):
        if self._autoscan_switch.get(): self._start_watch_mode()
        else: self._stop_watch_mode()

    def _get_watch_interval_seconds(self) -> int:
        return {"2 min":120,"5 min":300,"15 min":900,
                "30 min":1800,"1 hour":3600}.get(
            self._autoscan_interval.get(), 300)

    def _start_watch_mode(self):
        if self._scan_running:
            messagebox.showwarning("Scan Running",
                "Please wait for the current scan to finish\nbefore starting Watch Mode.")
            self._autoscan_switch.deselect(); return
        try:
            import module7
        except ImportError:
            self._log.append("[!] Watch Mode unavailable — please reinstall.")
            self._autoscan_switch.deselect(); return
        interval=self._get_watch_interval_seconds()
        orig_fn=module7._print_watch_alert
        def _gui_hook(diff, m3, scan_num):
            if diff and diff.get("has_changes"):
                self._q.put(("log",f"[*] Watch Mode — Scan #{scan_num} detected changes"))
                for d in diff.get("new_devices",[]):
                    self._q.put(("log",f"  [NEW]  {d['ip']}  Risk: {d['risk']}"))
                for d in diff.get("missing_devices",[]):
                    self._q.put(("log",f"  [GONE] {d['ip']}"))
                for c in diff.get("changed_ports",[]):
                    self._q.put(("log",f"  [PORT] {c['ip']}  +{c.get('added_ports',[])}"))
                for r in diff.get("risk_changes",[]):
                    self._q.put(("log",f"  [RISK] {r['ip']}  {r['old_risk']} → {r['new_risk']}"))
                self._q.put(("watch_alert",diff))
            else:
                self._q.put(("log",f"[*] Watch Mode — Scan #{scan_num} complete, no changes"))
        module7._print_watch_alert = _gui_hook
        self._watcher=module7.WatchMode(interval=interval,
            email_alerts=bool(self._alert_cfg.get("email_verified")))
        self._watcher._gui_scan_running = lambda: self._scan_running
        self._watcher.start(); self._autoscan_running=True
        ivl=self._autoscan_interval.get()
        self._autoscan_lbl.configure(text=f"● Watching every {ivl}",text_color=C["success"])
        self._log.append(f"[OK] Watch Mode started — checking every {ivl}")
        self._watch_mode_poll()

    def _stop_watch_mode(self):
        if self._watcher:
            try:
                if self._watcher.is_running():
                    self._watcher.stop(); self._log.append("[*] Watch Mode stopped.")
            except Exception: pass
        self._watcher=None; self._autoscan_running=False
        self._autoscan_lbl.configure(text="Monitors for changes",text_color=C["s_text_d"])
        if self._autoscan_after_id:
            self.after_cancel(self._autoscan_after_id); self._autoscan_after_id=None

    def _watch_mode_poll(self):
        if not self._autoscan_running or not self._watcher: return
        if self._watcher.is_running():
            n=self._watcher._scan_num
            self._autoscan_lbl.configure(
                text=f"● Watching  |  {n} scan(s) done", text_color=C["success"])
        self._autoscan_after_id=self.after(5000, self._watch_mode_poll)

    # Legacy stubs
    def _toggle_autoscan(self): self._toggle_watch_mode()
    def _get_autoscan_ms(self): return self._get_watch_interval_seconds()*1000
    def _schedule_next_autoscan(self): pass
    def _run_autoscan(self): pass

    # ══════════════════════════════════════════════════════════════════════════
    # ALERTS
    # ══════════════════════════════════════════════════════════════════════════

    def _rerun_email_wizard(self):
        EmailSetupWizard(self, on_complete=self._on_wizard_complete)

    def _on_wizard_complete(self, cfg):
        self._alert_cfg = cfg
        if "alerts" in self._tabs:
            self._tabs["alerts"].destroy(); del self._tabs["alerts"]
        if self._current_tab == "alerts":
            self._switch_tab("alerts")
        self._log.append("[OK] Email verified and connected.")

    def _save_alert_triggers(self):
        try: t=int(self._al_threshold.get() or 60)
        except ValueError: t=60
        self._alert_cfg["alert_new_device"]      = bool(self._al_new_device.get())
        self._alert_cfg["alert_score_drop"]      = bool(self._al_score_drop.get())
        self._alert_cfg["alert_score_threshold"] = t
        self._alert_cfg["alert_traffic"]         = bool(self._al_traffic.get())
        # New fields (guard with hasattr for sessions where alerts tab was not built yet)
        if hasattr(self, "_al_critical_risk"):
            self._alert_cfg["alert_critical_risk"] = bool(self._al_critical_risk.get())
        if hasattr(self, "_al_redteam_comp"):
            self._alert_cfg["alert_redteam_comp"]  = bool(self._al_redteam_comp.get())
        if hasattr(self, "_al_toast"):
            self._alert_cfg["toast_enabled"]       = bool(self._al_toast.get())
        if hasattr(self, "_al_email_on_scan"):
            self._alert_cfg["email_on_scan"]       = bool(self._al_email_on_scan.get())
        save_alert_settings(self._alert_cfg)
        self._log_alert("Alert preferences saved.")
        messagebox.showinfo("Saved", "Alert preferences saved.")

    def _send_test_email(self):
        if hasattr(self,"_al_test_lbl"):
            self._al_test_lbl.configure(text="Sending...", text_color=C["text_faint"])
        def _worker():
            ok,msg=self._do_send_email("IoT Scanner — Test Alert",
                "This is a test. Email alerts are working.")
            self._q.put(("test_email_result",(ok,msg)))
        threading.Thread(target=_worker, daemon=True).start()

    def _do_send_email(self, subject, body):
        to=self._alert_cfg.get("smtp_to","")
        if not to: return False,"No recipient — complete setup first"
        try:
            import mailer; return mailer.send_email(to,subject,f"<pre>{body}</pre>",body)
        except ImportError: return False,"mailer.py not found"
        except Exception as e: return False,str(e)

    def _check_device_changes(self, diff):
        if not diff or not diff.get("has_changes"): return
        new_devs=diff.get("new_devices",[])
        self._log.separator(); self._log.append("🔔  NETWORK CHANGE DETECTED")
        for d in new_devs: self._log.append(f"  [NEW]  {d['ip']}  Risk: {d['risk']}")
        for d in diff.get("missing_devices",[]): self._log.append(f"  [GONE] {d['ip']}")
        for c in diff.get("changed_ports",[]):
            self._log.append(f"  [PORT CHANGE] {c['ip']}  +{c['added_ports']}  -{c['removed_ports']}")
        self._log.separator()
        if new_devs and self._alert_cfg.get("alert_new_device"):
            msg = f"{len(new_devs)} new device(s) joined: {', '.join(d['ip'] for d in new_devs)}"
            self._toast("New Device", msg)
            self._log_alert(f"🆕 New device alert — {msg}")
            if self._alert_cfg.get("email_verified"):
                dev_list="\n".join(f"  - {d['ip']}  {d.get('vendor','Unknown')}  Risk: {d['risk']}"
                    for d in new_devs)
                threading.Thread(target=self._do_send_email,
                    args=(f"IoT Scanner Alert -- {len(new_devs)} new device(s) detected",
                          f"{len(new_devs)} new device(s) joined your network:\n\n{dev_list}"),
                    daemon=True).start()

    def _toast(self, title, message):
        try:
            script=(f"Add-Type -AssemblyName System.Windows.Forms; "
                f"$n = New-Object System.Windows.Forms.NotifyIcon; "
                f"$n.Icon = [System.Drawing.SystemIcons]::Information; "
                f"$n.Visible = $true; "
                f"$n.ShowBalloonTip(5000, '{title}', '{message}', "
                f"[System.Windows.Forms.ToolTipIcon]::Warning); "
                f"Start-Sleep -s 6; $n.Visible = $false")
            subprocess.Popen(["powershell","-WindowStyle","Hidden","-Command",script],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=_NO_WINDOW)
        except Exception: pass

    # ══════════════════════════════════════════════════════════════════════════
    # QUEUE CONSUMER
    # ══════════════════════════════════════════════════════════════════════════

    def _poll_queue(self):
        try:
            while True:
                event, data = self._q.get_nowait()

                if event == "log":
                    self._log.append(str(data))

                elif event == "progress":
                    self._anim_bar.set_progress(float(data))

                elif event == "error":
                    self._log.append(f"[X] {data}")
                    self._status(f"Error: {data}")
                    messagebox.showerror("Scan Error", str(data))

                elif event == "consent_required":
                    self._show_consent_dialog()

                elif event == "scan_complete":
                    sc=data["m3"]["score"]
                    self._log.section_header(
                        f"Scan complete  ·  Score: {sc}/100  ({data['m3']['score_label']})"
                        f"  ·  {len(data['m2'])} devices")
                    self._data_dirty=True
                    self._apply_scan_results(data)
                    self._status(
                        f"Scan complete — Score: {sc}/100 ({data['m3']['score_label']})"
                        f"  |  {len(data['m2'])} devices")
                    try:
                        import module6; diff=module6.compare_scans()
                        if diff: self._check_device_changes(diff)
                    except Exception: pass
                    if self._alert_cfg.get("alert_score_drop"):
                        thr=int(self._alert_cfg.get("alert_score_threshold",60))
                        if sc < thr:
                            self._toast("Score Alert",
                                f"Network score: {sc}/100 -- below threshold {thr}")
                            self._log_alert(f"📉 Score drop alert — score {sc}/100 is below threshold {thr}/100")
                            if self._alert_cfg.get("email_verified"):
                                threading.Thread(target=self._do_send_email,
                                    args=(f"IoT Scanner Alert -- Score dropped to {sc}/100",
                                          f"Your score dropped to {sc}/100 (threshold: {thr}/100)."),
                                    daemon=True).start()

                elif event == "scan_done":
                    self._scan_running=False
                    self._scan_btn.configure(text="▶  Start Scan",
                        state="normal", fg_color=C["accent"])
                    self._anim_bar.stop_animation()
                    self._anim_bar.set_progress(0)

                elif event == "watch_alert":
                    diff=data; new_devs=diff.get("new_devices",[])
                    risk_ups=[r for r in diff.get("risk_changes",[])
                              if r.get("new_risk") in ("CRITICAL","High")]
                    if new_devs:
                        self._toast("Watch Mode Alert",
                            f"{len(new_devs)} new device(s) on your network")
                    if risk_ups:
                        self._toast("Risk Escalation",
                            f"{risk_ups[0]['ip']} escalated to {risk_ups[0]['new_risk']}")

                elif event == "traffic_packet":
                    proto=data.get("proto","?"); src=data.get("src","?")
                    dst=data.get("dst","?"); port=data.get("port","—")
                    size=data.get("size",0); ts=data.get("ts","")
                    line=f"[{ts}]  {src:<18} → {dst:<18} {proto:<6} :{port:<5} {size}B"
                    self._traffic_packets.append(line)
                    if not self._feed_paused:
                        self._packet_feed._text.configure(state="normal")
                        self._packet_feed._text.insert("end", line+"\n")
                        self._packet_feed._text.configure(state="disabled")
                        self._packet_feed._text.see("end")
                    if hasattr(self,"_feed_count_lbl"):
                        self._feed_count_lbl.configure(
                            text=f"{len(self._traffic_packets):,} packets")

                elif event == "traffic_alert":
                    alert_line=(f"[{data.get('ts','')}]  [{data['type']}]  "
                                f"{data['src']}  —  {data['detail']}")
                    self._traffic_alerts.append(alert_line)
                    self._traffic_log.append(
                        f"[{data['type']}]  {data['src']}  —  {data['detail']}")
                    if hasattr(self,"_alert_count_lbl"):
                        self._alert_count_lbl.configure(
                            text=f"{len(self._traffic_alerts)} alerts")
                    if self._alert_cfg.get("alert_traffic"):
                        self._toast(f"Attack: {data['type']}", f"Source: {data['src']}")
                        self._log_alert(f"🚨 Traffic attack — [{data['type']}] from {data['src']}: {data['detail']}")

                elif event == "secure_log":
                    if hasattr(self,"_secure_log"):
                        self._secure_log.append(str(data))

                elif event == "secure_status":
                    self._update_secure_status_ui(data)

                elif event == "test_email_result":
                    ok,msg=data
                    if hasattr(self,"_al_test_lbl"):
                        self._al_test_lbl.configure(
                            text=f"{'✓' if ok else '✗'} {msg}",
                            text_color=C["success"] if ok else C["danger"])

                elif event == "pdf_done":
                    if hasattr(self,"_report_log"):
                        self._report_log.append(f"[OK] PDF saved → {data}")
                    self._pdf_btn.configure(state="normal",text="📄  Generate PDF Report")
                    self._refresh_past_reports()
                    try: os.startfile(os.path.dirname(data))
                    except Exception: pass

                elif event == "pdf_error":
                    if hasattr(self,"_report_log"):
                        self._report_log.append(f"[X] PDF error: {data}")
                    self._pdf_btn.configure(state="normal",text="📄  Generate PDF Report")

        except queue.Empty:
            pass
        finally:
            self.after(80, self._poll_queue)

    # ══════════════════════════════════════════════════════════════════════════
    # HELPERS
    # ══════════════════════════════════════════════════════════════════════════

    def _status(self, msg, busy=False):
        self._status_lbl.configure(text=msg)
        self._status_dot.configure(
            text_color=C["warning"] if busy else C["success"])

    def _check_admin(self):
        try:
            if sys.platform=="win32":
                if not ctypes.windll.shell32.IsUserAnAdmin():
                    self._log.append("[!] Not Administrator — ARP scan may fail.")
                    self._log.append("[!] Right-click → Run as administrator for full scan.")
        except Exception: pass

    def _check_first_launch(self):
        cfg=load_alert_settings()
        if not cfg.get("tour_shown",False):
            WelcomeTour(self, on_close=self._after_tour)
        elif not cfg.get("email_verified",False):
            EmailSetupWizard(self, on_complete=self._on_wizard_complete)

    def _after_tour(self):
        cfg=load_alert_settings(); cfg["tour_shown"]=True; save_alert_settings(cfg)
        if not cfg.get("email_verified",False):
            self.after(400, lambda: EmailSetupWizard(
                self, on_complete=self._on_wizard_complete))

# ══════════════════════════════════════════════════════════════════════════════
# SPLASH SCREEN
# ══════════════════════════════════════════════════════════════════════════════

class SplashScreen(ctk.CTk):
    _STEPS = [
        (0.15, "Initializing security engine..."),
        (0.30, "Loading network modules..."),
        (0.50, "Connecting to CVE database..."),
        (0.65, "Preparing scan pipeline..."),
        (0.80, "Loading scan history..."),
        (0.95, "Starting interface..."),
        (1.00, "Ready."),
    ]
    def __init__(self):
        super().__init__()
        self.overrideredirect(True); self.configure(fg_color="#F0F2F7")
        self.resizable(False,False)
        w=min(580,int(self.winfo_screenwidth()*0.44))
        h=min(360,int(self.winfo_screenheight()*0.46))
        sw=self.winfo_screenwidth(); sh=self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        self._build(); self._step_idx=0; self.after(200, self._animate)

    def _build(self):
        # Outer accent border
        border=ctk.CTkFrame(self, fg_color=C["accent"], corner_radius=16)
        border.pack(fill="both", expand=True, padx=2, pady=2)
        inner=ctk.CTkFrame(border, fg_color="#F0F2F7", corner_radius=14)
        inner.pack(fill="both", expand=True, padx=2, pady=2)
        center=ctk.CTkFrame(inner, fg_color="transparent")
        center.place(relx=0.5, rely=0.48, anchor="center")

        # Logo
        try:
            _ico=os.path.join(os.path.dirname(os.path.abspath(__file__)),"netprobe.ico")
            if not os.path.exists(_ico):
                _ico=os.path.join(getattr(sys,"_MEIPASS",
                    os.path.dirname(os.path.abspath(__file__))),"netprobe.ico")
            from PIL import Image as _PILImage
            _pil=_PILImage.open(_ico).convert("RGBA").resize((80,80),_PILImage.LANCZOS)
            _ctk_img=ctk.CTkImage(light_image=_pil,dark_image=_pil,size=(80,80))
            ctk.CTkLabel(center,image=_ctk_img,text="").pack(pady=(0,0))
        except Exception:
            ctk.CTkLabel(center,text="🛡️",font=ctk.CTkFont(size=_fs(72))).pack(pady=(0,0))

        ctk.CTkLabel(center,text="NetProbeSec",
            font=ctk.CTkFont(family="Helvetica",size=28,weight="bold"),
            text_color=C["text"]).pack(pady=(10,0))
        ctk.CTkLabel(center,text="Network Vulnerability Detection & Device Isolation",
            font=ctk.CTkFont(size=_fs(12)),text_color=C["accent"]).pack(pady=(4,0))
        ctk.CTkLabel(center,text="v1.0.0",
            font=ctk.CTkFont(size=_fs(11)),text_color=C["text_faint"]).pack(pady=(4,14))
        self._progress=ctk.CTkProgressBar(center,width=420,height=6,
            fg_color=C["border"],progress_color=C["accent"],corner_radius=3)
        self._progress.set(0); self._progress.pack(pady=(0,8))
        self._status=ctk.CTkLabel(center,text="Starting...",
            font=ctk.CTkFont(size=_fs(11)),text_color=C["text_dim"])
        self._status.pack()
        ctk.CTkLabel(inner,text="© 2026 NetProbeSec  ·  All rights reserved",
            font=ctk.CTkFont(size=_fs(10)),text_color=C["text_faint"]).place(
            relx=0.5,rely=0.96,anchor="center")

    def _animate(self):
        if self._step_idx >= len(self._STEPS): self.quit(); return
        progress,message=self._STEPS[self._step_idx]
        self._progress.set(progress); self._status.configure(text=message)
        self._step_idx+=1
        delay=600 if self._step_idx<len(self._STEPS) else 400
        self.after(delay, self._animate)

# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    # UAC elevation on Windows
    if sys.platform == "win32":
        try:
            is_admin=bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            is_admin=True
        if not is_admin:
            try:
                script=os.path.abspath(__file__)
                ret=ctypes.windll.shell32.ShellExecuteW(
                    None,"runas",sys.executable,f'"{script}"',None,1)
                if ret > 32: sys.exit(0)
            except Exception: pass

    splash=SplashScreen(); splash.mainloop(); splash.destroy()
    app=IoTScannerApp(); app.mainloop()

if __name__ == "__main__":
    main()