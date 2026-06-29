# module7.py
# IoT Security Scanner - Module 7 (Watch Mode)
# Continuously monitors the network and alerts on any changes
# Runs as a background thread — non-blocking

import threading
import time
import smtplib
import json
import os
from datetime  import datetime
from email.mime.text    import MIMEText
from email.mime.multipart import MIMEMultipart
from colorama  import Fore, Style, init

init(autoreset=True)

# ── EMAIL CONFIG FILE ──────────────────────────────────────────────────────────
# Stored next to this file — created on first run if missing
EMAIL_CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "email_config.json"
)

# ── DEFAULT MONITOR SETTINGS ───────────────────────────────────────────────────
DEFAULT_INTERVAL  = 60    # seconds between scans
CRITICAL_RISKS    = {"CRITICAL", "High"}   # risk levels that trigger alerts


# ===========================================================================
# 1.  Email Configuration
# ===========================================================================

def load_email_config() -> dict:
    """
    Loads email config from email_config.json.
    Returns empty dict (email disabled) if file not found or malformed.
    """
    if not os.path.exists(EMAIL_CONFIG_PATH):
        return {}
    try:
        with open(EMAIL_CONFIG_PATH, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_email_config(sender: str, password: str, recipient: str) -> None:
    """
    Saves Gmail credentials to email_config.json.
    Uses Gmail App Password — NOT your real Gmail password.
    Generate at: https://myaccount.google.com/apppasswords
    """
    config = {
        "sender":    sender,
        "password":  password,
        "recipient": recipient,
        "enabled":   True
    }
    with open(EMAIL_CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)
    print(f"{Fore.GREEN}[Module 7] Email config saved → {EMAIL_CONFIG_PATH}{Style.RESET_ALL}")


def send_alert_email(subject: str, body: str, config: dict) -> bool:
    """
    Sends an alert email via Gmail SMTP.

    Args:
        subject : email subject line
        body    : plain text email body
        config  : dict from load_email_config()

    Returns:
        True if sent successfully, False otherwise
    """
    if not config.get("enabled"):
        return False

    try:
        msg = MIMEMultipart()
        msg["From"]    = config["sender"]
        msg["To"]      = config["recipient"]
        msg["Subject"] = subject

        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=10) as server:
            server.login(config["sender"], config["password"])
            server.sendmail(config["sender"], config["recipient"], msg.as_string())

        print(f"{Fore.GREEN}[Module 7] Alert email sent to {config['recipient']}{Style.RESET_ALL}")
        return True

    except smtplib.SMTPAuthenticationError:
        print(f"{Fore.RED}[Module 7] Email failed — check Gmail App Password{Style.RESET_ALL}")
    except smtplib.SMTPException as e:
        print(f"{Fore.RED}[Module 7] SMTP error: {e}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[Module 7] Email error: {e}{Style.RESET_ALL}")

    return False


def build_alert_email_body(scan_num: int, diff: dict, score: int,
                            score_label: str, ip_range: str) -> tuple:
    """
    Builds subject + body text for an alert email.

    Returns:
        (subject: str, body: str)
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    subject = f"[IoT Scanner] Network Alert — Scan #{scan_num} | {timestamp}"

    lines = [
        "IoT Device Security Scanner — Watch Mode Alert",
        "=" * 50,
        f"Timestamp  : {timestamp}",
        f"IP Range   : {ip_range}",
        f"Scan #     : {scan_num}",
        f"Score      : {score}/100 ({score_label})",
        "",
    ]

    if diff["new_devices"]:
        lines.append(f"NEW DEVICES DETECTED ({len(diff['new_devices'])}):")
        for d in diff["new_devices"]:
            ports = ", ".join(str(p) for p in d["open_ports"]) or "None"
            lines.append(f"  + {d['ip']} | {d['vendor']} | Risk: {d['risk']} | Ports: {ports}")
        lines.append("")

    if diff["missing_devices"]:
        lines.append(f"DEVICES NO LONGER ON NETWORK ({len(diff['missing_devices'])}):")
        for d in diff["missing_devices"]:
            lines.append(f"  - {d['ip']} | {d['vendor']}")
        lines.append("")

    if diff["changed_ports"]:
        lines.append(f"PORT CHANGES ({len(diff['changed_ports'])}):")
        for c in diff["changed_ports"]:
            lines.append(f"  ~ {c['ip']} | {c['vendor']}")
            if c["added_ports"]:
                lines.append(f"      Ports opened : {c['added_ports']}")
            if c["removed_ports"]:
                lines.append(f"      Ports closed : {c['removed_ports']}")
        lines.append("")

    if diff["risk_changes"]:
        lines.append(f"RISK LEVEL CHANGES ({len(diff['risk_changes'])}):")
        for r in diff["risk_changes"]:
            lines.append(f"  ! {r['ip']} | {r['vendor']} | {r['old_risk']} -> {r['new_risk']}")
        lines.append("")

    lines.append("=" * 50)
    lines.append("Log in to your scanner to view the full report.")

    return subject, "\n".join(lines)


# ===========================================================================
# 2.  Single Monitor Scan Cycle
# ===========================================================================

def _run_scan_cycle(scan_num: int, ip_range_override: str = None) -> tuple:
    """
    Runs one full scan cycle: M1 → M2 → M3 → M6.
    Module 4 is NOT run in watch mode — active exploitation
    is only done with explicit user consent in the main scan.

    Args:
        scan_num          : current iteration count (for display)
        ip_range_override : optional fixed CIDR (skips auto-detect)

    Returns:
        (gateway, ip_range, m3, m6_result)
        All are None on failure.
    """
    # Import here to avoid circular imports at module level
    import module1
    import module2
    import module3
    import module6

    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"\n{Fore.CYAN}[Module 7] Scan #{scan_num} — {timestamp}{Style.RESET_ALL}")

    try:
        # ── Module 1: Discover devices ────────────────────────────────────────
        gateway, ip_range, m1_results = module1.run_module1()

        if not ip_range or not m1_results:
            print(f"{Fore.YELLOW}[Module 7] No devices found on scan #{scan_num} — retrying next cycle{Style.RESET_ALL}")
            return None, None, None, None

        print(f"  {Fore.GREEN}[M1]{Style.RESET_ALL} {len(m1_results)} device(s) found on {ip_range}")

        # ── Module 2: Enrich ──────────────────────────────────────────────────
        m2_results = module2.run_module2(m1_results)
        print(f"  {Fore.GREEN}[M2]{Style.RESET_ALL} Intelligence gathered")

        # ── Module 3: Score + CVE ─────────────────────────────────────────────
        m3 = module3.run_module3(m2_results)
        # Note: watch mode does not run red team (Module 4) — score shown
        # is the port-based score only. Full score incl. red team is only
        # available in a manual scan from the GUI.
        print(f"  {Fore.GREEN}[M3]{Style.RESET_ALL} Score: {m3['score']}/100 ({m3['score_label']}) [port-based]")

        # ── Module 6: Save + Compare ──────────────────────────────────────────
        m6_result = module6.run_module6(
            gateway  = gateway,
            ip_range = ip_range,
            m3       = m3,
        )

        return gateway, ip_range, m3, m6_result

    except Exception as e:
        print(f"{Fore.RED}[Module 7] Scan #{scan_num} error: {e}{Style.RESET_ALL}")
        return None, None, None, None


# ===========================================================================
# 3.  Alert Printer (console)
# ===========================================================================

def _print_watch_alert(diff: dict, m3: dict, scan_num: int) -> None:
    """Prints a concise colour-coded alert to the console."""
    if not diff or not diff["has_changes"]:
        return

    print(f"\n{Fore.YELLOW}{'━' * 65}")
    print(f"  ⚡ WATCH MODE ALERT — Scan #{scan_num}")
    print(f"{'━' * 65}{Style.RESET_ALL}")

    for dev in diff["new_devices"]:
        risk_col = Fore.RED if dev["risk"] in CRITICAL_RISKS else Fore.YELLOW
        ports    = ", ".join(str(p) for p in dev["open_ports"]) or "None"
        print(f"  {Fore.YELLOW}[NEW DEVICE]{Style.RESET_ALL}  "
              f"{dev['ip']} | {dev['vendor'][:25]} | "
              f"{risk_col}{dev['risk']}{Style.RESET_ALL} | ports: {ports}")

    for dev in diff["missing_devices"]:
        print(f"  {Fore.BLUE}[GONE]      {Style.RESET_ALL}  "
              f"{dev['ip']} | {dev['vendor'][:25]}")

    for ch in diff["changed_ports"]:
        print(f"  {Fore.MAGENTA}[PORT CHG]  {Style.RESET_ALL}  {ch['ip']} | {ch['vendor'][:25]}")
        if ch["added_ports"]:
            print(f"              {Fore.RED}+ opened: {ch['added_ports']}{Style.RESET_ALL}")
        if ch["removed_ports"]:
            print(f"              {Fore.GREEN}- closed: {ch['removed_ports']}{Style.RESET_ALL}")

    for rc in diff["risk_changes"]:
        arrow = "↑" if rc["new_risk"] in CRITICAL_RISKS else "↓"
        col   = Fore.RED if rc["new_risk"] in CRITICAL_RISKS else Fore.GREEN
        print(f"  {Fore.RED}[RISK CHG]  {Style.RESET_ALL}  {rc['ip']} | "
              f"{rc['old_risk']} {col}{arrow} {rc['new_risk']}{Style.RESET_ALL}")

    score_col = Fore.RED if m3["score"] < 50 else Fore.YELLOW if m3["score"] < 70 else Fore.GREEN
    print(f"\n  Network Score: {score_col}{m3['score']}/100 ({m3['score_label']}){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}{'━' * 65}{Style.RESET_ALL}\n")


# ===========================================================================
# 4.  Watch Loop (runs in a thread)
# ===========================================================================

class WatchMode:
    """
    Continuous network monitor.

    Usage
    -----
    watcher = WatchMode(interval=60, email_alerts=True)
    watcher.start()   # non-blocking — runs in background thread
    ...
    watcher.stop()    # graceful shutdown
    """

    def __init__(self, interval: int = DEFAULT_INTERVAL, email_alerts: bool = False):
        self.interval      = interval
        self.email_alerts  = email_alerts
        self.email_config  = load_email_config() if email_alerts else {}
        self._stop_event   = threading.Event()
        self._thread       = None
        self._scan_num     = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the monitor in a background daemon thread."""
        if self._thread and self._thread.is_alive():
            print(f"{Fore.YELLOW}[Module 7] Already running.{Style.RESET_ALL}")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target   = self._watch_loop,
            daemon   = True,           # exits when main program exits
            name     = "WatchMode"
        )
        self._thread.start()
        print(f"{Fore.CYAN}[Module 7] Watch Mode started "
              f"(interval: {self.interval}s, "
              f"email: {'ON' if self.email_alerts and self.email_config.get('enabled') else 'OFF'})"
              f"{Style.RESET_ALL}")

    def stop(self) -> None:
        """Signal the monitor to stop after the current scan finishes."""
        print(f"\n{Fore.YELLOW}[Module 7] Stopping watch mode...{Style.RESET_ALL}")
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self.interval + 30)
        print(f"{Fore.YELLOW}[Module 7] Watch mode stopped.{Style.RESET_ALL}")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ── Internal loop ─────────────────────────────────────────────────────────

    def _watch_loop(self) -> None:
        """Main loop — runs until stop() is called."""
        print(f"{Fore.CYAN}[Module 7] First scan starting...{Style.RESET_ALL}")

        while not self._stop_event.is_set():
            self._scan_num += 1

            gateway, ip_range, m3, m6_result = _run_scan_cycle(self._scan_num)

            if m3 and m6_result:
                diff = m6_result.get("diff")

                # ── Console alert ─────────────────────────────────────────────
                _print_watch_alert(diff, m3, self._scan_num)

                # ── Email alert — only on meaningful changes ───────────────────
                if diff and diff["has_changes"] and self.email_alerts:
                    self._maybe_send_email(diff, m3, ip_range)

            # ── Wait for next interval (interruptible) ────────────────────────
            if not self._stop_event.is_set():
                self._countdown(self.interval)

        print(f"{Fore.CYAN}[Module 7] Watch loop exited cleanly.{Style.RESET_ALL}")

    def _maybe_send_email(self, diff: dict, m3: dict, ip_range: str) -> None:
        """Send email only if email is configured and changes are significant."""
        if not self.email_config.get("enabled"):
            return

        # Only email for high-severity events
        has_critical_new = any(
            d["risk"] in CRITICAL_RISKS for d in diff["new_devices"]
        )
        has_risk_escalation = any(
            r["new_risk"] in CRITICAL_RISKS for r in diff["risk_changes"]
        )

        if has_critical_new or has_risk_escalation or diff["new_devices"]:
            subject, body = build_alert_email_body(
                scan_num    = self._scan_num,
                diff        = diff,
                score       = m3["score"],
                score_label = m3["score_label"],
                ip_range    = ip_range or "Unknown",
            )
            send_alert_email(subject, body, self.email_config)

    def _countdown(self, seconds: int) -> None:
        """
        Waits `seconds` but checks stop_event every second
        so Ctrl+C or stop() responds quickly.
        """
        for remaining in range(seconds, 0, -1):
            if self._stop_event.is_set():
                break
            if remaining in (60, 30, 10, 5) or remaining <= 3:
                print(f"{Fore.CYAN}[Module 7] Next scan in {remaining}s...{Style.RESET_ALL}",
                      end="\r")
            time.sleep(1)


# ===========================================================================
# 5.  Master Entry Point
# ===========================================================================

def run_module7(
    interval: int     = DEFAULT_INTERVAL,
    email_alerts: bool = False,
    blocking: bool    = False
) -> WatchMode:
    """
    Master function — starts Watch Mode.

    Args:
        interval      : seconds between scans (default 60)
        email_alerts  : send email on new/critical devices (requires email_config.json)
        blocking      : if True, blocks until Ctrl+C (use for standalone mode)
                        if False, returns WatchMode object (use from main.py)

    Returns:
        WatchMode instance (already started)

    Example — non-blocking (from main.py)
    ------
    watcher = run_module7(interval=60)
    # ... do other things ...
    watcher.stop()

    Example — blocking (standalone --monitor mode)
    ------
    run_module7(interval=60, blocking=True)
    """
    watcher = WatchMode(interval=interval, email_alerts=email_alerts)
    watcher.start()

    if blocking:
        print(f"\n{Fore.CYAN}  Press Ctrl+C to stop watch mode.{Style.RESET_ALL}\n")
        try:
            while watcher.is_running():
                time.sleep(1)
        except KeyboardInterrupt:
            watcher.stop()

    return watcher


# ===========================================================================
# 6.  Email Setup Wizard (called from main.py --setup-email)
# ===========================================================================

def setup_email_wizard() -> None:
    """
    Interactive wizard to configure Gmail alert emails.
    Saves credentials to email_config.json.

    IMPORTANT: Use a Gmail App Password, NOT your real Gmail password.
    Generate one at: https://myaccount.google.com/apppasswords
    """
    print(f"""
{Fore.CYAN}{'═' * 60}
  MODULE 7 — EMAIL ALERT SETUP
{'═' * 60}{Style.RESET_ALL}

  This wizard configures email alerts for Watch Mode.
  When a new device or critical risk is detected,
  you will receive an email notification.

  {Fore.YELLOW}You need a Gmail App Password (not your real password).
  Generate one at: https://myaccount.google.com/apppasswords{Style.RESET_ALL}

{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}
""")

    sender    = input("  Your Gmail address     : ").strip()
    password  = input("  Gmail App Password     : ").strip()
    recipient = input("  Alert recipient email  : ").strip()

    if not sender or not password or not recipient:
        print(f"{Fore.RED}  Setup cancelled — all fields required.{Style.RESET_ALL}")
        return

    # Test the connection before saving
    print(f"\n{Fore.YELLOW}  Testing connection...{Style.RESET_ALL}")
    test_config = {"sender": sender, "password": password,
                   "recipient": recipient, "enabled": True}
    ok = send_alert_email(
        subject = "[IoT Scanner] Email alerts configured successfully",
        body    = "Watch Mode email alerts are now active on your IoT Scanner.",
        config  = test_config
    )

    if ok:
        save_email_config(sender, password, recipient)
        print(f"{Fore.GREEN}  Email alerts configured. Test email sent.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}  Connection failed — credentials not saved.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}  Check your App Password and try again.{Style.RESET_ALL}")
