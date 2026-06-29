# mailer.py
# IoT Security Scanner — Official Software Mailer
#
# The software sends all emails FROM one official account.
# Users never configure SMTP — they just sign up with their email.
#
# ── SETUP (one-time, done by you the developer) ───────────────────────────────
#
#   1. Create a dedicated Gmail:  e.g. iotscanner.alerts@gmail.com
#   2. Enable 2-Step Verification on that account
#   3. Go to: myaccount.google.com → Security → App Passwords
#   4. Create an App Password → copy the 16-char key
#   5. Paste both below in SENDER_EMAIL and SENDER_APP_PASSWORD
#
# ─────────────────────────────────────────────────────────────────────────────

import smtplib
import email.mime.text
import email.mime.multipart
import datetime
import threading

# ══════════════════════════════════════════════════════════════════════════════
# ▼▼  FILL THESE IN  ▼▼
# ══════════════════════════════════════════════════════════════════════════════

SENDER_EMAIL        = "ooooojj56@gmail.com"   # ← your software Gmail
SENDER_APP_PASSWORD = "epqs yyfk meei roqg"     # ← Gmail App Password
SENDER_NAME         = "IoT Security Scanner"

# ══════════════════════════════════════════════════════════════════════════════

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587

# ── Email templates ────────────────────────────────────────────────────────────

def _build_email(to: str, subject: str, body_html: str, body_plain: str):
    """Builds a MIME email with both HTML and plain text fallback."""
    msg                = email.mime.multipart.MIMEMultipart("alternative")
    msg["From"]        = f"{SENDER_NAME} <{SENDER_EMAIL}>"
    msg["To"]          = to
    msg["Subject"]     = subject
    msg["X-Mailer"]    = "IoT-Security-Scanner/1.0"

    msg.attach(email.mime.text.MIMEText(body_plain, "plain"))
    msg.attach(email.mime.text.MIMEText(body_html,  "html"))
    return msg


def _html_wrapper(title: str, color: str, content: str) -> str:
    """Wraps content in a clean branded HTML email layout."""
    return f"""
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0D1117;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr>
      <td align="center" style="padding:30px 0;">
        <table width="560" cellpadding="0" cellspacing="0"
               style="background:#161B22;border-radius:12px;
                      border:1px solid #30363D;overflow:hidden;">

          <!-- Header -->
          <tr>
            <td style="background:{color};padding:20px 30px;">
              <span style="font-size:22px;font-weight:bold;color:#fff;">
                🛡 IoT Security Scanner
              </span><br>
              <span style="font-size:13px;color:rgba(255,255,255,0.8);">
                {title}
              </span>
            </td>
          </tr>

          <!-- Body -->
          <tr>
            <td style="padding:28px 30px;color:#E6EDF3;font-size:14px;
                       line-height:1.7;">
              {content}
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="background:#0D1117;padding:16px 30px;
                       border-top:1px solid #30363D;">
              <span style="font-size:11px;color:#8B949E;">
                This alert was sent by IoT Security Scanner.
                You are receiving this because you registered with this email.
              </span>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
# CORE SEND FUNCTION
# ══════════════════════════════════════════════════════════════════════════════

def send_email(to: str, subject: str,
               body_html: str, body_plain: str) -> tuple:
    """
    Sends an email from the official software account.

    Args:
        to         : recipient email address
        subject    : email subject line
        body_html  : HTML version of the body
        body_plain : plain text fallback

    Returns:
        (success: bool, message: str)
    """
    if not to or "@" not in to:
        return False, "Invalid recipient email"

    if (SENDER_EMAIL == "iotscanner.alerts@gmail.com" and
            SENDER_APP_PASSWORD == "your-16-char-app-password"):
        return False, (
            "Official email not configured. "
            "Open mailer.py and fill in SENDER_EMAIL and SENDER_APP_PASSWORD."
        )

    try:
        msg = _build_email(to, subject, body_html, body_plain)
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_APP_PASSWORD.replace(" ", ""))
            server.sendmail(SENDER_EMAIL, to, msg.as_string())
        return True, f"Sent to {to}"

    except smtplib.SMTPAuthenticationError:
        return False, (
            "Authentication failed. Check SENDER_APP_PASSWORD in mailer.py.\n"
            "Make sure it is the App Password, not your Gmail login password."
        )
    except smtplib.SMTPException as e:
        return False, f"SMTP error: {e}"
    except Exception as e:
        return False, str(e)


def send_async(to: str, subject: str,
               body_html: str, body_plain: str,
               callback=None) -> None:
    """
    Non-blocking version of send_email.
    Fires in a background thread.
    Optional callback(success: bool, message: str) called on completion.
    """
    def _worker():
        ok, msg = send_email(to, subject, body_html, body_plain)
        if callback:
            try:
                callback(ok, msg)
            except Exception:
                pass

    threading.Thread(target=_worker, daemon=True).start()


# ══════════════════════════════════════════════════════════════════════════════
# PRE-BUILT ALERT TEMPLATES
# ══════════════════════════════════════════════════════════════════════════════

def send_verification_code(to: str, code: str,
                           username: str = "") -> tuple:
    """
    Sends a 6-digit verification / OTP email.
    Used during signup to verify the user's email address.
    """
    greeting = f"Hi {username}," if username else "Hello,"
    html = _html_wrapper(
        title = "Email Verification",
        color = "#2D9CDB",
        content = f"""
        <p>{greeting}</p>
        <p>Your IoT Security Scanner verification code is:</p>
        <div style="text-align:center;margin:24px 0;">
          <span style="font-size:42px;font-weight:bold;
                       letter-spacing:12px;color:#2D9CDB;">
            {code}
          </span>
        </div>
        <p style="color:#8B949E;font-size:12px;">
          This code expires in <strong style="color:#F39C12;">10 minutes</strong>.
          If you did not create an account, you can safely ignore this email.
        </p>
        """
    )
    plain = (
        f"{greeting}\n\n"
        f"Your IoT Security Scanner verification code is:\n\n"
        f"  {code}\n\n"
        f"This code expires in 10 minutes.\n"
        f"If you did not create an account, ignore this email."
    )
    return send_email(to, "IoT Scanner — Your Verification Code", html, plain)


def send_welcome(to: str, username: str) -> None:
    """Sends a welcome email after successful registration. Non-blocking."""
    html = _html_wrapper(
        title = "Welcome to IoT Security Scanner",
        color = "#27AE60",
        content = f"""
        <p>Hi <strong>{username}</strong>,</p>
        <p>Your account is set up. You will now receive alerts at this address for:</p>
        <ul style="color:#8B949E;">
          <li>🔴 New unknown devices joining your network</li>
          <li>⚠️ Network security score drops</li>
          <li>🚨 Live traffic attack detection</li>
        </ul>
        <p>Open the IoT Security Scanner and run your first scan to get started.</p>
        <p style="color:#2D9CDB;font-weight:bold;">Stay secure. 🛡</p>
        """
    )
    plain = (
        f"Hi {username},\n\n"
        f"Your account is set up. You will receive alerts for:\n"
        f"  - New unknown devices on your network\n"
        f"  - Security score drops\n"
        f"  - Traffic attack detection\n\n"
        f"Run your first scan to get started.\n\nStay secure."
    )
    send_async(to, "Welcome to IoT Security Scanner", html, plain)


def send_new_device_alert(to: str, username: str,
                          devices: list, ssid: str = "") -> None:
    """
    Sends an alert when new devices are detected.

    devices: list of {'ip', 'vendor', 'risk', 'mac'}
    """
    count   = len(devices)
    subject = f"⚠ IoT Scanner — {count} New Device{'s' if count > 1 else ''} Detected"

    rows = ""
    for d in devices:
        risk  = d.get("risk", "Unknown")
        color = (
            "#E74C3C" if risk == "CRITICAL" else
            "#E67E22" if risk == "High"     else
            "#F1C40F" if risk == "Weak"     else
            "#27AE60"
        )
        rows += f"""
        <tr>
          <td style="padding:8px 12px;color:#E6EDF3;">
            {d.get('ip', '?')}
          </td>
          <td style="padding:8px 12px;color:#8B949E;">
            {d.get('vendor', 'Unknown')}
          </td>
          <td style="padding:8px 12px;">
            <span style="background:{color};color:#fff;
                         padding:2px 8px;border-radius:4px;
                         font-size:11px;font-weight:bold;">
              {risk}
            </span>
          </td>
        </tr>"""

    network_line = (
        f"<p>Network: <strong style='color:#2D9CDB;'>{ssid}</strong></p>"
        if ssid else ""
    )

    html = _html_wrapper(
        title = "New Device Alert",
        color = "#E74C3C",
        content = f"""
        <p>Hi <strong>{username}</strong>,</p>
        <p>
          <strong style="color:#E74C3C;">
            {count} new device{'s' if count > 1 else ''} joined your network.
          </strong>
        </p>
        {network_line}
        <table width="100%" cellpadding="0" cellspacing="0"
               style="border-collapse:collapse;margin:16px 0;
                      background:#0D1117;border-radius:8px;">
          <tr style="background:#1C2333;">
            <th style="padding:8px 12px;text-align:left;color:#8B949E;
                       font-size:12px;">IP</th>
            <th style="padding:8px 12px;text-align:left;color:#8B949E;
                       font-size:12px;">Vendor</th>
            <th style="padding:8px 12px;text-align:left;color:#8B949E;
                       font-size:12px;">Risk</th>
          </tr>
          {rows}
        </table>
        <p style="color:#8B949E;font-size:12px;">
          Open the scanner to investigate these devices.
        </p>
        """
    )
    plain = (
        f"Hi {username},\n\n"
        f"{count} new device(s) joined your network:\n\n" +
        "\n".join(
            f"  • {d.get('ip')}  {d.get('vendor', 'Unknown')}  [{d.get('risk')}]"
            for d in devices
        ) +
        "\n\nOpen the scanner to investigate."
    )
    send_async(to, subject, html, plain)


def send_score_alert(to: str, username: str,
                     score: int, label: str,
                     threshold: int) -> None:
    """Sends an alert when the network score drops below threshold."""
    color = "#E74C3C" if score < 50 else "#F39C12"
    html  = _html_wrapper(
        title = "Network Score Alert",
        color = color,
        content = f"""
        <p>Hi <strong>{username}</strong>,</p>
        <p>Your network security score has dropped below your alert threshold.</p>
        <div style="text-align:center;margin:24px 0;">
          <span style="font-size:52px;font-weight:bold;color:{color};">
            {score}
          </span>
          <span style="font-size:20px;color:#8B949E;">/100</span><br>
          <span style="font-size:16px;color:{color};font-weight:bold;">
            {label}
          </span>
        </div>
        <p style="color:#8B949E;">
          Your alert threshold is set to
          <strong style="color:#E6EDF3;">{threshold}/100</strong>.
          Open the scanner to review your devices and fix any issues.
        </p>
        """
    )
    plain = (
        f"Hi {username},\n\n"
        f"Your network security score dropped to {score}/100 ({label}).\n"
        f"This is below your alert threshold of {threshold}.\n\n"
        f"Open the scanner to investigate."
    )
    send_async(
        to,
        f"⚠ IoT Scanner — Network Score: {score}/100 ({label})",
        html, plain
    )


def send_traffic_alert(to: str, username: str,
                       attack_type: str, src_ip: str,
                       detail: str) -> None:
    """Sends an alert when a traffic attack is detected."""
    html = _html_wrapper(
        title = f"Attack Detected: {attack_type}",
        color = "#E74C3C",
        content = f"""
        <p>Hi <strong>{username}</strong>,</p>
        <p>
          <strong style="color:#E74C3C;">
            A {attack_type} attack was detected on your network.
          </strong>
        </p>
        <table width="100%" cellpadding="0" cellspacing="0"
               style="background:#0D1117;border-radius:8px;margin:16px 0;">
          <tr>
            <td style="padding:10px 16px;color:#8B949E;width:130px;">Attack Type</td>
            <td style="padding:10px 16px;color:#E74C3C;font-weight:bold;">
              {attack_type}
            </td>
          </tr>
          <tr style="background:#161B22;">
            <td style="padding:10px 16px;color:#8B949E;">Source IP</td>
            <td style="padding:10px 16px;color:#E6EDF3;">{src_ip}</td>
          </tr>
          <tr>
            <td style="padding:10px 16px;color:#8B949E;">Detail</td>
            <td style="padding:10px 16px;color:#E6EDF3;">{detail}</td>
          </tr>
          <tr style="background:#161B22;">
            <td style="padding:10px 16px;color:#8B949E;">Time</td>
            <td style="padding:10px 16px;color:#E6EDF3;">
              {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </td>
          </tr>
        </table>
        <p style="color:#8B949E;font-size:12px;">
          Open the Traffic Monitor tab in the scanner for full details.
        </p>
        """
    )
    plain = (
        f"Hi {username},\n\n"
        f"Attack Detected: {attack_type}\n"
        f"Source IP : {src_ip}\n"
        f"Detail    : {detail}\n"
        f"Time      : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        f"Open the Traffic Monitor tab for full details."
    )
    send_async(
        to,
        f"🚨 IoT Scanner — {attack_type} Detected",
        html, plain
    )


def send_password_reset(to: str, username: str, code: str) -> tuple:
    """Sends a password reset code."""
    html = _html_wrapper(
        title = "Password Reset",
        color = "#F39C12",
        content = f"""
        <p>Hi <strong>{username}</strong>,</p>
        <p>You requested a password reset. Your reset code is:</p>
        <div style="text-align:center;margin:24px 0;">
          <span style="font-size:42px;font-weight:bold;
                       letter-spacing:12px;color:#F39C12;">
            {code}
          </span>
        </div>
        <p style="color:#8B949E;font-size:12px;">
          This code expires in
          <strong style="color:#F39C12;">10 minutes</strong>.
          If you did not request a reset, ignore this email.
          Your password has not been changed.
        </p>
        """
    )
    plain = (
        f"Hi {username},\n\n"
        f"Your password reset code is: {code}\n\n"
        f"This code expires in 10 minutes.\n"
        f"If you did not request this, ignore this email."
    )
    return send_email(
        to,
        "IoT Scanner — Password Reset Code",
        html, plain
    )


# ══════════════════════════════════════════════════════════════════════════════
# SETUP CHECK  — call this on startup to warn developer if not configured
# ══════════════════════════════════════════════════════════════════════════════

def is_configured() -> bool:
    """Returns True if the official email credentials have been filled in."""
    return (
        SENDER_EMAIL != "iotscanner.alerts@gmail.com" or
        SENDER_APP_PASSWORD != "your-16-char-app-password"
    )


def test_connection() -> tuple:
    """
    Tests the SMTP connection without sending an email.
    Returns (success: bool, message: str).
    """
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=8) as server:
            server.ehlo()
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_APP_PASSWORD.replace(" ", ""))
        return True, f"Connected successfully as {SENDER_EMAIL}"
    except smtplib.SMTPAuthenticationError:
        return False, "Authentication failed — check App Password in mailer.py"
    except Exception as e:
        return False, str(e)


# ══════════════════════════════════════════════════════════════════════════════
# CLI TEST
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    if not is_configured():
        print("[!] mailer.py is not configured yet.")
        print("    Open mailer.py and fill in SENDER_EMAIL and SENDER_APP_PASSWORD.")
        sys.exit(1)

    print("Testing SMTP connection...")
    ok, msg = test_connection()
    if ok:
        print(f"[OK] {msg}")

        if len(sys.argv) > 1:
            test_to = sys.argv[1]
            print(f"Sending test email to {test_to}...")
            ok2, msg2 = send_verification_code(test_to, "123456", "TestUser")
            print(f"{'[OK]' if ok2 else '[!!]'} {msg2}")
    else:
        print(f"[!!] {msg}")
