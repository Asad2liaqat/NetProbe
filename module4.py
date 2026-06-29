# module4.py
# IoT Security Scanner - Module 4 (Red Team Active Testing)
# Contains: Default Credential Testing, RTSP Stream Access,
#           HTTP Auth Testing, FTP Anonymous, MQTT Auth, SMB Null Session
# ⚠ Only use on your own network and devices

import socket
import ftplib
import requests
import time


# ── DEFAULT CREDENTIALS ────────────────────────────────────────────────────────

ROUTER_CREDENTIALS = [
    ("admin",  "admin"),
    ("admin",  ""),
    ("admin",  "1234"),
    ("admin",  "12345"),
    ("admin",  "password"),
    ("root",   "root"),
    ("root",   ""),
    ("user",   "user"),
    ("admin",   "$@im0404")
    ]

CAMERA_CREDENTIALS = [
    ("admin",  ""),           # V380 most common
    ("admin",  "admin"),
    ("admin",  "888888"),     # V380 specific
    ("admin",  "666666"),     # V380 specific
    ("admin",  "111111"),
    ("admin",  "12345"),
    ("admin",  "123456"),
    ("guest",  "guest"),
    ("root",   "root"),
    ("root",   "vizxv"),      # Hikvision default
]

TELNET_CREDENTIALS = [
    ("root",   ""),
    ("root",   "root"),
    ("admin",  "admin"),
    ("admin",  ""),
    ("admin",  "1234"),
    ("user",   "user"),
    ("guest",  "guest"),
]

# RTSP paths to try on camera
RTSP_PATHS = [
    "/",
    "/live",
    "/stream",
    "/ch0",
    "/ch01.264",
    "/onvif1",
    "/video1",
    "/cam/realmonitor?channel=1&subtype=0",
    "/h264Preview_01_main",
]


# ── TELNET TEST ────────────────────────────────────────────────────────────────

def test_telnet(ip):
    """
    Attempts to login to Telnet (port 23) using default credentials.
    Uses raw socket instead of telnetlib (removed in Python 3.13)
    """
    results = {
        'tested':      True,
        'compromised': False,
        'credential':  None,
        'attempts':    []
    }

    for username, password in TELNET_CREDENTIALS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, 23))

            # Read banner
            time.sleep(0.5)
            sock.recv(1024)

            # Send username
            sock.send((username + "\n").encode())
            time.sleep(0.5)
            sock.recv(1024)

            # Send password
            sock.send((password + "\n").encode())
            time.sleep(1)

            # Read response
            response = sock.recv(2048).decode('ascii', errors='ignore')
            sock.close()

            attempt = f"{username}/{password if password else '(blank)'}"
            results['attempts'].append(attempt)

            # Check if login successful
            if any(s in response for s in ["#", "$", ">", "~", "root@", "admin@"]):
                results['compromised'] = True
                results['credential']  = attempt
                return results

        except (ConnectionRefusedError, socket.timeout, OSError):
            break
        except Exception:
            pass

        time.sleep(0.5)

    return results

# ── HTTP AUTH TEST ─────────────────────────────────────────────────────────────

def test_http_auth(ip, port=80, device_type="router"):
    """
    Attempts to login to HTTP web interface using default credentials.
    Tries both Basic Auth and form-based login.
    """
    results = {
        'tested':      True,
        'compromised': False,
        'credential':  None,
        'attempts':    []
    }

    credentials = CAMERA_CREDENTIALS if "camera" in device_type.lower() else ROUTER_CREDENTIALS

    for username, password in credentials:
        attempt = f"{username}/{password if password else '(blank)'}"
        results['attempts'].append(attempt)

        try:
            # Method 1 — Basic Authentication
            response = requests.get(
                f"http://{ip}:{port}",
                auth=(username, password),
                timeout=3,
                allow_redirects=True
            )

            # 200 = success, 401 = wrong password, 403 = forbidden
            if response.status_code == 200:
                # Make sure it is not just an open page
                if "login" not in response.text.lower() and \
                   "unauthorized" not in response.text.lower():
                    results['compromised'] = True
                    results['credential']  = attempt
                    return results

        except requests.exceptions.ConnectionError:
            break
        except requests.exceptions.Timeout:
            pass
        except Exception:
            pass

        time.sleep(0.5)

    return results


# ── RTSP STREAM TEST ───────────────────────────────────────────────────────────

def test_rtsp_stream(ip):
    """
    Tries to access the camera live stream without any credentials.
    If successful — anyone on the network can watch the camera feed.
    This is the most visually impressive demo for examiners.
    """
    results = {
        'tested':      True,
        'compromised': False,
        'stream_url':  None,
        'attempts':    []
    }

    for path in RTSP_PATHS:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, 554))

            # Send RTSP OPTIONS request — no credentials
            request = (
                f"OPTIONS rtsp://{ip}{path} RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"User-Agent: IoTSecurityScanner/1.0\r\n\r\n"
            )
            sock.send(request.encode())
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()

            stream_url = f"rtsp://{ip}{path}"
            results['attempts'].append(stream_url)

            if "RTSP/1.0 200" in response:
                results['compromised'] = True
                results['stream_url']  = stream_url
                return results

        except (socket.timeout, ConnectionRefusedError):
            break
        except Exception:
            pass

        time.sleep(0.3)

    # Also try with default credentials in RTSP URL
    for username, password in CAMERA_CREDENTIALS[:3]:
        for path in RTSP_PATHS[:3]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect((ip, 554))

                cred_url = f"rtsp://{username}:{password}@{ip}{path}"
                request  = (
                    f"OPTIONS {cred_url} RTSP/1.0\r\n"
                    f"CSeq: 1\r\n"
                    f"User-Agent: IoTSecurityScanner/1.0\r\n\r\n"
                )
                sock.send(request.encode())
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()

                results['attempts'].append(cred_url)

                if "RTSP/1.0 200" in response:
                    results['compromised'] = True
                    results['stream_url']  = cred_url
                    return results

            except Exception:
                pass

            time.sleep(0.3)

    return results


# ── FTP ANONYMOUS TEST ─────────────────────────────────────────────────────────

def test_ftp_anonymous(ip):
    """
    Tries anonymous FTP login — no credentials needed.
    Very common vulnerability on cheap IoT devices.
    """
    results = {
        'tested':      True,
        'compromised': False,
        'credential':  None,
        'attempts':    ['anonymous/(blank)']
    }

    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, 21, timeout=3)
        ftp.login('anonymous', '')
        ftp.quit()

        results['compromised'] = True
        results['credential']  = 'anonymous/(blank)'

    except ftplib.error_perm:
        pass   # Login rejected — good
    except (ConnectionRefusedError, socket.timeout, OSError):
        results['tested'] = False
    except Exception:
        pass

    return results


# ── MQTT AUTH TEST ─────────────────────────────────────────────────────────────

def test_mqtt_auth(ip):
    """
    Tries to connect to MQTT broker without any credentials.
    If accepted — all smart home messages are readable.
    """
    results = {
        'tested':      True,
        'compromised': False,
        'attempts':    ['No credentials']
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        sock.connect((ip, 1883))

        # Minimal MQTT CONNECT packet — no username/password
        connect_packet = bytearray([
            0x10,                    # CONNECT command
            0x12,                    # Remaining length
            0x00, 0x04,              # Protocol name length
            0x4D, 0x51, 0x54, 0x54, # "MQTT"
            0x04,                    # Protocol level (3.1.1)
            0x02,                    # Connect flags (clean session)
            0x00, 0x3C,              # Keep alive (60 seconds)
            0x00, 0x06,              # Client ID length
            0x53, 0x63, 0x61, 0x6E, # "Scan"
            0x65, 0x72               # "er"
        ])

        sock.send(bytes(connect_packet))
        response = sock.recv(4)
        sock.close()

        # CONNACK with return code 0x00 = connection accepted
        if len(response) >= 4 and response[3] == 0x00:
            results['compromised'] = True

    except (ConnectionRefusedError, socket.timeout, OSError):
        results['tested'] = False
    except Exception:
        pass

    return results


# ── SMB NULL SESSION TEST ──────────────────────────────────────────────────────

def test_smb_null(ip):
    """
    Tries unauthenticated SMB connection (null session).
    Common entry point for ransomware attacks.
    """
    results = {
        'tested':      True,
        'compromised': False,
        'attempts':    ['Null session (no credentials)']
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, 445))

        if result == 0:
            # Port is open — send SMB negotiation
            smb_negotiate = bytearray([
                0x00, 0x00, 0x00, 0x85,  # NetBIOS header
                0xFF, 0x53, 0x4D, 0x42,  # SMB magic bytes
                0x72,                     # Command: Negotiate Protocol
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xFF, 0xFF,
                0x00, 0x00, 0x00, 0x00,
            ])

            sock.send(bytes(smb_negotiate))
            response = sock.recv(1024)
            sock.close()

            # If we get a valid SMB response — port is accessible
            if len(response) > 4 and response[4:8] == b'\xffSMB':
                results['compromised'] = True

    except (ConnectionRefusedError, socket.timeout, OSError):
        results['tested'] = False
    except Exception:
        pass

    return results


# ── VERDICT ────────────────────────────────────────────────────────────────────

def get_verdict(test_results):
    """
    Determines overall verdict for a device based on all test results.
    """
    for test_name, result in test_results.items():
        if result.get('compromised'):
            return "COMPROMISED"
    return "SECURE"


# ── MASTER FUNCTION ────────────────────────────────────────────────────────────

def run_module4(module2_results):
    """
    Runs red team tests on each device based on its open ports.
    Only tests ports that are actually open — skips closed ones.

    Args:
        module2_results (list): Output from module2.run_module2()

    Returns:
        list of dicts: each device with full red team test results
    """
    all_results = []

    for device in module2_results:
        ip          = device['ip']
        open_ports  = device['open_ports']
        device_type = device.get('device_type', 'Unknown')
        vendor      = device.get('vendor_api', device.get('vendor', 'Unknown'))

        device_results = {
            'ip':          ip,
            'vendor':      vendor,
            'device_type': device_type,
            'tests':       {},
            'verdict':     'SECURE'
        }

        print(f"\n  Testing {ip} ({vendor})...")

        # Only test ports that are actually open
        if 23 in open_ports:
            print(f"    [TELNET]  Port open — testing credentials...")
            device_results['tests']['telnet'] = test_telnet(ip)

        if 80 in open_ports:
            print(f"    [HTTP]    Port open — testing web interface...")
            device_results['tests']['http'] = test_http_auth(ip, 80, device_type)

        if 8080 in open_ports:
            print(f"    [HTTP-ALT] Port open — testing alternate web interface...")
            device_results['tests']['http_alt'] = test_http_auth(ip, 8080, device_type)

        if 554 in open_ports:
            print(f"    [RTSP]    Port open — testing camera stream access...")
            device_results['tests']['rtsp'] = test_rtsp_stream(ip)

        if 21 in open_ports:
            print(f"    [FTP]     Port open — testing anonymous login...")
            device_results['tests']['ftp'] = test_ftp_anonymous(ip)

        if 1883 in open_ports:
            print(f"    [MQTT]    Port open — testing broker authentication...")
            device_results['tests']['mqtt'] = test_mqtt_auth(ip)

        if 445 in open_ports:
            print(f"    [SMB]     Port open — testing null session...")
            device_results['tests']['smb'] = test_smb_null(ip)

        if not device_results['tests']:
            print(f"    No testable ports open — skipping")

        device_results['verdict'] = get_verdict(device_results['tests'])
        all_results.append(device_results)

    return all_results