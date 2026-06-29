# module3.py
# IoT Security Scanner - Module 3 (Assessment Engine)
# Contains: Network Health Score, CVE Lookup, Fix Recommendations

import requests


# ── SCORING RULES ──────────────────────────────────────────────────────────────

SCORE_DEDUCTIONS = {
    23:   ("Telnet Open",                        20),
    21:   ("FTP Open",                           15),
    5555: ("ADB Open",                           20),
    445:  ("SMB Open",                           15),
    3389: ("RDP Open",                           15),
    554:  ("Exposed Camera Stream (RTSP)",        25),   # was 10 — unauthenticated camera = critical
    1883: ("Unencrypted MQTT Open",              10),
    80:   ("Unencrypted Web Interface",           5),
    8080: ("Alternate Web Interface",             5),
    5683: ("CoAP Sensor Port Open",               5),
}

# Penalty applied per device CONFIRMED COMPROMISED by red team
COMPROMISED_DEDUCTION = 20

# Reward per port successfully DEFENDED against red team attack
# e.g. RTSP open (-25) but camera rejected the attack → +5 back
DEFENCE_REWARD = 5

# Penalty per device when red team was SKIPPED
# (we couldn't verify exploitability, so assume worst case for dangerous ports)
SKIP_PENALTY_PER_DANGEROUS_DEVICE = 10

# Vendors that count as "unknown" for scoring and CVE lookup purposes
UNKNOWN_VENDOR_LABELS = {
    "Unknown Device",
    "Unknown Vendor",
    "Offline (No Internet)",
    "Lookup Timed Out",   # FIX: was missing from scoring check
}

UNKNOWN_DEVICE_DEDUCTION = 5
WEAK_TLS_DEDUCTION       = 10


# ── NETWORK HEALTH SCORE ───────────────────────────────────────────────────────

def calculate_score(devices):
    """
    Calculates an overall network health score from 0 to 100.
    Deducts points for every risk found across all devices.

    Scoring rules:
      - Each dangerous open port:  deducted per SCORE_DEDUCTIONS table
      - Unknown vendor + open ports: -5  (unknown AND suspicious)
      - Unknown vendor + no ports:   0   (safe device, no penalty)
      - Weak TLS version:           -10

    Args:
        devices (list): Enriched device list from Module 2

    Returns:
        tuple: (final_score, breakdown_list)
        breakdown_list = [{'ip', 'reason', 'deduction'}]
    """
    score     = 100
    breakdown = []

    for device in devices:
        ip         = device['ip']
        open_ports = device['open_ports']
        vendor     = device.get('display_name', device.get('vendor_api', device.get('vendor', 'Unknown Device')))
        tls        = device.get('tls', {})

        # ── Deduct for each dangerous open port ───────────────────────────────
        for port in open_ports:
            if port in SCORE_DEDUCTIONS:
                reason, points = SCORE_DEDUCTIONS[port]
                score -= points
                breakdown.append({
                    'ip':        ip,
                    'reason':    reason,
                    'deduction': points
                })

        # ── Deduct for unknown vendor ONLY if the device also has open ports ──
        # FIX: Phones and laptops with randomised MACs (iOS/Android privacy
        # feature) return "Unknown Vendor" from the API but are perfectly safe
        # if they have no open ports. Penalising them inflates the network
        # risk score unfairly. We only flag unknown devices that are also
        # exposing services — that combination is genuinely suspicious.
        if vendor in UNKNOWN_VENDOR_LABELS and open_ports:
            score -= UNKNOWN_DEVICE_DEDUCTION
            breakdown.append({
                'ip':        ip,
                'reason':    "Unknown Device with Open Ports",
                'deduction': UNKNOWN_DEVICE_DEDUCTION
            })

        # ── Deduct for weak TLS ───────────────────────────────────────────────
        if tls.get('status') == 'Weak':
            score -= WEAK_TLS_DEDUCTION
            breakdown.append({
                'ip':        ip,
                'reason':    f"Weak Encryption ({tls.get('version')})",
                'deduction': WEAK_TLS_DEDUCTION
            })

    # Score cannot go below 0
    final_score = max(0, score)
    return final_score, breakdown


def get_score_label(score):
    """
    Converts a numeric score into a human-readable label and ANSI colour.

    Returns:
        tuple: (label, ansi_color_code)
    """
    if score >= 90:
        return "Excellent", "\033[92m"   # Bright green
    elif score >= 70:
        return "Good",      "\033[93m"   # Yellow
    elif score >= 50:
        return "At Risk",   "\033[91m"   # Light red
    else:
        return "Critical",  "\033[31m"   # Red


def recalculate_with_redteam(m3_result: dict, m4_results: list) -> dict:
    """
    Adjusts the network score AFTER red team results are known.

    Three scenarios per device:

    1. COMPROMISED — red team broke in.
       Extra -20 on top of the port deduction already applied.
       Confirmed exploitable = worst possible outcome.

    2. DEFENDED (tested but not compromised) — red team attacked, device resisted.
       Give back +5 per tested port that was successfully defended.
       The port is still open (penalty already applied) but the device
       proved it has some protection — reward that.

    3. SKIPPED — red team was not run at all.
       Extra -10 per device with dangerous open ports.
       Uncertainty = risk. We couldn't verify exploitability.

    Args:
        m3_result  : the dict returned by run_module3()
        m4_results : list of red team results from run_module4(),
                     or the empty-m4 list if skipped (verdict == 'SKIPPED')

    Returns:
        Updated m3_result dict with adjusted score, label, color, and breakdown.
    """
    if not m4_results:
        return m3_result

    score     = m3_result['score']
    breakdown = list(m3_result.get('breakdown', []))

    skipped_all = all(d.get('verdict') == 'SKIPPED' for d in m4_results)

    if skipped_all:
        # ── Scenario 3: Red team was skipped entirely ─────────────────────────
        dangerous_ports = set(SCORE_DEDUCTIONS.keys())
        for device in m4_results:
            ip         = device.get('ip', '')
            open_ports = set(device.get('open_ports', []))
            if open_ports & dangerous_ports:
                score -= SKIP_PENALTY_PER_DANGEROUS_DEVICE
                breakdown.append({
                    'ip':        ip,
                    'reason':    'Red Team Skipped — exploitability unverified',
                    'deduction': SKIP_PENALTY_PER_DANGEROUS_DEVICE
                })

    else:
        # ── Scenarios 1 & 2: Red team ran ────────────────────────────────────
        for device in m4_results:
            ip      = device.get('ip', '')
            verdict = device.get('verdict', 'SECURE')
            tests   = device.get('tests', {})

            if verdict == 'COMPROMISED':
                # Scenario 1 — confirmed breach
                score -= COMPROMISED_DEDUCTION
                breakdown.append({
                    'ip':        ip,
                    'reason':    'Device COMPROMISED by red team',
                    'deduction': COMPROMISED_DEDUCTION
                })

            else:
                # Scenario 2 — count how many ports were actually tested
                # and successfully defended (tested=True, compromised=False)
                defended_ports = [
                    name for name, result in tests.items()
                    if result.get('tested') and not result.get('compromised')
                ]

                if defended_ports:
                    reward = len(defended_ports) * DEFENCE_REWARD
                    # Cap reward so it never exceeds the original port deductions
                    reward  = min(reward, 15)
                    score  += reward
                    breakdown.append({
                        'ip':        ip,
                        'reason':    (
                            f'Device defended against red team '
                            f'({len(defended_ports)} test(s) resisted) — score reward'
                        ),
                        'deduction': -reward   # negative = bonus in the breakdown table
                    })

    final_score = max(0, min(100, score))
    label, color = get_score_label(final_score)

    return {
        **m3_result,
        'score':       final_score,
        'score_label': label,
        'score_color': color,
        'breakdown':   breakdown,
    }


# ── CVE LOOKUP ─────────────────────────────────────────────────────────────────

def search_cves(vendor_name, max_results=3, firmware=None, os_name=None):
    """
    Searches the NVD for CVEs matching vendor, firmware server, or OS.
    Priority order: firmware version > OS > vendor name.
    This gives much more accurate matches for IoT devices.

    Args:
        vendor_name  : e.g. 'TP-Link Technologies'
        max_results  : how many CVEs to return (default 3)
        firmware     : dict from detect_firmware_from_banner e.g.
                       {'server': 'lighttpd', 'version': '1.4.35'}
        os_name      : OS string from module2 e.g. 'Linux 3.x'

    Returns:
        list of dicts: [{'id', 'description', 'severity', 'source'}]
        'source' tells you whether the match was on firmware, OS, or vendor.
    """
    if not vendor_name or vendor_name in UNKNOWN_VENDOR_LABELS:
        if not firmware and not os_name:
            return []

    results   = []
    seen_ids  = set()

    def _nvd_search(keyword, source_label, limit):
        """Inner helper — queries NVD and returns labelled CVE list."""
        if not keyword:
            return []
        try:
            url      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params   = {"keywordSearch": keyword, "resultsPerPage": limit}
            response = requests.get(url, params=params, timeout=20)
            if response.status_code != 200:
                return []

            cve_list = []
            for item in response.json().get("vulnerabilities", []):
                cve    = item.get("cve", {})
                cve_id = cve.get("id", "N/A")
                if cve_id in seen_ids:
                    continue

                descriptions = cve.get("descriptions", [])
                description  = next(
                    (d["value"] for d in descriptions if d["lang"] == "en"),
                    "No description available"
                )

                severity = "N/A"
                try:
                    metrics  = cve.get("metrics", {})
                    for key in ("cvssMetricV31", "cvssMetricV30"):
                        if metrics.get(key):
                            severity = metrics[key][0]["cvssData"]["baseSeverity"]
                            break
                    if severity == "N/A" and metrics.get("cvssMetricV2"):
                        severity = metrics["cvssMetricV2"][0]["baseSeverity"]
                except Exception:
                    pass

                seen_ids.add(cve_id)
                cve_list.append({
                    'id':          cve_id,
                    'description': description[:100] + "..." if len(description) > 100 else description,
                    'severity':    severity,
                    'source':      source_label,
                })
            return cve_list

        except requests.exceptions.ConnectionError:
            return [{'id': 'Offline',  'description': 'No internet connection',
                     'severity': 'N/A', 'source': source_label}]
        except requests.exceptions.Timeout:
            return [{'id': 'Timeout',  'description': 'NVD API timed out',
                     'severity': 'N/A', 'source': source_label}]
        except Exception:
            return []

    # 1. Most specific: firmware server + version (e.g. "lighttpd 1.4.35")
    if firmware and firmware.get('server') and firmware.get('version'):
        query = f"{firmware['server']} {firmware['version']}"
        results += _nvd_search(query, f"firmware ({query})", max_results)

    # 2. Just firmware server name (e.g. "GoAhead") if no version match
    if firmware and firmware.get('server') and len(results) < max_results:
        results += _nvd_search(firmware['server'], f"firmware server ({firmware['server']})",
                                max_results - len(results))

    # 3. OS name (e.g. "Linux 3.x")
    if os_name and os_name not in ('Unknown', '') and len(results) < max_results:
        os_keyword = os_name.split()[0]   # "Linux" from "Linux 3.x"
        results += _nvd_search(os_keyword, f"OS ({os_name})", max_results - len(results))

    # 4. Vendor name fallback (original behaviour)
    if vendor_name and vendor_name not in UNKNOWN_VENDOR_LABELS and len(results) < max_results:
        keyword = vendor_name.split()[0]
        results += _nvd_search(keyword, f"vendor ({vendor_name})", max_results - len(results))

    return results[:max_results]


# ── FIX RECOMMENDATIONS ────────────────────────────────────────────────────────

FIX_RECOMMENDATIONS = {
    23:   "Disable Telnet on your device. Log into your router/device settings and turn off Telnet access.",
    21:   "Disable FTP on your device. Use SFTP instead if file transfer is needed.",
    5555: "Disable ADB (Android Debug Bridge). Go to Settings > Developer Options and turn it off.",
    445:  "Disable SMB file sharing if not needed. Update Windows to patch known SMB vulnerabilities.",
    3389: "Disable Remote Desktop if not in use. If needed, use a VPN with strong password.",
    1883: "Secure your MQTT broker. Add username/password authentication or use port 8883 (encrypted).",
    554:  "Secure your camera stream. Add a strong password and disable public access.",
    80:   "Enable HTTPS on your device web interface. Avoid accessing settings over unencrypted HTTP.",
    8080: "Close this alternate web port if not needed. Check your device manual to disable it.",
    5683: "Secure your IoT sensors. Add device authentication to your CoAP endpoints.",
    22:   "Keep SSH but use a strong password or key-based authentication only.",
    443:  "HTTPS is good. Make sure the certificate is valid and not self-signed.",
}


def get_recommendations(devices):
    """
    Generates plain-English fix recommendations per device.

    Args:
        devices (list): Enriched device list from Module 2

    Returns:
        list of dicts: [{
            'ip':     '192.168.1.1',
            'vendor': 'TP-Link',
            'fixes':  ['Disable Telnet...', 'Enable HTTPS...']
        }]
    """
    recommendations = []

    for device in devices:
        fixes = [
            FIX_RECOMMENDATIONS[port]
            for port in device['open_ports']
            if port in FIX_RECOMMENDATIONS
        ]
        if fixes:
            recommendations.append({
                'ip':           device['ip'],
                'vendor':       device.get('display_name', device.get('vendor_api', device.get('vendor', 'Unknown'))),
                'display_name': device.get('display_name', device.get('vendor_api', device.get('vendor', 'Unknown'))),
                'fixes':        fixes
            })

    return recommendations


# ── MASTER FUNCTION ────────────────────────────────────────────────────────────

def run_module3(module2_results):
    """
    Runs the full Module 3 pipeline on enriched device data.

    Args:
        module2_results (list): Output from module2.run_module2()

    Returns:
        dict: {
            'score':           75,
            'score_label':     'Good',
            'score_color':     '\033[93m',
            'breakdown':       [{ip, reason, deduction}],
            'cve_results':     {ip: [cve_list]},
            'recommendations': [{ip, vendor, fixes}],
            'devices':         full enriched device list
        }
    """
    # 1. Calculate network score
    score, breakdown = calculate_score(module2_results)
    label, color     = get_score_label(score)

    # 2. CVE lookup per device
    cve_results = {}
    for device in module2_results:
        ip     = device['ip']
        vendor = device.get('display_name', device.get('vendor_api', device.get('vendor', '')))
        print(f"  Looking up CVEs for {ip} ({vendor})...")
        cve_results[ip] = search_cves(device.get('vendor_api', device.get('vendor', '')))

    # 3. Fix recommendations
    recommendations = get_recommendations(module2_results)

    return {
        'score':           score,
        'score_label':     label,
        'score_color':     color,
        'breakdown':       breakdown,
        'cve_results':     cve_results,
        'recommendations': recommendations,
        'devices':         module2_results
    }
