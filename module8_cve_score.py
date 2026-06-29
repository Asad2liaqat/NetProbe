# module8_cve_score.py
# IoT Security Scanner — CVE Risk Score Engine
#
# Calculates a numeric CVE Risk Score (0–100) for a device or entire network
# based on actual CVSS severity data returned by Module 3's NVD lookup.
#
# Score model:
#   Each CVE contributes a weighted base score:
#     CRITICAL  → 25 pts
#     HIGH      → 15 pts
#     MEDIUM    →  7 pts
#     LOW       →  2 pts
#     N/A       →  1 pt
#
#   Raw sum is normalised to 0–100 using a soft-cap curve so a single
#   CRITICAL CVE doesn't immediately pin the meter at 100.
#
#   Final grade:
#     80–100 → CRITICAL EXPOSURE
#     60–79  → HIGH EXPOSURE
#     40–59  → MODERATE EXPOSURE
#     20–39  → LOW EXPOSURE
#     0–19   → MINIMAL EXPOSURE


# ── Severity weights ──────────────────────────────────────────────────────────

SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH":     15,
    "MEDIUM":    7,
    "LOW":       2,
    "N/A":       1,
}

# CVSS numeric ranges per severity (midpoint used for display)
CVSS_RANGES = {
    "CRITICAL": (9.0, 10.0),
    "HIGH":     (7.0,  8.9),
    "MEDIUM":   (4.0,  6.9),
    "LOW":      (0.1,  3.9),
    "N/A":      (0.0,  0.0),
}

# Soft-cap normalisation ceiling — raw score above this maps to 100
_RAW_CAP = 80


# ── Per-device CVE score ──────────────────────────────────────────────────────

def score_device_cves(cve_list: list) -> dict:
    """
    Calculates a CVE Risk Score for a single device.

    Args:
        cve_list : list of CVE dicts from module3.search_cves()
                   Each dict must have at least {'id', 'severity', 'description'}

    Returns:
        dict: {
            'raw':         int,       # weighted sum before normalisation
            'score':       int,       # 0–100 normalised score
            'grade':       str,       # 'CRITICAL EXPOSURE' / 'HIGH' / etc.
            'grade_color': str,       # ANSI-style label for GUI
            'counts': {
                'CRITICAL': int,
                'HIGH':     int,
                'MEDIUM':   int,
                'LOW':      int,
                'N/A':      int,
                'total':    int,
            },
            'worst_severity': str,    # highest severity found
            'cvss_midpoint':  float,  # midpoint of worst CVE's CVSS range
            'top_cves':  list,        # top 3 CVEs sorted by severity
        }
    """
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "N/A": 0}
    raw    = 0

    # Sort order for severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "N/A": 4}

    sorted_cves = sorted(
        cve_list,
        key=lambda c: sev_order.get(c.get("severity", "N/A"), 4)
    )

    for cve in cve_list:
        sev = cve.get("severity", "N/A").upper()
        if sev not in counts:
            sev = "N/A"
        counts[sev] += 1
        raw += SEVERITY_WEIGHTS.get(sev, 1)

    counts["total"] = len(cve_list)

    # Normalise to 0–100 with soft cap
    score = min(100, int((raw / _RAW_CAP) * 100)) if raw > 0 else 0

    # Grade
    if score >= 80:
        grade = "CRITICAL EXPOSURE"
        color = "#E74C3C"
    elif score >= 60:
        grade = "HIGH EXPOSURE"
        color = "#E67E22"
    elif score >= 40:
        grade = "MODERATE EXPOSURE"
        color = "#F1C40F"
    elif score >= 20:
        grade = "LOW EXPOSURE"
        color = "#2ECC71"
    else:
        grade = "MINIMAL EXPOSURE"
        color = "#27AE60"

    # Worst severity found
    worst = "N/A"
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if counts[s] > 0:
            worst = s
            break

    # CVSS midpoint for worst severity
    lo, hi     = CVSS_RANGES.get(worst, (0.0, 0.0))
    cvss_mid   = round((lo + hi) / 2, 1) if hi > 0 else 0.0

    return {
        "raw":           raw,
        "score":         score,
        "grade":         grade,
        "grade_color":   color,
        "counts":        counts,
        "worst_severity": worst,
        "cvss_midpoint": cvss_mid,
        "top_cves":      sorted_cves[:3],
    }


# ── Network-wide CVE score ────────────────────────────────────────────────────

def score_network_cves(cve_results: dict) -> dict:
    """
    Calculates an aggregate CVE Risk Score across all devices.

    Args:
        cve_results : dict mapping IP → list of CVE dicts
                      (the 'cve_results' key from module3 output)

    Returns:
        dict: {
            'network_score':     int,        # 0–100 overall CVE risk
            'network_grade':     str,
            'network_grade_color': str,
            'total_cves':        int,
            'per_device':        {ip: device_score_dict},
            'worst_device_ip':   str,        # IP with highest CVE score
            'severity_totals': {
                'CRITICAL': int,
                'HIGH':     int,
                'MEDIUM':   int,
                'LOW':      int,
                'N/A':      int,
            },
            'all_top_cves':      list,       # top 5 CVEs network-wide
        }
    """
    per_device     = {}
    severity_totals = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "N/A": 0}
    all_cves       = []
    total_raw      = 0
    worst_ip       = None
    worst_score    = -1

    for ip, cves in cve_results.items():
        ds = score_device_cves(cves)
        per_device[ip] = ds
        total_raw     += ds["raw"]
        all_cves.extend(cves)

        for sev in severity_totals:
            severity_totals[sev] += ds["counts"].get(sev, 0)

        if ds["score"] > worst_score:
            worst_score = ds["score"]
            worst_ip    = ip

    # Network-wide normalisation uses a slightly higher cap so multiple
    # devices can compound the score meaningfully
    network_cap   = _RAW_CAP * max(len(cve_results), 1)
    network_score = min(100, int((total_raw / network_cap) * 100)) if total_raw > 0 else 0

    if network_score >= 80:
        net_grade = "CRITICAL EXPOSURE"
        net_color = "#E74C3C"
    elif network_score >= 60:
        net_grade = "HIGH EXPOSURE"
        net_color = "#E67E22"
    elif network_score >= 40:
        net_grade = "MODERATE EXPOSURE"
        net_color = "#F1C40F"
    elif network_score >= 20:
        net_grade = "LOW EXPOSURE"
        net_color = "#2ECC71"
    else:
        net_grade = "MINIMAL EXPOSURE"
        net_color = "#27AE60"

    # Sort all CVEs network-wide and return top 5
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "N/A": 4}
    all_cves_sorted = sorted(
        all_cves,
        key=lambda c: sev_order.get(c.get("severity", "N/A"), 4)
    )

    return {
        "network_score":      network_score,
        "network_grade":      net_grade,
        "network_grade_color": net_color,
        "total_cves":         len(all_cves),
        "per_device":         per_device,
        "worst_device_ip":    worst_ip,
        "severity_totals":    severity_totals,
        "all_top_cves":       all_cves_sorted[:5],
    }


# ── CVSS range lookup (for display) ──────────────────────────────────────────

def cvss_range_str(severity: str) -> str:
    """Returns human-readable CVSS range string e.g. '9.0 – 10.0'."""
    lo, hi = CVSS_RANGES.get(severity.upper(), (0.0, 0.0))
    if hi == 0.0:
        return "N/A"
    return f"{lo:.1f} – {hi:.1f}"


def cvss_midpoint(severity: str) -> float:
    """Returns numeric midpoint of a severity's CVSS range."""
    lo, hi = CVSS_RANGES.get(severity.upper(), (0.0, 0.0))
    return round((lo + hi) / 2, 1) if hi > 0 else 0.0


# ── Standalone runner ─────────────────────────────────────────────────────────

def run_module8(m3_output: dict) -> dict:
    """
    Entry point called from the scan pipeline.

    Args:
        m3_output : full dict from module3.run_module3()

    Returns:
        dict with network_score, per_device scores, and severity totals.
        This dict is merged into the scan result and passed to the GUI.
    """
    cve_results = m3_output.get("cve_results", {})
    result      = score_network_cves(cve_results)

    print(f"  CVE Risk Score: {result['network_score']}/100 — {result['network_grade']}")
    print(f"  Total CVEs: {result['total_cves']}  |  "
          f"CRITICAL: {result['severity_totals']['CRITICAL']}  "
          f"HIGH: {result['severity_totals']['HIGH']}  "
          f"MEDIUM: {result['severity_totals']['MEDIUM']}")

    if result["worst_device_ip"]:
        wd = result["per_device"][result["worst_device_ip"]]
        print(f"  Worst device: {result['worst_device_ip']} "
              f"(score {wd['score']}/100 — {wd['grade']})")

    return result
