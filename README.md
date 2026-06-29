<div align="center">

# 🛡️ NetProbeSec
### IoT Security Assessment Framework

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)]()
[![Version](https://img.shields.io/badge/Version-1.0.0-teal)]()
[![Website](https://img.shields.io/badge/Website-net--probesec.com-0D9488)](https://net-probesec.com)

**A professional IoT vulnerability scanner with an 8-module security assessment pipeline,  
CVE scoring engine, PDF reporting, and a sleek dark-mode GUI.**

[🌐 Download & Docs](https://net-probesec.com) · [📄 Research Paper](https://thesesjournal.com/index.php/1/article/view/2556) · [🐛 Report a Bug](https://github.com/Asad2liaqat/NetProbe/issues)


</div>

---

## 📌 Overview

**NetProbeSec** (academic name: IoTGuard) is a Final Year Project developed at **The Islamia University of Bahawalpur** for the BS Cyber Security & Digital Forensics program. It provides security professionals, researchers, and network administrators with a comprehensive toolkit to **discover, analyze, and assess IoT devices** on a network.

The tool was showcased at **TechXhibit 2026** (Air University Multan Campus, ACM-W FYP Competition) and is accompanied by a **published research paper** (Impact Factor 4.5).

---

## ✨ Features — 8 Integrated Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | 🔍 **Device Discovery** | ARP-based network scanning to detect all connected IoT devices |
| 2 | 🧠 **Threat Intelligence** | Vendor lookup, device fingerprinting, and MAC OUI resolution |
| 3 | 🎯 **Vulnerability Assessment** | Port scanning, service detection, and security posture analysis |
| 4 | 🔴 **Red Team Simulation** | Simulated attack vectors to test device resilience |
| 5 | 📊 **CVE Scoring Engine** | Real-time NVD CVE correlation with CVSS-based risk ranking |
| 6 | 📄 **PDF Report Generator** | Automated professional security reports with remediation steps |
| 7 | 🗄️ **Storage & History** | SQLite-backed scan history with export to CSV/JSON |
| 8 | 👁️ **Watch Mode** | Continuous monitoring with email alerts for new/changed devices |

---

## 🖥️ GUI Highlights

- **Dark navy/teal design** — built with `CustomTkinter`
- **Responsive layout** — auto-scales to any screen resolution (DPI-aware on Windows)
- **Splash screen** with animated progress bar
- **Sidebar navigation** with 10 sections
- **Risk badges** — color-coded: CRITICAL 🔴 / High 🟠 / Weak 🟡 / Safe 🟢
- **Device label manager** — persistent friendly names per MAC address
- **Email alert system** — SMTP notifications on new device detection

---

## 🚀 Quick Start

### Prerequisites

```bash
Python 3.11+
Windows (recommended) or Linux
Administrator / root privileges required for raw packet capture
```

### Installation

```bash
# Clone the repository
git clone https://github.com/Asad2liaqat/NetProbe.git
cd NetProbe

# Install dependencies
pip install -r requirements.txt

# Run (Windows — as Administrator)
python gui.py

# Run (Linux — as root)
sudo python gui.py
```

### Or download the compiled release
👉 **[net-probesec.com](https://net-probesec.com)** — free download, no install required

---

## 📦 Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.11 |
| GUI | CustomTkinter |
| Packet Capture | Scapy |
| Database | SQLite |
| API Layer | Flask |
| PDF Reports | fpdf2 |
| CVE Data | NVD API |
| Alerts | SMTP / smtplib |

---

## 📄 Research Paper

This tool is backed by a peer-reviewed publication:

> **A Comprehensive Review of IoT Vulnerability Scanning: Active, Passive, and Hybrid Methodologies**  
> M.H. Hayat, **Asad Liaqat*** (corresponding), L. Shoaib  
> *Spectrum of Engineering Sciences*, Vol. 4, Issue 4 — April 2026  
> Impact Factor: **4.5**  
> 🔗 [Read Paper](https://thesesjournal.com/index.php/1/article/view/2556)

---

## 👥 Team

| Name | Role |
|------|------|
| **Asad Liaqat** | Lead Developer, Corresponding Author |
| Muhammad Hamza Hayat | Co-Developer, Co-Author |
| Laiba Shoaib | Co-Developer, Co-Author |
| Dr. Abdul Rehman Chishti | Supervisor |

**Institution:** The Islamia University of Bahawalpur (IUB)  
**Program:** BS Cyber Security & Digital Forensics  
**Year:** 2024–2026

---

## 🏆 Recognition

- 🥇 **TechXhibit 2026** — Certificate of Appreciation  
  Air University Multan Campus, ACM-W FYP Competition (May 2026)

---

## 📬 Contact

**Asad Liaqat**  
📧 asad2liaqat@gmail.com  
🔗 [LinkedIn](https://linkedin.com/in/asad-liaqat)  
🌐 [net-probesec.com](https://net-probesec.com)

---

## ⚠️ Disclaimer

NetProbeSec is intended for **authorized security testing only**. Only scan networks you own or have explicit written permission to test. The authors are not responsible for any misuse of this tool.

---

<div align="center">
© 2026 NetProbeSec · net-probesec.com · All rights reserved
</div>
