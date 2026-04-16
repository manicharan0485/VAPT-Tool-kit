# 🔍 VAPT Toolkit

> **Personal Vulnerability Assessment & Penetration Testing automation scripts.**  
> Python + Bash tools built from real-world VAPT engagements — recon, scanning, exploitation assistance, and professional report generation.

![Python](https://img.shields.io/badge/Python-3776AB?style=flat&logo=python&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-4EAA25?style=flat&logo=gnubash&logoColor=white)
![Nmap](https://img.shields.io/badge/Nmap-0E83CD?style=flat)
![Metasploit](https://img.shields.io/badge/Metasploit-2596CD?style=flat)
![License](https://img.shields.io/badge/License-MIT-green)

---

> ⚠️ **DISCLAIMER**: These tools are for **authorized penetration testing and security research only**.  
> Unauthorized use against systems you do not own or have explicit permission to test is illegal.  
> Always obtain written authorization before conducting any security assessment.  
> See [DISCLAIMER.md](DISCLAIMER.md) for full terms.

---

## 📂 Structure

```
vapt-toolkit/
│
├── scripts/
│   ├── recon/
│   │   ├── passive_recon.py        # OSINT: WHOIS, DNS, Shodan, crt.sh
│   │   ├── subdomain_enum.py       # Subdomain enumeration via multiple sources
│   │   └── tech_fingerprint.py     # Detect web stack (headers, cookies, errors)
│   │
│   ├── scanning/
│   │   ├── nmap_wrapper.py         # Nmap automation with profile selection
│   │   ├── port_scanner.py         # Fast async TCP port scanner (no nmap dep)
│   │   ├── vuln_scanner.py         # CVE lookup via NVD API for detected services
│   │   └── ssl_checker.py          # TLS/SSL misconfiguration checker
│   │
│   ├── exploitation/
│   │   ├── msf_automation.py       # Metasploit RPC API automation
│   │   └── web_fuzzer.py           # Directory/parameter fuzzing (ffuf wrapper)
│   │
│   ├── reporting/
│   │   ├── report_generator.py     # HTML pentest report from JSON findings
│   │   └── cvss_calculator.py      # CVSS v3.1 score calculator
│   │
│   └── utils/
│       ├── scope_validator.py      # Validate targets are in-scope before testing
│       └── logger.py               # Structured logging for all tools
│
├── payloads/web/                   # Web testing payloads (XSS, SQLi patterns)
├── reports/templates/              # HTML report templates
├── wordlists/                      # Custom wordlists (NOT included — see setup)
└── docs/
    ├── SETUP.md
    └── METHODOLOGY.md
```

---

## 🚀 Quick Start

```bash
pip install -r requirements.txt

# 1. Passive recon
python scripts/recon/passive_recon.py --target example.com --output ./reports

# 2. Port scan
python scripts/scanning/nmap_wrapper.py --target 192.168.1.0/24 --profile discovery

# 3. CVE lookup from scan results
python scripts/scanning/vuln_scanner.py --input ./reports/nmap_results.json

# 4. SSL/TLS check
python scripts/scanning/ssl_checker.py --target example.com --port 443

# 5. Generate pentest report
python scripts/reporting/report_generator.py --input ./reports/findings.json --output ./reports/report
```

---

## 🔍 Tool Overview

| Tool | Purpose |
|------|---------|
| `passive_recon.py` | WHOIS, DNS enum, crt.sh, Shodan, dork builder |
| `nmap_wrapper.py` | Nmap profiles: discovery / quick / full / stealth / vuln |
| `port_scanner.py` | Async TCP scanner — no nmap dependency |
| `vuln_scanner.py` | Parse nmap XML → NVD API → CVE report |
| `ssl_checker.py` | Weak protocols, cipher suites, cert expiry, Heartbleed |
| `msf_automation.py` | Metasploit RPC: search modules, run exploits, collect results |
| `report_generator.py` | Professional HTML pentest report with CVSS ratings |
| `cvss_calculator.py` | CVSS v3.1 base score calculator |
| `scope_validator.py` | Block out-of-scope targets before any test |

---

## 📋 Methodology (PTES-based)

1. Pre-engagement → scope validation (`scope_validator.py`)
2. Intelligence Gathering → passive recon (`passive_recon.py`)
3. Vulnerability Analysis → scanning + CVE lookup
4. Exploitation → controlled, authorized only
5. Reporting → risk-rated findings + remediation steps

---

## 📄 License

MIT — For authorized security testing only. See DISCLAIMER.md.

---

## 👤 Author

**Manicharan Ravi** — Cloud Security Engineer | VAPT Specialist  
📍 Mainz, Germany | 🔐 AWS · Azure · GCP · VAPT · Metasploit · Nmap
