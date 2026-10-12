# 🔍 VAPT Toolkit

> **Personal Vulnerability Assessment & Penetration Testing automation scripts.**  
> Python tools for practising a VAPT workflow in authorised lab environments: recon, scanning, CVE lookup and report generation.

> 🧪 **Reference / lab project.** Original practice code written to demonstrate the approach. It is not taken from an employer's codebase. Review and adapt before using it in your own environment.

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
│   │   └── dns_recon.py            # DNS record enumeration
│   │
│   ├── scanning/
│   │   ├── nmap_wrapper.py         # Nmap automation with profile selection
│   │   ├── nmap_scanner.py         # Nmap scan runner with XML/JSON output
│   │   ├── vuln_scanner.py         # CVE lookup via NVD API for detected services
│   │   └── ssl_checker.py          # TLS/SSL misconfiguration checker
│   │
│   ├── reporting/
│   │   ├── report_generator.py     # HTML pentest report from JSON findings
│   │   └── cvss_calculator.py      # CVSS v3.1 score calculator
│   │
│   └── utils/
│       └── cve_lookup.py           # CVE details from the NVD API
│
├── reports/templates/
│   └── sample_findings.json        # Example findings input for the report generator
├── docs/
│   └── LEGAL.md                    # Authorisation and legal notes
├── DISCLAIMER.md
└── requirements.txt
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
python scripts/reporting/report_generator.py --input ./reports/templates/sample_findings.json --output ./reports/report
```

---

## 🔍 Tool Overview

| Tool | Purpose |
|------|---------|
| `passive_recon.py` | WHOIS, DNS enum, crt.sh, Shodan, dork builder |
| `nmap_wrapper.py` | Nmap profiles: discovery / quick / full / stealth / vuln |
| `vuln_scanner.py` | Parse nmap XML → NVD API → CVE report |
| `ssl_checker.py` | Weak protocols, cipher suites, cert expiry, Heartbleed |
| `report_generator.py` | Professional HTML pentest report with CVSS ratings |
| `cvss_calculator.py` | CVSS v3.1 base score calculator |

---

## 📋 Methodology (PTES-based)

1. Pre-engagement → written authorisation and agreed scope (see `docs/LEGAL.md`)
2. Intelligence Gathering → passive recon (`passive_recon.py`)
3. Vulnerability Analysis → scanning + CVE lookup
4. Exploitation → controlled, authorized only
5. Reporting → risk-rated findings + remediation steps

---

## 📄 License

MIT — For authorized security testing only. See DISCLAIMER.md.

---

## 👤 Author

**Manicharan Ravi** — IT Specialist & Cloud Engineer  
📍 Mainz, Germany | 🔐 AWS · Azure · GCP · VAPT · Metasploit · Nmap
