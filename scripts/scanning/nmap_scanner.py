#!/usr/bin/env python3
"""
nmap_scanner.py
─────────────────────────────────────────────────────────────────────────────
Nmap automation with structured JSON output and CVE correlation.

Scan profiles:
  quick   — Top 100 ports, fast (-T4)
  full    — All 65535 ports + service/version detection
  stealth — SYN scan (-sS), slower timing (-T2), less noisy
  vuln    — Default scripts + vuln detection scripts (--script vuln)
  web     — HTTP/HTTPS focused (80, 443, 8080, 8443, 8000)

Usage:
    python nmap_scanner.py --target 192.168.1.1
    python nmap_scanner.py --target 192.168.1.0/24 --profile full
    python nmap_scanner.py --target 10.0.0.1 --profile vuln --output ./reports

⚠️  Use only on systems you own or have written authorization to test.

Author:  Manicharan Ravi
Version: 1.3.0
"""

import argparse
import json
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path


SCAN_PROFILES = {
    "quick": {
        "args": ["-sV", "-sC", "--top-ports", "100", "-T4", "-oX"],
        "desc": "Top 100 ports, fast, service detection"
    },
    "full": {
        "args": ["-sV", "-sC", "-p-", "-T4", "--open", "-oX"],
        "desc": "All 65535 ports, service/version detection"
    },
    "stealth": {
        "args": ["-sS", "-sV", "--top-ports", "1000", "-T2", "-oX"],
        "desc": "SYN scan, slow/quiet, top 1000 ports (requires root)"
    },
    "vuln": {
        "args": ["-sV", "-sC", "--script", "vuln", "-p-", "-T4", "-oX"],
        "desc": "Vulnerability detection scripts (slow but thorough)"
    },
    "web": {
        "args": ["-sV", "-sC", "-p", "80,443,8080,8443,8000,8888,3000,5000",
                 "--script", "http-headers,http-title,ssl-cert,ssl-enum-ciphers", "-oX"],
        "desc": "HTTP/HTTPS focused scan with SSL/TLS analysis"
    },
}

# Port → service → known risk mapping
RISKY_PORTS = {
    21:    ("FTP",        "MEDIUM", "FTP transmits credentials in plaintext"),
    22:    ("SSH",        "INFO",   "SSH — check version for known CVEs"),
    23:    ("Telnet",     "HIGH",   "Telnet transmits all data in plaintext — replace with SSH"),
    25:    ("SMTP",       "MEDIUM", "SMTP — check for open relay"),
    53:    ("DNS",        "INFO",   "DNS — check for zone transfer, recursion"),
    80:    ("HTTP",       "MEDIUM", "HTTP — unencrypted web traffic"),
    110:   ("POP3",       "MEDIUM", "POP3 — plaintext email retrieval"),
    111:   ("RPCbind",    "MEDIUM", "RPCbind — often leads to NFS enumeration"),
    135:   ("MSRPC",      "MEDIUM", "MSRPC — Windows RPC, often exploitable"),
    139:   ("NetBIOS",    "HIGH",   "NetBIOS — Windows file sharing, SMB vulnerabilities"),
    143:   ("IMAP",       "MEDIUM", "IMAP — check for plaintext auth"),
    389:   ("LDAP",       "MEDIUM", "LDAP — check for anonymous bind"),
    443:   ("HTTPS",      "INFO",   "HTTPS — check SSL/TLS version and ciphers"),
    445:   ("SMB",        "HIGH",   "SMB — EternalBlue, ransomware vector — patch immediately"),
    512:   ("rexec",      "HIGH",   "rexec — legacy remote exec, replace with SSH"),
    513:   ("rlogin",     "HIGH",   "rlogin — legacy, unauthenticated access possible"),
    514:   ("rsh",        "HIGH",   "rsh — legacy, plaintext remote shell"),
    873:   ("rsync",      "MEDIUM", "rsync — check for unauthenticated access"),
    1433:  ("MSSQL",      "HIGH",   "MSSQL — check for default credentials, xp_cmdshell"),
    1521:  ("Oracle DB",  "HIGH",   "Oracle DB — check for default passwords"),
    2049:  ("NFS",        "HIGH",   "NFS — check for world-readable exports"),
    3306:  ("MySQL",      "HIGH",   "MySQL — should not be internet-facing"),
    3389:  ("RDP",        "HIGH",   "RDP — BlueKeep, DejaBlue — check version and exposure"),
    4444:  ("Metasploit", "CRITICAL","Port 4444 — potential active reverse shell/malware"),
    5432:  ("PostgreSQL", "HIGH",   "PostgreSQL — should not be internet-facing"),
    5900:  ("VNC",        "HIGH",   "VNC — often weak auth, plaintext"),
    6379:  ("Redis",      "HIGH",   "Redis — often unauthenticated by default"),
    8080:  ("HTTP-Alt",   "MEDIUM", "HTTP alternative — may expose admin interfaces"),
    8443:  ("HTTPS-Alt",  "INFO",   "HTTPS alternative"),
    9200:  ("Elasticsearch","HIGH", "Elasticsearch — often unauthenticated, data exposure"),
    27017: ("MongoDB",    "HIGH",   "MongoDB — often unauthenticated by default"),
}


class NmapScanner:
    def __init__(self, target: str, profile: str = "quick",
                 output_dir: str = "./reports", verbose: bool = False):
        self.target     = target
        self.profile    = profile
        self.output_dir = Path(output_dir)
        self.verbose    = verbose
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _check_nmap(self) -> bool:
        if not shutil.which("nmap"):
            print("[ERROR] nmap not found. Install: sudo apt-get install nmap")
            return False
        return True

    def run_scan(self) -> dict:
        if not self._check_nmap():
            sys.exit(1)

        profile_cfg = SCAN_PROFILES.get(self.profile, SCAN_PROFILES["quick"])
        ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
        xml_out     = self.output_dir / f"nmap_{self.target.replace('/', '_')}_{ts}.xml"

        cmd = ["nmap"] + profile_cfg["args"] + [str(xml_out), self.target]

        print(f"[SCAN] Target  : {self.target}")
        print(f"[SCAN] Profile : {self.profile} — {profile_cfg['desc']}")
        print(f"[SCAN] Command : {' '.join(cmd)}")
        print(f"[SCAN] Output  : {xml_out}\n")

        try:
            proc = subprocess.run(cmd, capture_output=not self.verbose,
                                  text=True, timeout=3600)
            if proc.returncode != 0 and self.verbose:
                print(f"[WARN] nmap stderr: {proc.stderr[:500]}")
        except subprocess.TimeoutExpired:
            print("[ERROR] Scan timed out after 1 hour")
            sys.exit(1)
        except FileNotFoundError:
            print("[ERROR] nmap binary not found")
            sys.exit(1)

        return self.parse_xml(str(xml_out))

    def parse_xml(self, xml_path: str) -> dict:
        """Parse Nmap XML output into structured dict."""
        if not Path(xml_path).exists():
            print(f"[ERROR] XML output not found: {xml_path}")
            return {}

        tree = ET.parse(xml_path)
        root = tree.getroot()

        results = {
            "scan_info":  {},
            "hosts":      [],
            "findings":   [],
            "statistics": {}
        }

        # Scan metadata
        run_stats = root.find("runstats/finished")
        results["scan_info"] = {
            "target":    self.target,
            "profile":   self.profile,
            "timestamp": datetime.utcnow().isoformat(),
            "nmap_version": root.attrib.get("version", ""),
            "elapsed":   run_stats.attrib.get("elapsed", "") if run_stats is not None else "",
        }

        # Parse hosts
        for host in root.findall("host"):
            status = host.find("status")
            if status is None or status.attrib.get("state") != "up":
                continue

            # IP address
            addr_el = host.find("address[@addrtype='ipv4']")
            if addr_el is None:
                addr_el = host.find("address[@addrtype='ipv6']")
            ip = addr_el.attrib.get("addr", "unknown") if addr_el is not None else "unknown"

            # Hostname
            hostname_el = host.find("hostnames/hostname")
            hostname = hostname_el.attrib.get("name", "") if hostname_el is not None else ""

            # OS detection
            os_el = host.find("os/osmatch")
            os_info = os_el.attrib.get("name", "Unknown") if os_el is not None else "Unknown"

            host_data = {
                "ip":       ip,
                "hostname": hostname,
                "os":       os_info,
                "ports":    [],
            }

            # Ports
            for port_el in host.findall("ports/port"):
                state_el   = port_el.find("state")
                service_el = port_el.find("service")
                if state_el is None or state_el.attrib.get("state") != "open":
                    continue

                portnum = int(port_el.attrib.get("portid", 0))
                proto   = port_el.attrib.get("protocol", "tcp")
                service = service_el.attrib.get("name", "") if service_el is not None else ""
                product = service_el.attrib.get("product", "") if service_el is not None else ""
                version = service_el.attrib.get("version", "") if service_el is not None else ""
                extra   = service_el.attrib.get("extrainfo", "") if service_el is not None else ""

                # Script output
                scripts = {}
                for script in port_el.findall("script"):
                    scripts[script.attrib.get("id", "")] = script.attrib.get("output", "")

                port_data = {
                    "port":    portnum,
                    "proto":   proto,
                    "service": service,
                    "product": product,
                    "version": version,
                    "extra":   extra,
                    "scripts": scripts,
                }
                host_data["ports"].append(port_data)

                # Risk assessment
                if portnum in RISKY_PORTS:
                    svc_name, severity, detail = RISKY_PORTS[portnum]
                    results["findings"].append({
                        "host":      ip,
                        "port":      portnum,
                        "service":   product or svc_name,
                        "version":   version,
                        "severity":  severity,
                        "detail":    detail,
                    })

            host_data["open_port_count"] = len(host_data["ports"])
            results["hosts"].append(host_data)

        results["statistics"] = {
            "hosts_up":      len(results["hosts"]),
            "total_findings": len(results["findings"]),
            "critical":      sum(1 for f in results["findings"] if f["severity"] == "CRITICAL"),
            "high":          sum(1 for f in results["findings"] if f["severity"] == "HIGH"),
            "medium":        sum(1 for f in results["findings"] if f["severity"] == "MEDIUM"),
        }

        # Save parsed JSON
        json_out = xml_path.replace(".xml", ".json")
        Path(json_out).write_text(json.dumps(results, indent=2))
        print(f"[INFO] JSON results: {json_out}")

        return results


def print_summary(results: dict):
    stats = results.get("statistics", {})
    print(f"\n{'='*55}")
    print(f"  Scan Summary")
    print(f"{'='*55}")
    print(f"  Hosts up     : {stats.get('hosts_up', 0)}")
    print(f"  Findings     : {stats.get('total_findings', 0)}")
    print(f"  CRITICAL     : {stats.get('critical', 0)}")
    print(f"  HIGH         : {stats.get('high', 0)}")
    print(f"  MEDIUM       : {stats.get('medium', 0)}")

    for host in results.get("hosts", []):
        print(f"\n  Host: {host['ip']} ({host.get('hostname','')}) — {host.get('os','')}")
        for p in host.get("ports", []):
            ver = f" v{p['version']}" if p.get("version") else ""
            print(f"    {p['port']:<6}/{p['proto']}  {p.get('product', p['service'])}{ver}")

    if results.get("findings"):
        print(f"\n  Findings:")
        for f in sorted(results["findings"], key=lambda x: ["CRITICAL","HIGH","MEDIUM","INFO"].index(x["severity"])):
            print(f"    [{f['severity']:<8}] {f['host']}:{f['port']} {f['service']} — {f['detail'][:60]}")
    print(f"{'='*55}\n")


def main():
    parser = argparse.ArgumentParser(description="Nmap Scanner — authorized use only")
    parser.add_argument("--target",  required=True, help="IP, hostname, or CIDR range")
    parser.add_argument("--profile", default="quick",
                        choices=list(SCAN_PROFILES.keys()), help="Scan profile")
    parser.add_argument("--output",  default="./reports")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    print(f"\n⚠️  AUTHORIZED USE ONLY — ensure you have written permission to scan {args.target}\n")

    scanner = NmapScanner(args.target, args.profile, args.output, args.verbose)
    results = scanner.run_scan()
    print_summary(results)


if __name__ == "__main__":
    main()
