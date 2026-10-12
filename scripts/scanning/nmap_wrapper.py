#!/usr/bin/env python3
"""
nmap_wrapper.py
─────────────────────────────────────────────────────────────────────────────
Nmap automation wrapper with preset scan profiles.

Profiles:
  discovery  — Host discovery only (ping sweep), no port scan
  quick      — Top 100 ports, service detection
  full       — All 65535 ports, service + OS detection
  stealth    — SYN scan, slow timing (T2), evasion-friendly
  vuln       — Service detection + NSE vuln scripts
  web        — Web-focused: HTTP methods, headers, common web CVEs

Output:
  - Nmap XML (for downstream processing)
  - JSON summary
  - Human-readable table

Requirements:
    nmap installed on system + pip install python-nmap

Usage:
    python nmap_wrapper.py --target 192.168.1.0/24 --profile discovery
    python nmap_wrapper.py --target 10.0.0.1 --profile vuln --output ./reports
    python nmap_wrapper.py --target example.com --profile web

Author:  Manicharan Ravi
Version: 1.1.0
"""

import argparse
import json
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Scan profiles
# ─────────────────────────────────────────────────────────────────────────────

PROFILES = {
    "discovery": {
        "description": "Host discovery — ping sweep only",
        "args": "-sn -T4 --open",
    },
    "quick": {
        "description": "Top 100 ports, service detection",
        "args": "-sV -sC -T4 --top-ports 100 --open",
    },
    "full": {
        "description": "All ports, service + OS detection",
        "args": "-sV -sC -O -T4 -p- --open",
    },
    "stealth": {
        "description": "SYN scan, slow timing (T2), reduced detection",
        "args": "-sS -T2 -p- --open --randomize-hosts",
    },
    "vuln": {
        "description": "Service detection + vulnerability NSE scripts",
        "args": "-sV -sC -T4 --open --script=vuln,exploit,auth -p-",
    },
    "web": {
        "description": "Web-focused: HTTP analysis, web vulnerability scripts",
        "args": "-sV -T4 --open -p 80,443,8080,8443,8000,8888 "
                "--script=http-methods,http-headers,http-auth,http-shellshock,"
                "http-sql-injection,http-stored-xss,http-csrf,http-title",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Scope validator (always check before scanning)
# ─────────────────────────────────────────────────────────────────────────────

def confirm_scope(target: str) -> bool:
    print(f"\n⚠️  SCOPE CONFIRMATION")
    print(f"   Target  : {target}")
    print(f"   You MUST have written authorization to scan this target.")
    confirm = input("   Type 'YES I HAVE AUTHORIZATION' to continue: ").strip()
    return confirm == "YES I HAVE AUTHORIZATION"


# ─────────────────────────────────────────────────────────────────────────────
# Run nmap
# ─────────────────────────────────────────────────────────────────────────────

def run_nmap(target: str, profile: str, output_prefix: str) -> tuple[int, str, str]:
    if profile not in PROFILES:
        print(f"Unknown profile: {profile}. Choose from: {list(PROFILES.keys())}")
        sys.exit(1)

    p    = PROFILES[profile]
    xml  = f"{output_prefix}.xml"
    args = p["args"]

    cmd = f"nmap {args} -oX {xml} {target}"
    print(f"\n[*] Profile   : {profile} — {p['description']}")
    print(f"[*] Command   : {cmd}")
    print(f"[*] Output    : {xml}")
    print(f"[*] Started   : {datetime.now().strftime('%H:%M:%S')}\n")

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.returncode, result.stdout, xml


# ─────────────────────────────────────────────────────────────────────────────
# Parse nmap XML
# ─────────────────────────────────────────────────────────────────────────────

def parse_nmap_xml(xml_file: str) -> dict:
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
    except Exception as e:
        return {"error": f"XML parse failed: {e}"}

    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        # Get IP
        addr = host.find("address[@addrtype='ipv4']")
        ip   = addr.get("addr") if addr is not None else "unknown"

        # Get hostname
        hostnames_el = host.find("hostnames")
        hostnames = []
        if hostnames_el is not None:
            hostnames = [h.get("name") for h in hostnames_el.findall("hostname")]

        # Get OS
        os_el  = host.find("os/osmatch")
        os_str = os_el.get("name") if os_el is not None else "unknown"

        # Get ports
        ports = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state_el   = port.find("state")
                service_el = port.find("service")
                if state_el is not None and state_el.get("state") == "open":
                    scripts = []
                    for script in port.findall("script"):
                        scripts.append({
                            "id":     script.get("id"),
                            "output": script.get("output", "")[:200],
                        })
                    ports.append({
                        "port":     int(port.get("portid")),
                        "protocol": port.get("protocol"),
                        "service":  service_el.get("name", "") if service_el is not None else "",
                        "product":  service_el.get("product", "") if service_el is not None else "",
                        "version":  service_el.get("version", "") if service_el is not None else "",
                        "scripts":  scripts,
                    })

        hosts.append({
            "ip":        ip,
            "hostnames": hostnames,
            "os":        os_str,
            "ports":     ports,
            "open_ports_count": len(ports),
        })

    return {
        "scan_time":    root.get("startstr", ""),
        "hosts_up":     len(hosts),
        "hosts":        hosts,
        "args":         root.get("args", ""),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Report
# ─────────────────────────────────────────────────────────────────────────────

def generate_report(parsed: dict, profile: str, output_prefix: str) -> None:
    json_path = f"{output_prefix}.json"
    Path(json_path).write_text(json.dumps(parsed, indent=2))

    html_path = f"{output_prefix}.html"

    host_rows = ""
    for h in parsed.get("hosts", []):
        port_rows = "".join(
            f"<tr><td>{p['port']}/{p['protocol']}</td>"
            f"<td>{p['service']}</td>"
            f"<td>{p['product']} {p['version']}</td>"
            f"<td style='font-size:.8em'>"
            + "".join(f"<b>{s['id']}:</b> {s['output'][:80]}<br>" for s in p['scripts'])
            + "</td></tr>"
            for p in h["ports"]
        )
        port_table = (
            f"<table style='margin-top:8px'>"
            f"<tr><th>Port</th><th>Service</th><th>Version</th><th>Script Output</th></tr>"
            f"{port_rows}</table>"
            if h["ports"] else "<p style='color:#888'>No open ports found.</p>"
        )
        host_rows += f"""<div class='host'>
            <h3>🖥 {h['ip']} {(' / ' + ', '.join(h['hostnames'])) if h['hostnames'] else ''}
            <span style='font-size:.8em;color:#888;font-weight:400'>OS: {h['os']} | {h['open_ports_count']} open ports</span></h3>
            {port_table}
        </div>"""

    html = f"""<!DOCTYPE html><html><head><meta charset='UTF-8'>
<title>Nmap Scan — {profile}</title>
<style>
body{{font-family:Segoe UI,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}}
header{{background:linear-gradient(135deg,#161b22,#21262d);border-bottom:1px solid #30363d;padding:24px 40px}}
header h1{{margin:0;color:#58a6ff}} header p{{margin:5px 0 0;color:#8b949e}}
main{{padding:30px 40px}}
.host{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px 22px;margin-bottom:16px}}
h3{{margin:0 0 10px;color:#79c0ff;font-size:1em}}
table{{width:100%;border-collapse:collapse;font-size:.85em}}
th{{background:#21262d;color:#8b949e;padding:7px 10px;text-align:left}}
td{{padding:6px 10px;border-bottom:1px solid #21262d;vertical-align:top}}
.kpi{{display:inline-block;background:#21262d;padding:10px 20px;border-radius:8px;margin:5px;text-align:center}}
.kv{{font-size:1.8em;font-weight:700;color:#58a6ff}} .kl{{font-size:.8em;color:#8b949e}}
</style></head><body>
<header>
  <h1>🔍 Nmap Scan Results — {profile.upper()} Profile</h1>
  <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} | {parsed.get('args','')[:100]}</p>
</header>
<main>
<div>
  <span class='kpi'><div class='kv'>{parsed.get('hosts_up',0)}</div><div class='kl'>Hosts Up</div></span>
  <span class='kpi'><div class='kv'>{sum(h['open_ports_count'] for h in parsed.get('hosts',[]))}</div><div class='kl'>Open Ports</div></span>
</div><br>
{host_rows or "<p>No live hosts found.</p>"}
</main></body></html>"""

    Path(html_path).write_text(html, encoding="utf-8")
    print(f"\n✅ Scan complete")
    print(f"   Hosts up  : {parsed.get('hosts_up', 0)}")
    print(f"   JSON      : {json_path}")
    print(f"   HTML      : {html_path}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Nmap wrapper with scan profiles")
    parser.add_argument("--target",       required=True)
    parser.add_argument("--profile",      default="quick", choices=list(PROFILES.keys()))
    parser.add_argument("--output",       default="./reports")
    parser.add_argument("--no-confirm",   action="store_true", help="Skip scope confirmation (use in lab only)")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_prefix = str(output_dir / f"nmap_{args.profile}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

    if not args.no_confirm and not confirm_scope(args.target):
        print("Scan cancelled.")
        sys.exit(0)

    rc, stdout, xml_file = run_nmap(args.target, args.profile, output_prefix)
    if rc != 0:
        print(f"[WARN] Nmap exited with code {rc}")

    parsed = parse_nmap_xml(xml_file)
    generate_report(parsed, args.profile, output_prefix)


if __name__ == "__main__":
    main()
