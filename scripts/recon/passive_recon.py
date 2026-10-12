#!/usr/bin/env python3
"""
passive_recon.py
─────────────────────────────────────────────────────────────────────────────
Passive reconnaissance / OSINT gathering tool.

Collects publicly available information without directly interacting with
the target's systems. All data sourced from public APIs and databases.

Gathers:
  - WHOIS (domain registration, registrar, nameservers)
  - DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA)
  - Certificate transparency (crt.sh — subdomains, cert history)
  - Shodan host info (requires free API key)
  - Google dork query builder

Requirements:
    pip install python-whois dnspython requests shodan

Usage:
    python passive_recon.py --target example.com
    python passive_recon.py --target 192.168.1.1 --output ./reports
    python passive_recon.py --target example.com --shodan-key YOUR_KEY

Author:  Manicharan Ravi
Version: 1.2.0
"""

import argparse
import json
import socket
import sys
from datetime import datetime
from pathlib import Path

import requests


# ─────────────────────────────────────────────────────────────────────────────
# Scope check
# ─────────────────────────────────────────────────────────────────────────────

def validate_not_private(target: str) -> bool:
    """Warn if target resolves to a private/reserved IP."""
    import ipaddress
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            print(f"[WARN] {target} is a private/reserved address — passive recon may yield no results.")
            return False
    except ValueError:
        pass  # It's a domain name, not an IP
    return True


# ─────────────────────────────────────────────────────────────────────────────
# WHOIS
# ─────────────────────────────────────────────────────────────────────────────

def whois_lookup(target: str) -> dict:
    try:
        import whois
        w = whois.whois(target)
        return {
            "domain_name":  str(w.domain_name),
            "registrar":    str(w.registrar),
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": list(w.name_servers) if w.name_servers else [],
            "emails":       list(w.emails) if w.emails else [],
            "org":          str(w.org),
            "country":      str(w.country),
        }
    except ImportError:
        return {"error": "python-whois not installed. Run: pip install python-whois"}
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# DNS Enumeration
# ─────────────────────────────────────────────────────────────────────────────

def dns_enum(target: str) -> dict:
    try:
        import dns.resolver
        import dns.reversename
    except ImportError:
        return {"error": "dnspython not installed. Run: pip install dnspython"}

    results = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(target, rtype)
            results[rtype] = [str(r) for r in answers]
        except Exception:
            results[rtype] = []

    # Reverse DNS on A records
    reverse_dns = {}
    for ip in results.get("A", []):
        try:
            rev = dns.reversename.from_address(ip)
            host = str(dns.resolver.resolve(rev, "PTR")[0])
            reverse_dns[ip] = host
        except Exception:
            reverse_dns[ip] = "No PTR record"
    results["PTR"] = reverse_dns

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Certificate Transparency (crt.sh)
# ─────────────────────────────────────────────────────────────────────────────

def crtsh_lookup(domain: str) -> dict:
    """Query crt.sh for certificates — reveals subdomains."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        data = r.json()

        subdomains = set()
        certs = []
        for entry in data[:50]:  # Limit to 50 most recent
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub and sub.endswith(domain):
                    subdomains.add(sub)
            certs.append({
                "id":         entry.get("id"),
                "common_name": entry.get("common_name"),
                "issuer":     entry.get("issuer_name", "")[:80],
                "not_before": entry.get("not_before", "")[:10],
                "not_after":  entry.get("not_after", "")[:10],
            })

        return {
            "subdomains_found": sorted(subdomains),
            "subdomain_count":  len(subdomains),
            "recent_certs":     certs[:10],
        }
    except requests.RequestException as e:
        return {"error": f"crt.sh request failed: {e}"}


# ─────────────────────────────────────────────────────────────────────────────
# Shodan (optional)
# ─────────────────────────────────────────────────────────────────────────────

def shodan_lookup(target: str, api_key: str) -> dict:
    if not api_key:
        return {"skipped": "No Shodan API key provided. Get free key at shodan.io"}
    try:
        import shodan
        api = shodan.Shodan(api_key)
        # Resolve domain to IP first
        try:
            ip = socket.gethostbyname(target)
        except Exception:
            ip = target
        host = api.host(ip)
        return {
            "ip":           host.get("ip_str"),
            "org":          host.get("org"),
            "isp":          host.get("isp"),
            "country":      host.get("country_name"),
            "city":         host.get("city"),
            "open_ports":   host.get("ports", []),
            "hostnames":    host.get("hostnames", []),
            "os":           host.get("os"),
            "vulns":        list(host.get("vulns", [])),
            "services": [
                {
                    "port":    s.get("port"),
                    "product": s.get("product", ""),
                    "version": s.get("version", ""),
                    "banner":  s.get("data", "")[:100],
                }
                for s in host.get("data", [])[:10]
            ],
        }
    except ImportError:
        return {"error": "shodan not installed. Run: pip install shodan"}
    except Exception as e:
        return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Google Dork Builder
# ─────────────────────────────────────────────────────────────────────────────

def build_dorks(target: str) -> list:
    """Build Google dork queries for manual use."""
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    return [
        {"description": "Exposed login pages",        "query": f"site:{domain} inurl:login OR inurl:admin OR inurl:wp-admin"},
        {"description": "Config/backup files",         "query": f"site:{domain} ext:env OR ext:bak OR ext:config OR ext:sql"},
        {"description": "Directory listings",          "query": f"site:{domain} intitle:\"Index of /\""},
        {"description": "Exposed sensitive files",     "query": f"site:{domain} filetype:pdf OR filetype:xls OR filetype:doc confidential"},
        {"description": "API endpoints",               "query": f"site:{domain} inurl:api OR inurl:v1 OR inurl:v2 OR inurl:swagger"},
        {"description": "Error messages",              "query": f"site:{domain} \"SQL syntax\" OR \"stack trace\" OR \"Exception\""},
        {"description": "Subdomains",                  "query": f"site:*.{domain} -www"},
        {"description": "Email addresses",             "query": f"\"@{domain}\" -site:{domain}"},
        {"description": "Cached pages",                "query": f"cache:{domain}"},
        {"description": "LinkedIn employees",          "query": f"site:linkedin.com/in \"at {domain.split('.')[0]}\""},
    ]


# ─────────────────────────────────────────────────────────────────────────────
# Report Generator
# ─────────────────────────────────────────────────────────────────────────────

def generate_report(target: str, results: dict, output_dir: Path) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")

    # JSON dump
    json_path = output_dir / f"recon_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    json_path.write_text(json.dumps(results, indent=2, default=str))

    # HTML report
    def section(title: str, content: str) -> str:
        return f"<section><h2>{title}</h2>{content}</section>"

    def kv_table(data: dict) -> str:
        if not data or "error" in data:
            return f"<p class='err'>{data.get('error','No data')}</p>"
        rows = "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in data.items())
        return f"<table><tr><th>Field</th><th>Value</th></tr>{rows}</table>"

    def list_block(items: list) -> str:
        if not items:
            return "<p>None found.</p>"
        return "<ul>" + "".join(f"<li><code>{i}</code></li>" for i in items) + "</ul>"

    # DNS section
    dns_data = results.get("dns", {})
    dns_html = ""
    for rtype, records in dns_data.items():
        if records:
            dns_html += f"<b>{rtype}:</b> {list_block(records) if isinstance(records, list) else kv_table(records)}"

    # Dorks section
    dorks_html = "<table><tr><th>Description</th><th>Query (copy to Google)</th></tr>"
    for d in results.get("dorks", []):
        dorks_html += f"<tr><td>{d['description']}</td><td><code>{d['query']}</code></td></tr>"
    dorks_html += "</table>"

    # Subdomains
    crt = results.get("crt_sh", {})
    subs = crt.get("subdomains_found", [])

    html = f"""<!DOCTYPE html><html><head><meta charset='UTF-8'>
<title>Passive Recon — {target}</title>
<style>
body{{font-family:Segoe UI,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}}
header{{background:linear-gradient(135deg,#161b22,#21262d);border-bottom:1px solid #30363d;padding:28px 40px}}
header h1{{margin:0;color:#58a6ff;font-size:1.8em}} header p{{margin:5px 0 0;color:#8b949e}}
main{{padding:30px 40px}}
section{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:22px;margin-bottom:20px}}
h2{{color:#58a6ff;margin-top:0;font-size:1.1em;border-bottom:1px solid #30363d;padding-bottom:8px}}
table{{width:100%;border-collapse:collapse;font-size:.9em}}
th{{background:#21262d;color:#8b949e;padding:8px 12px;text-align:left}}
td{{padding:7px 12px;border-bottom:1px solid #21262d;word-break:break-all}}
code{{background:#21262d;padding:2px 6px;border-radius:4px;font-size:.85em;color:#79c0ff}}
ul{{margin:0;padding-left:20px}} li{{margin:3px 0}}
.err{{color:#f85149}} b{{color:#e3b341}}
</style></head><body>
<header>
  <h1>🔍 Passive Recon Report</h1>
  <p>Target: <code>{target}</code> | Generated: {ts} | All data from public sources</p>
</header>
<main>
{section("WHOIS", kv_table(results.get("whois", {})))}
{section(f"DNS Records", dns_html or "<p>No DNS data.</p>")}
{section(f"Certificate Transparency — {len(subs)} subdomains found", list_block(subs))}
{section("Shodan Intelligence", kv_table(results.get("shodan", {})))}
{section("Google Dork Queries (manual use)", dorks_html)}
</main></body></html>"""

    html_path = output_dir / f"recon_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    html_path.write_text(html, encoding="utf-8")

    print(f"\n✅ Recon complete for: {target}")
    print(f"   Subdomains found : {len(subs)}")
    print(f"   JSON report      : {json_path}")
    print(f"   HTML report      : {html_path}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Passive OSINT recon tool")
    parser.add_argument("--target",      required=True, help="Domain or IP to recon")
    parser.add_argument("--output",      default="./reports", help="Output directory")
    parser.add_argument("--shodan-key",  default="", help="Shodan API key (optional)")
    parser.add_argument("--skip-whois",  action="store_true")
    parser.add_argument("--skip-shodan", action="store_true")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    validate_not_private(args.target)

    print(f"[*] Starting passive recon: {args.target}")
    results = {"target": args.target, "timestamp": datetime.now().isoformat()}

    if not args.skip_whois:
        print("[*] WHOIS lookup...")
        results["whois"] = whois_lookup(args.target)

    print("[*] DNS enumeration...")
    results["dns"] = dns_enum(args.target)

    print("[*] Certificate transparency (crt.sh)...")
    results["crt_sh"] = crtsh_lookup(args.target)

    if not args.skip_shodan:
        print("[*] Shodan lookup...")
        results["shodan"] = shodan_lookup(args.target, args.shodan_key)

    print("[*] Building Google dorks...")
    results["dorks"] = build_dorks(args.target)

    generate_report(args.target, results, output_dir)


if __name__ == "__main__":
    main()
