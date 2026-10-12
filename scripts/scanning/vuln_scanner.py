#!/usr/bin/env python3
"""
vuln_scanner.py
─────────────────────────────────────────────────────────────────────────────
CVE Vulnerability Lookup — parses nmap JSON output and queries the
NIST NVD API for CVEs affecting detected service versions.

Prioritises CVSS v3.1 Base Score >= 7.0 (High/Critical).

Requirements:
    pip install requests

Usage:
    python vuln_scanner.py --input ./reports/nmap_quick_20240101.json
    python vuln_scanner.py --input ./reports/nmap_full.json --min-cvss 7.0
    python vuln_scanner.py --service "apache httpd 2.4.49"

Author:  Manicharan Ravi
Version: 1.1.0
"""

import argparse
import json
import time
from datetime import datetime
from pathlib import Path

import requests

NVD_API  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_DELAY = 0.6  # NVD public API: 5 req/30s without key, 50/30s with key


def query_nvd(keyword: str, api_key: str = "") -> list:
    """Query NVD API for CVEs matching a keyword."""
    params = {
        "keywordSearch":    keyword,
        "keywordExactMatch": False,
        "resultsPerPage":   20,
    }
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        r = requests.get(NVD_API, params=params, headers=headers, timeout=15)
        r.raise_for_status()
        data = r.json()

        cves = []
        for item in data.get("vulnerabilities", []):
            cve     = item.get("cve", {})
            cve_id  = cve.get("id", "")
            desc    = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "No description"
            )

            # Get CVSS v3.1 score
            metrics   = cve.get("metrics", {})
            cvss_data = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
            score     = cvss_data.get("baseScore", 0.0)
            severity  = cvss_data.get("baseSeverity", "UNKNOWN")
            vector    = cvss_data.get("vectorString", "")

            # Fall back to v2 if no v3
            if score == 0.0 and metrics.get("cvssMetricV2"):
                cvss2 = metrics["cvssMetricV2"][0].get("cvssData", {})
                score    = cvss2.get("baseScore", 0.0)
                severity = cvss2.get("baseSeverity", "UNKNOWN")

            refs = [r["url"] for r in cve.get("references", [])[:3]]

            cves.append({
                "cve_id":      cve_id,
                "description": desc[:200],
                "cvss_score":  score,
                "severity":    severity,
                "vector":      vector,
                "published":   cve.get("published", "")[:10],
                "references":  refs,
            })

        return cves

    except requests.RequestException as e:
        return [{"error": str(e)}]


def scan_from_nmap_json(nmap_json_path: str, min_cvss: float, api_key: str) -> list:
    """Parse nmap JSON output and look up CVEs for each detected service."""
    data    = json.loads(Path(nmap_json_path).read_text())
    hosts   = data.get("hosts", [])
    results = []

    for host in hosts:
        for port in host.get("ports", []):
            product = port.get("product", "").strip()
            version = port.get("version", "").strip()
            service = port.get("service", "").strip()

            if not product:
                continue

            keyword = f"{product} {version}".strip()
            print(f"  [*] Querying NVD: {keyword} (port {port['port']})")

            cves = query_nvd(keyword, api_key)
            time.sleep(RATE_DELAY)

            high_cves = [c for c in cves if isinstance(c.get("cvss_score"), float) and c["cvss_score"] >= min_cvss]

            if high_cves:
                results.append({
                    "host":    host["ip"],
                    "port":    port["port"],
                    "service": f"{product} {version}",
                    "cves":    sorted(high_cves, key=lambda x: x["cvss_score"], reverse=True),
                })

    return results


def scan_single_service(service: str, min_cvss: float, api_key: str) -> list:
    print(f"  [*] Querying NVD: {service}")
    cves = query_nvd(service, api_key)
    return [c for c in cves if isinstance(c.get("cvss_score"), float) and c["cvss_score"] >= min_cvss]


def generate_report(findings: list, output_dir: Path, source: str) -> None:
    ts          = datetime.now().strftime("%Y-%m-%d %H:%M")
    total_cves  = sum(len(f.get("cves", [f])) for f in findings)
    critical    = sum(1 for f in findings for c in f.get("cves", [f]) if c.get("cvss_score", 0) >= 9.0)
    high        = sum(1 for f in findings for c in f.get("cves", [f]) if 7.0 <= c.get("cvss_score", 0) < 9.0)

    json_path = output_dir / f"vuln_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    json_path.write_text(json.dumps(findings, indent=2))

    host_sections = ""
    for f in findings:
        cve_rows = ""
        for c in f.get("cves", [f]):
            score   = c.get("cvss_score", 0)
            bg      = "#3d0000" if score >= 9 else "#2d1800" if score >= 7 else "#1a2200"
            col     = "#ff4444" if score >= 9 else "#ff8c00" if score >= 7 else "#88cc00"
            refs    = " ".join(f"<a href='{r}' style='color:#58a6ff'>[ref]</a>" for r in c.get("references", []))
            cve_rows += f"""<tr style='background:{bg}'>
                <td><b style='color:{col}'>{c.get('cve_id','')}</b></td>
                <td><b style='color:{col}'>{score}</b></td>
                <td>{c.get('severity','')}</td>
                <td style='font-size:.85em'>{c.get('description','')[:180]}</td>
                <td>{c.get('published','')}</td>
                <td>{refs}</td>
            </tr>"""

        host_sections += f"""<div class='finding'>
            <h3>🖥 {f.get('host','')} : {f.get('port','')} — <code>{f.get('service','')}</code></h3>
            <table>
            <tr><th>CVE ID</th><th>CVSS</th><th>Severity</th><th>Description</th><th>Published</th><th>Refs</th></tr>
            {cve_rows}
            </table></div>"""

    html = f"""<!DOCTYPE html><html><head><meta charset='UTF-8'>
<title>Vulnerability Scan Results</title>
<style>
body{{font-family:Segoe UI,sans-serif;margin:0;background:#0d1117;color:#c9d1d9}}
header{{background:linear-gradient(135deg,#161b22,#21262d);border-bottom:1px solid #30363d;padding:24px 40px}}
header h1{{margin:0;color:#f85149}} header p{{margin:5px 0 0;color:#8b949e}}
main{{padding:30px 40px}}
.finding{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:18px;margin-bottom:16px}}
h3{{margin:0 0 12px;color:#ff7b72;font-size:1em}}
table{{width:100%;border-collapse:collapse;font-size:.85em}}
th{{background:#21262d;color:#8b949e;padding:7px 10px;text-align:left}}
td{{padding:6px 10px;border-bottom:1px solid #21262d;vertical-align:top}}
code{{background:#21262d;padding:2px 6px;border-radius:4px;color:#79c0ff;font-size:.9em}}
.kpi{{display:inline-block;background:#21262d;padding:10px 20px;border-radius:8px;margin:5px;text-align:center}}
.kv{{font-size:1.8em;font-weight:700}} .kl{{font-size:.8em;color:#8b949e}}
</style></head><body>
<header>
  <h1>🔴 Vulnerability Scan Report</h1>
  <p>Source: {source} | Generated: {ts}</p>
</header>
<main>
<div>
  <span class='kpi'><div class='kv' style='color:#f85149'>{critical}</div><div class='kl'>Critical (≥9.0)</div></span>
  <span class='kpi'><div class='kv' style='color:#ff8c00'>{high}</div><div class='kl'>High (7.0–8.9)</div></span>
  <span class='kpi'><div class='kv' style='color:#58a6ff'>{total_cves}</div><div class='kl'>Total CVEs</div></span>
</div><br>
{host_sections or '<p>No vulnerabilities found above threshold.</p>'}
</main></body></html>"""

    html_path = output_dir / f"vuln_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    html_path.write_text(html, encoding="utf-8")

    print(f"\n{'='*50}")
    print(f"  CRITICAL (≥9.0) : {critical}")
    print(f"  HIGH (7.0–8.9)  : {high}")
    print(f"  Total CVEs      : {total_cves}")
    print(f"  HTML report     : {html_path}")
    print(f"{'='*50}\n")


def main():
    parser = argparse.ArgumentParser(description="CVE vulnerability scanner via NVD API")
    parser.add_argument("--input",     help="nmap JSON file from nmap_wrapper.py")
    parser.add_argument("--service",   help="Single service string, e.g. 'apache httpd 2.4.49'")
    parser.add_argument("--min-cvss",  type=float, default=7.0)
    parser.add_argument("--api-key",   default="", help="NVD API key for higher rate limits")
    parser.add_argument("--output",    default="./reports")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.input:
        print(f"[*] Scanning services from: {args.input}")
        findings = scan_from_nmap_json(args.input, args.min_cvss, args.api_key)
        source   = args.input
    elif args.service:
        cves     = scan_single_service(args.service, args.min_cvss, args.api_key)
        findings = [{"host": "N/A", "port": "N/A", "service": args.service, "cves": cves}]
        source   = args.service
    else:
        parser.print_help()
        return

    generate_report(findings, output_dir, source)


if __name__ == "__main__":
    main()
