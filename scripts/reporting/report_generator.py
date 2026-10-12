#!/usr/bin/env python3
"""
report_generator.py — Professional pentest HTML report generator.
Takes a JSON findings file and produces a styled, print-ready report.

Usage:
    python report_generator.py --input ./findings.json --output ./reports/report
    
Input JSON format: see docs/METHODOLOGY.md for full schema.

Author: Manicharan Ravi | Version: 1.1.0
"""

import argparse
import json
from datetime import datetime
from pathlib import Path

SEVERITY_ORDER  = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_COLORS = {
    "CRITICAL": ("#ff4444", "#3d0000"),
    "HIGH":     ("#ff8c00", "#2d1800"),
    "MEDIUM":   ("#ffcc00", "#2d2500"),
    "LOW":      ("#44cc44", "#0d2200"),
    "INFO":     ("#6699ff", "#0d1a33"),
}


def risk_summary(findings: list) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if sev in counts:
            counts[sev] += 1
    return counts


def generate_html_report(data: dict, output_path: str) -> None:
    eng      = data.get("engagement", {})
    findings = sorted(
        data.get("findings", []),
        key=lambda f: SEVERITY_ORDER.index(f.get("severity","INFO").upper())
        if f.get("severity","INFO").upper() in SEVERITY_ORDER else 99
    )
    counts = risk_summary(findings)
    score  = min(100, sum({"CRITICAL":40,"HIGH":20,"MEDIUM":10,"LOW":5,"INFO":1}.get(s,0)*n for s,n in counts.items()))
    ts     = datetime.now().strftime("%Y-%m-%d")

    kpi_html = "".join(
        f"<div class='kpi' style='border-left:4px solid {SEVERITY_COLORS[s][0]}'>"
        f"<div class='kv' style='color:{SEVERITY_COLORS[s][0]}'>{counts[s]}</div>"
        f"<div class='kl'>{s}</div></div>"
        for s in SEVERITY_ORDER
    )

    finding_cards = ""
    for f in findings:
        sev     = f.get("severity","INFO").upper()
        col, bg = SEVERITY_COLORS.get(sev, ("#888","#111"))
        refs    = "".join(f"<a href='{r}' style='color:#58a6ff;display:block;font-size:.85em'>{r}</a>" for r in f.get("references",[]))
        finding_cards += f"""<div class='finding' style='border-left:4px solid {col};background:{bg}22'>
            <span class='badge' style='background:{col};color:#000'>{sev}</span>
            <span style='font-family:monospace;font-size:.8em;color:#888;margin:0 10px'>{f.get("id","")}</span>
            <h3>{f.get("title","")}</h3>
            <div class='meta'>
              <span>🖥 {f.get("host","")}:{f.get("port","")}</span>
              <span>⚙️ {f.get("service","")}</span>
              <span>📊 CVSS {f.get("cvss_score","N/A")}</span>
              <code style='font-size:.75em'>{f.get("cve","")}</code>
            </div>
            <div class='sec'><b>Description</b><p>{f.get("description","")}</p></div>
            <div class='sec'><b>Impact</b><p>{f.get("impact","")}</p></div>
            {'<div class="sec"><b>Evidence / PoC</b><pre>' + str(f.get("evidence","")) + '</pre></div>' if f.get("evidence") else ""}
            <div class='sec rem'><b>🔧 Remediation</b><p>{f.get("remediation","")}</p></div>
            {f'<div class="sec"><b>References</b>{refs}</div>' if refs else ""}
        </div>"""

    html = f"""<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>
<title>Pentest Report — {eng.get("client","")}</title>
<style>
body{{font-family:Segoe UI,sans-serif;background:#0a0c10;color:#c9d1d9;margin:0;line-height:1.6}}
.cover{{min-height:100vh;display:flex;flex-direction:column;justify-content:center;
  background:linear-gradient(135deg,#0a0c10,#161b22);padding:60px 80px;border-bottom:1px solid #30363d}}
.cover h1{{font-size:2.8em;color:#e6edf3;margin-bottom:8px}}
.cover h1 span{{color:#58a6ff}}
.cover-meta{{margin-top:36px;display:grid;grid-template-columns:repeat(3,1fr);gap:16px}}
.cover-meta div{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:14px 18px}}
.cover-meta .lbl{{color:#8b949e;font-size:.78em;text-transform:uppercase;letter-spacing:1px}}
.cover-meta .val{{color:#e6edf3;font-weight:600;margin-top:4px}}
nav{{background:#161b22;border-bottom:1px solid #30363d;padding:12px 60px;
  position:sticky;top:0;z-index:99;display:flex;gap:22px}}
nav a{{color:#8b949e;text-decoration:none;font-size:.85em}}
nav a:hover{{color:#58a6ff}}
main{{padding:50px 60px;max-width:1100px}}
h2{{font-size:1.3em;color:#e6edf3;border-bottom:1px solid #30363d;padding-bottom:8px;margin-bottom:18px}}
.kpi-row{{display:flex;gap:14px;margin-bottom:28px}}
.kpi{{flex:1;border-radius:8px;padding:16px;background:#161b22;border:1px solid #30363d}}
.kv{{font-size:2em;font-weight:700}} .kl{{font-size:.78em;color:#8b949e;margin-top:4px;text-transform:uppercase}}
.finding{{border-radius:8px;padding:20px 24px;margin-bottom:18px}}
.badge{{font-size:.73em;font-weight:700;padding:2px 9px;border-radius:4px}}
.finding h3{{font-size:1em;color:#e6edf3;margin:8px 0 10px}}
.meta{{display:flex;gap:14px;flex-wrap:wrap;font-size:.82em;color:#8b949e;padding-bottom:12px;border-bottom:1px solid #30363d30;margin-bottom:12px}}
.sec{{margin-bottom:10px}} .sec b{{color:#e3b341;font-size:.82em;text-transform:uppercase;letter-spacing:.5px}}
.sec p{{margin-top:4px;font-size:.9em}}
pre{{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:12px;
  font-size:.82em;color:#79c0ff;overflow-x:auto;margin-top:6px;white-space:pre-wrap}}
.rem b{{color:#3fb950}}
code{{background:#21262d;padding:1px 6px;border-radius:4px;font-size:.85em}}
footer{{text-align:center;padding:24px;color:#30363d;font-size:.8em;border-top:1px solid #21262d}}
@media print{{nav{{display:none}}.cover{{page-break-after:always}}.finding{{page-break-inside:avoid}}}}
</style></head><body>

<div class='cover'>
  <div style='color:#f85149;font-size:.75em;letter-spacing:3px;text-transform:uppercase;margin-bottom:14px'>Confidential — Penetration Test Report</div>
  <h1>Security Assessment<br><span>{eng.get("client","[Client]")}</span></h1>
  <div class='cover-meta'>
    <div><div class='lbl'>Prepared By</div><div class='val'>{eng.get("tester","Manicharan Ravi")}</div></div>
    <div><div class='lbl'>Test Period</div><div class='val'>{eng.get("start_date","")} – {eng.get("end_date","")}</div></div>
    <div><div class='lbl'>Report Date</div><div class='val'>{eng.get("report_date",ts)}</div></div>
    <div><div class='lbl'>Scope</div><div class='val'>{", ".join(eng.get("scope",[]))}</div></div>
    <div><div class='lbl'>Total Findings</div><div class='val'>{len(findings)}</div></div>
    <div><div class='lbl'>Overall Risk Score</div>
      <div class='val' style='color:{"#f85149" if score>=60 else "#ff8c00" if score>=30 else "#3fb950"}'>{score}/100</div></div>
  </div>
</div>

<nav>
  <a href='#exec'>Executive Summary</a>
  <a href='#findings'>Findings ({len(findings)})</a>
  <a href='#appendix'>Appendix</a>
</nav>

<main>
<section id='exec'>
  <h2>📋 Executive Summary</h2>
  <p style='color:#8b949e;margin-bottom:20px'>
    A penetration test was conducted against <strong style='color:#e6edf3'>{eng.get("client","the client")}</strong>
    between {eng.get("start_date","")} and {eng.get("end_date","")}. The assessment identified
    <strong style='color:#e6edf3'>{len(findings)}</strong> security findings.
  </p>
  <div class='kpi-row'>{kpi_html}</div>
</section>

<section id='findings'>
  <h2>🔍 Detailed Findings</h2>
  {finding_cards or "<p>No findings recorded.</p>"}
</section>

<section id='appendix'>
  <h2>📎 Appendix — Tools & Methodology</h2>
  <p style='color:#8b949e;font-size:.9em'>
    Tools: Nmap, Metasploit Framework, Trivy, Burp Suite, custom Python scripts.<br>
    Methodology: Penetration Testing Execution Standard (PTES) — pre-engagement,
    intelligence gathering, threat modelling, vulnerability analysis, exploitation, reporting.
  </p>
</section>
</main>
<footer>CONFIDENTIAL — {eng.get("client","")} Penetration Test Report — {eng.get("report_date",ts)} — {eng.get("tester","")}</footer>
</body></html>"""

    html_path = f"{output_path}.html"
    Path(html_path).write_text(html, encoding="utf-8")
    print(f"\n✅ Report: {html_path}")
    print(f"   {len(findings)} findings — Critical:{counts['CRITICAL']} High:{counts['HIGH']} Medium:{counts['MEDIUM']}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",  required=True)
    parser.add_argument("--output", default="./reports/pentest_report")
    args = parser.parse_args()
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    generate_html_report(json.loads(Path(args.input).read_text()), args.output)


if __name__ == "__main__":
    main()
