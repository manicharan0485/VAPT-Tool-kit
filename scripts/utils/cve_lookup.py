#!/usr/bin/env python3
"""
cve_lookup.py
─────────────────────────────────────────────────────────────────────────────
NVD (National Vulnerability Database) CVE lookup tool.

Features:
  - Lookup CVE by ID (CVE-YYYY-NNNNN)
  - Search CVEs by product/service name and version
  - CVSS v3 scoring with severity classification
  - Remediation recommendations
  - Structured JSON output for report integration

API: NIST NVD (https://nvd.nist.gov/developers/vulnerabilities)
Rate limit: 5 requests/30s without API key; higher with NVD_API_KEY env var.

Usage:
    python cve_lookup.py --cve CVE-2021-44228
    python cve_lookup.py --service "Apache httpd" --version "2.4.49"
    python cve_lookup.py --service "OpenSSH" --version "7.4" --severity HIGH

Author:  Manicharan Ravi
Version: 1.1.0
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import requests


NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[31m",
    "MEDIUM":   "\033[33m",
    "LOW":      "\033[32m",
    "NONE":     "\033[37m",
    "RESET":    "\033[0m",
}


def cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >= 0.1: return "LOW"
    return "NONE"


def format_severity(sev: str) -> str:
    col = SEVERITY_COLORS.get(sev, "")
    rst = SEVERITY_COLORS["RESET"]
    return f"{col}{sev}{rst}"


class CVELookup:
    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get("NVD_API_KEY", "")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "vapt-toolkit/1.0 (security research)"})
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key

    def _get(self, params: dict) -> dict:
        """Make NVD API request with rate limit handling."""
        for attempt in range(3):
            try:
                resp = self.session.get(NVD_BASE, params=params, timeout=15)
                if resp.status_code == 403:
                    print("[WARN] Rate limited. Waiting 30 seconds...")
                    time.sleep(30)
                    continue
                resp.raise_for_status()
                return resp.json()
            except requests.RequestException as e:
                print(f"[ERROR] API request failed (attempt {attempt+1}): {e}")
                time.sleep(5)
        return {}

    def _parse_cve(self, item: dict) -> dict:
        """Parse a CVE item from NVD response into clean dict."""
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Descriptions (English)
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "No description available"
        )

        # CVSS scores
        cvss_v3 = cve.get("metrics", {}).get("cvssMetricV31", []) or \
                  cve.get("metrics", {}).get("cvssMetricV30", [])
        cvss_v2 = cve.get("metrics", {}).get("cvssMetricV2", [])

        score_v3 = None
        vector_v3 = None
        if cvss_v3:
            score_v3  = cvss_v3[0]["cvssData"]["baseScore"]
            vector_v3 = cvss_v3[0]["cvssData"]["vectorString"]

        score_v2 = cvss_v2[0]["cvssData"]["baseScore"] if cvss_v2 else None

        score    = score_v3 or score_v2 or 0.0
        severity = cvss_to_severity(float(score))

        # Affected versions
        affected = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable"):
                        affected.append({
                            "cpe":              match.get("criteria", ""),
                            "version_start":    match.get("versionStartIncluding", ""),
                            "version_end":      match.get("versionEndIncluding", ""),
                        })

        # References
        refs = [
            {"url": r["url"], "tags": r.get("tags", [])}
            for r in cve.get("references", [])[:5]  # limit to 5
        ]

        # CWE
        cwes = [
            w["description"][0]["value"]
            for w in cve.get("weaknesses", [])
            if w.get("description")
        ]

        return {
            "cve_id":     cve_id,
            "description": desc[:500],
            "cvss_v3_score":  score_v3,
            "cvss_v2_score":  score_v2,
            "cvss_vector":    vector_v3,
            "severity":       severity,
            "cwes":           cwes,
            "affected":       affected[:5],
            "references":     refs,
            "published":      cve.get("published", ""),
            "last_modified":  cve.get("lastModified", ""),
        }

    def lookup_cve(self, cve_id: str) -> dict:
        """Lookup a specific CVE by ID."""
        print(f"[INFO] Looking up {cve_id}...")
        data = self._get({"cveId": cve_id})
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            print(f"[WARN] CVE {cve_id} not found")
            return {}
        return self._parse_cve(vulns[0])

    def search_by_product(self, keyword: str, version: str = "",
                          severity_filter: str = "", max_results: int = 10) -> list:
        """Search CVEs for a product/service."""
        print(f"[INFO] Searching CVEs for: {keyword} {version}...")
        params = {
            "keywordSearch": f"{keyword} {version}".strip(),
            "resultsPerPage": min(max_results, 2000),
        }
        if severity_filter:
            params["cvssV3Severity"] = severity_filter.upper()

        data = self._get(params)
        vulns = data.get("vulnerabilities", [])
        print(f"[INFO] Found {len(vulns)} CVEs (showing top {min(max_results, len(vulns))})")

        results = [self._parse_cve(v) for v in vulns[:max_results]]
        # Sort by CVSS score descending
        return sorted(results, key=lambda x: x.get("cvss_v3_score") or 0, reverse=True)


def print_cve(cve: dict):
    sev    = cve.get("severity", "UNKNOWN")
    score  = cve.get("cvss_v3_score") or cve.get("cvss_v2_score") or "N/A"
    col    = SEVERITY_COLORS.get(sev, "")
    rst    = SEVERITY_COLORS["RESET"]

    print(f"\n  {col}{'─'*55}{rst}")
    print(f"  {col}CVE: {cve['cve_id']}  [{sev}]  CVSS: {score}{rst}")
    print(f"  {'─'*55}")
    print(f"  {cve['description'][:200]}")
    if cve.get("cwes"):
        print(f"  CWE: {', '.join(cve['cwes'])}")
    if cve.get("cvss_vector"):
        print(f"  Vector: {cve['cvss_vector']}")
    if cve.get("published"):
        print(f"  Published: {cve['published'][:10]}")
    if cve.get("references"):
        print(f"  References:")
        for r in cve["references"][:2]:
            print(f"    → {r['url']}")


def main():
    parser = argparse.ArgumentParser(description="CVE Lookup — NVD API")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--cve",     help="CVE ID (e.g., CVE-2021-44228)")
    group.add_argument("--service", help="Service/product name (e.g., 'Apache httpd')")
    parser.add_argument("--version",  default="", help="Version to search (use with --service)")
    parser.add_argument("--severity", default="",
                        choices=["", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Filter by minimum severity")
    parser.add_argument("--max",    type=int, default=10, help="Max results")
    parser.add_argument("--output", default="./reports")
    args = parser.parse_args()

    lookup  = CVELookup()
    results = []

    if args.cve:
        cve = lookup.lookup_cve(args.cve)
        if cve:
            print_cve(cve)
            results = [cve]
    else:
        cves = lookup.search_by_product(
            args.service, args.version, args.severity, args.max
        )
        for cve in cves:
            print_cve(cve)
        results = cves

    # Save JSON
    if results:
        output_dir = Path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
        tag     = (args.cve or args.service).replace(" ", "_").replace("/", "_")
        outfile = output_dir / f"cve_{tag}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        outfile.write_text(json.dumps({"results": results, "query": vars(args)}, indent=2))
        print(f"\n  JSON: {outfile}")


if __name__ == "__main__":
    main()
