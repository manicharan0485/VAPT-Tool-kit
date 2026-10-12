#!/usr/bin/env python3
"""
dns_recon.py
─────────────────────────────────────────────────────────────────────────────
DNS Reconnaissance tool — passive and active DNS enumeration.

Features:
  - A, AAAA, MX, NS, TXT, SOA, CNAME record enumeration
  - Zone transfer attempt (AXFR)
  - Reverse DNS lookup
  - SPF/DMARC/DKIM record extraction
  - Structured JSON output for report integration

Usage:
    python dns_recon.py --target example.com
    python dns_recon.py --target example.com --output ./reports --verbose
    python dns_recon.py --target 192.168.1.1 --reverse

⚠️  Use only on domains you own or have written authorization to test.

Author:  Manicharan Ravi
Version: 1.2.0
"""

import argparse
import json
import socket
import sys
from datetime import datetime
from pathlib import Path

try:
    import dns.resolver
    import dns.zone
    import dns.query
    import dns.reversename
    import dns.exception
except ImportError:
    print("Missing dependency: pip install dnspython")
    sys.exit(1)


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "PTR", "CAA"]


class DNSRecon:
    def __init__(self, target: str, verbose: bool = False):
        self.target  = target
        self.verbose = verbose
        self.results = {
            "target":    target,
            "timestamp": datetime.utcnow().isoformat(),
            "records":   {},
            "zone_transfer": None,
            "security_records": {},
            "nameservers": [],
            "findings": [],
        }

    def _log(self, msg: str, level: str = "INFO"):
        colors = {"INFO": "\033[36m", "WARN": "\033[33m", "OK": "\033[32m",
                  "FAIL": "\033[31m", "RESET": "\033[0m"}
        if self.verbose or level in ("WARN", "FAIL", "OK"):
            print(f"[{colors.get(level,'')}{level}{colors['RESET']}] {msg}")

    def enumerate_records(self) -> dict:
        """Enumerate all standard DNS record types."""
        self._log(f"Enumerating DNS records for: {self.target}")
        resolver = dns.resolver.Resolver()
        resolver.timeout  = 5
        resolver.lifetime = 10

        for rtype in RECORD_TYPES:
            try:
                answers = resolver.resolve(self.target, rtype)
                records = []
                for rdata in answers:
                    records.append(str(rdata))
                self.results["records"][rtype] = records
                self._log(f"  {rtype}: {records}", "OK")
            except dns.resolver.NXDOMAIN:
                self._log(f"  {rtype}: NXDOMAIN", "WARN")
                self.results["findings"].append({
                    "type": "NXDOMAIN",
                    "detail": f"Domain {self.target} does not exist"
                })
                break
            except dns.resolver.NoAnswer:
                pass
            except dns.exception.DNSException:
                pass

        return self.results["records"]

    def check_zone_transfer(self) -> list:
        """Attempt zone transfer (AXFR) — misconfigured servers expose full zone."""
        self._log("Attempting zone transfer (AXFR)...")
        ns_records = self.results["records"].get("NS", [])

        if not ns_records:
            try:
                ns_answers = dns.resolver.resolve(self.target, "NS")
                ns_records = [str(r) for r in ns_answers]
            except Exception:
                self._log("  Could not resolve NS records", "WARN")
                return []

        zone_data = []
        for ns in ns_records:
            ns = ns.rstrip(".")
            try:
                self._log(f"  Trying AXFR from {ns}...")
                z = dns.zone.from_xfr(dns.query.xfr(ns, self.target, timeout=10))
                records = [str(z[node].to_text(node)) for node in z.nodes.keys()]
                zone_data.extend(records)
                self._log(f"  ⚠️  ZONE TRANSFER SUCCEEDED on {ns}!", "WARN")
                self.results["findings"].append({
                    "severity": "HIGH",
                    "type":     "Zone Transfer Allowed",
                    "detail":   f"Nameserver {ns} allows zone transfers (AXFR). This exposes all DNS records.",
                    "remediation": "Restrict AXFR to authorised secondary DNS servers only."
                })
            except Exception:
                self._log(f"  AXFR refused by {ns} (expected)", "OK")

        self.results["zone_transfer"] = zone_data if zone_data else "Refused (secure)"
        return zone_data

    def check_security_records(self) -> dict:
        """Check SPF, DMARC, DKIM email security records."""
        self._log("Checking email security records (SPF, DMARC, DKIM)...")
        resolver = dns.resolver.Resolver()
        sec = {}

        # SPF
        try:
            txt = resolver.resolve(self.target, "TXT")
            spf = [str(r) for r in txt if "v=spf1" in str(r)]
            if spf:
                sec["SPF"] = spf[0]
                self._log(f"  SPF: {spf[0]}", "OK")
                # Check for ~all vs -all
                if "~all" in spf[0]:
                    self.results["findings"].append({
                        "severity": "LOW",
                        "type":     "SPF SoftFail (~all)",
                        "detail":   "SPF uses ~all (softfail). Consider -all (hardfail) for strict enforcement.",
                        "remediation": "Change ~all to -all in SPF record if all legitimate senders are listed."
                    })
                elif "+all" in spf[0]:
                    self.results["findings"].append({
                        "severity": "HIGH",
                        "type":     "SPF Allow All (+all)",
                        "detail":   "SPF +all allows ANY server to send mail as this domain — removes all protection.",
                        "remediation": "Immediately fix SPF record. Remove +all and list specific sending servers."
                    })
            else:
                sec["SPF"] = "MISSING"
                self.results["findings"].append({
                    "severity": "MEDIUM",
                    "type":     "No SPF Record",
                    "detail":   f"{self.target} has no SPF record — anyone can spoof email from this domain.",
                    "remediation": "Add an SPF TXT record: v=spf1 include:yourmailserver -all"
                })
        except Exception:
            sec["SPF"] = "MISSING"

        # DMARC
        try:
            dmarc = resolver.resolve(f"_dmarc.{self.target}", "TXT")
            dmarc_val = [str(r) for r in dmarc if "v=DMARC1" in str(r)]
            if dmarc_val:
                sec["DMARC"] = dmarc_val[0]
                self._log(f"  DMARC: {dmarc_val[0]}", "OK")
                if "p=none" in dmarc_val[0]:
                    self.results["findings"].append({
                        "severity": "LOW",
                        "type":     "DMARC Policy: none",
                        "detail":   "DMARC policy is 'none' (monitoring only). No enforcement.",
                        "remediation": "Upgrade to p=quarantine or p=reject after reviewing DMARC reports."
                    })
            else:
                sec["DMARC"] = "MISSING"
                self.results["findings"].append({
                    "severity": "MEDIUM",
                    "type":     "No DMARC Record",
                    "detail":   f"{self.target} has no DMARC record.",
                    "remediation": "Add: _dmarc.yourdomain.com TXT v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com"
                })
        except Exception:
            sec["DMARC"] = "MISSING"

        # DKIM (check common selectors)
        dkim_found = False
        for selector in ["default", "google", "mail", "k1", "s1", "selector1", "selector2"]:
            try:
                resolver.resolve(f"{selector}._domainkey.{self.target}", "TXT")
                sec[f"DKIM ({selector})"] = "FOUND"
                dkim_found = True
                self._log(f"  DKIM selector '{selector}': FOUND", "OK")
            except Exception:
                pass

        if not dkim_found:
            sec["DKIM"] = "Not found for common selectors"

        self.results["security_records"] = sec
        return sec

    def reverse_lookup(self, ip: str) -> str:
        """Perform reverse DNS lookup on an IP."""
        try:
            rev = dns.reversename.from_address(ip)
            ptr = str(dns.resolver.resolve(rev, "PTR")[0])
            self._log(f"  PTR {ip} → {ptr}", "OK")
            return ptr
        except Exception:
            return "No PTR record"

    def run(self) -> dict:
        self.enumerate_records()
        self.check_zone_transfer()
        self.check_security_records()
        return self.results


def main():
    parser = argparse.ArgumentParser(
        description="DNS Reconnaissance Tool — authorized use only"
    )
    parser.add_argument("--target",  required=True, help="Target domain or IP")
    parser.add_argument("--output",  default="./reports", help="Output directory")
    parser.add_argument("--reverse", action="store_true", help="Perform reverse DNS lookup (IP input)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    print(f"\n{'='*55}")
    print(f"  DNS Recon — {args.target}")
    print(f"  ⚠️  Authorized use only")
    print(f"{'='*55}\n")

    recon = DNSRecon(target=args.target, verbose=args.verbose)

    if args.reverse:
        ptr = recon.reverse_lookup(args.target)
        print(f"PTR Record: {ptr}")
        return

    results = recon.run()

    # Summary
    print(f"\n{'='*55}")
    print(f"  Results for: {args.target}")
    print(f"{'='*55}")
    for rtype, vals in results["records"].items():
        print(f"  {rtype:6s}: {', '.join(vals[:3])}" + (" ..." if len(vals) > 3 else ""))

    print(f"\n  Security Records:")
    for k, v in results["security_records"].items():
        icon = "✅" if v not in ("MISSING", "Not found for common selectors") else "❌"
        print(f"    {icon} {k}: {v[:80] if len(str(v)) > 80 else v}")

    if results["findings"]:
        print(f"\n  ⚠️  Findings ({len(results['findings'])}):")
        for f in results["findings"]:
            sev = f.get("severity", "INFO")
            print(f"    [{sev}] {f['type']}: {f['detail'][:80]}")

    # Save JSON
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_file = output_dir / f"dns_recon_{args.target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out_file.write_text(json.dumps(results, indent=2))
    print(f"\n  JSON saved: {out_file}")


if __name__ == "__main__":
    main()
