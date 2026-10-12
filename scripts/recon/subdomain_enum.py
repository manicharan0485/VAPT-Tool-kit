#!/usr/bin/env python3
"""
subdomain_enum.py
─────────────────────────────────────────────────────────────────────────────
Subdomain enumeration via:
  1. Wordlist brute-force (DNS resolution)
  2. Certificate Transparency logs (crt.sh API — passive, no target probing)
  3. Common pattern generation (mail, vpn, dev, staging, etc.)

Usage:
    python subdomain_enum.py --target example.com
    python subdomain_enum.py --target example.com --wordlist ./wordlists/subdomains-top1000.txt
    python subdomain_enum.py --target example.com --ct-only   # passive only

⚠️  Use only on domains you own or have written authorization to test.

Author:  Manicharan Ravi
Version: 1.1.0
"""

import argparse
import concurrent.futures
import json
import socket
import sys
from datetime import datetime
from pathlib import Path

import requests

try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("pip install dnspython requests")
    sys.exit(1)

# Common subdomains to always check regardless of wordlist
COMMON_SUBDOMAINS = [
    "www", "mail", "smtp", "pop", "imap", "webmail", "email",
    "ftp", "sftp", "ssh", "vpn", "remote", "rdp", "citrix",
    "dev", "staging", "test", "uat", "qa", "demo", "beta", "alpha",
    "api", "api-v2", "rest", "graphql", "ws",
    "admin", "portal", "dashboard", "panel", "manager",
    "login", "auth", "sso", "oauth", "idp",
    "cdn", "static", "assets", "images", "media",
    "blog", "news", "docs", "wiki", "help", "support",
    "git", "gitlab", "github", "bitbucket", "jira", "confluence",
    "jenkins", "ci", "build", "deploy",
    "db", "database", "mysql", "postgres", "redis", "mongodb",
    "backup", "archive", "old", "legacy",
    "shop", "store", "payment", "checkout",
    "monitoring", "grafana", "kibana", "prometheus", "elastic",
    "ns1", "ns2", "dns", "mx", "mx1", "mx2",
]


class SubdomainEnum:
    def __init__(self, target: str, wordlist: str = None, threads: int = 50,
                 verbose: bool = False, timeout: float = 3.0):
        self.target    = target
        self.wordlist  = wordlist
        self.threads   = threads
        self.verbose   = verbose
        self.timeout   = timeout
        self.found     = []
        self.resolver  = dns.resolver.Resolver()
        self.resolver.timeout  = timeout
        self.resolver.lifetime = timeout * 2

    def _log(self, msg: str, level: str = "INFO"):
        colors = {"INFO": "\033[36m", "FOUND": "\033[32m", "WARN": "\033[33m", "RESET": "\033[0m"}
        if self.verbose or level == "FOUND":
            print(f"[{colors.get(level,'')}{level}{colors['RESET']}] {msg}")

    def resolve_subdomain(self, sub: str) -> dict | None:
        """Try to resolve a subdomain. Returns result dict or None."""
        fqdn = f"{sub}.{self.target}"
        try:
            answers = self.resolver.resolve(fqdn, "A")
            ips = [str(r) for r in answers]

            # Also try to get CNAME
            cname = None
            try:
                cn = self.resolver.resolve(fqdn, "CNAME")
                cname = str(cn[0])
            except Exception:
                pass

            result = {
                "subdomain": fqdn,
                "ips":       ips,
                "cname":     cname,
                "status":    "RESOLVED",
            }
            self._log(f"  FOUND: {fqdn} → {', '.join(ips)}", "FOUND")
            return result
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            return None
        except Exception:
            return None

    def enum_from_ct_logs(self) -> list:
        """Query crt.sh Certificate Transparency logs — fully passive."""
        print("[INFO] Querying crt.sh Certificate Transparency logs (passive)...")
        found = set()
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            for entry in resp.json():
                name = entry.get("name_value", "")
                for sub in name.splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(f".{self.target}") or sub == self.target:
                        found.add(sub)
        except requests.RequestException as e:
            print(f"[WARN] crt.sh query failed: {e}")

        print(f"[INFO] CT logs found {len(found)} potential subdomains")
        return list(found)

    def enum_wordlist(self, wordlist_path: str) -> list:
        """DNS brute-force using wordlist."""
        path = Path(wordlist_path)
        if not path.exists():
            print(f"[WARN] Wordlist not found: {wordlist_path}")
            return []

        words = path.read_text().splitlines()
        words = [w.strip() for w in words if w.strip() and not w.startswith("#")]
        print(f"[INFO] Wordlist brute-force: {len(words)} words, {self.threads} threads...")

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self.resolve_subdomain, w): w for w in words}
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                if i % 100 == 0 and i > 0:
                    print(f"[INFO] Progress: {i}/{len(words)} ({len(results)} found)")
                result = future.result()
                if result:
                    results.append(result)

        return results

    def enum_common(self) -> list:
        """Check common subdomain patterns."""
        print(f"[INFO] Checking {len(COMMON_SUBDOMAINS)} common subdomains...")
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(self.resolve_subdomain, s): s for s in COMMON_SUBDOMAINS}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    results.append(result)
        return results

    def run(self, ct_only: bool = False) -> dict:
        results = {
            "target":    self.target,
            "timestamp": datetime.utcnow().isoformat(),
            "subdomains": [],
            "ct_log_raw": [],
            "summary": {}
        }

        # 1. CT logs (passive — always run)
        ct_subs = self.enum_from_ct_logs()
        results["ct_log_raw"] = ct_subs

        if not ct_only:
            # 2. Common patterns
            common = self.enum_common()
            results["subdomains"].extend(common)

            # 3. Wordlist (if provided)
            if self.wordlist:
                wl = self.enum_wordlist(self.wordlist)
                results["subdomains"].extend(wl)

            # 4. Resolve CT log subdomains
            print("[INFO] Resolving CT log subdomains...")
            ct_prefix = [s.replace(f".{self.target}", "").replace(self.target, "")
                         for s in ct_subs]
            ct_prefix = [p for p in ct_prefix if p and p != "@"]

            with concurrent.futures.ThreadPoolExecutor(max_workers=30) as ex:
                futures = {ex.submit(self.resolve_subdomain, p): p for p in ct_prefix}
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        # Deduplicate
                        existing = {r["subdomain"] for r in results["subdomains"]}
                        if result["subdomain"] not in existing:
                            results["subdomains"].append(result)

        # Deduplicate final list
        seen = set()
        unique = []
        for r in results["subdomains"]:
            if r["subdomain"] not in seen:
                seen.add(r["subdomain"])
                unique.append(r)
        results["subdomains"] = sorted(unique, key=lambda x: x["subdomain"])

        results["summary"] = {
            "total_found":   len(results["subdomains"]),
            "ct_log_count":  len(ct_subs),
            "unique_ips":    len({ip for r in results["subdomains"] for ip in r["ips"]}),
        }

        return results


def main():
    parser = argparse.ArgumentParser(
        description="Subdomain Enumeration — authorized use only"
    )
    parser.add_argument("--target",   required=True)
    parser.add_argument("--wordlist", default="./wordlists/subdomains-top1000.txt")
    parser.add_argument("--output",   default="./reports")
    parser.add_argument("--threads",  type=int, default=50)
    parser.add_argument("--ct-only",  action="store_true", help="Passive CT logs only")
    parser.add_argument("--verbose",  action="store_true")
    args = parser.parse_args()

    print(f"\n{'='*55}")
    print(f"  Subdomain Enumeration — {args.target}")
    print(f"  ⚠️  Authorized use only")
    print(f"{'='*55}\n")

    enumerator = SubdomainEnum(
        target=args.target,
        wordlist=args.wordlist,
        threads=args.threads,
        verbose=args.verbose
    )

    results = enumerator.run(ct_only=args.ct_only)

    # Summary
    print(f"\n{'='*55}")
    print(f"  Summary: {args.target}")
    print(f"  Subdomains found : {results['summary']['total_found']}")
    print(f"  CT log entries   : {results['summary']['ct_log_count']}")
    print(f"  Unique IPs       : {results['summary']['unique_ips']}")
    print(f"\n  Live subdomains:")
    for s in results["subdomains"][:20]:
        print(f"    {s['subdomain']:<40} {', '.join(s['ips'])}")
    if len(results["subdomains"]) > 20:
        print(f"    ... and {len(results['subdomains'])-20} more (see JSON)")
    print(f"{'='*55}")

    # Save
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / f"subdomain_{args.target.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    out.write_text(json.dumps(results, indent=2))
    print(f"  JSON: {out}")


if __name__ == "__main__":
    main()
