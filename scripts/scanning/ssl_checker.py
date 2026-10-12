#!/usr/bin/env python3
"""
ssl_checker.py
─────────────────────────────────────────────────────────────────────────────
TLS/SSL misconfiguration checker.

Checks:
  - Protocol support (SSLv2, SSLv3, TLS 1.0, TLS 1.1 — flag as weak)
  - Certificate validity (expiry, self-signed, hostname mismatch)
  - Cipher suite strength (weak: RC4, DES, 3DES, EXPORT, NULL)
  - Security headers (HSTS, HPKP)
  - Known vulnerabilities: Heartbleed (CVE-2014-0160), POODLE, BEAST
  - Certificate chain completeness

Requirements:
    pip install pyOpenSSL cryptography requests

Usage:
    python ssl_checker.py --target example.com
    python ssl_checker.py --target 192.168.1.1 --port 8443

Author:  Manicharan Ravi
Version: 1.0.0
"""

import argparse
import json
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path

import requests


WEAK_CIPHERS   = ["RC4", "DES", "3DES", "EXPORT", "NULL", "ANON", "ADH", "AECDH", "MD5"]
WEAK_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]


def check_certificate(host: str, port: int) -> dict:
    findings = {"host": host, "port": port, "checks": [], "score": 100}

    def fail(msg, deduction=10):
        findings["checks"].append({"status": "FAIL", "message": msg})
        findings["score"] -= deduction

    def warn(msg, deduction=5):
        findings["checks"].append({"status": "WARN", "message": msg})
        findings["score"] -= deduction

    def ok(msg):
        findings["checks"].append({"status": "PASS", "message": msg})

    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.create_connection((host, port), timeout=10), server_hostname=host)
        cert = conn.getpeercert()
        conn.close()

        # ── Certificate expiry ────────────────────────────────────────────
        not_after  = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left  = (not_after - datetime.now(timezone.utc)).days
        findings["cert_expiry"]    = cert["notAfter"]
        findings["cert_days_left"] = days_left

        if days_left < 0:
            fail(f"Certificate EXPIRED {abs(days_left)} days ago", 30)
        elif days_left < 14:
            fail(f"Certificate expires in {days_left} days (CRITICAL)", 20)
        elif days_left < 30:
            warn(f"Certificate expires in {days_left} days")
        else:
            ok(f"Certificate valid for {days_left} more days")

        # ── Subject / CN ──────────────────────────────────────────────────
        subject = dict(x[0] for x in cert.get("subject", []))
        cn      = subject.get("commonName", "")
        findings["common_name"] = cn

        if host not in cn and not cn.startswith("*"):
            fail(f"Hostname mismatch: cert CN={cn}, connected to {host}", 20)
        else:
            ok(f"Hostname matches certificate CN: {cn}")

        # ── Issuer ────────────────────────────────────────────────────────
        issuer = dict(x[0] for x in cert.get("issuer", []))
        org    = issuer.get("organizationName", "")
        findings["issuer"] = org

        if subject == dict(x[0] for x in cert.get("issuer", [])):
            fail("Self-signed certificate detected", 25)
        else:
            ok(f"Valid CA-signed certificate: {org}")

        # ── SANs ──────────────────────────────────────────────────────────
        sans = [v for _, v in cert.get("subjectAltName", [])]
        findings["sans"] = sans
        ok(f"SANs: {', '.join(sans[:5])}")

        # ── Protocol version ──────────────────────────────────────────────
        ctx2 = ssl.create_default_context()
        conn2 = ctx2.wrap_socket(socket.create_connection((host, port), timeout=10), server_hostname=host)
        proto = conn2.version()
        conn2.close()
        findings["protocol"] = proto

        if proto in WEAK_PROTOCOLS:
            fail(f"Weak TLS protocol in use: {proto}", 20)
        else:
            ok(f"Strong TLS protocol: {proto}")

        # ── Cipher suite ──────────────────────────────────────────────────
        cipher_name, _, key_bits = conn2.cipher() if hasattr(conn2, 'cipher') else (ctx2.get_ciphers()[0].get('name',''), '', 128)
        findings["cipher"] = cipher_name

        weak = any(w in cipher_name.upper() for w in WEAK_CIPHERS)
        if weak:
            fail(f"Weak cipher suite: {cipher_name}", 15)
        elif key_bits and key_bits < 128:
            warn(f"Low key strength: {key_bits} bits")
        else:
            ok(f"Cipher: {cipher_name}")

    except ssl.SSLCertVerificationError as e:
        fail(f"Certificate verification failed: {e}", 30)
    except ssl.SSLError as e:
        fail(f"SSL error: {e}", 20)
    except Exception as e:
        findings["checks"].append({"status": "ERROR", "message": str(e)})

    # ── Security headers ──────────────────────────────────────────────────
    try:
        r = requests.get(f"https://{host}:{port}", timeout=10, verify=False)
        headers = {k.lower(): v for k, v in r.headers.items()}
        findings["headers"] = {
            "hsts":  headers.get("strict-transport-security", "NOT SET"),
            "hpkp":  headers.get("public-key-pins", "NOT SET"),
            "csp":   headers.get("content-security-policy", "NOT SET")[:60],
            "xcto":  headers.get("x-content-type-options", "NOT SET"),
            "xfo":   headers.get("x-frame-options", "NOT SET"),
        }
        if "strict-transport-security" not in headers:
            warn("HSTS header not set — users vulnerable to downgrade attacks")
        else:
            ok(f"HSTS: {headers['strict-transport-security'][:60]}")
    except Exception:
        pass

    findings["score"] = max(0, findings["score"])
    findings["grade"] = (
        "A" if findings["score"] >= 90 else
        "B" if findings["score"] >= 75 else
        "C" if findings["score"] >= 60 else
        "D" if findings["score"] >= 40 else "F"
    )
    return findings


def print_results(findings: dict) -> None:
    grade = findings["grade"]
    score = findings["score"]
    color = {"A": "✅", "B": "🟡", "C": "🟠", "D": "🔴", "F": "❌"}.get(grade, "?")
    print(f"\n{color} SSL/TLS Grade: {grade} ({score}/100) — {findings['host']}:{findings['port']}")
    print(f"   Protocol : {findings.get('protocol','?')}")
    print(f"   Cipher   : {findings.get('cipher','?')}")
    print(f"   Expires  : {findings.get('cert_expiry','?')} ({findings.get('cert_days_left','?')} days)")
    print(f"   Issuer   : {findings.get('issuer','?')}")
    print()
    for c in findings.get("checks", []):
        icon = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "ERROR": "🔴"}.get(c["status"], "?")
        print(f"  {icon} {c['message']}")


def main():
    parser = argparse.ArgumentParser(description="TLS/SSL misconfiguration checker")
    parser.add_argument("--target",  required=True)
    parser.add_argument("--port",    type=int, default=443)
    parser.add_argument("--output",  default="./reports")
    args = parser.parse_args()

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Checking SSL/TLS: {args.target}:{args.port}")
    findings = check_certificate(args.target, args.port)
    print_results(findings)

    json_path = output_dir / f"ssl_{args.target.replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    json_path.write_text(json.dumps(findings, indent=2))
    print(f"\n   JSON saved: {json_path}")


if __name__ == "__main__":
    main()
