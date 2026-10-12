#!/usr/bin/env python3
"""
cvss_calculator.py
─────────────────────────────────────────────────────────────────────────────
CVSS v3.1 Base Score calculator.

Implements the official CVSS v3.1 specification scoring formula.
Accepts vector string or interactive metric selection.

Usage:
    python cvss_calculator.py --vector "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    python cvss_calculator.py --interactive

Author:  Manicharan Ravi
Version: 1.0.0
"""

import argparse
import math


# CVSS v3.1 metric weights
METRIC_VALUES = {
    "AV":  {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC":  {"L": 0.77, "H": 0.44},
    "PR":  {
        "N": {"U": 0.85, "C": 0.85},
        "L": {"U": 0.62, "C": 0.68},
        "H": {"U": 0.27, "C": 0.50},
    },
    "UI":  {"N": 0.85, "R": 0.62},
    "S":   {"U": "Unchanged", "C": "Changed"},
    "C":   {"N": 0.00, "L": 0.22, "H": 0.56},
    "I":   {"N": 0.00, "L": 0.22, "H": 0.56},
    "A":   {"N": 0.00, "L": 0.22, "H": 0.56},
}

METRIC_NAMES = {
    "AV": ("Attack Vector",       {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
    "AC": ("Attack Complexity",   {"L": "Low", "H": "High"}),
    "PR": ("Privileges Required", {"N": "None", "L": "Low", "H": "High"}),
    "UI": ("User Interaction",    {"N": "None", "R": "Required"}),
    "S":  ("Scope",               {"U": "Unchanged", "C": "Changed"}),
    "C":  ("Confidentiality",     {"N": "None", "L": "Low", "H": "High"}),
    "I":  ("Integrity",           {"N": "None", "L": "Low", "H": "High"}),
    "A":  ("Availability",        {"N": "None", "L": "Low", "H": "High"}),
}


def parse_vector(vector: str) -> dict:
    parts = vector.strip().split("/")
    # Strip CVSS:3.1 prefix if present
    parts = [p for p in parts if ":" in p and not p.startswith("CVSS")]
    return {k: v for k, v in (p.split(":") for p in parts)}


def calculate_cvss(metrics: dict) -> tuple[float, str]:
    scope    = metrics.get("S", "U")
    av       = METRIC_VALUES["AV"][metrics.get("AV", "N")]
    ac       = METRIC_VALUES["AC"][metrics.get("AC", "L")]
    pr_raw   = metrics.get("PR", "N")
    pr       = METRIC_VALUES["PR"][pr_raw][scope]
    ui       = METRIC_VALUES["UI"][metrics.get("UI", "N")]
    conf     = METRIC_VALUES["C"][metrics.get("C", "N")]
    integ    = METRIC_VALUES["I"][metrics.get("I", "N")]
    avail    = METRIC_VALUES["A"][metrics.get("A", "N")]

    # Exploitability sub-score
    ess = 8.22 * av * ac * pr * ui

    # Impact sub-scores
    iss_base = 1 - (1 - conf) * (1 - integ) * (1 - avail)

    if scope == "U":
        iss = 6.42 * iss_base
    else:
        iss = 7.52 * (iss_base - 0.029) - 3.25 * ((iss_base - 0.02) ** 15)

    if iss <= 0:
        base_score = 0.0
    else:
        if scope == "U":
            base_score = min(iss + ess, 10)
        else:
            base_score = min(1.08 * (iss + ess), 10)

    # Round up to 1 decimal
    base_score = math.ceil(base_score * 10) / 10

    severity = (
        "CRITICAL" if base_score >= 9.0 else
        "HIGH"     if base_score >= 7.0 else
        "MEDIUM"   if base_score >= 4.0 else
        "LOW"      if base_score >  0.0 else
        "NONE"
    )
    return round(base_score, 1), severity


def vector_to_string(metrics: dict) -> str:
    order = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
    return "CVSS:3.1/" + "/".join(f"{m}:{metrics[m]}" for m in order if m in metrics)


def interactive_mode() -> dict:
    print("\n=== CVSS v3.1 Base Score Calculator ===\n")
    metrics = {}
    for key, (name, options) in METRIC_NAMES.items():
        print(f"{name} ({key}):")
        for abbr, desc in options.items():
            print(f"  [{abbr}] {desc}")
        while True:
            val = input(f"  Select ({'/'.join(options.keys())}): ").strip().upper()
            if val in options:
                metrics[key] = val
                break
            print(f"  Invalid. Choose from: {list(options.keys())}")
        print()
    return metrics


def main():
    parser = argparse.ArgumentParser(description="CVSS v3.1 Base Score Calculator")
    parser.add_argument("--vector",      help="CVSS vector string, e.g. AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    parser.add_argument("--interactive", action="store_true")
    args = parser.parse_args()

    if args.vector:
        metrics = parse_vector(args.vector)
    elif args.interactive:
        metrics = interactive_mode()
    else:
        parser.print_help()
        return

    score, severity = calculate_cvss(metrics)
    vector_str      = vector_to_string(metrics)

    color = {
        "CRITICAL": "🔴", "HIGH": "🟠",
        "MEDIUM": "🟡", "LOW": "🟢", "NONE": "⚪"
    }.get(severity, "?")

    print(f"\n{'='*50}")
    print(f"  CVSS v3.1 Base Score: {score}")
    print(f"  Severity:             {color} {severity}")
    print(f"  Vector:               {vector_str}")
    print(f"{'='*50}")
    print("\nMetric breakdown:")
    for key, val in metrics.items():
        name, options = METRIC_NAMES[key]
        print(f"  {name:25s}: {options.get(val, val)}")


if __name__ == "__main__":
    main()
