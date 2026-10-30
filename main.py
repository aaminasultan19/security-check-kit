"""
security-check-kit: a small runner that re-runs a handful of real security
checks against a target web app and prints clear pass/fail results with
evidence.

Usage:
    python main.py --url http://localhost:3001
"""

import argparse

from checks import idor_basket, broken_auth , rate_limit ,security_headers ,mass_assignment


CHECKS = [
    idor_basket.run_check,
    broken_auth.run_check,
    rate_limit.run_check,
    security_headers.run_check,
    mass_assignment.run_check
]


def main():
    parser = argparse.ArgumentParser(description="Run automated security checks.")
    parser.add_argument(
        "--url",
        default="http://localhost:3001",
        help="Base URL of the target app (default: http://localhost:3001)",
    )
    args = parser.parse_args()

    print(f"Target: {args.url}\n")

    results = []
    for check in CHECKS:
        result = check(args.url)
        results.append(result)
        print_result(result)

    fails = [r for r in results if r["verdict"] == "FAIL"]
    print(f"\n{len(results)} check(s) run, {len(fails)} FAIL.")


def print_result(result):
    print("=" * 70)
    print(f"[{result['verdict']}] {result['name']}")
    print(f"Reason: {result['reason']}")
    print("Evidence:")
    for line in result["evidence"]:
        print(f"  - {line}")
    print()


if __name__ == "__main__":
    main()
