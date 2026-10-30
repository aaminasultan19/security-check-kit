"""
Security headers check: does the server send standard browser-level
protection headers?

Question this check answers:
    If something ever goes wrong (like a successful XSS injection), does the
    browser have extra safety nets in place, or is it relying only on the
    app's code being perfect?

How it works:
    1. Send one plain GET request to the target's homepage.
    2. Look for a few standard protective headers.
    3. If Content-Security-Policy (the most impactful one) is missing,
       that's a FAIL. Every header's presence/absence is listed as
       evidence either way.
"""

import requests

# Headers we check for, and a short plain-English reason each one matters.
HEADERS_TO_CHECK = {
    "Content-Security-Policy": (
        "Restricts which sources scripts/styles/images can load from, "
        "limiting damage if an injection bug (like XSS) is ever found."
    ),
    "X-Content-Type-Options": (
        "Stops the browser from guessing a file's type, preventing some "
        "disguised-file attacks."
    ),
    "X-Frame-Options": (
        "Stops the site from being embedded in a hidden iframe on another "
        "site (clickjacking protection)."
    ),
    "Strict-Transport-Security": (
        "Forces the browser to only ever connect over HTTPS, not HTTP."
    ),
}

# Missing this one specifically is enough to call the check a FAIL - it's
# the header with the biggest real-world impact of the four.
CRITICAL_HEADER = "Content-Security-Policy"


def run_check(base_url):
    name = "Security headers on the homepage"
    evidence = []

    resp = requests.get(base_url)
    # Header names aren't case-sensitive, so look them up case-insensitively
    # the same way requests itself does.
    headers = resp.headers

    missing = []
    for header_name, reason in HEADERS_TO_CHECK.items():
        if header_name in headers:
            evidence.append(f"PRESENT  {header_name}: {headers[header_name]}")
        else:
            evidence.append(f"MISSING  {header_name} - {reason}")
            missing.append(header_name)

    if CRITICAL_HEADER in missing:
        verdict = "FAIL"
        reason = (
            f"The response is missing the {CRITICAL_HEADER} header, the "
            "most impactful of the headers checked here. Without it, the "
            "browser has no extra protection if an injection bug is ever "
            "found on this site."
        )
    else:
        verdict = "PASS"
        reason = f"The {CRITICAL_HEADER} header is present."

    return {"name": name, "verdict": verdict, "reason": reason, "evidence": evidence}
