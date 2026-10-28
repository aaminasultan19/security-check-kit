"""
Rate-limit check: does the login endpoint stop me after N rapid, failed
login attempts?

Question this check answers:
    If someone fires off a burst of login attempts (as in a password-
    guessing attack), does the server eventually push back?

How it works:
    1. Send a batch of rapid login attempts, all with a wrong password.
    2. Count how many of them got blocked (HTTP 429 "Too Many Requests").
    3. If NONE were blocked, there is no rate limiting -> FAIL, and we say
       so plainly (this is a real, known gap - not our tool breaking).
    4. If at least one was blocked, some protection kicked in -> PASS.
"""

import requests

ATTEMPTS = 10


def run_check(base_url):
    name = "Rate limiting on login"
    evidence = []

    blocked_count = 0
    statuses = []

    for i in range(1, ATTEMPTS + 1):
        resp = requests.post(
            f"{base_url}/rest/user/login",
            json={"email": "nobody@example.com", "password": "wrongpassword"},
        )
        statuses.append(resp.status_code)
        if resp.status_code == 429:
            blocked_count += 1

    evidence.append(
        f"Sent {ATTEMPTS} rapid login attempts with a wrong password."
    )
    evidence.append(f"Status codes received: {statuses}")
    evidence.append(f"Requests blocked with 429 (Too Many Requests): {blocked_count}")

    if blocked_count == 0:
        verdict = "FAIL"
        reason = (
            f"FAIL: no rate limiting detected. All {ATTEMPTS} rapid login "
            "attempts were processed normally (no 429 responses). An "
            "attacker could try passwords as fast as their connection "
            "allows."
        )
    else:
        verdict = "PASS"
        reason = (
            f"{blocked_count} of {ATTEMPTS} rapid attempts were blocked "
            "with a 429 status, so some rate limiting is in place."
        )

    return {"name": name, "verdict": verdict, "reason": reason, "evidence": evidence}
