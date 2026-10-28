"""
IDOR check: Insecure Direct Object Reference on shopping baskets.

Question this check answers:
    If I'm logged in as User A, can I view User B's shopping basket just by
    changing the basket ID in the URL?

How it works:
    1. Register two brand-new throwaway users, A and B.
    2. Log both in to get their auth tokens and basket IDs.
    3. User A asks for their OWN basket (the "control" request) - this should
       work, and proves our test setup/tokens are valid.
    4. User A asks for User B's basket, using A's own token (the "attack"
       request).
    5. If step 4 returns User B's basket data, the app is vulnerable (FAIL).
       If it's blocked (401/403/404, or no data), access control is working
       (PASS).
"""

import uuid
import requests


def _register_user(base_url):
    """Create a brand-new throwaway user and return their email/password."""
    email = f"sentry-{uuid.uuid4().hex[:10]}@example.com"
    password = "Passw0rd!123"
    resp = requests.post(
        f"{base_url}/api/Users",
        json={"email": email, "password": password, "passwordRepeat": password},
    )
    resp.raise_for_status()
    return email, password


def _login(base_url, email, password):
    """Log in and return (token, basket_id)."""
    resp = requests.post(
        f"{base_url}/rest/user/login",
        json={"email": email, "password": password},
    )
    resp.raise_for_status()
    data = resp.json()["authentication"]
    return data["token"], data["bid"]


def _get_basket(base_url, basket_id, token):
    """Request a basket by ID using the given token. Returns the raw response."""
    return requests.get(
        f"{base_url}/rest/basket/{basket_id}",
        headers={"Authorization": f"Bearer {token}"},
    )


def run_check(base_url):
    """
    Run the IDOR basket check against the given base_url
    (e.g. "http://localhost:3001").

    Returns a dict: {"name", "verdict", "reason", "evidence"}
    """
    name = "IDOR: access another user's shopping basket"
    evidence = []

    # Step 1 & 2: create and log in two throwaway users.
    email_a, password_a = _register_user(base_url)
    email_b, password_b = _register_user(base_url)
    token_a, basket_id_a = _login(base_url, email_a, password_a)
    _token_b, basket_id_b = _login(base_url, email_b, password_b)

    evidence.append(f"Registered User A ({email_a}) with basket id {basket_id_a}")
    evidence.append(f"Registered User B ({email_b}) with basket id {basket_id_b}")

    # Step 3: control request - User A fetches their OWN basket.
    control_resp = _get_basket(base_url, basket_id_a, token_a)
    evidence.append(
        f"CONTROL  GET /rest/basket/{basket_id_a} as User A -> "
        f"status {control_resp.status_code}"
    )

    if control_resp.status_code != 200:
        return {
            "name": name,
            "verdict": "ERROR",
            "reason": (
                "Could not even fetch User A's own basket (status "
                f"{control_resp.status_code}). Test setup is broken, so "
                "this check can't reach a real verdict - not a finding "
                "about the app."
            ),
            "evidence": evidence,
        }

    # Step 4: attack request - User A fetches User B's basket.
    attack_resp = _get_basket(base_url, basket_id_b, token_a)
    evidence.append(
        f"ATTACK   GET /rest/basket/{basket_id_b} as User A (wrong basket) -> "
        f"status {attack_resp.status_code}"
    )
    evidence.append(f"Response body (first 300 chars): {attack_resp.text[:300]}")

    # Step 5: verdict.
    if attack_resp.status_code == 200:
        verdict = "FAIL"
        reason = (
            "User A was able to retrieve User B's basket contents using "
            "only their own token. The server did not check that the "
            "basket ID belongs to the logged-in user. This is an IDOR "
            "vulnerability."
        )
    else:
        verdict = "PASS"
        reason = (
            f"The server rejected the cross-user basket request with status "
            f"{attack_resp.status_code}, so access control appears to be "
            "enforced correctly."
        )

    return {"name": name, "verdict": verdict, "reason": reason, "evidence": evidence}
