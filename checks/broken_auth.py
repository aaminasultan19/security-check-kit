"""
Broken auth check: does a protected endpoint reject requests with no token,
or an invalid/fake token?

Question this check answers:
    If I ask for a user's shopping basket (private data) without proving who
    I am, does the server correctly refuse?

How it works:
    1. Register and log in one real user, so we have a basket ID that
       genuinely exists.
    2. Request that basket with NO Authorization header at all.
    3. Request that basket with a garbage/fake token.
    4. If either request succeeds (200, with real data), the endpoint is
       not properly protected -> FAIL. If both are blocked (401/403),
       access control is working -> PASS.
"""

import requests

from checks.idor_basket import _register_user, _login


def _get_basket_with_header(base_url, basket_id, headers):
    """Request a basket with whatever headers we're given (possibly none)."""
    return requests.get(f"{base_url}/rest/basket/{basket_id}", headers=headers)


def run_check(base_url):
    name = "Broken auth: protected endpoint without a valid token"
    evidence = []

    # Step 1: set up one real, logged-in user so we have a real basket to target.
    email, password = _register_user(base_url)
    _token, basket_id = _login(base_url, email, password)
    evidence.append(f"Registered user ({email}) with basket id {basket_id}")

    # Step 2: no token at all.
    no_token_resp = _get_basket_with_header(base_url, basket_id, headers={})
    evidence.append(
        f"NO TOKEN   GET /rest/basket/{basket_id} with no Authorization header "
        f"-> status {no_token_resp.status_code}"
    )

    # Step 3: a fake/garbage token.
    fake_headers = {"Authorization": "Bearer not.a.real.token"}
    fake_token_resp = _get_basket_with_header(base_url, basket_id, fake_headers)
    evidence.append(
        f"FAKE TOKEN GET /rest/basket/{basket_id} with a made-up token "
        f"-> status {fake_token_resp.status_code}"
    )

    # Step 4: verdict. Blocked means 401 or 403. Anything else that returns
    # real basket data (status 200) means the endpoint let an unproven
    # request through.
    no_token_blocked = no_token_resp.status_code in (401, 403)
    fake_token_blocked = fake_token_resp.status_code in (401, 403)

    if no_token_blocked and fake_token_blocked:
        verdict = "PASS"
        reason = (
            "The endpoint correctly rejected both a request with no token "
            "and a request with a fake token."
        )
    else:
        verdict = "FAIL"
        reason = (
            "The endpoint returned a non-error response to a request that "
            "had no valid proof of login. A request without a real token "
            "should never succeed."
        )

    return {"name": name, "verdict": verdict, "reason": reason, "evidence": evidence}
