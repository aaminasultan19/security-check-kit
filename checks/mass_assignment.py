"""
Mass assignment (BOPLA) check: can a brand-new user grant themselves admin
access just by adding an extra field to the signup request?

Question this check answers:
    Does the registration endpoint only accept the fields it should
    (email, password), or does it blindly accept ANY field sent to it,
    including ones that control privilege, like "role"?

How it works:
    1. Register a new user, sneaking an extra "role": "admin" field into
       the normal signup request.
    2. Log in as that user and decode their login token to see what role
       the server actually gave them.
    3. If the role came back as "admin", the signup endpoint let an
       anonymous person grant themselves admin access -> FAIL.
    4. If the extra field was ignored (role defaulted to something like
       "customer"), the endpoint is properly protected -> PASS.
"""

import base64
import json
import uuid

import requests


def _decode_jwt_role(token):
    """
    A JWT is 3 dot-separated parts: header.payload.signature. The payload
    is just base64-encoded JSON (NOT encrypted - anyone holding the token
    can read it), so we can decode it ourselves without a special library.
    """
    payload_b64 = token.split(".")[1]
    # base64 needs the text length to be a multiple of 4; add the padding
    # back if the token left it off.
    payload_b64 += "=" * (-len(payload_b64) % 4)
    payload_json = base64.urlsafe_b64decode(payload_b64)
    payload = json.loads(payload_json)
    return payload["data"]["role"]


def run_check(base_url):
    name = "Mass assignment: granting admin role via signup"
    evidence = []

    email = f"mass-assign-{uuid.uuid4().hex[:10]}@example.com"
    password = "Passw0rd!123"

    # The "attack": a normal-looking signup request, with one extra field
    # ("role": "admin") that a real signup form would never send.
    register_resp = requests.post(
        f"{base_url}/api/Users",
        json={
            "email": email,
            "password": password,
            "passwordRepeat": password,
            "role": "admin",
        },
    )
    evidence.append(
        f"POST /api/Users with an extra \"role\": \"admin\" field -> "
        f"status {register_resp.status_code}"
    )
    evidence.append(f"Registration response: {register_resp.text[:300]}")

    login_resp = requests.post(
        f"{base_url}/rest/user/login",
        json={"email": email, "password": password},
    )
    token = login_resp.json()["authentication"]["token"]
    actual_role = _decode_jwt_role(token)
    evidence.append(f"Role found in the login token: {actual_role!r}")

    if actual_role == "admin":
        verdict = "FAIL"
        reason = (
            "A brand-new, anonymous signup was able to grant itself the "
            "admin role just by adding an extra field to the registration "
            "request. The server should only accept email/password here, "
            "not trust the client to set its own role."
        )
    else:
        verdict = "PASS"
        reason = (
            f"The extra \"role\" field was ignored; the account was given "
            f"the role {actual_role!r} instead, so the endpoint is "
            "properly restricting which fields it accepts."
        )

    return {"name": name, "verdict": verdict, "reason": reason, "evidence": evidence}
