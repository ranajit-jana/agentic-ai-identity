"""
Tests the full delegation flow end-to-end:
  1. Generates a supervisor EC key + self-signed cert (no Step CA needed)
  2. Supervisor issues a scoped delegation token for a sub-agent
  3. Sends delegation claims to OPA and checks allow/deny decisions

Usage:
    docker compose up -d opa
    uv run python scripts/test_delegation.py
"""

import sys
import datetime
import httpx
from dotenv import load_dotenv
import os

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key

from identity.delegator import Delegator, MAX_DELEGATION_DEPTH

load_dotenv()
OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")
ALLOW_ENDPOINT = f"{OPA_URL}/v1/data/authz/allow"


# ---------------------------------------------------------------------------
# Generate a throwaway supervisor cert (self-signed, no Step CA needed)
# ---------------------------------------------------------------------------

def make_test_cert(agent_id: str):
    """Self-signed cert — gives us a real EC key pair to sign delegation tokens with."""
    key = generate_private_key(SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(minutes=10))
        .sign(key, hashes.SHA256())
    )
    return (
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()),
        cert.public_bytes(serialization.Encoding.PEM),
    )


def ask_opa(input_data: dict) -> bool:
    """POST input to OPA and return the allow decision."""
    r = httpx.post(ALLOW_ENDPOINT, json={"input": input_data})
    r.raise_for_status()
    return r.json().get("result", False)


def run(desc: str, input_data: dict, expected: bool):
    result = ask_opa(input_data)
    ok = result == expected
    print(f"  {'PASS' if ok else 'FAIL'}  {desc}")
    if not ok:
        print(f"         expected={expected}  got={result}")
    return ok


def main():
    print(f"OPA at {OPA_URL}\n")

    # Supervisor = agent-002 (role: supervisor, allowed_tools: weather + calculator per data.json)
    sup_key_pem, sup_cert_pem = make_test_cert("agent-002")
    delegator = Delegator("agent-002", sup_key_pem, sup_cert_pem)

    # Sub-agent = agent-001 (role: analyst) — the supervisor delegates a narrower scope to it
    SUB_ID = "agent-001"
    SUB_ROLE = "analyst"

    passed = failed = 0

    # --- Happy path: sub-agent calls a tool inside BOTH its role scope AND delegation scope ---
    # OPA allow rule (delegated): role has weather AND delegation_scope has weather → allow
    token = delegator.delegate(SUB_ID, scope=["weather"], supervisor_allowed_tools=["weather", "calculator"])
    claims = delegator.verify(token)   # also validates the token locally before sending to OPA

    ok = run(
        "sub-agent can call tool within its role AND delegation scope",
        {
            "agent_id": SUB_ID, "role": SUB_ROLE, "tool": "weather",
            "delegated_by": claims["delegated_by"],
            "delegation_scope": claims["delegation_scope"],   # ["weather"]
            "delegation_depth": claims["delegation_depth"],   # 1
            "params": {},
        },
        True,
    )
    passed += ok; failed += not ok

    # --- Tool is in role scope but NOT in delegation scope → deny ---
    # The analyst role allows calculator, but supervisor only delegated weather
    ok = run(
        "sub-agent CANNOT call tool outside delegation scope (calculator)",
        {
            "agent_id": SUB_ID, "role": SUB_ROLE, "tool": "calculator",
            "delegated_by": claims["delegated_by"],
            "delegation_scope": claims["delegation_scope"],   # only ["weather"]
            "delegation_depth": claims["delegation_depth"],
            "params": {},
        },
        False,
    )
    passed += ok; failed += not ok

    # --- Tool not in role scope at all → deny (admin requires admin role) ---
    ok = run(
        "sub-agent CANNOT call admin (not in role or delegation scope)",
        {
            "agent_id": SUB_ID, "role": SUB_ROLE, "tool": "admin",
            "delegated_by": claims["delegated_by"],
            "delegation_scope": claims["delegation_scope"],
            "delegation_depth": claims["delegation_depth"],
            "params": {},
        },
        False,
    )
    passed += ok; failed += not ok

    # --- Depth too deep → deny even if tool is in scope ---
    # OPA rule requires delegation_depth <= 2; 3 is beyond the limit
    ok = run(
        "delegation depth > 2 is denied",
        {
            "agent_id": SUB_ID, "role": SUB_ROLE, "tool": "weather",
            "delegated_by": claims["delegated_by"],
            "delegation_scope": ["weather"],
            "delegation_depth": 3,          # exceeds MAX_DELEGATION_DEPTH
            "params": {},
        },
        False,
    )
    passed += ok; failed += not ok

    # --- Python-side guardrails: checked before the token is even issued ---
    print("\n  Delegator guardrails (Python-side, before OPA):")

    # Supervisor cannot delegate "admin" because it doesn't have admin in its allowed tools
    try:
        delegator.delegate(SUB_ID, scope=["admin"], supervisor_allowed_tools=["weather", "calculator"])
        print("  FAIL  supervisor should not be able to delegate 'admin'")
        failed += 1
    except ValueError as e:
        print(f"  PASS  over-scope blocked: {e}")
        passed += 1

    # Delegation at MAX_DELEGATION_DEPTH cannot go further
    try:
        delegator.delegate(SUB_ID, scope=["weather"], supervisor_allowed_tools=["weather"],
                           current_depth=MAX_DELEGATION_DEPTH)
        print("  FAIL  depth limit should be enforced")
        failed += 1
    except ValueError as e:
        print(f"  PASS  depth limit enforced: {e}")
        passed += 1

    print(f"\n{passed}/{passed+failed} passed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
