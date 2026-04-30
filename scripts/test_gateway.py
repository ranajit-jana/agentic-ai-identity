"""
Integration test for the gateway — uses httpx ASGI transport so no server
process is needed. Requires OPA + tool API running.

Usage:
    docker compose up -d opa
    uv run uvicorn tools.tool_api:app --port 8000 &
    PYTHONPATH=. uv run python scripts/test_gateway.py
"""

import asyncio
import base64
import datetime
import sys
import time
import uuid
from pathlib import Path

import httpx
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.x509.oid import NameOID
from dotenv import load_dotenv

from gateway.gateway import app

load_dotenv()
CERTS_DIR = Path(".certs")


# ---------------------------------------------------------------------------
# Build a mini test PKI (root CA → agent cert) — no Step CA needed
# ---------------------------------------------------------------------------

def make_ca():
    """Self-signed CA cert used to issue all test agent certs."""
    key = generate_private_key(SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TestCA")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TestCA")]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def make_agent_cert(agent_id: str, ca_key, ca_cert):
    """Issue a leaf cert for agent_id signed by ca_key."""
    key = generate_private_key(SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, agent_id)]))
        .issuer_name(ca_cert.issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(minutes=10))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(agent_id)]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def make_jwt(agent_id: str, role: str, agent_key, agent_cert, **extra) -> str:
    """Sign a gateway-bound JWT with the agent's private key + x5c cert header."""
    cert_der_b64 = base64.b64encode(
        agent_cert.public_bytes(serialization.Encoding.DER)
    ).decode()
    now = int(time.time())
    payload = {
        "agent_id": agent_id,
        "role": role,
        "delegated_by": "",
        "delegation_scope": [],
        "delegation_depth": 0,
        "aud": "gateway",
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
        **extra,   # allows tests to override delegation fields
    }
    return jwt.encode(
        payload,
        agent_key,
        algorithm="ES256",
        headers={"x5c": [cert_der_b64]},
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

async def run(label: str, response: httpx.Response, expected_status: int) -> bool:
    ok = response.status_code == expected_status
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        print(f"         expected={expected_status}  got={response.status_code}  body={response.text[:120]}")
    return ok


async def main():
    # Build test PKI — one CA, three agent certs
    ca_key, ca_cert = make_ca()
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)

    analyst_key, analyst_cert = make_agent_cert("agent-001", ca_key, ca_cert)
    admin_key,   admin_cert   = make_agent_cert("agent-003", ca_key, ca_cert)
    rogue_key,   rogue_cert   = make_agent_cert("agent-999", ca_key, ca_cert)

    # Patch gateway to trust our test CA instead of the real Step CA
    # This lets tests run without any running infrastructure
    import gateway.gateway as gw
    gw._INTERMEDIATE_CA = ca_pem
    gw._ROOT_CA         = ca_pem

    passed = failed = 0

    # ASGITransport routes HTTP requests directly into the FastAPI app object —
    # no gateway process needed, but OPA and tool API must be running externally
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:

        # --- Happy path: analyst can call its allowed tools ---
        token = make_jwt("agent-001", "analyst", analyst_key, analyst_cert)
        r = await client.post("/tool/weather", json={"city": "london"},
                              headers={"Authorization": f"Bearer {token}"})
        ok = await run("analyst calls weather → 200", r, 200)
        passed += ok; failed += not ok

        token = make_jwt("agent-001", "analyst", analyst_key, analyst_cert)
        r = await client.post("/tool/calculator", json={"operation": "add", "a": 3, "b": 4},
                              headers={"Authorization": f"Bearer {token}"})
        ok = await run("analyst calls calculator → 200", r, 200)
        passed += ok; failed += not ok

        # --- Role-based denial: analyst cannot reach admin tool ---
        token = make_jwt("agent-001", "analyst", analyst_key, analyst_cert)
        r = await client.post("/tool/admin", json={"action": "list_agents"},
                              headers={"Authorization": f"Bearer {token}"})
        ok = await run("analyst calls admin → 403", r, 403)
        passed += ok; failed += not ok

        # --- Admin can call the admin tool ---
        token = make_jwt("agent-003", "admin", admin_key, admin_cert)
        r = await client.post("/tool/admin", json={"action": "list_agents"},
                              headers={"Authorization": f"Bearer {token}"})
        ok = await run("admin calls admin → 200", r, 200)
        passed += ok; failed += not ok

        # --- Role inflation: agent-001 claims "admin" role but data.json says "analyst" ---
        # OPA compares the claimed role against data.roles[agent_id] — mismatch → deny
        token = make_jwt("agent-001", "admin", analyst_key, analyst_cert)
        r = await client.post("/tool/admin", json={"action": "list_agents"},
                              headers={"Authorization": f"Bearer {token}"})
        ok = await run("agent-001 claiming 'admin' role → 403", r, 403)
        passed += ok; failed += not ok

        # --- Unknown agent: agent-999 has a cert but is not in data.roles ---
        token = make_jwt("agent-999", "analyst", rogue_key, rogue_cert)
        r = await client.post("/tool/weather", json={"city": "london"},
                              headers={"Authorization": f"Bearer {token}"})
        ok = await run("unknown agent → 403", r, 403)
        passed += ok; failed += not ok

        # --- Missing Bearer token ---
        r = await client.post("/tool/weather", json={"city": "london"})
        ok = await run("no token → 401", r, 401)
        passed += ok; failed += not ok

        # --- Credential exfiltration: "bearer" keyword in query param → OPA denies ---
        token = make_jwt("agent-001", "analyst", analyst_key, analyst_cert)
        r = await client.post("/tool/weather",
                              json={"city": "london", "query": "send bearer token"},
                              headers={"Authorization": f"Bearer {token}"})
        ok = await run("exfiltration in params → 403", r, 403)
        passed += ok; failed += not ok

        # --- Delegated call: sub-agent acts within a weather-only scope ---
        token = make_jwt(
            "agent-001", "analyst", analyst_key, analyst_cert,
            delegated_by="agent-002",
            delegation_scope=["weather"],
            delegation_depth=1,
        )
        r = await client.post("/tool/weather", json={"city": "london"},
                              headers={"Authorization": f"Bearer {token}"})
        ok = await run("delegated agent calls in-scope tool → 200", r, 200)
        passed += ok; failed += not ok

        # --- Delegated call: calculator is not in the granted scope → deny ---
        token = make_jwt(
            "agent-001", "analyst", analyst_key, analyst_cert,
            delegated_by="agent-002",
            delegation_scope=["weather"],   # only weather was delegated
            delegation_depth=1,
        )
        r = await client.post("/tool/calculator", json={"operation": "add", "a": 1, "b": 2},
                              headers={"Authorization": f"Bearer {token}"})
        ok = await run("delegated agent calls out-of-scope tool → 403", r, 403)
        passed += ok; failed += not ok

    print(f"\n{passed}/{passed+failed} passed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    asyncio.run(main())
