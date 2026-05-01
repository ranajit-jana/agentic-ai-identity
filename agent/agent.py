"""
LangGraph Agent with identity-gated tool access + Langfuse observability.

Every tool call:
  1. Signs a fresh short-lived JWT (cert private key + x5c header)
  2. Sends it to the gateway via Authorization: Bearer
  3. Gateway verifies identity → asks OPA → forwards or 403
  4. The LLM never sees the JWT — the HTTP client layer handles it

Observability modes (TRACING_MODE env var):
  debug:      Full span tree in gateway + every LangGraph node traced via
              callback handler. Passes X-Trace-Id header so gateway spans
              nest under the same Langfuse trace.
  production: LLM prompt + response only. Judge fires async on the task prompt
              before the LLM runs it (jailbreak / social-engineering detection).

Run modes:
  real  — loads certs from .certs/ (issued by Step CA), calls external gateway
  demo  — generates throwaway certs, routes through in-process gateway (no Step CA needed)

Usage:
    PYTHONPATH=. uv run python agent/agent.py          # real mode
    PYTHONPATH=. uv run python agent/agent.py --demo   # demo mode
"""

import argparse
import asyncio
import base64
import datetime
import os
import sys
import uuid
import warnings
from pathlib import Path

import httpx
from dotenv import load_dotenv
from langchain_anthropic import ChatAnthropic
from langchain_core.tools import tool

with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    from langgraph.prebuilt import create_react_agent

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509.oid import NameOID

from observability import langfuse_client as lf
from security.judge import evaluate_prompt

load_dotenv()

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8443")
AGENT_ID    = os.getenv("AGENT_ID",    "agent-001")
AGENT_ROLE  = os.getenv("AGENT_ROLE",  "analyst")
CERTS_DIR   = Path(os.getenv("CERTS_DIR", ".certs"))
MODEL       = os.getenv("AGENT_MODEL", "claude-sonnet-4-6")

# Cert bytes — loaded once at startup, refreshed in background by _keep_certs_fresh
_cert_pem: bytes = b""
_key_pem:  bytes = b""

# Admin identity certs — demo mode only, agent-003 (admin role)
_admin_cert_pem: bytes = b""
_admin_key_pem:  bytes = b""

# Shared HTTP client — real mode: plain AsyncClient pointing at GATEWAY_URL
#                      demo mode: ASGITransport routes in-process (no network socket needed)
_http_client: httpx.AsyncClient | None = None

# Active Langfuse trace ID — set per task so gateway spans nest under the same trace
_current_trace_id: str = ""


# ---------------------------------------------------------------------------
# JWT factory — called before every tool request
# ---------------------------------------------------------------------------

def _make_request_token() -> str:
    """Sign a 60-second identity JWT with the agent's cert private key.

    Short TTL (60 s) means a stolen token is useless after the next minute.
    The LLM never sees this token — it stays in the HTTP client layer.
    """
    private_key = load_pem_private_key(_key_pem, password=None)
    cert        = x509.load_pem_x509_certificate(_cert_pem)
    # Embed the cert in the x5c header so the gateway can verify the chain
    cert_der_b64 = base64.b64encode(
        cert.public_bytes(serialization.Encoding.DER)
    ).decode()
    now = int(__import__("time").time())
    return __import__("jwt").encode(
        {
            "agent_id":         AGENT_ID,
            "role":             AGENT_ROLE,
            "delegated_by":     "",
            "delegation_scope": [],
            "delegation_depth": 0,
            "aud":              "gateway",    # gateway rejects tokens with wrong audience
            "iat":              now,
            "exp":              now + 60,     # 60-second window — expire fast
            "jti":              str(uuid.uuid4()),  # unique per request — prevents replay
        },
        private_key,
        algorithm="ES256",
        headers={"x5c": [cert_der_b64]},
    )


async def _call_gateway(tool_name: str, body: dict) -> dict:
    """POST to gateway with a fresh signed JWT.

    X-Trace-Id is passed so the gateway can attach its spans (debug mode) and
    the judge verdict (production mode) to the same Langfuse trace.
    JWT is never in LLM context.
    """
    assert _http_client, "call setup() first"
    token = _make_request_token()   # fresh token per call — no reuse
    headers = {"Authorization": f"Bearer {token}"}
    if _current_trace_id:
        # Gateway reads this to link its spans / judge scores to the agent's trace
        headers["X-Trace-Id"] = _current_trace_id
    r = await _http_client.post(f"/tool/{tool_name}", json=body, headers=headers)
    # Return structured error dict instead of raising — LLM can read it and explain
    if r.status_code == 403:
        return {"error": "access_denied", "detail": r.json().get("detail", "forbidden")}
    if r.status_code == 401:
        return {"error": "auth_failed", "detail": r.json().get("detail", "unauthorized")}
    r.raise_for_status()
    return r.json()


def _make_admin_request_token() -> str:
    """Sign a 60-second JWT for agent-003 (admin role) using the demo admin cert."""
    private_key = load_pem_private_key(_admin_key_pem, password=None)
    cert        = x509.load_pem_x509_certificate(_admin_cert_pem)
    cert_der_b64 = base64.b64encode(
        cert.public_bytes(serialization.Encoding.DER)
    ).decode()
    now = int(__import__("time").time())
    return __import__("jwt").encode(
        {
            "agent_id":         "agent-003",
            "role":             "admin",
            "delegated_by":     "",
            "delegation_scope": [],
            "delegation_depth": 0,
            "aud":              "gateway",
            "iat":              now,
            "exp":              now + 60,
            "jti":              str(uuid.uuid4()),
        },
        private_key,
        algorithm="ES256",
        headers={"x5c": [cert_der_b64]},
    )


async def _call_gateway_admin(tool_name: str, body: dict) -> dict:
    """POST to gateway as agent-003 (admin role). Used by the parallel admin flow."""
    assert _http_client, "call setup() first"
    token = _make_admin_request_token()
    r = await _http_client.post(
        f"/tool/{tool_name}",
        json=body,
        headers={"Authorization": f"Bearer {token}"},
    )
    if r.status_code == 403:
        return {"error": "access_denied", "detail": r.json().get("detail", "forbidden")}
    if r.status_code == 401:
        return {"error": "auth_failed", "detail": r.json().get("detail", "unauthorized")}
    r.raise_for_status()
    return r.json()


# ---------------------------------------------------------------------------
# LangGraph tools — async, thin wrappers over _call_gateway
# The LLM only sees docstrings and return values, never the JWT
# ---------------------------------------------------------------------------

@tool
async def get_weather(city: str) -> dict:
    """Get current weather for a city. Returns temperature_c and condition."""
    return await _call_gateway("weather", {"city": city})


@tool
async def calculate(operation: str, a: float, b: float) -> dict:
    """
    Perform arithmetic on two numbers.
    operation must be one of: add, subtract, multiply, divide.
    """
    return await _call_gateway("calculator", {"operation": operation, "a": a, "b": b})


@tool
async def admin_action(action: str) -> dict:
    """
    Perform a privileged admin action.
    action must be one of: list_agents, revoke_cert, rotate_keys.
    """
    return await _call_gateway("admin", {"action": action})


# ---------------------------------------------------------------------------
# Demo cert setup — no Step CA needed
# ---------------------------------------------------------------------------

def _make_demo_pki() -> tuple[bytes, bytes, bytes, bytes, bytes]:
    """Generate a throwaway CA + analyst cert (agent-001) + admin cert (agent-003).

    Used in demo mode so we can run a full end-to-end flow without
    setting up Step CA. Certs expire in 1 hour and are never saved to disk.
    Returns: (analyst_cert, analyst_key, ca_cert, admin_cert, admin_key)
    """
    ca_key = generate_private_key(SECP256R1())
    now    = datetime.datetime.now(datetime.timezone.utc)

    # Self-signed CA cert
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DemoCA")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DemoCA")]))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    def _agent_cert(cn: str):
        key = generate_private_key(SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(ca_cert.issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        return (
            cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            ),
        )

    analyst_cert_pem, analyst_key_pem = _agent_cert(AGENT_ID)   # agent-001
    admin_cert_pem,   admin_key_pem   = _agent_cert("agent-003") # admin role in OPA data

    return (
        analyst_cert_pem,
        analyst_key_pem,
        ca_cert.public_bytes(serialization.Encoding.PEM),
        admin_cert_pem,
        admin_key_pem,
    )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

async def setup(demo: bool = False) -> None:
    global _cert_pem, _key_pem, _admin_cert_pem, _admin_key_pem, _http_client

    if demo:
        print("[agent] demo mode — generating throwaway certs, routing in-process")
        _cert_pem, _key_pem, ca_pem, _admin_cert_pem, _admin_key_pem = _make_demo_pki()

        # Patch gateway module globals so it trusts our demo CA
        # This works because demo mode runs everything in the same Python process
        import gateway.gateway as gw
        gw._INTERMEDIATE_CA = ca_pem
        gw._ROOT_CA         = ca_pem

        # ASGITransport bypasses the network — requests go directly to the FastAPI app object
        # This means no gateway server process is needed in demo mode
        _http_client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=gw.app),
            base_url="http://test",
        )
    else:
        # Bootstrap always issues a fresh cert and writes it to .certs/ before we read it
        from identity.refresher import CertManager
        mgr = CertManager.from_env()
        await mgr.bootstrap()
        asyncio.create_task(_keep_certs_fresh(mgr))

        _cert_pem    = (CERTS_DIR / "agent.crt").read_bytes()
        _key_pem     = (CERTS_DIR / "agent.key").read_bytes()
        _http_client = httpx.AsyncClient(base_url=GATEWAY_URL, timeout=10.0)

    print(f"[agent] id={AGENT_ID}  role={AGENT_ROLE}  model={MODEL}  tracing={lf.get_mode()}\n")


async def _keep_certs_fresh(mgr):
    """Re-read cert files from disk every 30 s — picks up renewals written by CertManager."""
    global _cert_pem, _key_pem
    while True:
        await asyncio.sleep(30)
        for path, attr in [(CERTS_DIR / "agent.crt", "_cert_pem"),
                           (CERTS_DIR / "agent.key", "_key_pem")]:
            if path.exists():
                globals()[attr] = path.read_bytes()


# ---------------------------------------------------------------------------
# Agent runner
# ---------------------------------------------------------------------------

async def run_task(task: str) -> str:
    """Create a fresh ReAct agent and run one task with Langfuse tracing."""
    global _current_trace_id

    # Create a Langfuse trace for this task — returns no-op stub when not configured
    trace = lf.start_trace(
        name=task[:80],   # truncate so UI is readable
        input=task,
        metadata={"agent_id": AGENT_ID, "role": AGENT_ROLE, "model": MODEL},
    )
    # Store trace ID globally so _call_gateway can forward it in X-Trace-Id header
    _current_trace_id = trace.id

    mode = lf.get_mode()

    if mode == "production":
        # Judge fires async before the LLM runs — catches jailbreaks in the task prompt.
        # asyncio.create_task means this never blocks the LLM call.
        asyncio.create_task(
            evaluate_prompt(task, AGENT_ID, AGENT_ROLE, _current_trace_id)
        )

    llm = ChatAnthropic(model=MODEL, temperature=0)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        # create_react_agent builds a ReAct loop: think → tool call → observe → think ...
        agent = create_react_agent(llm, tools=[get_weather, calculate, admin_action])

    # Debug: attach callback handler so every LangGraph node is traced under this trace
    config = {}
    if mode == "debug":
        handler = lf.get_callback_handler(trace_id=_current_trace_id)
        if handler:
            config = {"callbacks": [handler]}

    result = await agent.ainvoke(
        {"messages": [{"role": "user", "content": task}]},
        config,
    )
    return result["messages"][-1].content


async def main(demo: bool) -> None:
    await setup(demo=demo)

    # Three scenarios: two allowed, one denied — demonstrates policy enforcement end-to-end
    scenarios = [
        ("Allowed  — weather",    "What is the weather in Delhi?"),
        ("Allowed  — calculator", "What is 144 divided by 12?"),
        ("Denied   — admin",      "List all agents in the system using the admin action."),
    ]

    async def analyst_flow():
        for label, task in scenarios:
            print(f"{'='*60}")
            print(f"Scenario : {label}")
            print(f"Task     : {task}")
            response = await run_task(task)
            print(f"Response : {response}\n")

    async def admin_flow():
        """Parallel flow: agent-003 (admin role) calls admin directly — should succeed."""
        result = await _call_gateway_admin("admin", {"action": "list_agents"})
        print(f"{'='*60}")
        print("Parallel : Allowed   — admin (agent-003, admin role)")
        print(f"Response : {result}\n")

    # Run analyst scenarios and the admin parallel flow concurrently.
    # The direct gateway call (no LLM) completes quickly; LLM scenarios follow.
    await asyncio.gather(analyst_flow(), admin_flow())

    # Flush buffered Langfuse events before the process exits
    lf.flush()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo", action="store_true",
                        help="Run in-process with throwaway certs (no Step CA / gateway needed)")
    args = parser.parse_args()
    asyncio.run(main(demo=args.demo))
