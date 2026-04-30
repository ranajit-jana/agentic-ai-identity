# Secure Agentic Tool Access — Identity + Policy + Injection Defense

An AI agent that can only call tools when it has a **verifiable machine identity** and **OPA policy permits it**. Every request is cert-backed, every decision is audited, every agent output is sanitized before it reaches the LLM.

---

## What This Demonstrates

- **Dynamic identity** — agents get short-lived X.509 certs from Step CA, not static API keys
- **Policy-gated tool access** — OPA decides who can call what; role + delegation scope both enforced
- **Delegated authority** — supervisor mints a scoped token for a sub-agent; sub-agent can only use a subset of supervisor's tools
- **Prompt injection defense** — tool responses are sanitized before the LLM sees them; injection in tool output is redacted, not passed through
- **Malicious agent defense** — inter-agent messages verified by OPA trust map + sanitizer + ECDSA signature

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│  agent.py (LangGraph ReAct)                              │
│  • gets throwaway cert (demo) or Step CA cert (real)     │
│  • signs 60-second JWT before every tool call            │
│  • LLM never sees the JWT — HTTP client handles it       │
│                                                          │
│  tools the agent can attempt:                            │
│    weather · calculator · admin (OPA decides who gets in)│
└────────────────────┬─────────────────────────────────────┘
                     │  POST /tool/{name}  OR  POST /message/{to}
                     │  Authorization: Bearer <signed-JWT>
                     ▼
┌──────────────────────────────────────────────────────────┐
│  gateway.py  (FastAPI)                                   │
│                                                          │
│  /tool/weather         /message/{to_agent}               │
│  /tool/calculator      1. verify JWT + x5c               │
│  /tool/admin           2. ask OPA (allow_message)        │
│                        3. Pydantic schema check          │
│  For every /tool/* :   4. sanitize message body          │
│  1. verify JWT + x5c   5. verify ECDSA signature         │
│  2. ask OPA (allow)    6. audit log                      │
│  3. forward to tool                                      │
│  4. sanitize response                                    │
│  5. audit log                                            │
└──────┬───────────────────────────────────────────────────┘
       │ ask OPA              │ forward (if allowed)
       ▼                      ▼
┌─────────────┐       ┌────────────────────┐
│  OPA server │       │  tool_api.py       │
│ policy.rego │       │  /tool/weather     │
│ data.json   │       │  /tool/calculator  │
└─────────────┘       │  /tool/admin       │
                      └────────────────────┘
```

---

## Project Structure

```
agentic-ai-identity/
│
├── agent/
│   ├── agent.py          # LangGraph agent — signs JWT, calls tools via gateway
│   ├── supervisor.py     # Demo: shows 4 malicious-agent attack scenarios
│   └── schemas.py        # Pydantic schemas for inter-agent messages
│
├── gateway/
│   ├── gateway.py        # FastAPI: identity → OPA → sanitize → forward → audit
│   └── auth.py           # JWT + x5c cert chain verification
│
├── identity/
│   ├── refresher.py      # CertManager: bootstrap + auto-renew from Step CA
│   ├── delegator.py      # Supervisor mints scoped token for sub-agent
│   └── signer.py         # ECDSA sign/verify for inter-agent messages
│
├── security/
│   ├── sanitizer.py      # Scans strings for injection patterns (BLOCK / WARN)
│   └── audit.py          # Append-only JSONL audit log
│
├── tools/
│   └── tool_api.py       # FastAPI: weather, calculator, admin endpoints (no auth)
│
├── policy/
│   ├── policy.rego       # OPA: allow rules for tool access + agent messaging
│   └── data.json         # Roles, allowed tools, agent trust map
│
├── scripts/
│   ├── extract_key.py    # One-time: decrypt provisioner JWK from Step CA
│   ├── test_security.py  # Security tests — no external services needed
│   ├── test_policy.py    # OPA rule tests — needs OPA
│   ├── test_delegation.py# Delegation flow tests — needs OPA
│   └── test_gateway.py   # End-to-end gateway tests — needs OPA + tool API
│
├── docker-compose.yml    # OPA + Step CA containers
└── .env                  # Config (ports, agent ID, model)
```

---

## Running the Tests

Tests are split by what they need. Start here — no services required.

### `test_security.py` — No external services needed

Covers all security defenses: sanitizer, message signer, Pydantic schemas, gateway injection redaction, and the `/message` endpoint. Everything is mocked in-process.

```bash
PYTHONPATH=. uv run python scripts/test_security.py
```

```
── Part 1: Sanitizer — injection pattern detection ──
  PASS  clean content passes through
  PASS  ignore_instructions → redacted
  PASS  bearer token in response → redacted
  PASS  JWT pattern in response → redacted
  ...

── Part 2: Message Signer — ECDSA signing and tamper detection ──
  PASS  valid signature verifies
  PASS  tampered payload fails verification
  PASS  cert from wrong CA fails verification
  ...

── Part 3: Schema Validation ──
── Part 4: Tool Response — gateway redacts injection ──
── Part 5: Message Gateway — /message endpoint defenses ──

Result: 56/56 passed
```

---

### `test_policy.py` — Needs OPA

Tests OPA Rego rules directly: role-based allow/deny, exfiltration detection, agent trust map.

```bash
docker compose up -d opa
PYTHONPATH=. uv run python scripts/test_policy.py
```

```
  PASS  analyst can call weather
  PASS  analyst CANNOT call admin
  PASS  wrong role claim is denied
  PASS  query with 'bearer' keyword is denied
  PASS  agent-002 can message agent-001 (in trust map)
  PASS  agent-999 CANNOT message anyone (not in trust map)
  ...
```

---

### `test_delegation.py` — Needs OPA

Tests the delegated authority flow: supervisor issues a scoped token, OPA enforces that the sub-agent can only call tools within the granted scope.

```bash
docker compose up -d opa
PYTHONPATH=. uv run python scripts/test_delegation.py
```

```
  PASS  sub-agent can call tool within its role AND delegation scope
  PASS  sub-agent CANNOT call tool outside delegation scope (calculator)
  PASS  delegation depth > 2 is denied
  PASS  over-scope blocked: Supervisor cannot delegate tools it doesn't have
  ...
```

---

### `test_gateway.py` — Needs OPA + Tool API

End-to-end gateway tests: JWT verification, OPA allow/deny, delegation enforcement, exfiltration detection. Runs in-process via ASGI transport — no gateway server needed.

```bash
docker compose up -d opa
PYTHONPATH=. uv run uvicorn tools.tool_api:app --port 8000 &

PYTHONPATH=. uv run python scripts/test_gateway.py
```

```
  PASS  analyst calls weather → 200
  PASS  analyst calls admin → 403
  PASS  agent-001 claiming 'admin' role → 403
  PASS  unknown agent → 403
  PASS  exfiltration in params → 403
  PASS  delegated agent calls in-scope tool → 200
  PASS  delegated agent calls out-of-scope tool → 403
  ...
```

---

## Running the Agent Demo

### Demo mode — no Step CA, no gateway server needed

Only needs OPA and the tool API. Generates throwaway certs in-process.

```bash
# start dependencies
docker compose up -d opa
PYTHONPATH=. uv run uvicorn tools.tool_api:app --port 8000 &

# run agent
PYTHONPATH=. uv run python agent/agent.py --demo
```

```
======================================================
Scenario : Allowed  — weather
Task     : What is the weather in Delhi?
Response : The weather in Delhi is currently 38°C and sunny.

======================================================
Scenario : Allowed  — calculator
Task     : What is 144 divided by 12?
Response : 144 divided by 12 equals 12.

======================================================
Scenario : Denied   — admin
Task     : List all agents in the system using the admin action.
Response : I was unable to perform the admin action — access was denied (403).
```

### Malicious agent demo — shows 4 attack scenarios

```bash
PYTHONPATH=. uv run python agent/supervisor.py --demo
```

```
Scenario 1 — Trusted supervisor, clean message         PASS ✓
Scenario 2 — Malicious agent (agent-999)               BLOCKED ✓  (OPA)
Scenario 3 — Trusted supervisor, injected content      BLOCKED ✓  (sanitizer)
Scenario 4a — Properly signed message                  PASS ✓
Scenario 4b — Tampered signed message                  BLOCKED ✓  (sig verify)
```

---

## Full Setup (Real Mode with Step CA)

### 1. Prerequisites

```bash
# install uv if needed
curl -LsSf https://astral.sh/uv/install.sh | sh

# install dependencies
uv sync
```

### 2. Configure environment

```bash
cp .env.example .env
# edit .env — set ANTHROPIC_API_KEY at minimum
```

### 3. Start Step CA + OPA

```bash
docker compose up -d
```

Step CA initialises on first run and writes its config to `./ca-data/`.

### 4. Extract the provisioner key (one time only)

Step CA encrypts the provisioner key in `ca-data/config/ca.json`. This script decrypts it and writes `identity/provisioner.json` which the agent uses to request certs.

```bash
PYTHONPATH=. uv run python scripts/extract_key.py
# prints the CA fingerprint — paste it into .env as STEP_CA_FINGERPRINT
```

### 5. Start the tool API

```bash
PYTHONPATH=. uv run uvicorn tools.tool_api:app --port 8000 --reload
```

### 6. Start the gateway

```bash
PYTHONPATH=. uv run uvicorn gateway.gateway:app --port 8443 --reload
```

### 7. Run the agent

```bash
PYTHONPATH=. uv run python agent/agent.py
```

---

## How Each Layer Works

### Identity — cert-backed JWT

Every agent gets a short-lived X.509 cert from Step CA. Before each tool call it signs a 60-second JWT with its cert private key and embeds the cert in the `x5c` header. The gateway verifies the cert chain → verifies the JWT signature → checks `agent_id` matches the cert CN. The LLM never sees the JWT.

```
Agent private key (Step CA issued)
  └─▶ sign JWT (60s TTL, jti per request)
        └─▶ gateway: x5c chain ✓ → sig ✓ → CN match ✓ → identity confirmed
```

### Policy — OPA Rego

The gateway asks OPA before forwarding every request. OPA checks role, allowed tools, delegation scope, depth limit, and exfiltration keywords — all in one policy call.

```
OPA input:  { agent_id, role, tool, delegated_by, delegation_scope, delegation_depth, params }
OPA output: true / false
```

### Delegation

A supervisor issues a scoped JWT to a sub-agent. The sub-agent can only call tools that appear in **both** its own role's allowed tools and the delegation scope. OPA enforces both conditions.

```
Supervisor (weather, calculator, admin)
  └─▶ delegate(sub_agent, scope=["weather"])
        └─▶ OPA: tool in role_scope ∩ delegation_scope → allow
              │   tool only in role_scope but not delegation_scope → deny
```

### Injection Defense

Tool responses are scanned for injection patterns before being returned to the LLM. BLOCK-level content (e.g. `"Ignore previous instructions"`, bearer tokens, raw JWTs) is replaced with `[REDACTED]`. Every detection is written to `audit.jsonl`.

### Agent Communication

Inter-agent messages go through `POST /message/{to_agent}`. The gateway enforces four layers in order:

| # | Check | Blocks |
|---|---|---|
| 1 | OPA `allow_message` | Untrusted senders (not in trust map) |
| 2 | Pydantic schema | Oversized or malformed messages |
| 3 | Sanitizer | Injection from trusted-but-compromised agents |
| 4 | ECDSA signature | In-transit tampering (MITM) |

---

## Tech Stack

| Layer | Tool | Why |
|---|---|---|
| CA / Identity | Step CA (`smallstep/step-ca`) | Issues short-lived X.509 certs, auto-renewal |
| Policy | OPA (`openpolicyagent/opa`) | Rego rules — role, delegation, trust map |
| Gateway | FastAPI + httpx | Cert verification, OPA proxy, sanitizer |
| Agent | LangGraph + Claude | ReAct loop; HTTP client holds cert, not LLM |
| Signing | `cryptography` (ECDSA) | Message signing and chain verification |
| Schemas | Pydantic | Typed inter-agent messages |
| Audit | JSONL append-only file | Immutable decision trail |
