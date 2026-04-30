"""
Smoke-tests OPA policy decisions against expected outcomes.

Usage:
    docker compose up -d opa
    uv run python scripts/test_policy.py
"""

import httpx
from dotenv import load_dotenv
import os
import sys

load_dotenv()
OPA_URL = os.getenv("OPA_URL", "http://localhost:8181")
POLICY_ENDPOINT  = f"{OPA_URL}/v1/data/authz/allow"
MESSAGE_ENDPOINT = f"{OPA_URL}/v1/data/authz/allow_message"


def ask_opa(endpoint: str, input_data: dict) -> bool:
    r = httpx.post(endpoint, json={"input": input_data})
    r.raise_for_status()
    return r.json().get("result", False)


# Each entry: (description, endpoint, input, expected_result)
# Input fields mirror what the gateway sends to OPA for each request type.
TEST_CASES = [
    # --- Tool access: role-based allow ---
    ("analyst can call weather",
     POLICY_ENDPOINT,
     # delegated_by/scope omitted → OPA treats them as empty → non-delegated path
     {"agent_id": "agent-001", "role": "analyst", "tool": "weather", "params": {}},
     True),

    ("analyst can call calculator",
     POLICY_ENDPOINT,
     {"agent_id": "agent-001", "role": "analyst", "tool": "calculator", "params": {}},
     True),

    # analyst's allowed_tools does not include "admin" → deny
    ("analyst CANNOT call admin",
     POLICY_ENDPOINT,
     {"agent_id": "agent-001", "role": "analyst", "tool": "admin", "params": {}},
     False),

    ("admin can call admin tool",
     POLICY_ENDPOINT,
     {"agent_id": "agent-003", "role": "admin", "tool": "admin", "params": {}},
     True),

    # agent-001's registered role is "analyst" but it claims "admin" → mismatch → deny
    ("wrong role claim is denied",
     POLICY_ENDPOINT,
     {"agent_id": "agent-001", "role": "admin", "tool": "admin", "params": {}},
     False),

    # agent-999 is not in data.roles → data.roles["agent-999"] is undefined → deny
    ("unknown agent is denied",
     POLICY_ENDPOINT,
     {"agent_id": "agent-999", "role": "analyst", "tool": "weather", "params": {}},
     False),

    # --- Credential exfiltration detection ---
    # The params.query contains "bearer" → exfiltration_attempt fires → deny
    ("query with 'bearer' keyword is denied",
     POLICY_ENDPOINT,
     {"agent_id": "agent-001", "role": "analyst", "tool": "weather",
      "params": {"query": "get weather bearer token abc"}},
     False),

    # --- Agent communication trust map ---
    # agent_trust["agent-002"]["agent-001"] == "trusted" → allow
    ("agent-001 can message agent-002 (in trust map)",
     MESSAGE_ENDPOINT,
     {"from_agent": "agent-001", "to_agent": "agent-002"},
     True),

    # agent_trust["agent-001"]["agent-002"] == "trusted" → allow
    # (agent-001 explicitly trusts agent-002 per policy/data.json)
    ("agent-002 can message agent-001 (in trust map)",
     MESSAGE_ENDPOINT,
     {"from_agent": "agent-002", "to_agent": "agent-001"},
     True),

    # agent-999 is not listed under any agent's trust map → deny
    ("agent-999 CANNOT message anyone (not in trust map)",
     MESSAGE_ENDPOINT,
     {"from_agent": "agent-999", "to_agent": "agent-001"},
     False),
]


def main():
    print(f"OPA at {OPA_URL}\n")
    passed = failed = 0

    for desc, endpoint, inp, expected in TEST_CASES:
        try:
            result = ask_opa(endpoint, inp)
            ok = result == expected
        except Exception as e:
            print(f"  ERROR  {desc}\n         {e}")
            failed += 1
            continue

        icon = "PASS" if ok else "FAIL"
        print(f"  {icon}  {desc}")
        if not ok:
            print(f"         expected={expected}  got={result}")
        passed += ok
        failed += not ok

    print(f"\n{passed}/{passed+failed} passed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
