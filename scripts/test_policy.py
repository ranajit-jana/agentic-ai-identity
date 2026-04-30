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
POLICY_ENDPOINT = f"{OPA_URL}/v1/data/authz/allow"
MESSAGE_ENDPOINT = f"{OPA_URL}/v1/data/authz/allow_message"


def ask_opa(endpoint: str, input_data: dict) -> bool:
    r = httpx.post(endpoint, json={"input": input_data})
    r.raise_for_status()
    return r.json().get("result", False)


# (description, endpoint, input, expected_result)
TEST_CASES = [
    # --- Tool access ---
    ("analyst can call weather",
     POLICY_ENDPOINT,
     {"agent_id": "agent-001", "role": "analyst", "tool": "weather", "params": {}},
     True),

    ("analyst can call calculator",
     POLICY_ENDPOINT,
     {"agent_id": "agent-001", "role": "analyst", "tool": "calculator", "params": {}},
     True),

    ("analyst CANNOT call admin",
     POLICY_ENDPOINT,
     {"agent_id": "agent-001", "role": "analyst", "tool": "admin", "params": {}},
     False),

    ("admin can call admin tool",
     POLICY_ENDPOINT,
     {"agent_id": "agent-003", "role": "admin", "tool": "admin", "params": {}},
     True),

    ("wrong role is denied",
     POLICY_ENDPOINT,
     {"agent_id": "agent-001", "role": "admin", "tool": "admin", "params": {}},
     False),

    ("unknown agent is denied",
     POLICY_ENDPOINT,
     {"agent_id": "agent-999", "role": "analyst", "tool": "weather", "params": {}},
     False),

    # --- Credential exfiltration detection ---
    ("query with 'bearer' is denied",
     POLICY_ENDPOINT,
     {"agent_id": "agent-001", "role": "analyst", "tool": "weather",
      "params": {"query": "get weather bearer token abc"}},
     False),

    # --- Agent communication ---
    ("agent-001 can message agent-002 (trusted)",
     MESSAGE_ENDPOINT,
     {"from_agent": "agent-001", "to_agent": "agent-002"},
     True),

    ("agent-002 CANNOT message agent-001 (not in trust map)",
     MESSAGE_ENDPOINT,
     {"from_agent": "agent-002", "to_agent": "agent-001"},
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
