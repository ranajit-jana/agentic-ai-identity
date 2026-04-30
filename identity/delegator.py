"""
Delegated Authority — supervisor issues a signed delegation token to a sub-agent.

Flow:
  1. Supervisor has its own X.509 cert (identity, from Step CA).
  2. Supervisor calls delegate() → signed JWT with sub-agent ID + scoped tools.
  3. Sub-agent presents: X.509 cert (who I am) + delegation JWT (what I'm allowed).
  4. Gateway verifies both; OPA checks tool is in BOTH role scope AND delegation scope.

Key constraint: delegation scope can only be a SUBSET of the supervisor's own allowed tools.
The supervisor cannot grant more than it has.
"""

import time
from pathlib import Path

import jwt
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# Prevent deep delegation chains — supervisor → sub-agent → sub-sub-agent is the limit.
# Deeper chains are hard to audit and give attackers more hops to exploit.
MAX_DELEGATION_DEPTH = 2


class Delegator:
    def __init__(self, supervisor_id: str, supervisor_key_pem: bytes, supervisor_cert_pem: bytes):
        self.supervisor_id = supervisor_id
        # The private key is used to sign delegation tokens — sub-agent verifies with cert public key
        self._private_key = load_pem_private_key(supervisor_key_pem, password=None)
        self._cert_pem = supervisor_cert_pem

    @classmethod
    def from_certs_dir(cls, supervisor_id: str, certs_dir: Path = Path(".certs")) -> "Delegator":
        # Convenience factory — reads certs from the standard Step CA output directory
        return cls(
            supervisor_id=supervisor_id,
            supervisor_key_pem=(certs_dir / "agent.key").read_bytes(),
            supervisor_cert_pem=(certs_dir / "agent.crt").read_bytes(),
        )

    def delegate(
        self,
        sub_agent_id: str,
        scope: list[str],                        # tools the sub-agent is allowed to call
        supervisor_allowed_tools: list[str],     # what the supervisor itself can call
        ttl_seconds: int = 300,                  # short TTL reduces blast radius if token leaks
        current_depth: int = 0,
    ) -> str:
        """
        Issue a signed delegation JWT for sub_agent_id.

        scope must be a subset of supervisor_allowed_tools — a supervisor
        cannot grant permissions it doesn't have.
        """
        # Enforce depth limit before issuing — OPA also checks this, but fail-fast here too
        if current_depth >= MAX_DELEGATION_DEPTH:
            raise ValueError(
                f"Delegation depth {current_depth} exceeds max ({MAX_DELEGATION_DEPTH})"
            )

        # Prevent scope escalation — can't delegate what you don't have
        over_scoped = set(scope) - set(supervisor_allowed_tools)
        if over_scoped:
            raise ValueError(
                f"Supervisor '{self.supervisor_id}' cannot delegate tools it doesn't have: {over_scoped}"
            )

        now = int(time.time())
        payload = {
            "iss": self.supervisor_id,            # who issued this delegation
            "sub": sub_agent_id,                  # who the delegation is for
            "iat": now,
            "exp": now + ttl_seconds,
            "delegated_by": self.supervisor_id,   # gateway reads this to detect delegated calls
            "delegation_scope": scope,            # OPA intersects this with role's allowed tools
            "delegation_depth": current_depth + 1,  # gateway passes to OPA for depth check
        }
        # Sign with supervisor's Step CA key — recipient verifies with supervisor's cert public key
        return jwt.encode(payload, self._private_key, algorithm="ES256")

    def verify(self, token: str) -> dict:
        """
        Verify a delegation token against the supervisor's cert public key.
        Returns the decoded claims if valid.
        """
        # Use the cert public key (not the private key) for verification
        cert = x509.load_pem_x509_certificate(self._cert_pem)
        return jwt.decode(
            token,
            cert.public_key(),
            algorithms=["ES256"],
            # Require these claims — a delegation token without them is invalid
            options={"require": ["iss", "sub", "exp", "delegation_scope", "delegated_by"]},
        )


def parse_delegation_token(token: str, supervisor_cert_pem: bytes) -> dict:
    """
    Verify and decode a delegation token using the supervisor's public key.
    Used by the gateway to validate incoming delegation claims.
    """
    cert = x509.load_pem_x509_certificate(supervisor_cert_pem)
    return jwt.decode(
        token,
        cert.public_key(),
        algorithms=["ES256"],
        options={"require": ["iss", "sub", "exp", "delegation_scope", "delegated_by"]},
    )
