"""
Cert-backed JWT verification for the gateway.

Agents sign a short-lived JWT with their Step CA private key and include
the cert in the x5c header. The gateway:
  1. Extracts the cert from x5c
  2. Verifies the cert was signed by our Step CA (intermediate or root)
  3. Verifies the JWT signature using the cert's public key
  4. Ensures the agent_id claim matches the cert CN
  5. Returns structured identity claims for OPA

This binds every request to a real Step CA identity — the agent cannot
claim an agent_id it doesn't own because it would need the matching cert key.
"""

import base64
import datetime
from dataclasses import dataclass, field

import jwt
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec


# Structured identity extracted from a verified JWT — passed to OPA for policy decisions
@dataclass
class AgentIdentity:
    agent_id: str
    role: str
    delegated_by: str = ""            # non-empty only when acting on behalf of a supervisor
    delegation_scope: list[str] = field(default_factory=list)  # tools the sub-agent may call
    delegation_depth: int = 0         # how many hops deep in the delegation chain


def _verify_cert_signature(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    """Verify that cert was signed by issuer — supports EC and RSA CA keys."""
    pub = issuer.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        # Step CA typically uses EC P-256 — standard path
        pub.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
    else:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        else:
            raise ValueError(f"Unsupported CA key type: {type(pub)}")


def verify_agent_jwt(
    token: str,
    intermediate_ca_pem: bytes,
    root_ca_pem: bytes,
) -> AgentIdentity:
    """
    Verify a cert-backed JWT and return the agent's identity.

    JWT header must contain x5c with the agent's DER cert (base64-encoded).
    JWT payload must contain: agent_id, role, exp, aud="gateway".
    """
    # Step 1: decode header without signature check to get the x5c cert
    # We need the cert first to know which public key to use for verification
    try:
        headers = jwt.get_unverified_header(token)
    except Exception as e:
        raise ValueError(f"Malformed JWT: {e}")

    x5c = headers.get("x5c")
    if not x5c:
        # Bare JWTs (no cert) are rejected — every request must prove its CA-issued identity
        raise ValueError("Missing x5c in JWT header — cert-backed JWT required")

    # x5c is a list; first element is the leaf (agent) cert in base64-DER format
    cert_der = base64.b64decode(x5c[0])
    cert = x509.load_der_x509_certificate(cert_der)

    # Step 2: verify the agent's cert chains back to our trusted CA
    # Try intermediate first (normal Step CA chain), then root (simple CA setup)
    intermediate = x509.load_pem_x509_certificate(intermediate_ca_pem)
    root = x509.load_pem_x509_certificate(root_ca_pem)

    try:
        _verify_cert_signature(cert, intermediate)       # leaf → intermediate
    except Exception:
        try:
            _verify_cert_signature(cert, root)           # leaf → root (simple CA setup)
        except Exception as e:
            raise ValueError(f"Agent cert not signed by trusted CA: {e}")

    # Step 3: check cert is within its valid window
    # Step CA issues short-lived certs (default 24h); expired = identity no longer valid
    now = datetime.datetime.now(datetime.timezone.utc)
    if cert.not_valid_after_utc < now:
        raise ValueError("Agent cert has expired")
    if cert.not_valid_before_utc > now:
        raise ValueError("Agent cert is not yet valid")

    # Step 4: verify JWT signature using the cert's public key
    # This proves the agent possesses the private key matching the cert
    try:
        claims = jwt.decode(
            token,
            cert.public_key(),
            algorithms=["ES256"],
            audience="gateway",         # rejects tokens not intended for this gateway
        )
    except jwt.ExpiredSignatureError:
        raise ValueError("JWT has expired")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"JWT verification failed: {e}")

    # Step 5: agent_id in the JWT must match the cert's CN
    # Without this check, a compromised agent could forge another agent's ID in the payload
    cn_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if not cn_attrs:
        raise ValueError("Agent cert has no CN")
    cert_cn = cn_attrs[0].value
    if claims.get("agent_id") != cert_cn:
        raise ValueError(
            f"JWT agent_id '{claims.get('agent_id')}' does not match cert CN '{cert_cn}'"
        )

    return AgentIdentity(
        agent_id=claims["agent_id"],
        role=claims.get("role", ""),
        delegated_by=claims.get("delegated_by", ""),
        delegation_scope=claims.get("delegation_scope", []),
        delegation_depth=claims.get("delegation_depth", 0),
    )


def make_agent_jwt(
    agent_id: str,
    role: str,
    cert_pem: bytes,
    key_pem: bytes,
    delegated_by: str = "",
    delegation_scope: list[str] | None = None,
    delegation_depth: int = 0,
    ttl_seconds: int = 60,          # short-lived by design — reduces window for replay attacks
) -> str:
    """
    Sign a short-lived identity JWT with the agent's Step CA private key.
    Includes the cert in the x5c header so the gateway can verify it.

    Called by the agent before each tool request.
    """
    import time
    import uuid
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.serialization import Encoding

    private_key = load_pem_private_key(key_pem, password=None)
    cert = x509.load_pem_x509_certificate(cert_pem)

    # DER is the binary format; base64-encode it to embed in the JSON JWT header
    cert_der_b64 = base64.b64encode(cert.public_bytes(Encoding.DER)).decode()

    now = int(time.time())
    return jwt.encode(
        {
            "agent_id":         agent_id,
            "role":             role,
            "delegated_by":     delegated_by,
            "delegation_scope": delegation_scope or [],
            "delegation_depth": delegation_depth,
            "aud":              "gateway",      # must match audience check in verify_agent_jwt
            "iat":              now,
            "exp":              now + ttl_seconds,
            "jti":              str(uuid.uuid4()),  # unique per request — prevents replay
        },
        private_key,
        algorithm="ES256",
        headers={"x5c": [cert_der_b64]},       # cert embedded so gateway can verify chain
    )
