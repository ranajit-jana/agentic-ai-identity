"""
Inter-agent message signing and verification.

Every agent signs its output with its CA-issued private key before passing
it to another agent. The recipient verifies the signature against the CA
before letting the content anywhere near its LLM context.

Format:  {**payload, "sig": <base64url-ECDSA-SHA256>, "x5c": <base64-DER-cert>}
Signing: ECDSA-SHA256 over canonical JSON of the payload (sorted keys, compact)
"""

import base64
import json

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def _canonical(payload: dict) -> bytes:
    """Stable UTF-8 JSON for signing — sorted keys prevents key-ordering attacks."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def sign_message(payload: dict, key_pem: bytes, cert_pem: bytes) -> dict:
    """
    Sign payload with the agent's private key.
    Returns {**payload, "sig": <base64url>, "x5c": <base64-DER>}.

    The x5c field embeds the signer's cert so the recipient can verify
    the chain without a separate cert lookup.
    """
    key  = load_pem_private_key(key_pem, password=None)
    cert = x509.load_pem_x509_certificate(cert_pem)

    # Sign the canonical form of the payload — any field modification breaks the sig
    raw_sig  = key.sign(_canonical(payload), ec.ECDSA(hashes.SHA256()))

    # base64url (no padding) is compact and safe in JSON
    sig_b64  = base64.urlsafe_b64encode(raw_sig).rstrip(b"=").decode()

    # DER is the binary cert format; base64-standard (not url-safe) is conventional for x5c
    cert_b64 = base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()

    return {**payload, "sig": sig_b64, "x5c": cert_b64}


def verify_message(signed_msg: dict, ca_pem: bytes) -> tuple[bool, str]:
    """
    Verify a signed inter-agent message:
      1. x5c cert chains to ca_pem (proves sender has a CA-issued identity)
      2. sig is a valid ECDSA-SHA256 signature over the payload fields
         (proves message was not tampered with after signing)

    Returns (ok, reason).
    """
    try:
        sig_b64 = signed_msg.get("sig", "")
        x5c     = signed_msg.get("x5c", "")
        if not sig_b64 or not x5c:
            return False, "missing sig or x5c"

        # Reconstruct the signed payload — exclude sig and x5c themselves
        payload  = {k: v for k, v in signed_msg.items() if k not in ("sig", "x5c")}
        cert_der = base64.b64decode(x5c)
        cert     = x509.load_der_x509_certificate(cert_der)

        # Re-add padding stripped during encoding (base64url requires mod-4 alignment)
        raw_sig  = base64.urlsafe_b64decode(sig_b64 + "==")

        # Verify the sender's cert was issued by our CA
        # This prevents a rogue agent from generating its own self-signed cert
        ca_cert = x509.load_pem_x509_certificate(ca_pem)
        ca_pub  = ca_cert.public_key()
        if isinstance(ca_pub, ec.EllipticCurvePublicKey):
            ca_pub.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                ec.ECDSA(cert.signature_hash_algorithm),  # read hash algo from cert itself
            )
        else:
            return False, f"unsupported CA key type: {type(ca_pub)}"

        # Verify the payload was signed by the private key matching this cert
        cert.public_key().verify(raw_sig, _canonical(payload), ec.ECDSA(hashes.SHA256()))

        return True, "ok"

    except InvalidSignature:
        # Raised by verify() calls — covers both cert chain and payload signature failures
        return False, "signature verification failed"
    except Exception as e:
        return False, str(e)
