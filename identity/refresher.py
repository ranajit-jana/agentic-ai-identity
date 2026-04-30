"""
CertManager — requests a short-lived X.509 cert from Step CA and auto-renews it.

Bootstrap flow  : generate EC key + CSR → sign one-time token (OTT) with
                  provisioner JWK → POST /1.0/sign → get cert.
Renewal flow    : present current cert via mTLS → POST /1.0/renew → get new cert.
                  No OTT needed after first cert — cert authenticates the renewal.
"""

import asyncio
import base64
import hashlib
import json
import ssl
import struct
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import httpx
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePrivateNumbers,
    EllipticCurvePublicNumbers,
    generate_private_key,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.x509.oid import NameOID


# ---------------------------------------------------------------------------
# JWK / JWE helpers
# ---------------------------------------------------------------------------

def _b64d(s: str) -> bytes:
    # base64url decode — add padding that the standard expects but JWE omits
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _jwk_to_private_key(jwk: dict):
    """Decode an EC P-256 JWK (with 'd') into a cryptography private key."""
    # JWK stores x, y, d as base64url-encoded big-endian integers
    x = int.from_bytes(_b64d(jwk["x"]), "big")
    y = int.from_bytes(_b64d(jwk["y"]), "big")
    d = int.from_bytes(_b64d(jwk["d"]), "big")
    pub = EllipticCurvePublicNumbers(x=x, y=y, curve=SECP256R1())
    return EllipticCurvePrivateNumbers(private_value=d, public_numbers=pub).private_key()


def decrypt_pbes2_jwe(token: str, password: str) -> bytes:
    """
    Decrypt a PBES2-HS256+A128KW JWE compact token.
    Supports A256GCM and A128CBC-HS256 content encryption (detects from header).

    Step CA stores the provisioner's private JWK encrypted this way in ca.json.
    We need to decrypt it to get the signing key for OTTs (one-time tokens).
    """
    import hmac as _hmac
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # JWE compact serialization: header.encryptedKey.iv.ciphertext.tag
    header_b64, enc_key_b64, iv_b64, ciphertext_b64, tag_b64 = token.split(".")
    header = json.loads(_b64d(header_b64))

    # 1. Derive the key-wrapping key using PBKDF2
    # The salt must include the algorithm name as a prefix (PBES2 spec requirement)
    salt = header["alg"].encode() + b"\x00" + _b64d(header["p2s"])
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=header["p2c"])
    kek = kdf.derive(password.encode())   # A128KW always uses a 16-byte key

    # 2. Unwrap the content-encryption key (CEK) using AES-128 key wrap
    cek = aes_key_unwrap(kek, _b64d(enc_key_b64), None)

    iv, ciphertext, tag = _b64d(iv_b64), _b64d(ciphertext_b64), _b64d(tag_b64)
    aad = header_b64.encode()   # authenticated additional data = original header bytes

    # 3. Decrypt — Step CA uses A256GCM; fallback to A128CBC-HS256 for older configs
    if "GCM" in header.get("enc", "A256GCM"):
        # GCM authentication tag is appended to ciphertext in the AESGCM API
        return AESGCM(cek).decrypt(iv, ciphertext + tag, aad)

    # A128CBC-HS256: first half of CEK is MAC key, second half is encryption key
    mac_key, enc_key = cek[:16], cek[16:]
    # AL field = AAD length in bits as a big-endian 64-bit integer (JOSE spec)
    mac_input = aad + iv + ciphertext + struct.pack(">Q", len(aad) * 8)
    expected_tag = _hmac.new(mac_key, mac_input, "sha256").digest()[:16]
    if not _hmac.compare_digest(expected_tag, tag):
        raise ValueError("JWE HMAC verification failed — wrong password?")
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
    padded = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
    # Strip PKCS#7 padding — last byte tells us how many padding bytes were added
    return padded[: -padded[-1]]


# ---------------------------------------------------------------------------
# CertManager
# ---------------------------------------------------------------------------

@dataclass
class _Cert:
    pem: bytes
    key_pem: bytes
    expires_at: float   # Unix timestamp from the cert's notAfter field


class CertManager:
    """
    Manages a short-lived X.509 identity cert for one agent.

    Usage:
        mgr = CertManager.from_env()
        await mgr.bootstrap()
        asyncio.create_task(mgr.refresh_loop())
        # then use mgr.ssl_context on every outbound httpx call
    """

    def __init__(
        self,
        ca_url: str,
        agent_id: str,
        provisioner_jwk: dict,
        ca_fingerprint: str,
        certs_dir: Path = Path(".certs"),
    ):
        self.ca_url = ca_url.rstrip("/")
        self.agent_id = agent_id
        self.provisioner_jwk = provisioner_jwk    # decrypted provisioner key from ca.json
        self.ca_fingerprint = ca_fingerprint      # SHA-256 of CA root cert — prevents MITM on first fetch
        self.certs_dir = Path(certs_dir)
        self.certs_dir.mkdir(exist_ok=True)
        self._cert: _Cert | None = None
        self._ca_pem: bytes | None = None

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> "CertManager":
        # Reads all config from environment variables + the decrypted provisioner key file
        from dotenv import load_dotenv
        import os
        load_dotenv()
        provisioner_path = Path("identity/provisioner.json")
        if not provisioner_path.exists():
            raise FileNotFoundError(
                "identity/provisioner.json not found — run: uv run python scripts/extract_key.py"
            )
        return cls(
            ca_url=os.environ["STEP_CA_URL"],
            agent_id=os.environ["AGENT_ID"],
            provisioner_jwk=json.loads(provisioner_path.read_text()),
            ca_fingerprint=os.environ["STEP_CA_FINGERPRINT"],
            certs_dir=Path(os.getenv("CERTS_DIR", ".certs")),
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def bootstrap(self) -> None:
        """Fetch root CA cert then request the first identity cert."""
        await self._fetch_root_ca()
        await self._sign()
        self._save()
        print(f"[identity] cert issued  agent={self.agent_id}  expires={time.ctime(self._cert.expires_at)}")

    async def refresh_loop(self) -> None:
        """Background task: renew the cert when <90 s remain on its TTL."""
        while True:
            await asyncio.sleep(30)
            # Renew with plenty of time to spare — avoids race between expiry and next request
            if self._cert and (self._cert.expires_at - time.time()) < 90:
                await self._renew()
                self._save()
                print(f"[identity] cert renewed agent={self.agent_id}  expires={time.ctime(self._cert.expires_at)}")

    @property
    def ssl_context(self) -> ssl.SSLContext:
        """mTLS SSLContext — pass as verify= in httpx.AsyncClient."""
        if not self._cert:
            raise RuntimeError("call bootstrap() first")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cadata=self._ca_pem.decode())
        ctx.load_cert_chain(
            self.certs_dir / "agent.crt",
            self.certs_dir / "agent.key",
        )
        return ctx

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _fetch_root_ca(self) -> None:
        # Fetch CA cert by its SHA-256 fingerprint — fingerprint is pinned in .env
        # so an attacker can't substitute a different CA on the network
        async with httpx.AsyncClient(verify=False) as c:
            r = await c.get(f"{self.ca_url}/root/{self.ca_fingerprint}")
            r.raise_for_status()
        self._ca_pem = r.json()["ca"].encode()

    def _make_ott(self) -> str:
        """One-time token — JWT signed with the provisioner's EC private key."""
        now = int(time.time())
        private_key = _jwk_to_private_key(self.provisioner_jwk)
        return jwt.encode(
            {
                "aud": f"{self.ca_url}/1.0/sign",   # token is scoped to this endpoint only
                "exp": now + 60,
                "iat": now,
                "iss": self.provisioner_jwk["kid"],  # provisioner identity
                "jti": str(uuid.uuid4()),             # unique — prevents OTT reuse
                "nbf": now,
                "sans": [self.agent_id],              # requested SAN in the cert
                "sub": self.agent_id,
                "sha": self.ca_fingerprint,
            },
            private_key,
            algorithm="ES256",
            headers={"kid": self.provisioner_jwk["kid"]},
        )

    def _generate_csr(self) -> tuple:
        # Fresh key for each cert — never reuse keys across cert issuances
        key = generate_private_key(SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.agent_id)]))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(self.agent_id)]),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )
        return key, csr.public_bytes(serialization.Encoding.PEM).decode()

    def _parse_response(self, key, data: dict) -> _Cert:
        cert_pem = data["crt"].encode()
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        cert_obj = x509.load_pem_x509_certificate(cert_pem)
        return _Cert(
            pem=cert_pem,
            key_pem=key_pem,
            expires_at=cert_obj.not_valid_after_utc.timestamp(),
        )

    def _ca_ssl(self) -> ssl.SSLContext:
        # One-way TLS — we verify the CA cert but don't present a client cert yet
        # (we don't have one until after the first /sign call)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_verify_locations(cadata=self._ca_pem.decode())
        return ctx

    async def _sign(self) -> None:
        # First cert issuance requires an OTT (one-time token) from the provisioner key
        key, csr_pem = self._generate_csr()
        async with httpx.AsyncClient(verify=self._ca_ssl()) as c:
            r = await c.post(
                f"{self.ca_url}/1.0/sign",
                json={"csr": csr_pem, "ott": self._make_ott()},
            )
            r.raise_for_status()
        data = r.json()
        # Step CA signs leaf certs with its intermediate CA — save it for chain verification
        self._intermediate_ca_pem = data.get("ca", "").encode() or self._ca_pem
        self._cert = self._parse_response(key, data)

    async def _renew(self) -> None:
        # Renewal uses the existing cert as mTLS auth — no OTT needed
        key, csr_pem = self._generate_csr()
        async with httpx.AsyncClient(verify=self.ssl_context) as c:
            r = await c.post(f"{self.ca_url}/1.0/renew", json={"csr": csr_pem})
            r.raise_for_status()
        data = r.json()
        self._intermediate_ca_pem = data.get("ca", "").encode() or self._ca_pem
        self._cert = self._parse_response(key, data)

    def _save(self) -> None:
        (self.certs_dir / "agent.crt").write_bytes(self._cert.pem)
        (self.certs_dir / "agent.key").write_bytes(self._cert.key_pem)
        (self.certs_dir / "ca.crt").write_bytes(self._ca_pem)
        # Intermediate CA — used by gateway to verify agent certs in the chain
        intermediate = getattr(self, "_intermediate_ca_pem", self._ca_pem)
        (self.certs_dir / "intermediate_ca.crt").write_bytes(intermediate)
