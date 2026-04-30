"""
One-time setup script — run AFTER `docker compose up step-ca` has initialised.

What it does:
  1. Reads ca-data/config/ca.json (written by Step CA on first boot)
  2. Decrypts the provisioner JWK (PBES2-encrypted) using STEP_CA_PASSWORD
  3. Saves plaintext JWK to identity/provisioner.json
  4. Computes the root CA fingerprint and prints the .env line to add

Usage:
    docker compose up -d step-ca
    # wait ~10 s for Step CA to initialise
    uv run python scripts/extract_key.py
    # copy the STEP_CA_FINGERPRINT=... line into .env
"""

import json
import sys
from pathlib import Path

from dotenv import load_dotenv
import os

load_dotenv()

CA_DATA_DIR = Path("ca-data")
PROVISIONER_NAME = os.getenv("STEP_CA_PROVISIONER", "admin")
CA_PASSWORD = os.getenv("STEP_CA_PASSWORD", "changeme")


def _b64d(s: str) -> bytes:
    import base64
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _decrypt_provisioner_key(encrypted_key: str, password: str) -> dict:
    """
    Decrypt PBES2-HS256+A128KW JWE — supports A256GCM and A128CBC-HS256 content encryption.
    Step CA currently uses A256GCM.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
    import hmac, struct

    header_b64, enc_key_b64, iv_b64, ciphertext_b64, tag_b64 = encrypted_key.split(".")
    header = json.loads(_b64d(header_b64))

    # 1. Derive 16-byte key-wrapping key (PBES2-HS256+A128KW always uses 16 bytes)
    salt = header["alg"].encode() + b"\x00" + _b64d(header["p2s"])
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=16, salt=salt, iterations=header["p2c"])
    kek = kdf.derive(password.encode())

    # 2. Unwrap CEK
    cek = aes_key_unwrap(kek, _b64d(enc_key_b64), None)

    iv, ciphertext, tag = _b64d(iv_b64), _b64d(ciphertext_b64), _b64d(tag_b64)
    aad = header_b64.encode()

    # 3. Decrypt content — detect enc algorithm from header
    enc = header.get("enc", "A256GCM")
    if "GCM" in enc:
        plaintext = AESGCM(cek).decrypt(iv, ciphertext + tag, aad)
    else:
        # A128CBC-HS256 fallback
        mac_key, enc_key = cek[:16], cek[16:]
        mac_input = aad + iv + ciphertext + struct.pack(">Q", len(aad) * 8)
        expected_tag = hmac.new(mac_key, mac_input, "sha256").digest()[:16]
        if not hmac.compare_digest(expected_tag, tag):
            sys.exit("Wrong password — HMAC mismatch. Check STEP_CA_PASSWORD in .env")
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        padded = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
        plaintext = padded[: -padded[-1]]

    return json.loads(plaintext)


def _ca_fingerprint() -> str:
    import hashlib
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    root_cert_path = CA_DATA_DIR / "certs" / "root_ca.crt"
    cert = x509.load_pem_x509_certificate(root_cert_path.read_bytes())
    der = cert.public_bytes(Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def main():
    ca_config_path = CA_DATA_DIR / "config" / "ca.json"
    if not ca_config_path.exists():
        sys.exit(
            f"Step CA config not found at {ca_config_path}\n"
            "Run:  docker compose up -d step-ca && sleep 10"
        )

    config = json.loads(ca_config_path.read_text())
    provisioners = config.get("authority", {}).get("provisioners", [])
    provisioner = next(
        (p for p in provisioners if p.get("type") == "JWK" and p.get("name") == PROVISIONER_NAME),
        None,
    )
    if not provisioner:
        names = [p.get("name") for p in provisioners]
        sys.exit(f"No JWK provisioner '{PROVISIONER_NAME}' found. Available: {names}")

    print(f"Found provisioner: {PROVISIONER_NAME}")
    plaintext_jwk = _decrypt_provisioner_key(provisioner["encryptedKey"], CA_PASSWORD)

    out = Path("identity") / "provisioner.json"
    out.write_text(json.dumps(plaintext_jwk, indent=2))
    print(f"Provisioner key saved → {out}")

    fingerprint = _ca_fingerprint()
    print(f"\nAdd this line to your .env:")
    print(f"  STEP_CA_FINGERPRINT={fingerprint}")


if __name__ == "__main__":
    main()
