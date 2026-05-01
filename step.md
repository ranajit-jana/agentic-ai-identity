# Step CA — From Basics to Production Internals

## 1. What Is Step CA?

Step CA (`step-ca`) is a private Certificate Authority (CA) server built by Smallstep. It issues short-lived X.509 certificates to anything that can prove its identity — humans, machines, containers, or AI agents.

The two core ideas it is built on:

1. **Short-lived certs instead of revocation.** Traditional CAs issue certs valid for 1–2 years and rely on revocation lists (CRL/OCSP) to invalidate them. Step CA issues certs valid for hours or minutes. When the cert expires the machine simply requests a new one. There is no revocation list to maintain or check.

2. **Automated issuance over a REST API.** The server exposes a small HTTPS API (`/1.0/sign`, `/1.0/renew`, `/health`, etc.) so software can request certs without human involvement.

---

## 2. PKI Primer (what Step CA is built on)

### 2.1 Public Key Infrastructure basics

A **certificate** binds a public key to a name. It is signed by a CA so that anyone who trusts the CA can verify the binding without contacting the CA again.

```
Root CA  (self-signed, highest trust, kept offline)
  └── Intermediate CA  (signs leaf certs, can be rotated)
        └── Leaf cert  (issued to agent-001, expires in 1 h)
```

Step CA creates this three-level hierarchy automatically on first run:
- `root_ca.crt` — root, pinned by clients via its SHA-256 fingerprint
- `intermediate_ca.crt` — signs every leaf cert
- Leaf certs — issued to your agents / services

### 2.2 The CA fingerprint

Before a client can trust the CA it must pin the CA's root cert. Step CA identifies the root by the SHA-256 fingerprint of `root_ca.crt`. This fingerprint is distributed out-of-band (e.g., in `.env`) so a MITM attacker cannot substitute a different CA.

```
STEP_CA_FINGERPRINT=a3f1...  ← must match output of:
step certificate fingerprint /home/step/certs/root_ca.crt
```

### 2.3 Chain of Trust

The chain of trust is the **cryptographic lineage** that lets any verifier accept a cert it has never seen before. Each level is vouched for by the one above it via a digital signature:

```
root_ca.crt        ← trusted because its SHA-256 fingerprint is pinned in .env
     │ (signs)
     ▼
intermediate_ca.crt ← trusted because root signed it
     │ (signs)
     ▼
agent.crt           ← trusted because intermediate signed it
```

A verifier (the gateway) checks three things in sequence:

1. Was `agent.crt` signed by `intermediate_ca.crt`?
2. Was `intermediate_ca.crt` signed by `root_ca.crt`?
3. Does `root_ca.crt`'s fingerprint match the pinned value?

If all three pass, the cert is trusted — without the gateway ever having seen that specific `agent.crt` before. Trust flows **downward**, one signature at a time.

The root CA's private key (`ca-data/secrets/root_ca_key`) is the most sensitive file in the system. Compromising it breaks the entire chain. In production it would be kept offline; here it lives in `ca-data/secrets/` which is git-ignored.

---

## 3. Provisioners — How Step CA Knows Who to Trust

Before Step CA will sign a CSR it needs to verify the requester is legitimate. That is the job of a **provisioner**: a configured authentication method.

Step CA supports many provisioner types (OIDC, AWS IAM, GCP, ACME, etc.). This project uses the **JWK provisioner**.

### 3.1 JWK Provisioner

A JWK (JSON Web Key) provisioner works like this:

1. During CA setup, a key pair is generated. The public key goes into `ca.json` under `authority.provisioners`. The private key is encrypted and also stored in `ca.json` as `encryptedKey`.
2. To request a cert, the client signs a short-lived JWT with the provisioner's **private key**. This JWT is called a **one-time token (OTT)**.
3. The CA verifies the OTT signature against the provisioner's **public key** in `ca.json`, then signs the CSR.

The provisioner entry in `ca.json` looks like:

```json
{
  "type": "JWK",
  "name": "admin",
  "key": {
    "kty": "EC", "crv": "P-256", "alg": "ES256",
    "kid": "M23caEdGh5ZAyCWHaJxSKmCxTRvSPuoIVwQO3yJRUp0",
    "x": "rcYe...", "y": "kLSP..."
  },
  "encryptedKey": "eyJhbGci..."
}
```

`name` is the human-readable identifier (e.g. `"admin"`). `kid` is a short random identifier for the key. These two fields play very different roles — see Section 7 for the critical distinction.

### 3.2 Extracting the provisioner private key

The `encryptedKey` is a JWE (JSON Web Encryption) token encrypted with PBES2-HS256+A128KW using the CA password. To sign OTTs programmatically you must decrypt it first:

```python
# identity/refresher.py: decrypt_pbes2_jwe()
plaintext_jwk = decrypt_pbes2_jwe(encrypted_key_string, ca_password)
```

This project stores the decrypted JWK in `identity/provisioner.json` (git-ignored).

---

## 4. The Bootstrap Flow — Getting the First Cert

An agent that has never had a cert uses the OTT flow:

```
Agent                                       Step CA
  |                                           |
  |-- GET /root/{fingerprint} -------------> |
  |<-- { ca: "<root PEM>" } ---------------- |
  |                                           |
  | generate EC key + CSR                     |
  | build OTT (signed JWT)                    |
  |                                           |
  |-- POST /1.0/sign  { csr, ott } -------> |
  |  (one-way TLS — CA cert only)             | verify OTT signature
  |                                           | sign CSR with intermediate CA
  |<-- { crt, ca, certChain } -------------- |
  |                                           |
  | save agent.crt, agent.key to .certs/      |
```

In code: [identity/refresher.py](identity/refresher.py) — `CertManager.bootstrap()` → `_fetch_root_ca()` → `_sign()`.

### 4.1 What the OTT contains

The OTT is a standard JWT. Step CA requires these claims:

| Claim | Value | Purpose |
|-------|-------|---------|
| `iss` | provisioner **name** (e.g. `"admin"`) | tells CA which provisioner to look up |
| `sub` | agent ID (e.g. `"agent-001"`) | requested cert subject |
| `aud` | `https://<ca>/1.0/sign` | binds token to this endpoint only |
| `jti` | UUID | prevents token reuse |
| `exp` | `now + 60` | token expires in 60 s |
| `sans`| `["agent-001"]` | requested Subject Alternative Names |
| `sha` | CA fingerprint | ties token to this CA |

The JWT **header** carries:

| Field | Value | Purpose |
|-------|-------|---------|
| `alg` | `"ES256"` | signing algorithm |
| `kid` | key ID from JWK | tells CA which key to verify with |

---

## 5. The Renewal Flow — Staying Alive

After the first cert, renewal is simpler: the agent presents its current cert as mTLS client authentication and Step CA issues a fresh one. No OTT is needed.

```
Agent (has cert)                            Step CA
  |                                           |
  |-- POST /1.0/renew  { csr } ------------> |
  |  (mTLS — presents current cert)          | verify cert chain
  |                                           | sign new CSR
  |<-- { crt, ca } ------------------------- |
```

In code: [identity/refresher.py](identity/refresher.py) — `CertManager.refresh_loop()` triggers `_renew()` when `< 90 s` remain on the cert.

The renewal loop checks every 30 s:

```python
while True:
    await asyncio.sleep(30)
    if (self._cert.expires_at - time.time()) < 90:
        await self._renew()
```

---

## 6. How This Project Uses Step CA

```
docker-compose up step-ca
       |
       v
  Step CA running at https://localhost:9000
  Root cert fingerprinted in .env: STEP_CA_FINGERPRINT=...
       |
       v
  CertManager.from_env()        reads: STEP_CA_URL, AGENT_ID,
                                        STEP_CA_FINGERPRINT, STEP_CA_PROVISIONER
                                        identity/provisioner.json (decrypted JWK)
       |
       v
  CertManager.bootstrap()        fetches root CA, signs OTT, POSTs /1.0/sign
       |
       v
  .certs/agent.crt               leaf cert (1 h TTL, renewed automatically)
  .certs/agent.key               private key (fresh per issuance)
  .certs/ca.crt                  root CA cert
  .certs/intermediate_ca.crt     intermediate CA cert
       |
       v
  CertManager.ssl_context        mTLS SSLContext for outbound httpx calls
```

Agents sign their messages with their private key and embed the cert chain in each message (`x5c` field). Recipients verify the chain against `ca.crt` before passing any content to the LLM. See [identity/signer.py](identity/signer.py).

### 6.1 Circle of Trust

The circle of trust is the **runtime membership boundary** — which agents are allowed to call which other agents or tools. It is not about cryptographic lineage; it is about **policy**.

Where the chain of trust asks *"is this cert authentic?"*, the circle of trust asks *"is this agent allowed to do this?"*

The circle is enforced in three layers in this project:

**OPA policy** (`policy/policy.rego` + `policy/data.json`) — maps agent identities (the CN from their leaf cert) to allowed tools:

```
agent-001 → weather, calculator   ✓ inside the circle
agent-001 → admin endpoint        ✗ outside the circle → denied
```

**Gateway auth** (`gateway/auth.py`) — on every inbound request, verifies the `x5c` cert chain (chain of trust), extracts the CN, then asks OPA whether that CN is in the circle for the requested tool. Both checks must pass.

**Delegation** (`identity/delegator.py`) — a supervisor can delegate a subset of its permissions to a sub-agent. The sub-agent's circle is always a **strict subset** of the delegator's — delegation can narrow the circle but never expand it.

```
Supervisor (weather, calculator, admin)
  └── delegates to Sub-agent (weather only)
        └── Sub-agent circle = {weather}   ← cannot self-elevate to admin
```

| | Chain of Trust | Circle of Trust |
|---|---|---|
| **Question** | Is this cert cryptographically authentic? | Is this agent allowed to do this? |
| **Enforced by** | X.509 signatures + fingerprint pin | OPA policy + gateway auth |
| **Static or dynamic** | Static — set at cert issuance | Dynamic — policy can change at runtime |
| **Lives in** | `ca-data/certs/`, `.certs/` | `policy/policy.rego`, `policy/data.json` |

The chain of trust proves **who you are**. The circle of trust decides **what you're allowed to do**.

---

## 7. The `iss` vs `kid` Distinction — A Critical Bug

### What went wrong

The `_make_ott()` method originally set the `iss` claim to `self.provisioner_jwk["kid"]`, which is a short random string like `"M23caEdGh5ZAyCWHaJxSKmCxTRvSPuoIVwQO3yJRUp0"`.

```python
# WRONG — this was the broken code
jwt.encode(
    {"iss": self.provisioner_jwk["kid"], ...},   # <-- BUG: kid is not the name
    private_key,
    headers={"kid": self.provisioner_jwk["kid"]},
)
```

Step CA rejected every OTT with:

```
error="authority.Authorize: authority.authorizeSign: provisioner not found or invalid audience"
```

### Why Step CA rejected it

Step CA looks up the provisioner using the `iss` claim in the JWT **payload**. It iterates through `ca.json`'s `authority.provisioners` list and finds the entry whose `name` field matches `iss`. There is no provisioner named `"M23caEdGh5ZAyCWHaJxSKmCxTRvSPuoIVwQO3yJRUp0"` — so Step CA returns "provisioner not found".

### How it was found

Comparing the OTT our code generated against the one produced by the `step` CLI inside the container:

| Field | Our broken OTT | `step` CLI OTT |
|-------|---------------|----------------|
| JWT header `kid` | `"M23caEdG..."` | `"M23caEdG..."` |
| JWT payload `iss` | `"M23caEdG..."` | `"admin"` |

The CLI used `"iss": "admin"` (the provisioner name). We used the `kid` value in both places.

### The rule

```
JWT header  kid = WHICH KEY  (e.g. "M23caEdGh5ZA...")
JWT payload iss = WHO IS ISSUING  (e.g. "admin")
```

Step CA uses `kid` (header) to locate the public key for signature verification. It uses `iss` (payload) to locate the provisioner by name. They are independent lookups. Using the `kid` value as `iss` breaks the name lookup.

### The fix

```python
# identity/refresher.py — CertManager.__init__() now takes provisioner_name
self.provisioner_name = provisioner_name   # default: "admin"

def _make_ott(self) -> str:
    ...
    return jwt.encode(
        {
            "iss": self.provisioner_name,              # ← provisioner name, not kid
            ...
        },
        private_key,
        algorithm="ES256",
        headers={"kid": self.provisioner_jwk["kid"]}, # ← kid stays in header only
    )
```

`STEP_CA_PROVISIONER=admin` in `.env` sets the provisioner name, defaulting to `"admin"`.

---

## 8. JWE — How the Provisioner Key Is Stored

Step CA stores the provisioner private key encrypted inside `ca.json` as `encryptedKey`. The format is **PBES2-HS256+A128KW** (password-based key derivation + AES key wrap).

Decryption steps (implemented in `decrypt_pbes2_jwe()`):

```
1. Base64url-decode the 5 parts of the JWE compact token
   header.encryptedKey.iv.ciphertext.tag

2. Derive a 16-byte key-wrapping key (KEK):
   salt = alg_name_bytes + 0x00 + header["p2s"]
   KEK = PBKDF2-HMAC-SHA256(password, salt, iterations=header["p2c"], length=16)

3. Unwrap the content-encryption key (CEK):
   CEK = AES-128-KeyUnwrap(KEK, encryptedKey)

4. Decrypt the payload:
   if enc == "A256GCM":   plaintext = AESGCM(CEK).decrypt(iv, ciphertext+tag, header)
   if enc == "A128CBC":   plaintext = AES-CBC(CEK[16:], iv, ciphertext)  + HMAC check
```

The result is the raw JSON of the provisioner JWK including the `"d"` field (private key scalar).

---

## 9. Putting It All Together

```
ca.json (Step CA config)
  └── authority.provisioners[].encryptedKey
        │
        │  decrypt with CA password (PBES2-JWE)
        ▼
  provisioner.json  (decrypted JWK, git-ignored)
        │
        │  _jwk_to_private_key()
        ▼
  EC P-256 private key
        │
        │  jwt.encode( { iss: "admin", sub: "agent-001", aud: "/1.0/sign", ... },
        │               key, headers={ kid: "M23ca..." } )
        ▼
  OTT (one-time token)
        │
        │  POST /1.0/sign { csr: "...", ott: "eyJ..." }
        ▼
  Step CA verifies:
    1. JWT header.kid → find public key in ca.json
    2. JWT payload.iss → find provisioner by name in ca.json
    3. Verify ES256 signature
    4. Check aud == request URL, exp not expired, jti not reused
    5. Sign CSR with intermediate CA
        │
        ▼
  .certs/agent.crt  (leaf cert, CN=agent-001, SAN=agent-001, 1 h TTL)
  .certs/agent.key  (matching private key)
```

After bootstrap, the agent uses its cert for mTLS on every request and renews automatically before it expires.

---

## 10. How the PKI Was Created in the First Place

### Step 1 — Docker Compose bootstrapped Step CA automatically

When you run `docker compose up step-ca` for the **first time**, the `smallstep/step-ca` container detects that `./ca-data` (mounted at `/home/step`) is empty and runs `step ca init` automatically using these env vars from `docker-compose.yml`:

```yaml
DOCKER_STEPCA_INIT_NAME: AgentCA
DOCKER_STEPCA_INIT_DNS_NAMES: localhost,step-ca
DOCKER_STEPCA_INIT_PASSWORD: ${STEP_CA_PASSWORD:-changeme}
```

That single first-run init generates **all three levels** in one shot:

| File | What it is | Where |
|---|---|---|
| `root_ca.crt` | Self-signed root, valid 10 years | `ca-data/certs/root_ca.crt` |
| `root_ca_key` | Root CA private key (encrypted) | `ca-data/secrets/root_ca_key` |
| `intermediate_ca.crt` | Signed by root, valid 10 years | `ca-data/certs/intermediate_ca.crt` |
| `intermediate_ca_key` | Intermediate CA private key (encrypted) | `ca-data/secrets/intermediate_ca_key` |
| `ca.json` | Runtime config — the CA server reads this | `ca-data/config/ca.json` |

The `ca-data/` directory is a Docker volume bind mount — so these files survive container restarts. The CA hierarchy is created exactly once and persisted on disk.

### Step 2 — JWK provisioner key pair was also generated at init time

Inside `ca-data/config/ca.json`, Step CA init also generates a **JWK provisioner** key pair:
- **Public key** → stored in `authority.provisioners[].key` (the EC P-256 `x`/`y` coords)
- **Private key** → encrypted as JWE and stored in `encryptedKey` in the same file

This provisioner is what allows agents to prove identity and request leaf certs.

### Step 3 — Leaf certs are issued at runtime (not at init)

Every time an agent calls `CertManager.bootstrap()` in `identity/refresher.py`, it:
1. Decrypts the provisioner private key from `ca.json` (the JWE blob — see Section 8)
2. Mints a short-lived JWT (OTT) signed with that key
3. Posts a CSR + OTT to Step CA's `/1.0/sign` endpoint
4. Step CA signs the CSR with the **intermediate CA** and returns the leaf cert

The leaf cert lands in `.certs/agent.crt` with a 1-hour TTL and auto-renews via the loop in Section 5.

```
docker compose up step-ca   ← first run only
       │
       │  ca-data/ is empty → step ca init runs automatically
       ▼
  root_ca.crt          (self-signed, O=AgentCA, 10-year validity)
  root_ca_key          (encrypted EC private key)
  intermediate_ca.crt  (signed by root, 10-year validity)
  intermediate_ca_key  (encrypted EC private key)
  ca.json              (provisioner JWK embedded as encryptedKey)
       │
       │  persisted to disk via bind mount — created once, reused forever
       ▼
  docker compose up (subsequent runs)
       │
       │  ca-data/ already exists → Step CA skips init, starts serving
       ▼
  CertManager.bootstrap()  (runtime, per agent)
       │
       ├─ decrypt encryptedKey → provisioner private key
       ├─ mint OTT (JWT signed with provisioner key)
       └─ POST /1.0/sign → leaf cert signed by intermediate CA
              │
              ▼
         .certs/agent.crt   (1-hour TTL, renewed automatically)
```

**In short:** `root_ca.crt` and `intermediate_ca.crt` were created automatically by the Step CA Docker container on its very first start. You never ran `openssl` manually — Step CA's init routine did all of it.
