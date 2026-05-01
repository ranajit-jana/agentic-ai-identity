# Debugging Session — Step CA Certificate Issuance

## Problem
Running `PYTHONPATH=. uv run python agent/agent.py` failed with:
```
[agent] .certs/agent.crt not found.
  Bootstrap Step CA first, or run with --demo.
```
Then after fixing the startup order, a `401 Unauthorized` from Step CA's `/1.0/sign` endpoint.

---

## Step 1 — Check if .certs directory and its contents exist

```bash
ls /home/rj/projects/agentic-ai-identity/.certs/
```

**Finding:** Directory existed but was empty — no cert had ever been issued.

---

## Step 2 — Check Docker service status

```bash
docker compose ps
```

**Finding:** `step-ca`, `opa`, and `ollama` were all running. `opa` was unhealthy but not the immediate issue.

---

## Step 3 — Check cert-related code in agent.py

```bash
grep -n "agent.crt\|\.certs\|cert" agent/agent.py | head -30
```

**Finding:** The agent exited immediately if `agent.crt` didn't exist — *before* calling `mgr.bootstrap()`, which is the call that actually issues the cert. Classic chicken-and-egg bug.

---

## Step 4 — Check .env for non-secret config values

```bash
cat .env | grep -v "KEY\|SECRET\|PASSWORD"
```

**Finding:** `STEP_CA_FINGERPRINT` was already set, meaning `extract_key.py` had been run. `STEP_CA_URL=https://localhost:9000`.

---

## Step 5 — Check docker-compose.yml for cert provisioning

```bash
grep -n "cert\|step\|provision" docker-compose.yml
```

**Finding:** `DOCKER_STEPCA_INIT_PASSWORD` defaults to `${STEP_CA_PASSWORD:-changeme}`.

---

## Step 6 — Check scripts directory for cert issuance scripts

```bash
ls scripts/
```

**Finding:** No cert-issuance script — the initial cert must come from `CertManager.bootstrap()`.

---

## Step 7 — Check provisioner.json exists

```bash
ls identity/provisioner.json
```

**Finding:** File exists — `extract_key.py` had been run successfully.

---

## Step 8 — After fixing startup order, test bootstrap manually (got 401)

```bash
PYTHONPATH=. uv run python3 -c "
import asyncio, json, ssl, httpx
from pathlib import Path
from identity.refresher import CertManager

async def test():
    mgr = CertManager.from_env()
    async with httpx.AsyncClient(verify=False) as c:
        r = await c.get(f'{mgr.ca_url}/root/{mgr.ca_fingerprint}')
        mgr._ca_pem = r.json()['ca'].encode()
        print('Root CA fetched OK')

    key, csr_pem = mgr._generate_csr()
    ott = mgr._make_ott()
    print(f'OTT payload: {json.loads(__import__(\"base64\").urlsafe_b64decode(ott.split(\".\")[1] + \"==\").decode())}')
    async with httpx.AsyncClient(verify=mgr._ca_ssl()) as c:
        r = await c.post(f'{mgr.ca_url}/1.0/sign', json={'csr': csr_pem, 'ott': ott})
        print(f'Status: {r.status_code}')
        print(f'Body: {r.text}')

asyncio.run(test())
"
```

**Finding:** `401 Unauthorized` — Step CA rejected the OTT.

---

## Step 9 — Check Step CA logs for the actual rejection reason

```bash
docker compose logs --tail=30 step-ca
```

**Finding:** `error="authority.Authorize: authority.authorizeSign: provisioner not found or invalid audience"` — the OTT's `iss` claim was wrong.

---

## Step 10 — Verify our provisioner key matches Step CA's public key

```bash
PYTHONPATH=. uv run python3 -c "
import json
from pathlib import Path
from identity.refresher import _jwk_to_private_key

our_jwk = json.loads(Path('identity/provisioner.json').read_text())
our_key = _jwk_to_private_key(our_jwk)
our_pub = our_key.public_key().public_numbers()
print(f'Our key x: {our_pub.x}')

import subprocess
result = subprocess.run(['docker','compose','exec','step-ca','cat','/home/step/config/ca.json'], capture_output=True, text=True)
ca_config = json.loads(result.stdout)
provs = ca_config.get('authority',{}).get('provisioners',[])
for p in provs:
    if p.get('name') == 'admin' and p.get('type') == 'JWK':
        pub_jwk = p.get('key',{})
        import base64
        x = int.from_bytes(base64.urlsafe_b64decode(pub_jwk['x'] + '=='), 'big')
        print(f'CA  key x: {x}')
        print(f'Match: {our_pub.x == x}')
"
```

**Finding:** Keys matched — the private key in `provisioner.json` is correct.

---

## Step 11 — Verify the CA fingerprint matches

```bash
docker compose exec step-ca step certificate fingerprint /home/step/certs/root_ca.crt
grep STEP_CA_FINGERPRINT .env
```

**Finding:** Both returned the same fingerprint — not the issue.

---

## Step 12 — Check STEP_CA_PASSWORD in .env

```bash
grep -i "STEP_CA_PASSWORD" .env
```

**Finding:** `STEP_CA_PASSWORD=changeme` — matches the docker-compose default.

---

## Step 13 — Check provisioner kid in Step CA's ca.json

```bash
docker compose exec step-ca cat /home/step/config/ca.json | python3 -c "
import json, sys
d = json.load(sys.stdin)
provs = d.get('authority',{}).get('provisioners',[])
for p in provs:
    print(json.dumps({k: v for k,v in p.items() if k != 'encryptedKey'}, indent=2))
"
```

**Finding:** `kid` matched `provisioner.json`. Issue was elsewhere.

---

## Step 14 — Check Step CA config for DNS names and URL

```bash
docker compose exec step-ca cat /home/step/config/ca.json | python3 -c "
import json, sys
d = json.load(sys.stdin)
print({k: v for k,v in d.items() if k not in ['authority']})
print('authority keys:', {k: v for k,v in d.get('authority',{}).items() if k != 'provisioners'})
"
```

```bash
docker compose exec step-ca cat /home/step/config/defaults.json
```

**Finding:** CA URL is `https://localhost:9000`, matching `.env`. DNS names: `localhost`, `step-ca`.

---

## Step 15 — Issue a cert directly via the step CLI inside the container

```bash
docker compose exec step-ca sh -c "step ca certificate agent-001 /tmp/test.crt /tmp/test.key \
  --provisioner=admin \
  --provisioner-password-file=<(echo -n 'changeme') \
  --not-after=5m"
```

**Finding:** Cert issued successfully. Step CA itself works. The OTT generated by the `step` CLI must differ from ours.

---

## Step 16 — Compare our OTT with the step CLI's OTT from Step CA logs

```bash
docker compose logs --tail=10 step-ca
```

**Finding (critical):** The successful OTT from the `step` CLI had `"iss":"admin"` (provisioner **name**). Our code was setting `"iss"` to the provisioner `kid`. Step CA requires the provisioner name in `iss`, with the `kid` only in the JWT header.

---

## Step 17 — Verify the fix works

```bash
PYTHONPATH=. uv run python3 -c "
import asyncio
from identity.refresher import CertManager

async def test():
    mgr = CertManager.from_env()
    await mgr.bootstrap()
    print('Success! Cert issued.')

asyncio.run(test())
"
```

**Finding:** `[identity] cert issued  agent=agent-001  expires=...` — fix confirmed.

---

## Root Causes

1. **`agent.py`** — cert-exists check ran before `CertManager.bootstrap()`, so the agent always exited before the cert could be created. Fixed by moving bootstrap before the file read.

2. **`identity/refresher.py` — `_make_ott()`** — `iss` was set to `self.provisioner_jwk["kid"]` but Step CA requires `iss` to be the provisioner **name** (e.g. `admin`). The `kid` belongs only in the JWT header. Fixed by adding `provisioner_name` to `CertManager` and using it in the `iss` claim.
