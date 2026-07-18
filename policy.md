# Zero Trust Workload Security Architecture

### SPIFFE · Cilium · Envoy · OPA · Kyverno

A broader architecture note on how the identity and policy concepts used in this project (SPIFFE, OPA) fit into a full Kubernetes zero-trust stack. See the [README](README.md) for how this project implements the SPIFFE + OPA slice in a local, runnable form (via Step CA instead of SPIRE, no Cilium/Envoy/Kyverno).

## Overview

A modern Kubernetes security architecture separates **workload identity**, **network enforcement**, **runtime authorization**, and **cluster governance** into different layers.

The key principle:

- **SPIFFE/SPIRE** answers: *"Who is this workload?"*
- **Cilium/Envoy** answers: *"Can this workload communicate?"*
- **OPA** answers: *"Is this specific request allowed?"*
- **Kyverno** answers: *"Should this Kubernetes workload be allowed to run?"*

---

## 1. SPIFFE / SPIRE — Workload Identity

SPIFFE provides a cryptographic identity for workloads. A workload receives an X.509-SVID certificate containing a SPIFFE ID as a SAN (Subject Alternative Name) — this SAN *is* the workload identity:

```
SAN: spiffe://example.org/ns/default/sa/orders-api
```

Example:

```
Service:  orders-api
Identity: spiffe://example.org/ns/default/sa/orders-api
```

The certificate is:

- Short-lived
- Automatically rotated
- Signed by a trusted CA
- Used for mTLS authentication

SPIRE is responsible for:

- Attesting workloads
- Validating Kubernetes identity
- Issuing X.509-SVID certificates

---

## 2. Kubernetes PSAT (Projected Service Account Token)

Kubernetes Service Account Tokens are used as workload proof during identity bootstrapping.

```
Pod
 │ Kubernetes Projected Service Account Token (PSAT)
 ▼
SPIRE Server
 │ Validate workload identity
 ▼
Issue X.509-SVID
```

PSAT is short-lived, audience-bound, and automatically rotated. It is an identity proof, not a secret.

---

## 3. Cilium — Network Enforcement

Cilium provides Kubernetes networking and security using eBPF, operating mainly at the L3/L4 network layer and the service communication layer.

```
Allow: orders-api → payments-api
```

Cilium can enforce policy based on pod identity, labels, and namespace boundaries. However, eBPF cannot inspect TLS certificates or directly read SPIFFE SAN values — for certificate-aware authorization, traffic moves to Envoy.

---

## 4. Envoy — Runtime Traffic Enforcement

Envoy acts as the policy enforcement point. During mTLS, Envoy extracts the SPIFFE ID from the peer certificate's SAN:

```
Service A
   │ X.509 Certificate
   ▼
Envoy
   │ Extract SAN
   ▼
SPIFFE ID: spiffe://example.org/ns/default/sa/orders-api
```

Envoy validates the certificate chain, certificate validity, and peer identity, then enforces policy via native RBAC or external authorization (`ext_authz`).

---

## 5. OPA — Runtime Authorization Engine

OPA (Open Policy Agent) provides fine-grained authorization.

```
Envoy
 │ ext_authz request
 ▼
OPA
 │ Rego Policy + Configuration Data
 ▼
ALLOW / DENY
```

Example decision:

```
Request:
  Caller: spiffe://example.org/ns/default/sa/orders-api
  Method: GET
  Path:   /api/orders

OPA evaluates: "Is orders-api allowed to GET /api/orders?"
Response:      ALLOW
```

### OPA Policy Design

Avoid hardcoding identities inside Rego.

**Bad:**

```rego
input.source_spiffe_id == "spiffe://example.org/ns/default/sa/orders-api"
```

**Better** — separate authorization logic (Rego) from identities and permissions (data):

```
SPIFFE Identity → Role → Permissions
```

```yaml
orders-reader:
  identity:
    spiffe://example.org/ns/default/sa/orders-api
  permissions:
    GET /api/orders
```

This allows policies to change without modifying Rego code — the same pattern this project uses in [policy/policy.rego](policy/policy.rego) + [policy/data.json](policy/data.json).

---

## 6. Kyverno — Kubernetes Admission Security

Kyverno operates during Kubernetes object creation and answers: *"Should this workload be allowed into the cluster?"*

```
Developer
    ▼
Kubernetes API Server
    ▼
Kyverno Admission Controller
    ▼
Allow / Deny / Mutate
```

Examples:

| Policy | Rule |
|---|---|
| Block privileged containers | Reject `securityContext.privileged: true` |
| Require non-root execution | Require `runAsNonRoot: true` |
| Restrict host access | Block `hostNetwork: true`, `hostPID: true` |
| Image governance | Allow only images from `registry.company.com/*` |
| Resource governance | Require CPU/memory limits and requests |

---

## 7. Relationship Between Components

```
                 Deployment Time

Developer
    │
    ▼
Kubernetes API
    │
    ▼
Kyverno
    │ Validate workload security
    ▼
Pod Created


                 Runtime

Service A
    │ mTLS
    ▼
Envoy
    │ Extract SPIFFE SAN
    ▼
OPA (optional)
    │ Authorization decision
    ▼
Service B
```

---

## 8. Security Responsibility Matrix

| Security Question | Component |
|---|---|
| Who is this workload? | SPIFFE/SPIRE |
| How is identity proven? | X.509-SVID |
| How is traffic encrypted? | mTLS |
| Can workload communicate? | Cilium |
| Can this API request execute? | Envoy + OPA |
| Can this pod be deployed? | Kyverno |
| Where are secrets managed? | Vault |

---

## 9. Recommended Enterprise Pattern

```
SPIFFE/SPIRE
    │ Workload Identity
    ▼
Cilium + Envoy
    │ Traffic Enforcement
    ▼
OPA
    │ Runtime Authorization
    ▼
Kyverno
    │ Kubernetes Governance
```
