# Sovereign Security — Security Model & Zero-Trust Architecture

## 1. Zero-Trust Core Directive

Sovereign Security adheres strictly to the **Zero-Trust Principle**:
> *Never trust, always verify. Enforce least privilege by default.*

No component, user, agent, or service is assumed to be trusted simply by being located within the internal network perimeter. Every request must be authenticated, authorized, evaluated against policy, and recorded in the audit trail.

---

## 2. Identity Roles & Least Privilege (RBAC)

The architecture establishes 5 normalized subject roles:

| Role | Operational Scope | Default Permissions | Prohibited Restrictions |
| :--- | :--- | :--- | :--- |
| `ADMIN` | Platform configuration & operational maintenance | `READ`, `WRITE`, `EXECUTE`, `ADMINISTER` | Cannot certify financial reports or override executive veto without dual authorization. |
| `EXECUTIVE` | Strategic leadership & regulatory certification | `READ`, `CERTIFY` | Cannot directly modify infrastructure or mutate system credentials. |
| `SYSTEM` | Automated background services & orchestrators | `READ`, `WRITE`, `EXECUTE` | Cannot administer user roles or certify reports. |
| `AGENT` | Autonomous AI agents (e.g., VEGA) | `READ`, `EXECUTE` (Scoped) | Strictly prohibited from fund transfers, production data deletion, IAM modification, or destructive deployments. |
| `SERVICE` | Scoped external API integrations | `READ`, `EXECUTE` | Scoped strictly to assigned API boundaries. |

---

## 3. Permissions Model

Permissions are conceptually defined as:
1. `READ`: Querying telemetry, logs, data views, and configurations.
2. `WRITE`: Mutating application records, updating tickets, or writing drafts.
3. `EXECUTE`: Invoking specific actions, running pipelines, or calling APIs.
4. `CERTIFY`: Formal executive sign-off, regulatory attestation, or approval.
5. `ADMINISTER`: Modifying security policies, IAM bindings, or role assignments.

By default, an actor possessing role `AGENT` receives zero write or administrative privileges.

---

## 4. Secret Management & Non-Exposure

- **Zero Hardcoding**: All credentials, keys, and tokens are strictly banned from source code.
- **Environment Isolation**: Keys must be loaded via `.env` files.
- **Git Protection**: `.gitignore` quarantines `.env`, `*.pem`, `*.key`, and secret directories.
- **Automated Redaction**: Structured logging (`StructuredLogger`) and telemetry pipelines sanitize keys before persistence or display.

---

## 5. Dynamic Attribute-Based Access Control (ABAC) (Milestone V0.3)

Beyond static RBAC, the ABAC engine dynamically evaluates contextual dimensions:
- **Subject Attributes**: Security clearance levels (1 to 5), department affiliation, tenant partition, device health posture (`MANAGED_SECURE` vs `QUARANTINED`), and hardware token binding.
- **Resource Attributes**: Data classification tiers (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`, `TOP_SECRET`), required clearance thresholds, department boundaries, and geofencing whitelists.
- **Environmental Attributes**: Real-time fleet threat level (`LOW`, `GUARDED`, `ELEVATED`, `HIGH`, `CRITICAL`), country of origin, and timestamp.

---

## 6. Ephemeral Just-In-Time (JIT) Privilege Escalation (Milestone V0.3)

To prevent standing high privileges, administrative and incident containment rights are granted strictly Just-In-Time:
- **Incident Justification**: Mandatory incident or change ticket ID (e.g. `INCIDENT-409`).
- **Time-to-Live (TTL)**: Grants are bounded between 5 and 60 minutes.
- **Executive Approval**: Grants must be authorized by an executive or security administrator.
- **Automated Revocation**: Grants automatically expire upon TTL completion and are recorded in the cryptographic audit trail.

---

## 7. Hardware Security Key (WebAuthn / FIDO2) Step-Up (Milestone V0.3)

Access to `RESTRICTED` or `TOP_SECRET` resources mandates physical hardware security key proof-of-possession:
- Nonce challenge generated with 5-minute TTL.
- Authenticator signature verification.
- Enforced single-use challenge consumption preventing replay attacks.

---

## 8. Multi-Tenant Boundary Governance (Milestone V0.3)

Multi-tenant partitioning ensures complete cryptographic segregation among Sovereign business units:
- Cross-tenant requests are denied by default under zero-trust.
- Explicit `TenantFederationAgreement` contracts govern mutual resource sharing (e.g. Metro Task Force sharing dispatch telemetry with Sovereign OS) with bounded resource scopes and expiration times.
