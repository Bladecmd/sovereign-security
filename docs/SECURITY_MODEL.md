# Sovereign Security — Security Model & Zero-Trust Architecture

## 1. Zero-Trust Core Directive

Sovereign Security adheres strictly to the **Zero-Trust Principle**:
> *Never trust, always verify. Enforce least privilege by default.*

No component, user, agent, or service is assumed to be trusted simply by being located within the internal network perimeter. Every request must be authenticated, authorized, evaluated against policy, and recorded in the audit trail.

---

## 2. Identity Roles & Least Privilege

The V0.1 architecture establishes 5 normalized subject roles:

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
