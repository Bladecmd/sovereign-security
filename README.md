# Sovereign Security — Foundation V0.1

> **Defensive Security, Identity, Risk, and Governance Layer for the Sovereign Ecosystem**

[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-v24-green.svg)](https://nodejs.org/)
[![Architecture](https://img.shields.io/badge/Architecture-Zero--Trust-red.svg)](#security-boundary--principles)
[![Status](https://img.shields.io/badge/Release-V0.1%20Foundation-orange.svg)](#capability-matrix)

---

## 1. Project Objective

**Sovereign Security** is an independent, decoupled security, identity, risk, threat detection, and security governance platform engineered to protect:

- **Sovereign OS** (Executive Intelligence & Business Operations)
- **Metro Task Force** (Operational Task Force Dispatch & Investigation Systems)
- **Compliance Labs** (Regulatory Compliance & Audit Frameworks)
- **AudioBlue** (Media, Acoustic, & Communication Infrastructure)
- **GriDD Corp** (Core Cloud & Distributed Infrastructure)
- **Future Personal Sovereign AI** (Autonomous Agents & Personal Intelligence)

---

## 2. Security Boundary & Principles

> [!CAUTION]
> **Defensive Scope Only**:
> Sovereign Security is strictly defensive. It is exclusively engineered for systems and data owned or explicitly authorized by the operator.
> - **NO** offensive capabilities.
> - **NO** arbitrary or intrusive port/network scanning without explicit authorization.
> - **NO** malware, exploit payloads, credential theft tools, or unauthorized intrusion mechanisms.

### Architectural Decoupling:
```
┌─────────────────────────────────────────────────────────┐
│                      SOVEREIGN OS                       │
│        Executive Intelligence + Business Operations     │
└───────────────────────────┬─────────────────────────────┘
                            │ Controlled APIs & Events
                            │ (No Direct DB Coupling)
┌───────────────────────────▼─────────────────────────────┐
│                   SOVEREIGN SECURITY                    │
│   Identity + Security + Risk + Threats + Governance    │
└─────────────────────────────────────────────────────────┘
```

---

## 3. Capability Matrix (Honest Implementation Status)

| Capability Domain | Sub-Component | Status | Description |
| :--- | :--- | :--- | :--- |
| **Security Contracts** | `SecurityEvent` Schema | **IMPLEMENTED** | Normalized, strictly typed contract with runtime Zod validation. |
| | `SecurityAlert` Schema | **IMPLEMENTED** | Normalized incident tracking contract with full lifecycle statuses. |
| **Identity & Access** | Least Privilege RBAC | **IMPLEMENTED** | 5 core roles (`ADMIN`, `EXECUTIVE`, `SYSTEM`, `AGENT`, `SERVICE`) & 5 permissions. |
| | Advanced ABAC / Hardware Keys | **PLANNED (V0.3)** | WebAuthn, FIDO2, and dynamic attribute conditions. |
| **Policy Engine** | Multi-Tier Policy Decision | **IMPLEMENTED** | Evaluates actor, resource, action, context, and risk into `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, `ESCALATE`. |
| **AI Security** | Tool Permission Registry | **IMPLEMENTED** | Machine-readable policies restricting AI agent actions (e.g., VEGA cannot transfer funds or drop data). |
| | AI Pipeline Interface | **FOUNDATION** | Test contracts for input sanitization, risk classification, output validation, and tool interception. |
| | Neural Prompt Defense | **PLANNED (V0.6)** | Semantic boundary enforcement and neural injection classifiers. |
| **Threat Engine** | Deterministic Threat Rules | **IMPLEMENTED** | Sliding window brute force login detection, unauthorized privileged action alarms, and secret leak alerts. |
| | Autonomous Threat Agents | **PLANNED (V0.7)** | AI sentinel agents for automated quarantine and remediation. |
| **Risk Scoring** | Deterministic Risk Engine | **IMPLEMENTED** | Normalized 0-100 scoring based on severity, asset criticality, auth state, action sensitivity, and frequency. |
| **Audit Trail** | Tamper-Evident Audit Service | **IMPLEMENTED** | Append-oriented audit logs with sequential SHA-256 cryptographic hash-chain verification. |
| **Secrets Security** | Secret Detection & Redaction | **IMPLEMENTED** | Pattern-based scanner and structured logger with automatic secret masking. |
| | Automated Key Rotation | **PLANNED (V0.4)** | Automated HSM key rotation and zero-downtime secret cycling. |
| **Integrations** | `SovereignSecurityClient` | **IMPLEMENTED** | Decoupled client adapter for Sovereign OS communication. |
| | `MetroTaskForceAdapter` | **IMPLEMENTED** | Ingestion and normalization adapter for MTF security telemetry. |
| **Dashboard** | Security Operations UI | **PLANNED (V0.2)** | Visual dashboard for alerts, risk telemetry, and audit logs. |

---

## 4. Quick Start & Verification

### Prerequisites
- Node.js 20+ (Node.js 24 recommended)
- npm 10+

### Installation
```bash
npm install
```

### Running Tests
All unit and contract tests run strictly against synthetic mock data:
```bash
npm test
```

### Type Checking & Build
```bash
npm run typecheck
npm run build
```

---

## 5. Documentation Directory

Detailed architectural and design specifications are located in [`docs/`](./docs/):

- [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md) — System boundaries, event-driven pipelines, and isolation principles.
- [`docs/SECURITY_MODEL.md`](./docs/SECURITY_MODEL.md) — Zero-trust identity, least privilege RBAC, and permission models.
- [`docs/EVENT_SCHEMA.md`](./docs/EVENT_SCHEMA.md) — Specification of `SecurityEvent` and `SecurityAlert` schemas.
- [`docs/POLICY_ENGINE.md`](./docs/POLICY_ENGINE.md) — Policy evaluation lifecycle, rule priorities, and escalation mechanics.
- [`docs/AI_SECURITY.md`](./docs/AI_SECURITY.md) — AI pipeline stages, VEGA tool permission policies, and safety constraints.
- [`docs/INTEGRATION.md`](./docs/INTEGRATION.md) — Sovereign OS and Metro Task Force adapter specifications.
- [`docs/THREAT_MODEL.md`](./docs/THREAT_MODEL.md) — Defensive threat scenarios, risk factors, and roadmap markers (V0.2 - V1.0).

---

## 6. License & Perimeter
Proprietary — strictly authorized for Sovereign Ecosystem assets and controlled test environments only.
