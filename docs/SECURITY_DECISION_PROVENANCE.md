# Security Decision Provenance & Policy Boundary Enforcement

## Overview
The Security Decision Provenance Engine guarantees that no critical, destructive, or privileged operation within Sovereign OS, MTF, or ecosystem services can execute without an immutable, auditable decision artifact.

## Decision Pipeline Architecture

```mermaid
graph TD
    REQ[Request Ingestion] --> ID[Identity & RBAC/ABAC Evaluation]
    ID --> RES[Resource Classification]
    RES --> ACT[Action Authorization]
    ACT --> POL[Deterministic Policy Engine]
    POL --> RISK[Risk Engine Signal]
    RISK --> DEC{Decision Outcome}
    DEC -->|ALLOW| EXEC[Execution Permitted]
    DEC -->|DENY| BLK[Blocked & Logged]
    DEC -->|REQUIRE_APPROVAL| DUAL[Dual-Key Human Approval]
    DEC -->|ESCALATE| ESC[Executive Desk Escalation]
    EXEC --> SEAL[Cryptographic SHA-256 Seal]
    BLK --> SEAL
    DUAL --> SEAL
    ESC --> SEAL
    SEAL --> LEDGER[Persistent Audit Ledger]
```

## Provenance Schema Fields
| Field | Type | Description |
| :--- | :--- | :--- |
| `decisionId` | `string` | Cryptographically unique decision identifier. |
| `correlationId` | `string` | Trace ID linking the decision to initial client request. |
| `actor` | `object` | Verified actor identity, roles, and authentication method. |
| `resource` | `string` | Target ecosystem asset identifier. |
| `action` | `string` | Requested operation. |
| `riskEvaluation` | `object` | Input risk score and classified risk tier (LOW, MEDIUM, HIGH, CRITICAL). |
| `policyEvaluation`| `object` | Matched policy rule and rule priority. |
| `decision` | `enum` | Outcome: `ALLOW`, `DENY`, `REQUIRE_APPROVAL`, `ESCALATE`. |
| `reasonCode` | `string` | Deterministic rationale explaining the policy verdict. |
| `approvalRequirements` | `object` | Mandatory dual approver roles if sensitive action. |
| `cryptographicSignature` | `string` | SHA-256 digest sealing canonical decision fields. |
