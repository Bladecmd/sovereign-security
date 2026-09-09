# Sovereign Security — Production Hardening & Zero-Trust Runtime Specification

## Milestone: Phase 2A
**Status**: ACTIVE PRODUCTION HARDENED  
**Version**: 2.0.0-phase2a  
**Classification**: MISSION-CRITICAL DEFENSIVE INFRASTRUCTURE  

---

## 1. Zero-Trust Runtime & Security Perimeter
Sovereign Security provides decoupled, standalone defensive security services for the Sovereign ecosystem:
- **Sovereign OS**: Operational core and user application execution environment.
- **Metro Task Force (MTF)**: Mission telemetry and rapid incident detection.
- **Compliance Labs**: Governance, audit integrity, and regulatory validation.
- **AudioBlue & GriDD Corp**: Partner streaming and distributed network nodes.

### Security Guarantees:
1. **Decoupled Architecture**: Sovereign Security does NOT share database tables, schemas, or state stores with Sovereign OS.
2. **Defensive-Only Execution**: Actions are strictly confined to authorized ecosystem assets. Autonomous offensive actions or external counter-attacks are strictly prohibited.
3. **No Synthetic Telemetry**: All status metrics, liveness signals, and integrity checks reflect real deterministic runtime states.

---

## 2. Container Security Architecture
The production runtime is packaged via a multi-stage, hardened Docker container:
- **Base OS**: Minimal `node:22-alpine` footprint.
- **Non-Root Execution**: Runs under restricted user `sovereign:sovereign` (`UID 10001`, `GID 10001`, shell `/sbin/nologin`).
- **Read-Only Root Filesystem**: Root filesystem is mounted read-only (`read_only: true`).
- **Ephemeral Storage**: `/tmp` mounted as restricted `tmpfs` (`size=64m, noexec, nosuid`).
- **Capability Dropping**: Drops `ALL` Linux capabilities, retaining only `NET_BIND_SERVICE`.
- **Process Supervisor**: Managed by `dumb-init` (PID 1) for reliable POSIX signal handling and graceful shutdown.
- **Probes**: Native HTTP health checks against `/health` and `/ready`.

---

## 3. Persistent Cryptographic Audit Ledger
Located at `$DATA_DIR/audit.ledger` (default `/data/audit.ledger`):
- **Append-Only Durability**: Written as sequential newline-delimited JSON (`JSONL`).
- **SHA-256 Hash Chaining**: Every record links to its prior record's hash, anchored at genesis `0000...0000`.
- **Crash Recovery**: Cold restart scans and verifies the full hash chain before accepting writes.
- **Tamper Protection**: Any out-of-order sequence, bit flip, or line modification triggers immutable fail-stop protection and marks the system as degraded (`503 Service Unavailable` on `/ready`).

---

## 4. Security Decision Provenance
Every policy evaluation traverses the Zero-Trust Decision Pipeline:
`REQUEST -> IDENTITY -> RESOURCE -> ACTION -> POLICY -> RISK -> DECISION -> APPROVAL -> EXECUTION -> AUDIT`

Every decision generates a cryptographically sealed `SecurityDecisionProvenance` record containing:
- Unique `decisionId` and request `correlationId`.
- Full Identity subject representation (roles, clearance, authMethod).
- Categorized risk evaluation.
- Explicit policy rule ID and evaluation priority.
- Mandatory approval constraints for sensitive/destructive operations.
- SHA-256 cryptographic signature sealing the decision payload.
