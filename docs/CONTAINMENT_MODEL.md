# Automated Containment & Fail-Safe Isolation Model

## Defensive Principles
Containment operations isolate compromised entities (Actors, IP addresses, Agents, Services) to arrest threat spread while ensuring business continuity and preventing unbounded lockouts.

## Fail-Safe TTL & Lifecycle
1. **Mandatory TTL**: Every quarantine record enforces an expiration deadline (`expiresAt`).
2. **Maximum TTL Clamp**: Requests specifying excessive durations are automatically clamped to the system maximum (`maxTtlMs`, default 24 hours).
3. **Lifecycle States**:
   - `ACTIVE`: Target is actively restricted and blocked across policy boundary.
   - `EXPIRED`: Time-to-live expired naturally without manual release.
   - `RELEASED`: Manually released by authorized security operator with auditable justification.
   - `FAILED`: Containment mechanism encountered an execution failure.

## Auditable Release Requirements
Quarantines can only be released when accompanied by:
- Verified operator identity (`releasedBy`).
- Incident justification ticket or remediation explanation (`releaseReason`).
- Automated cryptographic audit event appended to persistent ledger.
