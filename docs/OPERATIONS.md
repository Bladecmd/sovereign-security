# Sovereign Security Operational Runbook

## Endpoints & Probes

### Liveness Probe (`GET /health`)
- **Purpose**: Verifies process responsiveness and runtime memory bounds.
- **HTTP Code**: `200 OK`
- **Payload**:
  ```json
  {
    "status": "UP",
    "service": "sovereign-security",
    "version": "0.2.0",
    "phase": "2A",
    "uptimeSeconds": 3600,
    "memory": {
      "heapUsedMB": 42,
      "heapTotalMB": 64,
      "rssMB": 88
    }
  }
  ```

### Readiness Probe (`GET /ready`)
- **Purpose**: Verifies that the persistent audit ledger is mounted and uncompromised, and policy/threat engines are fully active.
- **HTTP Codes**:
  - `200 OK`: All checks passed.
  - `503 Service Unavailable`: Ledger integrity compromised or engines degraded.
- **Payload**:
  ```json
  {
    "ready": true,
    "service": "sovereign-security",
    "checks": {
      "policyEngine": "READY",
      "auditLedger": "VERIFIED",
      "persistentStorage": "MOUNTED",
      "quarantineEngine": "READY",
      "threatEngine": "READY"
    },
    "auditTotalRecords": 1420
  }
  ```

### Prometheus Telemetry (`GET /metrics`)
- **Format**: Prometheus plain text format (`version=0.0.4`).
- **Core Metrics**:
  - `sovereign_policy_evaluations_total` (counter)
  - `sovereign_policy_decisions_total{outcome="ALLOW|DENY|REQUIRE_APPROVAL|ESCALATE"}` (counter)
  - `sovereign_active_quarantines` (gauge)
  - `sovereign_audit_ledger_records` (gauge)
  - `sovereign_audit_ledger_integrity_status` (gauge: 1 = valid, 0 = compromised)
  - `sovereign_policy_evaluation_duration_ms` (histogram)
