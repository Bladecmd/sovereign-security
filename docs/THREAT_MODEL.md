# Defensive Threat Model & Trust Boundaries

## Threat Surface Analysis

| Threat ID | Threat Vector | Mitigation Mechanism |
| :--- | :--- | :--- |
| **TM-01** | Unauthorized Privilege Escalation | Deterministic Identity RBAC/ABAC engine with least privilege; zero-trust deny fallback. |
| **TM-02** | Audit Trail Alteration / Deletion | Append-only SHA-256 hash chaining, disk persistence, cold-boot verification, fail-stop on tampering. |
| **TM-03** | AI Prompt Injection & Jailbreak | Multi-tier AI Security Gateway inspecting input semantics and rejecting injection patterns. |
| **TM-04** | Accidental Secret Exposure in Logs | StructuredLogger secret detector redacting passwords, private keys, API keys, and connection URIs. |
| **TM-05** | Rogue Process Escalation in Container | Multi-stage Dockerfile running as non-root user `sovereign:sovereign`, read-only root FS, dropped Linux capabilities. |
| **TM-06** | Unbounded Entity Quarantine / DoS | Fail-safe TTL clamping and automated expiration on all quarantines. |
