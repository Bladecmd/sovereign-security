# Sovereign Security — Defensive Threat Model & Risk Engineering

## 1. Defensive Boundary Statement

> [!IMPORTANT]
> **Strictly Defensive Mandate**:
> Sovereign Security does not perform offensive scanning, probe third-party networks, craft exploits, or harvest credentials. Its surveillance and telemetry mechanisms apply solely to owned or explicitly authorized assets within the Sovereign ecosystem.

---

## 2. Threat Scenarios & Detection Logic

### Scenario 1: Credential Stuffing & Admin Brute Force
- **Vector**: Adversary attempts repeated credential combinations against administrative login endpoints.
- **Defensive Rule**: `THREAT_BRUTE_FORCE_AUTH`
- **Logic**: Aggregates `ADMIN_LOGIN_FAILED` events across a sliding 10-minute time window for a single actor IP or target resource.
- **Response**: Upon reaching 5 failed attempts, generates a `HIGH` severity `SecurityAlert` containing all source event IDs and triggers IP throttling.

### Scenario 2: Privilege Escalation & Rogue Internal Actor
- **Vector**: An internal actor or compromised service account attempts to execute unauthorized destructive actions (e.g., dropping database tables, deleting backups, or transferring funds).
- **Defensive Rule**: `THREAT_UNAUTHORIZED_PRIVILEGED_ACTION`
- **Logic**: Flags any denied action matching privileged signatures.
- **Response**: Generates a `CRITICAL` severity `SecurityAlert`, logs to the immutable hash chain, and triggers executive notification.

### Scenario 3: Accidental Credential Exposure
- **Vector**: Developer or automated script outputs raw API keys, private keys, or database connection strings into logs, commit history, or chat prompts.
- **Defensive Rule**: `THREAT_SECRET_EXPOSURE`
- **Logic**: Pattern-based recognition of RSA/EC private keys, JWTs, and API key tokens.
- **Response**: Generates an immediate `CRITICAL` alert with recommended revocation actions, masks text snippets, and notifies the security desk.

---

## 3. Deterministic Risk Engine Formula

The Risk Engine calculates an integer risk score in the range `[0, 100]`:

$$\text{RawScore} = \left( \text{BaseSeverity} + \text{ActionSensitivity} \right) \times \text{CriticalityMultiplier} + \text{AuthStateAdjustment} + \text{FrequencyBump}$$

Where:
- **BaseSeverity**: `INFO` = 5, `LOW` = 20, `MEDIUM` = 45, `HIGH` = 75, `CRITICAL` = 95
- **ActionSensitivity**: Read = 0, Write = +5, Delete = +15, Fund Transfer = +15, Admin/Root = +20
- **CriticalityMultiplier**: Low = 0.85, Medium = 1.0, High = 1.25, Mission-Critical = 1.5
- **AuthStateAdjustment**: Unauthenticated = +30, Password Only = +10, MFA Verified = -15, Certificate Bound = -20
- **FrequencyBump**: $\min(25, (\text{repetitions} - 1) \times 5)$

---

## 4. Architectural Roadmap Markers (V0.2 — V1.0)

| Version | Milestone Title | Core Deliverables | Status |
| :--- | :--- | :--- | :--- |
| **V0.1** | **Foundation Security Architecture** | Normalized schemas, RBAC, deterministic policy & risk engines, VEGA tool permissions, audit hash chaining, Sovereign OS & MTF adapters. | **IMPLEMENTED / FOUNDATION** |
| **V0.2** | **Security Dashboard** | Executive real-time triage workspace, risk visualization, audit log inspector. | **PLANNED** |
| **V0.3** | **Advanced Identity & RBAC** | Dynamic ABAC engine, hardware key WebAuthn/FIDO2 enforcement, tenant isolation. | **PLANNED** |
| **V0.4** | **Secrets Detection & Automated Rotation** | AST code scanning, automated key rotation webhooks, HSM orchestration. | **PLANNED** |
| **V0.5** | **Dependency & Vulnerability Intelligence** | Continuous SBOM (CycloneDX), real-time CVE correlation, supply chain provenance. | **PLANNED** |
| **V0.6** | **AI Security Gateway** | Semantic boundary enforcement, neural prompt injection classifier, model sandboxing. | **PLANNED** |
| **V0.7** | **Autonomous Security Agents** | Sentinel Agent (triage), Containment Agent (quarantine), Forensics Agent (investigation). | **PLANNED** |
| **V1.0** | **Integrated Sovereign Security Operations Platform** | Full-spectrum autonomous operations platform across all ecosystem assets. | **PLANNED** |
