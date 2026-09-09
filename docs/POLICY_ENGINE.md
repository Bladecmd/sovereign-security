# Sovereign Security — Policy Engine Specification

## 1. Engine Overview

The **Policy Engine** evaluates requested actions independently from any graphical user interface or business workflow engine. It acts as an automated decision gateway that answers:
> *"May Subject `A` execute Action `B` on Resource `C` in Context `D` given calculated Risk `E`?"*

---

## 2. Policy Decisions

The engine outputs one of four deterministic decisions:

| Decision | Semantic Meaning | Runtime Behavior |
| :--- | :--- | :--- |
| `ALLOW` | Operation is verified and authorized. | Immediate execution granted. |
| `DENY` | Operation violates security policy, RBAC, or risk limits. | Execution aborted immediately; security event logged. |
| `REQUIRE_APPROVAL` | Action is sensitive or destructive; requires human dual-authorization. | Execution halted; approval request queued to designated approvers. |
| `ESCALATE` | High-risk operation in production environment; requires higher-tier intervention. | Alert raised directly to the Executive Security Desk. |

---

## 3. Evaluation Inputs

Evaluation inputs are strictly validated via Zod schemas:
- `actor`: `IdentitySubject` (id, type, name, roles, explicitPermissions, organizationId)
- `resource`: string URI / identifier of target resource
- `action`: string verb of requested operation (e.g., `execute_fund_transfer`)
- `context`: Environment parameters (environment, IP, authMethod, timestamp, MFA)
- `riskScore`: Pre-computed normalized risk score (0 - 100)

---

## 4. Built-in Prioritized Rules (Foundation V0.1)

Rules are evaluated in descending priority order. The first rule to return a decision governs the request.

1. **Extreme Risk Blocker (Priority: 100)**:
   - *Condition*: `riskScore >= 90`
   - *Decision*: `DENY`
2. **Production High Risk Escalation (Priority: 80)**:
   - *Condition*: `context.environment === 'production' && riskScore >= 75`
   - *Decision*: `ESCALATE` (Target: `EXECUTIVE_SECURITY_DESK`)
3. **Sensitive Action Approval Requirement (Priority: 70)**:
   - *Condition*: `action` in `[delete_production_database, execute_fund_transfer, revoke_security_certificates, ...]`
   - *Decision*: `REQUIRE_APPROVAL` (Required: `SECURITY_ADMIN`, `EXECUTIVE_APPROVER`)
4. **RBAC & Role Restriction Verification (Priority: 50)**:
   - *Condition*: Fails `IdentityAccessEvaluator.hasPermission`
   - *Decision*: `DENY`
5. **Authorized Standard Allow (Priority: 10)**:
   - *Condition*: Passes all prior checks
   - *Decision*: `ALLOW`
6. **Zero-Trust Fallback (Priority: 0)**:
   - *Condition*: Unmatched by any rule
   - *Decision*: `DENY`
