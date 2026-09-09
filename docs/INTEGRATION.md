# Sovereign Security — Integration Adapters Specification

## 1. Integration Philosophy

Sovereign Security communicates with ecosystem applications strictly through controlled, typed APIs and normalized event streams.
- **Zero Database Coupling**: Databases are completely segregated. Sovereign Security never queries Sovereign OS or MTF application databases directly.
- **Zero Business Logic Duplication**: Domain rules (e.g., dispatch logic or financial accounting) remain in their respective platforms.

---

## 2. Sovereign OS Adapter: `SovereignSecurityClient`

The `SovereignSecurityClient` provides Sovereign OS components (and agents like VEGA) with an ergonomic client SDK:

```typescript
import { SovereignSecurityClient } from 'sovereign-security';

const security = new SovereignSecurityClient({
  sourceId: 'sovereign-os',
  environment: 'production',
});

// 1. Emit security telemetry
const { event, triggeredAlerts } = await security.emitSecurityEvent({
  businessId: 'biz-sovereign-01',
  severity: 'INFO',
  category: 'AUTHENTICATION',
  eventType: 'ADMIN_LOGIN_SUCCESS',
  actorId: 'usr-admin-01',
  resourceId: 'api/v1/auth',
  action: 'authenticate',
  result: 'SUCCESS',
  riskScore: 10,
  metadata: { authMode: 'webauthn' },
  correlationId: 'trace-abc-123',
});

// 2. Check policy authorization before sensitive operations
const decision = await security.checkPolicy({
  actor: currentSubject,
  resource: 'vault/disbursement',
  action: 'execute_fund_transfer',
  context: { environment: 'production', timestamp: new Date().toISOString() },
  riskScore: 40,
});

// 3. Check agent tool permissions (e.g., VEGA)
const permission = await security.checkAgentPermission('vega', 'read_business_telemetry');
if (permission.decision !== 'ALLOW') {
  throw new Error(`Tool execution prohibited: ${permission.reason}`);
}

// 4. Record tamper-evident audit record
await security.recordAuditEvent({
  who: 'usr-admin-01',
  what: 'UPDATE_ROLES',
  where: 'sovereign-os/admin',
  why: 'Ticket SEC-104',
  result: 'SUCCESS',
  details: { role: 'AUDITOR' },
});
```

---

## 3. Metro Task Force Adapter: `MetroTaskForceAdapter`

The `MetroTaskForceAdapter` receives operational events from the Metro Task Force platform and normalizes them into standard `SecurityEvent` contracts without pulling in MTF dependencies:

### Supported MTF Event Types
- `ADMIN_LOGIN_FAILED` -> Maps to `AUTHENTICATION`, `HIGH` severity, calculates threat threshold.
- `ADMIN_LOGIN_SUCCESS` -> Maps to `AUTHENTICATION`, `INFO` severity.
- `RATE_LIMIT_TRIGGERED` -> Maps to `API`, `MEDIUM` severity.
- `PERMISSION_DENIED` -> Maps to `AUTHORIZATION`, `MEDIUM` severity.
- `SUSPICIOUS_API_ACTIVITY` -> Maps to `API`, `HIGH` severity.
- `SECRET_EXPOSURE` -> Maps to `SECRETS`, `CRITICAL` severity, generates immediate incident alert.
- `DEPLOYMENT_EVENT` -> Maps to `DEPLOYMENT`, `INFO` severity.
- `PAYMENT_SECURITY_EVENT` -> Maps to `APPLICATION`, `HIGH` severity.
