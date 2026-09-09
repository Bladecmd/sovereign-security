# Sovereign Security — Normalized Event & Alert Schemas

## 1. SecurityEvent Contract

The `SecurityEvent` schema is the common telemetry currency of the Sovereign ecosystem. All subsystems (Sovereign OS, Metro Task Force, Compliance Labs, AudioBlue, GriDD Corp) normalize their security telemetry into this standard schema.

### Schema Fields
```typescript
interface SecurityEvent {
  eventId: string;             // Globally unique event identifier (UUID or prefix-timestamp-hash)
  timestamp: string;           // ISO 8601 UTC timestamp
  source: string;              // Originating system (e.g., "sovereign-os", "metro-task-force")
  businessId: string;          // Business entity identifier (e.g., "mtf-hq", "biz-sovereign-01")
  environment: string;         // "development" | "staging" | "production"
  severity: SecuritySeverity;  // "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  category: SecurityCategory;  // 11 distinct domain categories (see below)
  eventType: string;           // Canonical event type (e.g., "ADMIN_LOGIN_FAILED")
  actorId: string;             // User ID, Agent ID, or Service identifier
  resourceId: string;          // Target resource URI, table, or endpoint
  action: string;              // Action attempted (e.g., "read", "authenticate", "execute")
  result: SecurityResult;      // "SUCCESS" | "FAILURE" | "DENIED" | "PENDING" | "ERROR"
  riskScore: number;           // Normalized score between 0 and 100
  verificationStatus: string;  // "UNVERIFIED" | "VERIFIED" | "TAMPERED"
  metadata: Record<string, unknown>; // Domain-specific contextual metadata
  correlationId: string;       // Distributed trace correlation identifier
}
```

### Security Categories
1. `IDENTITY`: User lifecycle, role changes, privilege elevations
2. `AUTHENTICATION`: Login attempts, token issuance, MFA challenges
3. `AUTHORIZATION`: Permission checks, policy evaluations, access denials
4. `API`: Endpoint traffic, rate limiting, request throttling
5. `INFRASTRUCTURE`: Cloud instances, cluster status, gateway events
6. `APPLICATION`: App state changes, operational errors, anomalies
7. `DATA`: Database queries, export jobs, bulk modifications
8. `SECRETS`: Credential detection, rotation events, exposure alerts
9. `AI_SECURITY`: Agent tool calls, prompt injection attempts, output leaks
10. `DEPLOYMENT`: Build triggers, pipeline rollouts, container updates
11. `AUDIT`: Administrative actions, governance reviews, compliance sign-offs

---

## 2. SecurityAlert Contract

A `SecurityAlert` is generated when threat rules, risk thresholds, or security anomalies are triggered.

### Schema Fields
```typescript
interface SecurityAlert {
  alertId: string;             // Unique alert identifier
  createdAt: string;           // ISO 8601 UTC timestamp
  severity: SecuritySeverity;  // "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
  category: SecurityCategory;  // Origin category
  title: string;               // Concise alert title
  description: string;         // Detailed explanation of the threat or violation
  sourceEventIds: string[];    // Array of underlying SecurityEvent eventIds
  affectedResource: string;    // Resource affected or targeted
  riskScore: number;           // Normalized risk score (0 - 100)
  status: AlertStatus;         // Lifecycle status (see below)
  assignedTo?: string;         // Assigned security analyst or automated responder
  resolution?: string;         // Resolution summary
  resolvedAt?: string;         // ISO 8601 UTC timestamp of resolution
}
```

### Alert Lifecycle Statuses
- `OPEN`: Newly generated alert awaiting initial triage.
- `ACKNOWLEDGED`: Assigned analyst or orchestrator has acknowledged receipt.
- `INVESTIGATING`: Active analysis or log inspection in progress.
- `CONTAINED`: Threat mitigated (e.g., actor blocked, credential revoked).
- `RESOLVED`: Incident completed and verified secure.
- `FALSE_POSITIVE`: Reviewed and classified as benign.
