/**
 * Sovereign Security — Foundation V0.1
 * Normalized SecurityEvent Schema & Types
 */

export type SecuritySeverity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type SecurityCategory =
  | 'IDENTITY'
  | 'AUTHENTICATION'
  | 'AUTHORIZATION'
  | 'API'
  | 'INFRASTRUCTURE'
  | 'APPLICATION'
  | 'DATA'
  | 'SECRETS'
  | 'AI_SECURITY'
  | 'DEPLOYMENT'
  | 'AUDIT';

export type SecurityResult = 'SUCCESS' | 'FAILURE' | 'DENIED' | 'PENDING' | 'ERROR';

export type VerificationStatus = 'UNVERIFIED' | 'VERIFIED' | 'TAMPERED';

export interface SecurityEvent {
  eventId: string;
  timestamp: string; // ISO 8601 UTC
  source: string; // e.g. "sovereign-os", "metro-task-force", "compliance-labs", "audioblue", "gridd-corp"
  businessId: string;
  environment: 'development' | 'staging' | 'production' | string;
  severity: SecuritySeverity;
  category: SecurityCategory;
  eventType: string; // e.g. "ADMIN_LOGIN_FAILED", "PERMISSION_DENIED"
  actorId: string; // User ID, Agent ID, or Service Account
  resourceId: string; // Target URI, Table, API endpoint, or Asset ID
  action: string; // e.g. "read", "write", "execute", "authenticate"
  result: SecurityResult;
  riskScore: number; // Normalized 0 - 100
  verificationStatus: VerificationStatus;
  metadata: Record<string, unknown>;
  correlationId: string;
}

export type CreateSecurityEventInput = Omit<
  SecurityEvent,
  'eventId' | 'timestamp' | 'verificationStatus'
> & {
  eventId?: string;
  timestamp?: string;
  verificationStatus?: VerificationStatus;
};
