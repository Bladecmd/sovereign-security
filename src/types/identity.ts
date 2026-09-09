/**
 * Sovereign Security — Foundation V0.1 & V0.3
 * Identity & Access Management (RBAC, ABAC, JIT, WebAuthn) Types
 */

export type Role = 'ADMIN' | 'EXECUTIVE' | 'SYSTEM' | 'AGENT' | 'SERVICE';

export type Permission = 'READ' | 'WRITE' | 'EXECUTE' | 'CERTIFY' | 'ADMINISTER';

export type DataClassification = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED' | 'TOP_SECRET';

export type ClearanceLevel = 1 | 2 | 3 | 4 | 5;

export interface IdentitySubject {
  id: string;
  type: Role;
  name: string;
  roles: Role[];
  explicitPermissions?: Permission[];
  organizationId: string;
  attributes?: Record<string, unknown>;
}

export interface RoleDefinition {
  role: Role;
  description: string;
  allowedPermissions: readonly Permission[];
  restrictedActions?: readonly string[];
}

// ==========================================
// V0.3: Dynamic Attribute-Based Access Control (ABAC)
// ==========================================

export interface ABACSubjectAttributes {
  clearanceLevel: ClearanceLevel;
  department: string;
  tenantId: string;
  devicePosture: 'MANAGED_SECURE' | 'UNMANAGED' | 'QUARANTINED';
  mfaVerified: boolean;
  hardwareTokenBound?: boolean;
}

export interface ABACResourceAttributes {
  resourceId: string;
  tenantId: string;
  classification: DataClassification;
  requiredClearance: ClearanceLevel;
  restrictedToDepartments?: string[];
  geoFenceAllowed?: string[]; // e.g. ["US", "EU", "GB"]
}

export interface ABACEnvironmentAttributes {
  timestamp: string;
  ipAddress: string;
  countryCode?: string;
  currentFleetThreatLevel: 'LOW' | 'GUARDED' | 'ELEVATED' | 'HIGH' | 'CRITICAL';
}

export interface ABACEvaluationInput {
  subject: IdentitySubject;
  subjectAttrs: ABACSubjectAttributes;
  resourceAttrs: ABACResourceAttributes;
  envAttrs: ABACEnvironmentAttributes;
  action: string;
}

export interface ABACPolicyDecision {
  allowed: boolean;
  reason: string;
  requiredStepUp?: 'HARDWARE_TOKEN' | 'EXECUTIVE_APPROVAL';
}

// ==========================================
// V0.3: Ephemeral Just-In-Time (JIT) Elevation
// ==========================================

export type JITStatus = 'PENDING' | 'APPROVED' | 'ACTIVE' | 'EXPIRED' | 'REVOKED';

export interface JITRequest {
  requestId: string;
  subjectId: string;
  targetRole: Role;
  elevatedPermissions: Permission[];
  justificationTicket: string; // e.g. "INCIDENT-409" or "SEC-CHANGE-12"
  durationMinutes: number; // TTL (typically 5 to 60 minutes)
  requestedAt: string;
  status: JITStatus;
}

export interface JITGrant {
  grantId: string;
  requestId: string;
  subjectId: string;
  grantedRole: Role;
  grantedPermissions: Permission[];
  approvedBy: string; // Executive or Security Admin ID
  issuedAt: string;
  expiresAt: string;
  status: JITStatus;
}

// ==========================================
// V0.3: Hardware Token (FIDO2/WebAuthn) Step-Up
// ==========================================

export interface WebAuthnStepUpChallenge {
  challengeId: string;
  subjectId: string;
  nonce: string; // Cryptographic random nonce
  actionToAuthorize: string;
  expiresAt: string;
}

export interface WebAuthnStepUpAssertion {
  challengeId: string;
  subjectId: string;
  credentialId: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
}
