/**
 * Sovereign Security — Foundation V0.1 & Milestone V0.4
 * Secrets Security Interfaces & Contracts
 */

export type SecretClassification =
  | 'API_KEY'
  | 'DATABASE_CREDENTIAL'
  | 'PRIVATE_KEY'
  | 'JWT_SECRET'
  | 'OAUTH_TOKEN'
  | 'GENERIC_PASSWORD'
  | 'INFRASTRUCTURE_KEY';

export interface SecretDetectionResult {
  detected: boolean;
  classification?: SecretClassification;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  location: {
    source: string;
    field?: string;
    line?: number;
    snippetMasked: string; // Sanitized preview with redaction
  };
}

export interface SecretExposureEvent {
  exposureId: string;
  detectedAt: string;
  classification: SecretClassification;
  severity: 'HIGH' | 'CRITICAL';
  sourceLocation: string;
  affectedService: string;
  recommendedAction: string;
  correlationId: string;
}

export interface CredentialRotationReminder {
  credentialId: string;
  service: string;
  classification: SecretClassification;
  lastRotatedAt: string;
  expiresAt: string;
  daysRemaining: number;
  status: 'CURRENT' | 'DUE_SOON' | 'OVERDUE';
}

// ==========================================
// V0.4: Codebase Secret Scanning & Entropy
// ==========================================

export interface CodeScanFinding {
  line: number;
  ruleId: string;
  classification: SecretClassification;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  entropy: number;
  maskedSnippet: string;
  remediation: string;
}

export interface CodeScanReport {
  scannedAt: string;
  totalLinesScanned: number;
  secretsFound: number;
  findings: CodeScanFinding[];
  passed: boolean;
}

// ==========================================
// V0.4: Automated Zero-Downtime Dual-Key Rotation
// ==========================================

export type RotationPhase =
  | 'INITIATED'
  | 'SECONDARY_DEPLOYED'
  | 'PRIMARY_PROMOTED'
  | 'OLD_KEY_DEPRECATED'
  | 'COMPLETED';

export interface ServiceCredentialDescriptor {
  credentialId: string;
  service: string;
  classification: SecretClassification;
  version: number;
  activeKeyHash: string; // SHA-256 fingerprint
  createdAt: string;
  expiresAt: string;
  status: 'ACTIVE' | 'DEPRECATED' | 'REVOKED';
}

export interface ZeroDowntimeRotationJob {
  jobId: string;
  service: string;
  oldCredentialId: string;
  newCredentialId: string;
  currentPhase: RotationPhase;
  startedAt: string;
  completedAt?: string;
  auditTrail: string[];
}

// ==========================================
// V0.4: KMS / HSM Envelope Encryption
// ==========================================

export type KMSKeyState = 'PENDING_GENERATION' | 'ACTIVE' | 'DEPRECATED' | 'DESTROYED';

export interface KMSEnvelope {
  keyId: string;
  keyVersion: number;
  algorithm: 'AES-256-GCM';
  iv: string; // Hex initialization vector
  authTag: string; // Hex GCM authentication tag
  wrappedDataKey: string; // Master-wrapped encrypted DEK
  ciphertext: string; // Payload encrypted under DEK
}

export interface KMSMasterKeyDescriptor {
  keyId: string;
  alias: string;
  state: KMSKeyState;
  algorithm: string;
  createdAt: string;
  lastRotatedAt: string;
}
