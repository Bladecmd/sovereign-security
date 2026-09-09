/**
 * Sovereign Security — Foundation V0.1
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
