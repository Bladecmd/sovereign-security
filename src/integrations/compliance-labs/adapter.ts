/**
 * Sovereign Security — Phase 2B: Ecosystem Fleet Wiring
 * Compliance Labs Integration Adapter
 *
 * Supports independent auditor requests from Compliance Labs:
 * - Evidence requests for SOC 2, ISO 27001, CIS, HIPAA
 * - Tamper-evident Audit Ledger integrity verification
 * - Cryptographic proof-of-integrity hashes
 * - Zero synthetic data: returns genuine audit records and cryptographic verification status
 */

import { AuditService } from '../../audit/audit-service.js';
import { ComplianceCertificationEngine } from '../../compliance/certification.js';
import { AuditRecord } from '../../types/audit.js';
import { ComplianceCertificationReport, ComplianceFrameworkId } from '../../types/compliance.js';
import { EcosystemAuthenticator, EcosystemCredentials } from '../auth/credentials.js';

export interface AuditEvidenceRequest {
  framework: ComplianceFrameworkId;
  requestedBy: string;
  auditScope: string;
  correlationId?: string;
}

export interface AuditEvidenceBundle {
  attestation: ComplianceCertificationReport;
  verifiedAuditTrail: {
    recordCount: number;
    headHash: string;
    chainValid: boolean;
    brokenAtRecordId?: string;
  };
  sampleEvidenceRecords: AuditRecord[];
  exportedAt: string;
}

export class ComplianceLabsAdapter {
  private auditService: AuditService;
  private certEngine: ComplianceCertificationEngine;

  constructor(auditService?: AuditService) {
    this.auditService = auditService || new AuditService();
    this.certEngine = new ComplianceCertificationEngine();
  }

  /**
   * Generates a verifiable compliance evidence bundle for Compliance Labs
   */
  public generateVerifiableEvidenceBundle(
    request: AuditEvidenceRequest,
    credentials: EcosystemCredentials
  ): { success: boolean; bundle?: AuditEvidenceBundle; error?: string } {
    // 1. Authenticate Compliance Labs
    const auth = EcosystemAuthenticator.verifyCredentials(credentials);
    if (!auth.authenticated) {
      return {
        success: false,
        error: `ECOSYSTEM_AUTH_FAILED: ${auth.errorMessage}`,
      };
    }

    // 2. Run real compliance certification audit
    const attestation = this.certEngine.certify(request.framework);

    // 3. Cryptographically verify audit trail integrity
    const records = this.auditService.getRecords();
    const chainVerification = this.auditService.verifyIntegrity();
    const lastRecord = records.length > 0 ? records[records.length - 1] : undefined;
    const headHash = lastRecord ? lastRecord.currentHash : 'GENESIS';

    const bundle: AuditEvidenceBundle = {
      attestation,
      verifiedAuditTrail: {
        recordCount: records.length,
        headHash,
        chainValid: chainVerification.isValid,
        brokenAtRecordId: chainVerification.tamperedRecordId,
      },
      sampleEvidenceRecords: records.slice(-10),
      exportedAt: new Date().toISOString(),
    };

    return {
      success: true,
      bundle,
    };
  }

  /**
   * Standalone audit chain verification request
   */
  public verifyAuditIntegrity(credentials: EcosystemCredentials): {
    success: boolean;
    valid?: boolean;
    totalRecords?: number;
    error?: string;
  } {
    const auth = EcosystemAuthenticator.verifyCredentials(credentials);
    if (!auth.authenticated) {
      return {
        success: false,
        error: `ECOSYSTEM_AUTH_FAILED: ${auth.errorMessage}`,
      };
    }

    const verification = this.auditService.verifyIntegrity();
    const records = this.auditService.getRecords();

    return {
      success: true,
      valid: verification.isValid,
      totalRecords: records.length,
    };
  }
}
