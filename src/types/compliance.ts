/**
 * Sovereign Security — Milestone V1.0
 * Compliance, Posture Synchronization, and Platform Types
 */

export type ComplianceFrameworkId =
  | 'NIST_SP_800_207'
  | 'SOC2_TYPE_II'
  | 'ISO_IEC_27001_2022';

export type ComplianceControlStatus =
  | 'COMPLIANT'
  | 'NON_COMPLIANT'
  | 'PARTIAL'
  | 'NOT_APPLICABLE';

export interface ComplianceControl {
  id: string;
  framework: ComplianceFrameworkId;
  title: string;
  description: string;
  category: string;
  status: ComplianceControlStatus;
  evidence: string;
  evaluatedAt: string;
}

export type CertificationStatus = 'CERTIFIED' | 'PROVISIONAL' | 'NON_COMPLIANT';

export interface ComplianceCertificationReport {
  reportId: string;
  framework: ComplianceFrameworkId;
  frameworkName: string;
  certifiedAt: string;
  overallScore: number; // 0 - 100%
  totalControls: number;
  compliantControls: number;
  controls: ComplianceControl[];
  certificationStatus: CertificationStatus;
  signatureHash: string;
}

export type EcosystemEntity =
  | 'SOVEREIGN_OS'
  | 'METRO_TASK_FORCE'
  | 'COMPLIANCE_LABS'
  | 'AUDIOBLUE'
  | 'GRIDD_CORP'
  | 'PERSONAL_SOVEREIGN_AI';

export interface EntityPosture {
  entity: EcosystemEntity;
  displayName: string;
  hardeningScore: number; // 0 - 100
  lastSyncAt: string;
  activeDefenses: string[];
  compliant: boolean;
  findings: string[];
}

export interface EcosystemPostureReport {
  reportId: string;
  timestamp: string;
  overallHardeningScore: number; // 0 - 100
  entities: Record<EcosystemEntity, EntityPosture>;
  criticalFindings: string[];
  synchronizedBaselines: string[];
}

export interface PlatformSummary {
  version: string;
  releaseTag: string;
  status: 'OPTIMAL' | 'DEGRADED' | 'MAINTENANCE';
  bootTimestamp: string;
  components: Record<string, 'ACTIVE' | 'INITIALIZED' | 'STANDBY'>;
  activeQuarantines: number;
  auditChainIntegrity: boolean;
  totalAuditRecords: number;
  ecosystemHardeningScore: number;
  complianceCertifications: Record<ComplianceFrameworkId, CertificationStatus>;
}
