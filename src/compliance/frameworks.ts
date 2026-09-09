/**
 * Sovereign Security — Milestone V1.0
 * Standard Compliance Framework Specifications
 */

import { ComplianceControl, ComplianceFrameworkId } from '../types/compliance.js';

export interface FrameworkDefinition {
  id: ComplianceFrameworkId;
  name: string;
  version: string;
  description: string;
  controls: Array<Omit<ComplianceControl, 'status' | 'evidence' | 'evaluatedAt'>>;
}

export const COMPLIANCE_FRAMEWORKS: Record<ComplianceFrameworkId, FrameworkDefinition> = {
  NIST_SP_800_207: {
    id: 'NIST_SP_800_207',
    name: 'NIST SP 800-207 Zero Trust Architecture (ZTA)',
    version: '2020 Revision',
    description: 'Federal standard for Zero Trust Architecture emphasizing continuous verification, micro-segmentation, and dynamic policy enforcement.',
    controls: [
      {
        id: 'ZTA-PEP-01',
        framework: 'NIST_SP_800_207',
        title: 'Policy Enforcement Point (PEP) Gatekeeper',
        description: 'All resource access requests are intercepted and gated by strict enforcement boundaries before reaching backend systems.',
        category: 'ACCESS_CONTROL',
      },
      {
        id: 'ZTA-PDP-02',
        framework: 'NIST_SP_800_207',
        title: 'Deterministic Policy Decision Point (PDP)',
        description: 'Policy decisions (ALLOW, DENY, REQUIRE_APPROVAL, ESCALATE) are deterministically evaluated against multi-factor risk and subject attributes.',
        category: 'POLICY_EVALUATION',
      },
      {
        id: 'ZTA-ID-03',
        framework: 'NIST_SP_800_207',
        title: 'Continuous Identity & Device Posture Verification',
        description: 'Dynamic ABAC rules evaluate subject clearance, department boundary, and quarantined device posture in real time.',
        category: 'IDENTITY_GOVERNANCE',
      },
      {
        id: 'ZTA-AUDIT-04',
        framework: 'NIST_SP_800_207',
        title: 'Cryptographic Tamper-Evident Audit Logging',
        description: 'All system transactions are logged in an immutable append-only SHA-256 hash chain with automated integrity verification.',
        category: 'DATA_INTEGRITY',
      },
      {
        id: 'ZTA-CRYPTO-05',
        framework: 'NIST_SP_800_207',
        title: 'Envelope Encryption & Key Lifecycle Management',
        description: 'Sensitive assets are encrypted using KMS envelope encryption with dual-key zero-downtime rotation and cryptographic shredding.',
        category: 'CRYPTOGRAPHY',
      },
    ],
  },
  SOC2_TYPE_II: {
    id: 'SOC2_TYPE_II',
    name: 'AICPA SOC 2 Type II Trust Services Criteria',
    version: '2022',
    description: 'Industry benchmark for security, availability, processing integrity, and confidentiality across cloud environments.',
    controls: [
      {
        id: 'SOC2-CC6.1',
        framework: 'SOC2_TYPE_II',
        title: 'Logical Access Controls & Least Privilege',
        description: 'Logical access to production assets is restricted to authorized roles with JIT privilege escalation and time-bound TTLs.',
        category: 'ACCESS_MANAGEMENT',
      },
      {
        id: 'SOC2-CC6.6',
        framework: 'SOC2_TYPE_II',
        title: 'Boundary Protection & Adversarial Input Defense',
        description: 'AI Security Gateway inspects and neutralizes prompt injections, delimiter hijacking, and unauthorized tool calls.',
        category: 'SYSTEM_PROTECTION',
      },
      {
        id: 'SOC2-CC6.7',
        framework: 'SOC2_TYPE_II',
        title: 'Data Exfiltration Prevention & Model Armor',
        description: 'Output filtering masks PII, credentials, and canary tokens before delivery to clients.',
        category: 'DATA_PROTECTION',
      },
      {
        id: 'SOC2-CC7.2',
        framework: 'SOC2_TYPE_II',
        title: '24/7 Security Threat Monitoring & Incident Alerting',
        description: 'Deterministic threat engine and Sentinel agent perform continuous 24/7 monitoring and triage.',
        category: 'SECURITY_OPERATIONS',
      },
      {
        id: 'SOC2-CC8.1',
        framework: 'SOC2_TYPE_II',
        title: 'Software Supply Chain Integrity & Provenance',
        description: 'Automated CycloneDX SBOM generation and CVE vulnerability matching for all deployed dependencies.',
        category: 'CHANGE_MANAGEMENT',
      },
    ],
  },
  ISO_IEC_27001_2022: {
    id: 'ISO_IEC_27001_2022',
    name: 'ISO/IEC 27001:2022 Information Security Management',
    version: '2022 Standard',
    description: 'International standard for establishing, implementing, maintaining, and continually improving an Information Security Management System (ISMS).',
    controls: [
      {
        id: 'ISO-A.8.2',
        framework: 'ISO_IEC_27001_2022',
        title: 'Privileged Access Rights & Hardware Authentication',
        description: 'High-risk operations enforce WebAuthn/FIDO2 hardware security keys and multi-tenant isolation boundaries.',
        category: 'ACCESS_CONTROL',
      },
      {
        id: 'ISO-A.8.24',
        framework: 'ISO_IEC_27001_2022',
        title: 'Use of Cryptography & Key Management',
        description: 'Cryptographic master keys are managed through isolated KMS modules with zero hardcoded secrets.',
        category: 'CRYPTOGRAPHY',
      },
      {
        id: 'ISO-A.8.28',
        framework: 'ISO_IEC_27001_2022',
        title: 'Secure Coding & Pre-Commit Secrets Blocking',
        description: 'Git pre-commit hooks and Shannon entropy analysis intercept secrets prior to source code repository staging.',
        category: 'DEVELOPMENT_SECURITY',
      },
      {
        id: 'ISO-A.8.30',
        framework: 'ISO_IEC_27001_2022',
        title: 'Supplier Relationships & SLSA Level 3 Verification',
        description: 'Non-falsifiable build provenance attestations verify build materials and trusted builder identities.',
        category: 'SUPPLY_CHAIN',
      },
      {
        id: 'ISO-A.8.16',
        framework: 'ISO_IEC_27001_2022',
        title: 'Monitoring Activities, Automated Containment & RCA',
        description: 'Autonomous Containment agent quarantines compromised entities, and Forensics agent reconstructs incident RCAs.',
        category: 'INCIDENT_MANAGEMENT',
      },
    ],
  },
};
