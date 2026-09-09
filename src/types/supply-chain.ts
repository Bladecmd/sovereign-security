/**
 * Sovereign Security — Milestone V0.5
 * Software Supply Chain & Vulnerability Intelligence Types
 *
 * Covers:
 * - CycloneDX / SPDX Software Bill of Materials (SBOM)
 * - Known CVE Vulnerability Advisories & CVSS Scoring
 * - SLSA Level 3 Build Provenance Attestations
 * - Software License Compliance Governance
 */

import { SecuritySeverity } from './events.js';

// ==========================================
// 1. SBOM Contracts (CycloneDX v1.5 JSON)
// ==========================================

export interface SBOMComponentHash {
  algorithm: 'SHA-256' | 'SHA-512' | 'MD5';
  value: string;
}

export interface SBOMComponent {
  type: 'library' | 'framework' | 'application' | 'container' | 'operating-system';
  name: string;
  version: string;
  purl?: string; // Package URL e.g. "pkg:npm/zod@3.23.8"
  hashes?: SBOMComponentHash[];
  licenses?: Array<{ license: { id?: string; name?: string } }>;
  description?: string;
  scope?: 'required' | 'optional' | 'excluded';
}

export interface CycloneDXSBOM {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  serialNumber: string; // urn:uuid:...
  version: number;
  metadata: {
    timestamp: string;
    tools: Array<{ vendor: string; name: string; version: string }>;
    component: {
      type: string;
      name: string;
      version: string;
    };
  };
  components: SBOMComponent[];
  dependencies?: Array<{ ref: string; dependsOn: string[] }>;
}

// ==========================================
// 2. Known CVE Vulnerability Contracts
// ==========================================

export interface CVEAdvisory {
  cveId: string; // e.g. "CVE-2024-21538"
  packageName: string;
  affectedVersionRange: string; // semver range e.g. "< 3.22.0"
  fixedVersion?: string; // e.g. "3.22.1"
  cvssScore: number; // 0.0 - 10.0
  severity: SecuritySeverity; // INFO, LOW, MEDIUM, HIGH, CRITICAL
  title: string;
  description: string;
  publishedAt: string;
  remediation: string;
}

export interface VulnerabilityScanMatch {
  cveId: string;
  packageName: string;
  installedVersion: string;
  fixedVersion?: string;
  severity: SecuritySeverity;
  cvssScore: number;
  title: string;
  remediation: string;
}

export interface SupplyChainScanReport {
  scannedAt: string;
  totalComponentsScanned: number;
  vulnerabilitiesFound: number;
  vulnerabilities: VulnerabilityScanMatch[];
  licenseViolations: LicenseComplianceViolation[];
  passed: boolean;
}

// ==========================================
// 3. SLSA Level 3 Build Provenance
// ==========================================

export interface SLSABuilder {
  id: string; // URI of trusted hermetic builder e.g. "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1"
}

export interface SLSAMaterial {
  uri: string; // Source repository URI
  digest: {
    sha1?: string;
    sha256?: string;
  };
}

export interface SLSAProvenancePredicate {
  builder: SLSABuilder;
  buildType: string;
  invocation: {
    configSource: {
      uri: string;
      digest: Record<string, string>;
      entryPoint: string;
    };
    parameters?: Record<string, unknown>;
  };
  materials: SLSAMaterial[];
}

export interface SLSAProvenanceStatement {
  _type: 'https://in-toto.io/Statement/v0.1';
  subject: Array<{
    name: string;
    digest: {
      sha256: string;
    };
  }>;
  predicateType: 'https://slsa.dev/provenance/v0.2';
  predicate: SLSAProvenancePredicate;
}

export interface SLSAVerificationResult {
  verified: boolean;
  slsaLevel: 'NONE' | 'SLSA_BUILD_L1' | 'SLSA_BUILD_L2' | 'SLSA_BUILD_L3';
  builderVerified: boolean;
  materialsVerified: boolean;
  tamperDetected: boolean;
  reason: string;
}

// ==========================================
// 4. Software License Compliance
// ==========================================

export type LicenseRiskTier = 'PERMISSIVE' | 'NOTICE_REQUIRED' | 'RESTRICTIVE' | 'PROHIBITED';

export interface LicensePolicyDefinition {
  spdxId: string;
  name: string;
  tier: LicenseRiskTier;
  commercialUseAllowed: boolean;
  copyleft: boolean;
}

export interface LicenseComplianceViolation {
  packageName: string;
  packageVersion: string;
  detectedLicense: string;
  tier: LicenseRiskTier;
  reason: string;
}
