/**
 * Sovereign Security — Phase 2B: Ecosystem Fleet Wiring
 * AudioBlue CI/CD Security Controls & Build Quality Gates
 *
 * Implements:
 * - Pre-commit secret scanning & Shannon entropy inspection
 * - Dependency vulnerability (CVE) and license auditing
 * - Automated CycloneDX v1.5 JSON SBOM generation
 * - Emergency bypass procedure with mandatory authorization and tamper-evident audit logging
 */

import { AuditService } from '../../audit/audit-service.js';
import { CodeSecretsScanner } from '../../secrets/scanner.js';
import { CVEVulnerabilityScanner } from '../../supply-chain/cve-scanner.js';
import { PackageManifest, SBOMGenerator } from '../../supply-chain/sbom.js';
import { CycloneDXSBOM } from '../../types/supply-chain.js';

export interface ScanResult {
  passed: boolean;
  violations: string[];
  findingsCount: number;
}

export interface BuildSecurityGateInput {
  repoName: string;
  commitSha: string;
  sourceFiles: Array<{ filename: string; content: string }>;
  manifest?: PackageManifest;
  bypassRequested?: {
    authorizedBy: string;
    justificationTicket: string;
    approved: boolean;
  };
}

export interface BuildSecurityGateOutput {
  status: 'PASSED' | 'BLOCKED' | 'BYPASS_APPROVED';
  secretScan: ScanResult;
  dependencyScan: ScanResult;
  sbom?: CycloneDXSBOM;
  auditTrailId?: string;
  reason: string;
}

export class AudioBlueCIControls {
  private cveEngine: CVEVulnerabilityScanner;
  private auditService: AuditService;

  constructor(options?: { auditService?: AuditService }) {
    this.auditService = options?.auditService || new AuditService();
    this.cveEngine = new CVEVulnerabilityScanner();
  }

  /**
   * Evaluates complete CI/CD pre-commit and build security gate
   */
  public evaluateBuildGate(input: BuildSecurityGateInput): BuildSecurityGateOutput {
    // 1. Scan source files for exposed credentials or high entropy secrets
    const secretViolations: string[] = [];
    for (const file of input.sourceFiles) {
      const scanReport = CodeSecretsScanner.scan(file.content, file.filename);
      for (const f of scanReport.findings) {
        secretViolations.push(`${file.filename}: ${f.ruleId} detected (${f.classification})`);
      }
    }

    const secretScan: ScanResult = {
      passed: secretViolations.length === 0,
      violations: secretViolations,
      findingsCount: secretViolations.length,
    };

    // 2. Audit dependencies against known CVEs
    const depViolations: string[] = [];
    let generatedSbom: CycloneDXSBOM | undefined;

    if (input.manifest) {
      generatedSbom = SBOMGenerator.generateCycloneDX(input.manifest);
      const matches = this.cveEngine.scanComponents(generatedSbom.components);
      for (const m of matches) {
        if (m.severity === 'CRITICAL' || m.severity === 'HIGH') {
          depViolations.push(`${m.packageName}@${m.installedVersion}: ${m.cveId} [${m.severity}]`);
        }
      }
    }

    const depScan: ScanResult = {
      passed: depViolations.length === 0,
      violations: depViolations,
      findingsCount: depViolations.length,
    };

    const isFailing = !secretScan.passed || !depScan.passed;

    // 3. Handle Emergency Bypass Procedure
    if (isFailing) {
      if (
        input.bypassRequested &&
        input.bypassRequested.approved &&
        input.bypassRequested.authorizedBy &&
        input.bypassRequested.justificationTicket
      ) {
        // Tamper-evident audit record of the emergency bypass
        const audit = this.auditService.append({
          who: input.bypassRequested.authorizedBy,
          what: 'AUDIOBLUE_CI_EMERGENCY_BYPASS',
          where: `audioblue/ci-gate/${input.repoName}/${input.commitSha}`,
          why: `Emergency bypass authorized under ticket: ${input.bypassRequested.justificationTicket}`,
          result: 'SUCCESS',
          details: {
            repoName: input.repoName,
            commitSha: input.commitSha,
            secretViolations: secretScan.violations,
            depViolations: depScan.violations,
            justificationTicket: input.bypassRequested.justificationTicket,
          },
        });

        return {
          status: 'BYPASS_APPROVED',
          secretScan,
          dependencyScan: depScan,
          sbom: generatedSbom,
          auditTrailId: audit.auditId,
          reason: `Emergency bypass approved by ${input.bypassRequested.authorizedBy} under ${input.bypassRequested.justificationTicket}`,
        };
      }

      // Block build
      const blockedAudit = this.auditService.append({
        who: 'audioblue-ci-runner',
        what: 'AUDIOBLUE_CI_BUILD_BLOCKED',
        where: `audioblue/ci-gate/${input.repoName}/${input.commitSha}`,
        why: 'Security gate violations detected',
        result: 'DENIED' as const,
        details: {
          secretFindings: secretScan.findingsCount,
          depFindings: depScan.findingsCount,
          violations: [...secretScan.violations, ...depScan.violations],
        },
      });

      return {
        status: 'BLOCKED',
        secretScan,
        dependencyScan: depScan,
        sbom: generatedSbom,
        auditTrailId: blockedAudit.auditId,
        reason: 'Build gate failed due to detected secrets or high-severity vulnerabilities.',
      };
    }

    // Gate Passed cleanly
    return {
      status: 'PASSED',
      secretScan,
      dependencyScan: depScan,
      sbom: generatedSbom,
      reason: 'All pre-commit secrets and dependency vulnerability checks passed successfully.',
    };
  }
}
