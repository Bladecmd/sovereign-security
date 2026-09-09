/**
 * Sovereign Security — Milestone V0.5
 * Software License Compliance & Legal Risk Analyzer
 *
 * Enforces intellectual property governance and copyleft isolation
 * across Sovereign OS and ecosystem applications.
 */

import {
  LicenseComplianceViolation,
  LicensePolicyDefinition,
  LicenseRiskTier,
  SBOMComponent,
} from '../types/supply-chain.js';

export class LicenseComplianceAnalyzer {
  private static readonly POLICIES: Map<string, LicensePolicyDefinition> = new Map([
    // Permissive Licenses
    ['MIT', { spdxId: 'MIT', name: 'MIT License', tier: 'PERMISSIVE', commercialUseAllowed: true, copyleft: false }],
    ['Apache-2.0', { spdxId: 'Apache-2.0', name: 'Apache License 2.0', tier: 'PERMISSIVE', commercialUseAllowed: true, copyleft: false }],
    ['BSD-3-Clause', { spdxId: 'BSD-3-Clause', name: 'BSD 3-Clause "New" or "Revised" License', tier: 'PERMISSIVE', commercialUseAllowed: true, copyleft: false }],
    ['ISC', { spdxId: 'ISC', name: 'ISC License', tier: 'PERMISSIVE', commercialUseAllowed: true, copyleft: false }],

    // Notice Required / Weak Copyleft
    ['MPL-2.0', { spdxId: 'MPL-2.0', name: 'Mozilla Public License 2.0', tier: 'NOTICE_REQUIRED', commercialUseAllowed: true, copyleft: true }],
    ['LGPL-3.0-only', { spdxId: 'LGPL-3.0-only', name: 'GNU Lesser General Public License v3.0 only', tier: 'RESTRICTIVE', commercialUseAllowed: true, copyleft: true }],

    // Strong Copyleft / Prohibited in Proprietary Closed Source Distribution
    ['GPL-3.0-only', { spdxId: 'GPL-3.0-only', name: 'GNU General Public License v3.0 only', tier: 'PROHIBITED', commercialUseAllowed: false, copyleft: true }],
    ['GPL-2.0-only', { spdxId: 'GPL-2.0-only', name: 'GNU General Public License v2.0 only', tier: 'PROHIBITED', commercialUseAllowed: false, copyleft: true }],
    ['AGPL-3.0-only', { spdxId: 'AGPL-3.0-only', name: 'GNU Affero General Public License v3.0', tier: 'PROHIBITED', commercialUseAllowed: false, copyleft: true }],
  ]);

  /**
   * Evaluate a license against organizational risk tier policy
   */
  public static evaluateLicense(spdxId: string): LicensePolicyDefinition {
    const clean = spdxId.trim();
    const policy = this.POLICIES.get(clean);
    if (policy) return policy;

    // Fallback classification
    if (clean.includes('GPL') || clean.includes('AGPL')) {
      return {
        spdxId: clean,
        name: clean,
        tier: 'PROHIBITED',
        commercialUseAllowed: false,
        copyleft: true,
      };
    }

    return {
      spdxId: clean,
      name: clean,
      tier: 'NOTICE_REQUIRED',
      commercialUseAllowed: true,
      copyleft: false,
    };
  }

  /**
   * Scan SBOM components for prohibited or restrictive license violations
   */
  public static scanComponents(
    components: SBOMComponent[],
    prohibitedTiers: LicenseRiskTier[] = ['PROHIBITED', 'RESTRICTIVE']
  ): LicenseComplianceViolation[] {
    const violations: LicenseComplianceViolation[] = [];

    for (const comp of components) {
      if (!comp.licenses || comp.licenses.length === 0) continue;

      for (const lic of comp.licenses) {
        const id = lic.license.id || lic.license.name || 'UNKNOWN';
        const evaluation = this.evaluateLicense(id);

        if (prohibitedTiers.includes(evaluation.tier)) {
          violations.push({
            packageName: comp.name,
            packageVersion: comp.version,
            detectedLicense: id,
            tier: evaluation.tier,
            reason: `License '${id}' is classified as ${evaluation.tier}. Strong copyleft may mandate source disclosure.`,
          });
        }
      }
    }

    return violations;
  }
}
