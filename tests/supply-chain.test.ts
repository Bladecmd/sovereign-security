/**
 * Sovereign Security — Milestone V0.5
 * Software Supply Chain, SBOM, CVE, SLSA, and License Tests
 */

import assert from 'node:assert/strict';
import test, { beforeEach, describe } from 'node:test';
import { CVEVulnerabilityScanner } from '../src/supply-chain/cve-scanner.js';
import { LicenseComplianceAnalyzer } from '../src/supply-chain/license.js';
import { PackageManifest, SBOMGenerator } from '../src/supply-chain/sbom.js';
import { SLSALevel3Verifier } from '../src/supply-chain/slsa.js';
import { SLSAProvenanceStatement } from '../src/types/supply-chain.js';

describe('Milestone V0.5: Supply Chain & Vulnerability Intelligence', () => {
  describe('Software Bill of Materials (SBOM) - CycloneDX v1.5', () => {
    test('generates valid CycloneDX v1.5 JSON SBOM from package manifest', () => {
      const manifest: PackageManifest = {
        name: 'sovereign-os-gateway',
        version: '1.2.0',
        dependencies: {
          zod: '^3.23.8',
          express: '4.19.2',
        },
        devDependencies: {
          typescript: '^5.7.3',
        },
      };

      const sbom = SBOMGenerator.generateCycloneDX(manifest, { includeDev: true });

      assert.equal(sbom.bomFormat, 'CycloneDX');
      assert.equal(sbom.specVersion, '1.5');
      assert.ok(sbom.serialNumber.startsWith('urn:uuid:'));
      assert.equal(sbom.metadata.component.name, 'sovereign-os-gateway');
      assert.equal(sbom.components.length, 3); // zod, express, typescript

      const zodComponent = sbom.components.find((c) => c.name === 'zod');
      assert.ok(zodComponent);
      assert.equal(zodComponent.version, '3.23.8');
      assert.ok(zodComponent.purl?.includes('pkg:npm/zod@3.23.8'));
      assert.equal(zodComponent.hashes?.[0]?.algorithm, 'SHA-256');

      // Test parser
      const serialized = JSON.stringify(sbom);
      const parsed = SBOMGenerator.parseCycloneDX(serialized);
      assert.equal(parsed.components.length, 3);
    });
  });

  describe('Known CVE Vulnerability Intelligence Engine', () => {
    let cveScanner: CVEVulnerabilityScanner;

    beforeEach(() => {
      cveScanner = new CVEVulnerabilityScanner();
    });

    test('detects known critical vulnerability in outdated package version', () => {
      const components = [
        {
          type: 'library' as const,
          name: '@babel/traverse',
          version: '7.22.0', // Vulnerable (< 7.23.2)
        },
        {
          type: 'library' as const,
          name: 'safe-package',
          version: '1.0.0',
        },
      ];

      const matches = cveScanner.scanComponents(components);
      assert.equal(matches.length, 1);
      assert.equal(matches[0]?.cveId, 'CVE-2023-45133');
      assert.equal(matches[0]?.severity, 'CRITICAL');
      assert.equal(matches[0]?.fixedVersion, '7.23.2');
      assert.equal(matches[0]?.cvssScore, 9.3);

      // Verify alert creation
      const alerts = cveScanner.generateAlertsForMatches(matches, 'sovereign-os/core');
      assert.equal(alerts.length, 1);
      assert.equal(alerts[0]?.severity, 'CRITICAL');
      assert.equal(alerts[0]?.riskScore, 93);
      assert.match(alerts[0]?.title || '', /CVE-2023-45133/);
    });

    test('passes patched components without raising alerts', () => {
      const components = [
        {
          type: 'library' as const,
          name: '@babel/traverse',
          version: '7.24.0', // Patched (> 7.23.2)
        },
        {
          type: 'library' as const,
          name: 'semver',
          version: '7.6.0', // Patched (> 7.5.2)
        },
      ];

      const matches = cveScanner.scanComponents(components);
      assert.equal(matches.length, 0);
    });
  });

  describe('SLSA Level 3 Build Provenance Verification', () => {
    const validStatement: SLSAProvenanceStatement = {
      _type: 'https://in-toto.io/Statement/v0.1',
      subject: [
        {
          name: 'sovereign-os-binary',
          digest: {
            sha256: '9f82c4e1a0b3d5f782194c3e80a1d6b99f82c4e1a0b3d5f782194c3e80a1d6b9',
          },
        },
      ],
      predicateType: 'https://slsa.dev/provenance/v0.2',
      predicate: {
        builder: {
          id: 'https://github.com/sovereign-security/.github/workflows/hermetic-builder.yml@v1',
        },
        buildType: 'https://slsa.dev/container-based-build/v0.1',
        invocation: {
          configSource: {
            uri: 'git+https://github.com/sovereign/sovereign-os',
            digest: { sha1: 'e4d909c290d0fb1ca068ffaddf22cbd0add91c9e' },
            entryPoint: '.github/workflows/build.yml',
          },
        },
        materials: [
          {
            uri: 'git+https://github.com/sovereign/sovereign-os',
            digest: {
              sha1: 'e4d909c290d0fb1ca068ffaddf22cbd0add91c9e',
            },
          },
        ],
      },
    };

    test('successfully verifies authentic SLSA Level 3 build provenance', () => {
      const result = SLSALevel3Verifier.verifyProvenance(validStatement, {
        trustedBuilderId:
          'https://github.com/sovereign-security/.github/workflows/hermetic-builder.yml@v1',
        expectedRepoUri: 'git+https://github.com/sovereign/sovereign-os',
        expectedCommitSha: 'e4d909c290d0fb1ca068ffaddf22cbd0add91c9e',
        expectedArtifactHash:
          '9f82c4e1a0b3d5f782194c3e80a1d6b99f82c4e1a0b3d5f782194c3e80a1d6b9',
      });

      assert.equal(result.verified, true);
      assert.equal(result.slsaLevel, 'SLSA_BUILD_L3');
      assert.equal(result.tamperDetected, false);
    });

    test('detects tampered builder identity', () => {
      const result = SLSALevel3Verifier.verifyProvenance(validStatement, {
        trustedBuilderId: 'https://malicious-external-runner.io/builder.yml',
        expectedRepoUri: 'git+https://github.com/sovereign/sovereign-os',
        expectedCommitSha: 'e4d909c290d0fb1ca068ffaddf22cbd0add91c9e',
      });

      assert.equal(result.verified, false);
      assert.equal(result.tamperDetected, true);
      assert.match(result.reason, /Untrusted builder ID/);
    });

    test('detects commit SHA mismatch between manifest and build materials', () => {
      const result = SLSALevel3Verifier.verifyProvenance(validStatement, {
        trustedBuilderId:
          'https://github.com/sovereign-security/.github/workflows/hermetic-builder.yml@v1',
        expectedRepoUri: 'git+https://github.com/sovereign/sovereign-os',
        expectedCommitSha: 'fake_commit_hash_unauthorized_build',
      });

      assert.equal(result.verified, false);
      assert.match(result.reason, /Commit SHA mismatch/);
    });
  });

  describe('Software License Compliance & Legal Risk Analyzer', () => {
    test('classifies permissive licenses and allows commercial use', () => {
      const mit = LicenseComplianceAnalyzer.evaluateLicense('MIT');
      assert.equal(mit.tier, 'PERMISSIVE');
      assert.equal(mit.commercialUseAllowed, true);

      const apache = LicenseComplianceAnalyzer.evaluateLicense('Apache-2.0');
      assert.equal(apache.tier, 'PERMISSIVE');
    });

    test('flags prohibited copyleft licenses (AGPL-3.0) and generates violation reports', () => {
      const agpl = LicenseComplianceAnalyzer.evaluateLicense('AGPL-3.0-only');
      assert.equal(agpl.tier, 'PROHIBITED');
      assert.equal(agpl.copyleft, true);

      const components = [
        {
          type: 'library' as const,
          name: 'permissive-lib',
          version: '1.0.0',
          licenses: [{ license: { id: 'MIT' } }],
        },
        {
          type: 'library' as const,
          name: 'copyleft-danger',
          version: '2.4.0',
          licenses: [{ license: { id: 'AGPL-3.0-only' } }],
        },
      ];

      const violations = LicenseComplianceAnalyzer.scanComponents(components);
      assert.equal(violations.length, 1);
      assert.equal(violations[0]?.packageName, 'copyleft-danger');
      assert.equal(violations[0]?.tier, 'PROHIBITED');
      assert.match(violations[0]?.reason || '', /mandate source disclosure/);
    });
  });
});
