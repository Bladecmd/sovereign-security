/**
 * Sovereign Security — Milestone V0.4
 * Advanced Secrets Detection, Shannon Entropy, Zero-Downtime Rotation, and KMS Tests
 */

import assert from 'node:assert/strict';
import test, { beforeEach, describe } from 'node:test';
import { GitPreCommitHook } from '../src/secrets/git-hook.js';
import { KMSKeyManager } from '../src/secrets/kms.js';
import { KeyRotationOrchestrator } from '../src/secrets/rotation-orchestrator.js';
import { CodeSecretsScanner } from '../src/secrets/scanner.js';

describe('Milestone V0.4: Secrets Security & Key Governance', () => {
  describe('Shannon Information Entropy Analysis', () => {
    test('calculates low entropy for repetitive text', () => {
      const lowEntropy = CodeSecretsScanner.calculateShannonEntropy('aaaaaaaaaaaaaaa');
      assert.equal(lowEntropy, 0);

      const repetitiveProse = CodeSecretsScanner.calculateShannonEntropy('hello hello hello world world');
      assert.ok(repetitiveProse < 3.0);
    });

    test('calculates high entropy for cryptographic tokens', () => {
      const cryptoToken = CodeSecretsScanner.calculateShannonEntropy('9f82c4e1a0b3d5f782194c3e80a1d6b9');
      assert.ok(cryptoToken >= 3.5);

      const base64Secret = CodeSecretsScanner.calculateShannonEntropy('Kx9+bV/29f82c4e1a0b3d5f782194c3e80a1d6b9');
      assert.ok(base64Secret >= 4.0);
    });
  });

  describe('CodeSecretsScanner & Signatures', () => {
    test('detects exposed private key block', () => {
      const sample = `
        const config = {
          host: "db.internal",
          privateKey: "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0..."
        };
      `;
      const report = CodeSecretsScanner.scan(sample, 'src/config.ts');
      assert.equal(report.passed, false);
      assert.equal(report.secretsFound, 1);
      assert.equal(report.findings[0]?.classification, 'PRIVATE_KEY');
      assert.match(report.findings[0]?.remediation || '', /Store key in KMS/i);
    });

    test('detects exposed database connection URI with credentials', () => {
      const sample = `const dbUri = "postgres://admin_user:SuperSecretP@ssw0rd123@prod-db.internal:5432/main";`;
      const report = CodeSecretsScanner.scan(sample, 'src/db.ts');
      assert.equal(report.passed, false);
      assert.equal(report.findings[0]?.classification, 'DATABASE_CREDENTIAL');
    });

    test('passes clean code using environment variables', () => {
      const sample = `
        const apiKey = process.env.SOVEREIGN_API_KEY;
        const port = Number(process.env.PORT) || 4000;
        console.log("Ready on port", port);
      `;
      const report = CodeSecretsScanner.scan(sample, 'src/index.ts');
      assert.equal(report.passed, true);
      assert.equal(report.secretsFound, 0);
    });
  });

  describe('Automated Zero-Downtime Key Rotation Orchestrator', () => {
    let orchestrator: KeyRotationOrchestrator;

    beforeEach(() => {
      orchestrator = new KeyRotationOrchestrator();
    });

    test('progresses through 5-phase zero-downtime rotation lifecycle', () => {
      // 1. Register initial credential
      const initial = orchestrator.registerCredential('sovereign-os-gateway', 'API_KEY');
      assert.equal(initial.version, 1);
      assert.equal(initial.status, 'ACTIVE');

      // 2. Initiate rotation
      const job = orchestrator.initiateRotation('sovereign-os-gateway');
      assert.equal(job.currentPhase, 'INITIATED');

      // 3. Deploy secondary
      orchestrator.stepDeploySecondary(job.jobId);
      assert.equal(job.currentPhase, 'SECONDARY_DEPLOYED');

      // 4. Promote primary
      orchestrator.stepPromotePrimary(job.jobId);
      assert.equal(job.currentPhase, 'PRIMARY_PROMOTED');
      const activeCred = orchestrator.getCredential('sovereign-os-gateway')!;
      assert.equal(activeCred.version, 2);
      assert.equal(activeCred.status, 'ACTIVE');

      // 5. Deprecate old key
      orchestrator.stepDeprecateOldKey(job.jobId);
      assert.equal(job.currentPhase, 'OLD_KEY_DEPRECATED');

      // 6. Complete and revoke
      orchestrator.stepCompleteAndRevoke(job.jobId);
      assert.equal(job.currentPhase, 'COMPLETED');
      assert.ok(job.completedAt);
      assert.equal(job.auditTrail.length, 5);
    });
  });

  describe('KMS Envelope Encryption Engine', () => {
    let kms: KMSKeyManager;

    beforeEach(() => {
      kms = new KMSKeyManager();
    });

    test('encrypts and decrypts payload using ephemeral DEK wrapped by master KEK', () => {
      const sensitiveData = 'SOVEREIGN-EXECUTIVE-LEDGER-HASH-998877';
      const envelope = kms.encryptEnvelope(sensitiveData);

      assert.equal(envelope.algorithm, 'AES-256-GCM');
      assert.ok(envelope.wrappedDataKey.includes(':'));
      assert.notEqual(envelope.ciphertext, sensitiveData);

      // Decrypt
      const decrypted = kms.decryptEnvelope(envelope);
      assert.equal(decrypted, sensitiveData);
    });

    test('cryptographic shredding: destroyed master key prevents decryption', () => {
      const descriptor = kms.createMasterKey('temp-kek-01', 'Temporary KEK');
      const envelope = kms.encryptEnvelope('secret payload', descriptor.keyId);

      // Decrypt before shredding
      assert.equal(kms.decryptEnvelope(envelope), 'secret payload');

      // Cryptographically destroy key
      kms.destroyMasterKey(descriptor.keyId);

      // Decrypt after destruction must fail
      assert.throws(() => {
        kms.decryptEnvelope(envelope);
      }, /destroyed or missing/i);
    });
  });

  describe('Git Pre-Commit Guardrail Hook', () => {
    test('permits clean files and blocks commits containing secrets', () => {
      const stagedFiles = new Map<string, string>();
      stagedFiles.set('src/utils.ts', 'export function add(a: number, b: number) { return a + b; }');
      stagedFiles.set(
        'src/leaked.ts',
        'const key = "-----BEGIN PRIVATE KEY-----\\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC..."'
      );

      const result = GitPreCommitHook.validateStagedContent(stagedFiles);
      assert.equal(result.allowed, false);
      assert.equal(result.blockedFiles.length, 1);
      assert.equal(result.blockedFiles[0], 'src/leaked.ts');
      assert.match(result.reportSummary[0] || '', /PRIVATE_KEY/);
    });
  });
});
