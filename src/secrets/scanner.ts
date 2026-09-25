/**
 * Sovereign Security — Milestone V0.4
 * Deep Codebase & Git Diff Secrets Scanner with Shannon Entropy Analysis
 *
 * Scans code files, commit diffs, and staged buffers to prevent secret leakage.
 * Combines high-precision regex signatures with Shannon information entropy scoring.
 */

import { CodeScanFinding, CodeScanReport, SecretClassification } from '../types/secrets.js';

interface ScanSignature {
  ruleId: string;
  classification: SecretClassification;
  regex: RegExp;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  minEntropy?: number;
  remediation: string;
}

export class CodeSecretsScanner {
  private static readonly SIGNATURES: ScanSignature[] = [
    {
      ruleId: 'SEC_RULE_PRIVATE_KEY',
      classification: 'PRIVATE_KEY',
      regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/i,
      confidence: 'HIGH',
      remediation: 'Remove raw private key immediately. Store key in KMS or secret manager.',
    },
    {
      ruleId: 'SEC_RULE_AWS_KEY',
      classification: 'API_KEY',
      regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
      confidence: 'HIGH',
      remediation: 'Revoke exposed AWS access key ID and audit AWS CloudTrail logs.',
    },
    {
      ruleId: 'SEC_RULE_OPENAI_KEY',
      classification: 'API_KEY',
      regex: /sk-[a-zA-Z0-9]{20,48}/,
      confidence: 'HIGH',
      minEntropy: 3.5,
      remediation: 'Revoke API key in provider console. Load key via process.env.API_KEY.',
    },
    {
      ruleId: 'SEC_RULE_GITHUB_PAT',
      classification: 'OAUTH_TOKEN',
      regex: /ghp_[a-zA-Z0-9]{20,}/,
      confidence: 'HIGH',
      remediation: 'Revoke GitHub personal access token in GitHub Developer Settings.',
    },
    {
      ruleId: 'SEC_RULE_DATABASE_URI',
      classification: 'DATABASE_CREDENTIAL',
      regex: /(?:postgres|mysql|mongodb|redis):\/\/[^:\s]+:([^@\s]+)@/i,
      confidence: 'HIGH',
      remediation: 'Remove embedded credentials from database connection string.',
    },
    {
      ruleId: 'SEC_RULE_HIGH_ENTROPY_ASSIGNMENT',
      classification: 'GENERIC_PASSWORD',
      regex: /(?:secret|password|passwd|api_key|token)\s*[:=]\s*['"]([a-zA-Z0-9_\-+/=]{16,})['"]/i,
      confidence: 'MEDIUM',
      minEntropy: 3.8,
      remediation: 'Extract literal secret value to environment configuration file (.env).',
    },
  ];

  /**
   * Calculate Shannon Entropy (bits per character) of a string.
   * High entropy (> 3.5 - 4.5) strongly correlates with cryptographic keys and secrets.
   */
  public static calculateShannonEntropy(str: string): number {
    if (!str || str.length === 0) return 0;

    const frequencies: Map<string, number> = new Map();
    for (const char of str) {
      frequencies.set(char, (frequencies.get(char) || 0) + 1);
    }

    let entropy = 0;
    const len = str.length;
    for (const count of frequencies.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return Math.round(entropy * 100) / 100;
  }

  /**
   * Scan text content line-by-line for leaked secrets
   */
  public static scan(content: string, _sourceName = 'buffer'): CodeScanReport {
    const lines = content.split(/\r?\n/);
    const findings: CodeScanFinding[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]!;
      const lineNumber = i + 1;

      // Skip comment indicators in common languages if explicitly labeled mock
      if (line.includes('YOUR_') || line.includes('MOCK_') || line.includes('EXAMPLE_')) {
        continue;
      }

      for (const sig of this.SIGNATURES) {
        const match = sig.regex.exec(line);
        if (match) {
          const matchedText = match[1] || match[0];
          const entropy = this.calculateShannonEntropy(matchedText);

          // If signature requires minimum entropy, enforce it
          if (sig.minEntropy && entropy < sig.minEntropy) {
            continue;
          }

          findings.push({
            line: lineNumber,
            ruleId: sig.ruleId,
            classification: sig.classification,
            confidence: sig.confidence,
            entropy,
            maskedSnippet: this.maskSnippet(line),
            remediation: sig.remediation,
          });

          // Move to next line once a critical secret is flagged on this line
          break;
        }
      }
    }

    return {
      scannedAt: new Date().toISOString(),
      totalLinesScanned: lines.length,
      secretsFound: findings.length,
      findings,
      passed: findings.length === 0,
    };
  }

  private static maskSnippet(line: string): string {
    const trimmed = line.trim();
    if (trimmed.length <= 12) return '************';
    const prefix = trimmed.substring(0, 6);
    const suffix = trimmed.substring(trimmed.length - 4);
    return `${prefix}****[REDACTED_SECRET]****${suffix}`;
  }
}
