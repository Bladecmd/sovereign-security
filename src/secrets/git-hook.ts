/**
 * Sovereign Security — Milestone V0.4
 * Git Pre-Commit Security Guardrail Hook
 *
 * Scans all staged content before commit creation.
 * Halts commit execution if hardcoded private keys, credentials, or high-entropy tokens are detected.
 */

import { CodeSecretsScanner } from './scanner.js';

export interface PreCommitValidationResult {
  allowed: boolean;
  blockedFiles: string[];
  totalViolations: number;
  reportSummary: string[];
}

export class GitPreCommitHook {
  /**
   * Validate a map of filenames to staged file content buffers
   */
  public static validateStagedContent(
    stagedFiles: Map<string, string>
  ): PreCommitValidationResult {
    const blockedFiles: string[] = [];
    const reportSummary: string[] = [];
    let totalViolations = 0;

    for (const [filename, content] of stagedFiles.entries()) {
      // Ignore binary files and explicit environment templates
      if (filename.endsWith('.png') || filename.endsWith('.jpg') || filename.endsWith('.env.example')) {
        continue;
      }

      const report = CodeSecretsScanner.scan(content, filename);
      if (!report.passed) {
        blockedFiles.push(filename);
        totalViolations += report.secretsFound;
        for (const f of report.findings) {
          reportSummary.push(
            `[BLOCKED] ${filename}:${f.line} - Found ${f.classification} (${f.ruleId}, entropy: ${f.entropy}): ${f.remediation}`
          );
        }
      }
    }

    return {
      allowed: blockedFiles.length === 0,
      blockedFiles,
      totalViolations,
      reportSummary,
    };
  }
}
