/**
 * Sovereign Security — Milestone V0.6
 * Model Armor & Real-Time Output Exfiltration Filter
 */

import { ModelArmorResult, ModelViolation } from '../types/ai-gateway.js';

export interface ModelArmorOptions {
  canaryTokens?: string[];
  systemPromptFingerprints?: string[];
  blockOnPii?: boolean;
}

export class ModelArmorFilter {
  private canaryTokens: Set<string>;
  private systemPromptFingerprints: string[];
  private blockOnPii: boolean;

  constructor(options: ModelArmorOptions = {}) {
    this.canaryTokens = new Set(options.canaryTokens || []);
    this.systemPromptFingerprints = options.systemPromptFingerprints || [];
    this.blockOnPii = options.blockOnPii ?? false;
  }

  public registerCanaryToken(token: string): void {
    if (token && token.trim().length > 0) {
      this.canaryTokens.add(token.trim());
    }
  }

  public registerSystemFingerprint(phrase: string): void {
    if (phrase && phrase.trim().length > 0) {
      this.systemPromptFingerprints.push(phrase.trim());
    }
  }

  /**
   * Scans and sanitizes LLM output text
   */
  public inspect(output: string): ModelArmorResult {
    const violations: ModelViolation[] = [];
    let sanitized = output;

    // 1. Canary Token Leakage (CRITICAL)
    for (const canary of this.canaryTokens) {
      if (output.includes(canary)) {
        violations.push({
          type: 'CANARY_LEAK',
          description: `Internal canary token exfiltration detected`,
          severity: 'CRITICAL',
          redactedMatch: `[CANARY_TOKEN:${canary.substring(0, 4)}...]`,
        });
        sanitized = sanitized.split(canary).join('[PROTECTED_CANARY_REDACTED]');
      }
    }

    // 2. System Prompt Instruction Leakage
    for (const fingerprint of this.systemPromptFingerprints) {
      if (output.toLowerCase().includes(fingerprint.toLowerCase())) {
        violations.push({
          type: 'SYSTEM_PROMPT_LEAK',
          description: `Model output leaked system prompt instruction: "${fingerprint.substring(0, 30)}..."`,
          severity: 'HIGH',
          redactedMatch: '[SYSTEM_INSTRUCTION_LEAK]',
        });
        const escaped = fingerprint.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        sanitized = sanitized.replace(new RegExp(escaped, 'gi'), '[SYSTEM_INSTRUCTION_REDACTED]');
      }
    }

    // 3. Private Key Blocks
    const privateKeyRegex = /-----BEGIN\s+([A-Z\s]+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+([A-Z\s]+)?PRIVATE\s+KEY-----/g;
    if (privateKeyRegex.test(sanitized)) {
      violations.push({
        type: 'CREDENTIAL_EXPOSURE',
        description: 'Private cryptographic key block detected in model output',
        severity: 'CRITICAL',
        redactedMatch: '[PRIVATE_KEY_REDACTED]',
      });
      sanitized = sanitized.replace(privateKeyRegex, '[PRIVATE_KEY_REDACTED]');
    }

    // 4. API Keys & Authentication Tokens
    const credentialPatterns = [
      { name: 'OpenAI/Standard API Key', regex: /\bsk-[a-zA-Z0-9]{32,}\b/g },
      { name: 'AWS Access Key ID', regex: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g },
      { name: 'GitHub Personal Token', regex: /\bghp_[0-9a-zA-Z]{36}\b/g },
      { name: 'Sovereign Token', regex: /\bsov_[a-zA-Z0-9]{32,}\b/g },
      { name: 'Database Connection URI', regex: /(?:postgres|postgresql|mongodb(?:\+srv)?|mysql):\/\/[^\s:@]+:[^\s@]+@[^\s/]+/gi },
    ];

    for (const pat of credentialPatterns) {
      if (pat.regex.test(sanitized)) {
        violations.push({
          type: 'CREDENTIAL_EXPOSURE',
          description: `Exposed ${pat.name} detected in output`,
          severity: 'HIGH',
          redactedMatch: '[CREDENTIAL_REDACTED]',
        });
        sanitized = sanitized.replace(pat.regex, '[CREDENTIAL_REDACTED]');
      }
    }

    // 5. PII: Social Security Numbers
    const ssnRegex = /\b\d{3}-\d{2}-\d{4}\b/g;
    if (ssnRegex.test(sanitized)) {
      violations.push({
        type: 'PII_EXPOSURE',
        description: 'US Social Security Number pattern detected',
        severity: 'HIGH',
        redactedMatch: '[SSN_REDACTED]',
      });
      sanitized = sanitized.replace(ssnRegex, '[SSN_REDACTED]');
    }

    // 6. PII: Credit Card Numbers (Luhn Check)
    const ccRegex = /\b(?:\d[ -]*?){13,16}\b/g;
    const ccMatches = sanitized.match(ccRegex) || [];
    for (const rawCard of ccMatches) {
      const cleanNum = rawCard.replace(/\D/g, '');
      if (cleanNum.length >= 13 && cleanNum.length <= 16 && this.passesLuhnCheck(cleanNum)) {
        violations.push({
          type: 'PII_EXPOSURE',
          description: 'Valid credit card PAN number detected in output',
          severity: 'HIGH',
          redactedMatch: '[CARD_NUMBER_REDACTED]',
        });
        sanitized = sanitized.replace(rawCard, '[CARD_NUMBER_REDACTED]');
      }
    }

    // Determine Action
    const hasCritical = violations.some((v) => v.severity === 'CRITICAL');
    const hasCanary = violations.some((v) => v.type === 'CANARY_LEAK');

    let action: 'ALLOW' | 'REDACT' | 'BLOCK' = 'ALLOW';
    if (hasCanary) {
      action = 'BLOCK';
      sanitized = '[CRITICAL OUTPUT BLOCKED: CANARY EXFILTRATION PREVENTED]';
    } else if (hasCritical || (this.blockOnPii && violations.some((v) => v.type === 'PII_EXPOSURE'))) {
      action = 'BLOCK';
      sanitized = '[OUTPUT BLOCKED DUE TO SEVERE EXFILTRATION VIOLATIONS]';
    } else if (violations.length > 0) {
      action = 'REDACT';
    }

    return {
      clean: violations.length === 0,
      originalText: output,
      sanitizedText: sanitized,
      violations,
      action,
    };
  }

  /**
   * Luhn algorithm validation for credit card numbers
   */
  private passesLuhnCheck(cardNumber: string): boolean {
    let sum = 0;
    let shouldDouble = false;
    for (let i = cardNumber.length - 1; i >= 0; i--) {
      let digit = parseInt(cardNumber.charAt(i), 10);
      if (shouldDouble) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      shouldDouble = !shouldDouble;
    }
    return sum % 10 === 0;
  }
}
