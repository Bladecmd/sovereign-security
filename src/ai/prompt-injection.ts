/**
 * Sovereign Security — Milestone V0.6
 * Multi-Layer Prompt Injection & Jailbreak Defense Engine
 */

import {
  PromptInjectionCategory,
  PromptInjectionResult,
  PromptInjectionRiskLevel,
} from '../types/ai-gateway.js';

interface PatternRule {
  category: PromptInjectionCategory;
  name: string;
  regex: RegExp;
  weight: number;
}

export class PromptInjectionDetector {
  private rules: PatternRule[] = [];

  constructor() {
    this.initializeRules();
  }

  private initializeRules(): void {
    // 1. Direct System & Instruction Overrides
    this.rules.push(
      {
        category: 'DIRECT_OVERRIDE',
        name: 'ignore_instructions',
        regex: /(ignore|disregard|forget|skip)\s+(?:(?:all|any|the|previous|prior|above|existing)\s+)*(?:instructions|prompts|directions|rules|guidelines)/i,
        weight: 0.9,
      },
      {
        category: 'DIRECT_OVERRIDE',
        name: 'system_override',
        regex: /(system\s+override|system_override|override\s+system)\s*[:=]?\s*(disable|bypass|ignore|elevate|admin)/i,
        weight: 0.95,
      },
      {
        category: 'DIRECT_OVERRIDE',
        name: 'bypass_safety_guardrails',
        regex: /(bypass|disable|turn\s*off)\s+(?:(?:all|any|the)\s+)*(?:security|safety|content|authorization)\s*(filters|checks|protocols|guardrails|rules)/i,
        weight: 0.9,
      },
      {
        category: 'DIRECT_OVERRIDE',
        name: 'unbound_freedom',
        regex: /(you\s+are\s+no\s+longer\s+bound\s+by|free\s+from\s+all\s+constraints)/i,
        weight: 0.85,
      }
    );

    // 2. Delimiter Hijacking & Format Mimicry
    this.rules.push(
      {
        category: 'DELIMITER_HIJACK',
        name: 'chatml_tokens',
        regex: /(<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>)/i,
        weight: 0.95,
      },
      {
        category: 'DELIMITER_HIJACK',
        name: 'inst_sys_tokens',
        regex: /(\[INST\]|\[\/INST\]|\[SYSTEM\]|\[\/SYSTEM\]|<<SYS>>|<<\/SYS>>)/i,
        weight: 0.9,
      },
      {
        category: 'DELIMITER_HIJACK',
        name: 'comment_system_spoof',
        regex: /(<!--\s*system\s*-->|<!--\s*#system\s*-->|\[\[system\]\])/i,
        weight: 0.85,
      },
      {
        category: 'DELIMITER_HIJACK',
        name: 'raw_role_markers',
        regex: /(###\s*(System|Human|Assistant|Developer)\s*:|(?:^|\n)\s*(System|Human|Assistant|Developer)\s*:\s*)/im,
        weight: 0.85,
      }
    );

    // 3. Instruction Hierarchy & Authority Impersonation
    this.rules.push(
      {
        category: 'INSTRUCTION_HIERARCHY',
        name: 'authority_impersonation',
        regex: /(?:i\s+am|speaking\s+as|acting\s+as)\s+(?:the\s+)?(?:root|system|chief|lead|senior|principal|security)\s+(?:system\s+)?(?:admin|administrator|developer|architect|officer)\b/i,
        weight: 0.9,
      },
      {
        category: 'INSTRUCTION_HIERARCHY',
        name: 'priority_override',
        regex: /(?:priority|supreme|critical|higher\s+priority)\s+(?:override|directive|instruction|system\s+update)\s*[:=]/i,
        weight: 0.9,
      },
      {
        category: 'INSTRUCTION_HIERARCHY',
        name: 'simulated_system_envelope',
        regex: /(?:<system>|<\/system>|<developer>|<\/developer>|\[system_instruction\]|\[admin_directive\])/i,
        weight: 0.9,
      },
      {
        category: 'INSTRUCTION_HIERARCHY',
        name: 'developer_override_authority',
        regex: /(?:developer\s+override|admin\s+mode\s+authorized|elevated\s+execution\s+context\s+granted)/i,
        weight: 0.9,
      }
    );

    // 4. Roleplay & Jailbreak Personas
    this.rules.push(
      {
        category: 'ROLEPLAY_JAILBREAK',
        name: 'dan_jailbreak',
        regex: /(do\s+anything\s+now|act\s+as\s+dan|simulate\s+dan|dan\s+mode)/i,
        weight: 0.95,
      },
      {
        category: 'ROLEPLAY_JAILBREAK',
        name: 'developer_mode_jailbreak',
        regex: /(you\s+are\s+now\s+in\s+developer\s+mode|enable\s+developer\s+mode|developer\s+mode\s+enabled)/i,
        weight: 0.9,
      },
      {
        category: 'ROLEPLAY_JAILBREAK',
        name: 'unrestricted_persona',
        regex: /(act\s+as\s+an?\s+(unrestricted|unfiltered|evil|jailbroken)\s+(ai|bot|assistant))/i,
        weight: 0.85,
      },
      {
        category: 'ROLEPLAY_JAILBREAK',
        name: 'hypothetical_evil_bypass',
        regex: /(hypothetical\s+scenario\s+where\s+you\s+have\s+no\s+(rules|ethics|limits))/i,
        weight: 0.8,
      }
    );

    // 5. System Prompt Extraction
    this.rules.push(
      {
        category: 'SYSTEM_PROMPT_EXTRACTION',
        name: 'extract_system_prompt',
        regex: /(repeat\s+(everything|the\s+words|all\s+instructions)\s+above|what\s+(is|was)\s+your\s+(original|initial|system)\s+(prompt|instructions)|repeat\s+everything\s+above\s+starting\s+from)/i,
        weight: 0.85,
      },
      {
        category: 'SYSTEM_PROMPT_EXTRACTION',
        name: 'print_internal_rules',
        regex: /(output|print|reveal|display|leak)\s+(your\s+)?(?:(?:internal|hidden|secret|developer|system|original|initial)\s+)*(?:prompt|rules|configuration|instructions|directives)/i,
        weight: 0.9,
      }
    );
  }

  /**
   * Helper: Normalize leetspeak substitutions
   */
  private normalizeLeetspeak(text: string): string {
    return text
      .replace(/0/g, 'o')
      .replace(/1/g, 'i')
      .replace(/3/g, 'e')
      .replace(/4/g, 'a')
      .replace(/5/g, 's')
      .replace(/7/g, 't')
      .replace(/@/g, 'a')
      .replace(/\$/g, 's');
  }

  /**
   * Helper: ROT13 decode
   */
  private decodeRot13(text: string): string {
    return text.replace(/[a-zA-Z]/g, (char) => {
      const start = char <= 'Z' ? 65 : 97;
      return String.fromCharCode(((char.charCodeAt(0) - start + 13) % 26) + start);
    });
  }

  /**
   * Helper: Inspect Base64 embedded payloads
   */
  private inspectBase64Payloads(text: string): { detected: boolean; decodedMatches: string[] } {
    const base64Regex = /\b[A-Za-z0-9+/]{20,}={0,2}\b/g;
    const matches = text.match(base64Regex);
    if (!matches) return { detected: false, decodedMatches: [] };

    const decodedMatches: string[] = [];
    for (const match of matches) {
      try {
        const decoded = Buffer.from(match, 'base64').toString('utf-8');
        // Check if decoded text resembles printable English text
        if (/^[\x20-\x7E\s]+$/.test(decoded)) {
          for (const rule of this.rules) {
            if (rule.regex.test(decoded)) {
              decodedMatches.push(`Base64 encoded "${rule.name}": "${decoded.substring(0, 50)}"`);
            }
          }
        }
      } catch {
        // Not valid base64 or decoding error
      }
    }

    return {
      detected: decodedMatches.length > 0,
      decodedMatches,
    };
  }

  /**
   * Primary evaluation entrypoint
   */
  public detect(prompt: string): PromptInjectionResult {
    const matchedPatterns: string[] = [];
    const detectedCategories = new Set<PromptInjectionCategory>();
    let maxWeight = 0;
    let weightSum = 0;

    // 1. Direct Pattern Inspection
    for (const rule of this.rules) {
      if (rule.regex.test(prompt)) {
        matchedPatterns.push(`direct:${rule.name}`);
        detectedCategories.add(rule.category);
        maxWeight = Math.max(maxWeight, rule.weight);
        weightSum += rule.weight;
      }
    }

    // 2. Leetspeak Normalization Check
    const normalizedLeet = this.normalizeLeetspeak(prompt);
    if (normalizedLeet !== prompt) {
      for (const rule of this.rules) {
        if (!rule.regex.test(prompt) && rule.regex.test(normalizedLeet)) {
          matchedPatterns.push(`leetspeak:${rule.name}`);
          detectedCategories.add(rule.category);
          maxWeight = Math.max(maxWeight, rule.weight * 0.9);
          weightSum += rule.weight * 0.9;
        }
      }
    }

    // 3. ROT13 Cipher Check
    const rot13Text = this.decodeRot13(prompt);
    for (const rule of this.rules) {
      if (rule.regex.test(rot13Text) && !rule.regex.test(prompt)) {
        matchedPatterns.push(`rot13:${rule.name}`);
        detectedCategories.add('OBFUSCATED_PAYLOAD');
        maxWeight = Math.max(maxWeight, rule.weight * 0.85);
        weightSum += rule.weight * 0.85;
      }
    }

    // 4. Base64 Obfuscation Check
    const base64Inspection = this.inspectBase64Payloads(prompt);
    if (base64Inspection.detected) {
      for (const match of base64Inspection.decodedMatches) {
        matchedPatterns.push(`obfuscated:${match}`);
      }
      detectedCategories.add('OBFUSCATED_PAYLOAD');
      maxWeight = Math.max(maxWeight, 0.95);
      weightSum += 0.95;
    }

    // Compute Confidence (0.0 to 1.0)
    const detected = matchedPatterns.length > 0;
    let confidence = 0;
    if (detected) {
      // Compound confidence formula: maxWeight + diminishing returns for additional matches
      confidence = Math.min(1.0, maxWeight + Math.min(0.2, (weightSum - maxWeight) * 0.1));
      confidence = Math.round(confidence * 100) / 100;
    }

    // Determine Risk Level
    let riskLevel: PromptInjectionRiskLevel = 'LOW';
    let action: 'ALLOW' | 'SANITIZE' | 'BLOCK' | 'ESCALATE' = 'ALLOW';

    if (confidence >= 0.85) {
      riskLevel = 'CRITICAL';
      action = 'BLOCK';
    } else if (confidence >= 0.65) {
      riskLevel = 'HIGH';
      action = 'BLOCK';
    } else if (confidence >= 0.4) {
      riskLevel = 'MEDIUM';
      action = 'SANITIZE';
    } else if (detected) {
      riskLevel = 'LOW';
      action = 'SANITIZE';
    }

    // Build Sanitized Prompt
    let sanitizedPrompt = prompt;
    if (action === 'SANITIZE') {
      // Neutralize delimiter hijacking tokens
      sanitizedPrompt = sanitizedPrompt
        .replace(/<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>/gi, '[STRIPPED_TOKEN]')
        .replace(/\[INST\]|\[\/INST\]|\[SYSTEM\]|\[\/SYSTEM\]|<<SYS>>|<<\/SYS>>/gi, '[STRIPPED_TOKEN]')
        .replace(/<!--\s*system\s*-->/gi, '[STRIPPED_COMMENT]');
    } else if (action === 'BLOCK') {
      sanitizedPrompt = '[BLOCKED: PROMPT INJECTION DETECTED]';
    }

    return {
      detected,
      confidence,
      riskLevel,
      matchedPatterns,
      detectedCategories: Array.from(detectedCategories),
      action,
      sanitizedPrompt,
    };
  }
}
