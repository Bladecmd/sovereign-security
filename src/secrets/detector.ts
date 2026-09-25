/**
 * Sovereign Security — Foundation V0.1
 * Secrets Detection & Redaction Service
 *
 * Scans strings and payloads for exposed credentials, private keys, and tokens.
 * Applies masking / redaction to prevent secret leakage into logs or telemetry.
 */

import {
  CredentialRotationReminder,
  SecretClassification,
  SecretDetectionResult,
  SecretExposureEvent,
} from '../types/secrets.js';

interface SecretPattern {
  classification: SecretClassification;
  regex: RegExp;
  confidence: 'LOW' | 'MEDIUM' | 'HIGH';
  description: string;
}

export class SecretsDetector {
  private static readonly PATTERNS: SecretPattern[] = [
    {
      classification: 'PRIVATE_KEY',
      regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/i,
      confidence: 'HIGH',
      description: 'Asymmetric Private Key block',
    },
    {
      classification: 'API_KEY',
      regex: /(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})['"]?/i,
      confidence: 'HIGH',
      description: 'API Key assignment or parameter',
    },
    {
      classification: 'JWT_SECRET',
      regex: /ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/,
      confidence: 'HIGH',
      description: 'JSON Web Token (JWT)',
    },
    {
      classification: 'DATABASE_CREDENTIAL',
      regex: /(?:postgres|mysql|mongodb|redis):\/\/[^:\s]+:([^@\s]+)@/i,
      confidence: 'HIGH',
      description: 'Database Connection String with embedded password',
    },
    {
      classification: 'GENERIC_PASSWORD',
      regex: /(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]{8,})['"]?/i,
      confidence: 'MEDIUM',
      description: 'Password assignment',
    },
  ];

  /**
   * Scan text content for potential secrets
   */
  public static scanText(text: string, sourceName = 'unknown'): SecretDetectionResult {
    for (const pattern of this.PATTERNS) {
      const match = pattern.regex.exec(text);
      if (match) {
        const rawMatched = match[0];
        const snippetMasked = this.maskSecretSnippet(rawMatched);

        return {
          detected: true,
          classification: pattern.classification,
          confidence: pattern.confidence,
          location: {
            source: sourceName,
            snippetMasked,
          },
        };
      }
    }

    return {
      detected: false,
      confidence: 'LOW',
      location: {
        source: sourceName,
        snippetMasked: '',
      },
    };
  }

  /**
   * Redact all sensitive fields and matched secrets from an object or payload
   */
  public static redactPayload(payload: unknown): unknown {
    if (payload === null || payload === undefined) {
      return payload;
    }

    if (typeof payload === 'string') {
      let sanitized = payload;
      for (const pattern of this.PATTERNS) {
        sanitized = sanitized.replace(pattern.regex, '[REDACTED_SECRET]');
      }
      return sanitized;
    }

    if (Array.isArray(payload)) {
      return payload.map((item) => this.redactPayload(item));
    }

    if (typeof payload === 'object') {
      const sensitiveKeySubstrings = [
        'password',
        'secret',
        'token',
        'apikey',
        'api_key',
        'privatekey',
        'private_key',
        'authorization',
        'credential',
      ];

      const result: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(payload as Record<string, unknown>)) {
        const isSensitiveKey = sensitiveKeySubstrings.some((sub) =>
          key.toLowerCase().includes(sub)
        );

        if (isSensitiveKey && typeof value === 'string') {
          result[key] = '[REDACTED]';
        } else {
          result[key] = this.redactPayload(value);
        }
      }
      return result;
    }

    return payload;
  }

  /**
   * Create a SecretExposureEvent from a detected leak
   */
  public static createExposureEvent(
    detection: SecretDetectionResult,
    affectedService: string,
    correlationId: string
  ): SecretExposureEvent {
    return {
      exposureId: `exposure-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      detectedAt: new Date().toISOString(),
      classification: detection.classification || 'API_KEY',
      severity: 'CRITICAL',
      sourceLocation: detection.location.source,
      affectedService,
      recommendedAction:
        'Immediately revoke and rotate the exposed credential. Audit recent access logs.',
      correlationId,
    };
  }

  /**
   * Generate credential rotation reminders
   */
  public static checkRotationStatus(
    credentialId: string,
    service: string,
    classification: SecretClassification,
    lastRotatedDate: Date,
    maxAgeDays = 90
  ): CredentialRotationReminder {
    const now = new Date().getTime();
    const lastRotatedTime = lastRotatedDate.getTime();
    const elapsedDays = Math.floor((now - lastRotatedTime) / (1000 * 60 * 60 * 24));
    const daysRemaining = maxAgeDays - elapsedDays;
    const expiresAt = new Date(lastRotatedTime + maxAgeDays * 24 * 60 * 60 * 1000).toISOString();

    let status: 'CURRENT' | 'DUE_SOON' | 'OVERDUE' = 'CURRENT';
    if (daysRemaining <= 0) {
      status = 'OVERDUE';
    } else if (daysRemaining <= 14) {
      status = 'DUE_SOON';
    }

    return {
      credentialId,
      service,
      classification,
      lastRotatedAt: lastRotatedDate.toISOString(),
      expiresAt,
      daysRemaining,
      status,
    };
  }

  private static maskSecretSnippet(snippet: string): string {
    if (snippet.length <= 8) {
      return '****';
    }
    const prefix = snippet.substring(0, 4);
    const suffix = snippet.substring(snippet.length - 4);
    return `${prefix}****${suffix}`;
  }
}
