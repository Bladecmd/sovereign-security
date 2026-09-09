/**
 * Sovereign Security — Foundation V0.1
 * SecurityEvent Runtime Zod Schema & Validation
 */

import { z } from 'zod';

export const SecuritySeveritySchema = z.enum(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

export const SecurityCategorySchema = z.enum([
  'IDENTITY',
  'AUTHENTICATION',
  'AUTHORIZATION',
  'API',
  'INFRASTRUCTURE',
  'APPLICATION',
  'DATA',
  'SECRETS',
  'AI_SECURITY',
  'DEPLOYMENT',
  'AUDIT',
]);

export const SecurityResultSchema = z.enum(['SUCCESS', 'FAILURE', 'DENIED', 'PENDING', 'ERROR']);

export const VerificationStatusSchema = z.enum(['UNVERIFIED', 'VERIFIED', 'TAMPERED']);

export const SecurityEventSchema = z.object({
  eventId: z.string().min(1, 'eventId cannot be empty'),
  timestamp: z.string().datetime({ message: 'timestamp must be a valid ISO 8601 string' }),
  source: z.string().min(1, 'source identifier is required'),
  businessId: z.string().min(1, 'businessId is required'),
  environment: z.string().min(1, 'environment is required'),
  severity: SecuritySeveritySchema,
  category: SecurityCategorySchema,
  eventType: z.string().min(1, 'eventType is required'),
  actorId: z.string().min(1, 'actorId is required'),
  resourceId: z.string().min(1, 'resourceId is required'),
  action: z.string().min(1, 'action is required'),
  result: SecurityResultSchema,
  riskScore: z.number().min(0).max(100, 'riskScore must be between 0 and 100'),
  verificationStatus: VerificationStatusSchema.default('UNVERIFIED'),
  metadata: z.record(z.unknown()).default({}),
  correlationId: z.string().min(1, 'correlationId is required'),
});

export type SecurityEventParsed = z.infer<typeof SecurityEventSchema>;

export function validateSecurityEvent(input: unknown): SecurityEventParsed {
  return SecurityEventSchema.parse(input);
}

export function safeValidateSecurityEvent(input: unknown) {
  return SecurityEventSchema.safeParse(input);
}
