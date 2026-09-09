/**
 * Sovereign Security — Foundation V0.1
 * SecurityAlert Runtime Zod Schema & Validation
 */

import { z } from 'zod';
import { SecurityCategorySchema, SecuritySeveritySchema } from './event.schema.js';

export const AlertStatusSchema = z.enum([
  'OPEN',
  'ACKNOWLEDGED',
  'INVESTIGATING',
  'CONTAINED',
  'RESOLVED',
  'FALSE_POSITIVE',
]);

export const SecurityAlertSchema = z.object({
  alertId: z.string().min(1, 'alertId cannot be empty'),
  createdAt: z.string().datetime({ message: 'createdAt must be a valid ISO 8601 string' }),
  severity: SecuritySeveritySchema,
  category: SecurityCategorySchema,
  title: z.string().min(1, 'title is required'),
  description: z.string().min(1, 'description is required'),
  sourceEventIds: z.array(z.string()).min(1, 'At least one source event ID is required'),
  affectedResource: z.string().min(1, 'affectedResource is required'),
  riskScore: z.number().min(0).max(100, 'riskScore must be between 0 and 100'),
  status: AlertStatusSchema.default('OPEN'),
  assignedTo: z.string().optional(),
  resolution: z.string().optional(),
  resolvedAt: z.string().datetime().optional(),
});

export type SecurityAlertParsed = z.infer<typeof SecurityAlertSchema>;

export function validateSecurityAlert(input: unknown): SecurityAlertParsed {
  return SecurityAlertSchema.parse(input);
}

export function safeValidateSecurityAlert(input: unknown) {
  return SecurityAlertSchema.safeParse(input);
}
