/**
 * Sovereign Security — Foundation V0.1
 * Policy Engine Runtime Zod Schemas
 */

import { z } from 'zod';

export const RoleSchema = z.enum(['ADMIN', 'EXECUTIVE', 'SYSTEM', 'AGENT', 'SERVICE']);

export const PermissionSchema = z.enum(['READ', 'WRITE', 'EXECUTE', 'CERTIFY', 'ADMINISTER']);

export const IdentitySubjectSchema = z.object({
  id: z.string().min(1, 'Subject id is required'),
  type: RoleSchema,
  name: z.string().min(1, 'Subject name is required'),
  roles: z.array(RoleSchema).min(1, 'Subject must possess at least one role'),
  explicitPermissions: z.array(PermissionSchema).optional(),
  organizationId: z.string().min(1, 'organizationId is required'),
  attributes: z.record(z.unknown()).optional(),
});

export const PolicyDecisionTypeSchema = z.enum(['ALLOW', 'DENY', 'REQUIRE_APPROVAL', 'ESCALATE']);

export const PolicyContextSchema = z.object({
  environment: z.string().min(1),
  ipAddress: z.string().optional(),
  timestamp: z.string().datetime(),
  authMethod: z.string().optional(),
  mfaVerified: z.boolean().optional(),
  businessContext: z.record(z.unknown()).optional(),
  metadata: z.record(z.unknown()).optional(),
});

export const PolicyEvaluationInputSchema = z.object({
  actor: IdentitySubjectSchema,
  resource: z.string().min(1, 'Resource URI or ID is required'),
  action: z.string().min(1, 'Action is required'),
  context: PolicyContextSchema,
  riskScore: z.number().min(0).max(100),
});

export const PolicyDecisionSchema = z.object({
  decision: PolicyDecisionTypeSchema,
  reason: z.string().min(1),
  ruleId: z.string().optional(),
  evaluatedAt: z.string().datetime(),
  requiredApprovers: z.array(z.string()).optional(),
  escalationTarget: z.string().optional(),
  metadata: z.record(z.unknown()).optional(),
});
