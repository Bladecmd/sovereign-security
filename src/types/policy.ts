/**
 * Sovereign Security — Foundation V0.1
 * Policy Engine Abstraction & Types
 */

import { IdentitySubject } from './identity.js';

export type PolicyDecisionType = 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL' | 'ESCALATE';

export interface PolicyContext {
  environment: string;
  ipAddress?: string;
  timestamp: string;
  authMethod?: string;
  mfaVerified?: boolean;
  businessContext?: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

export interface PolicyEvaluationInput {
  actor: IdentitySubject;
  resource: string;
  action: string;
  context: PolicyContext;
  riskScore: number;
}

export interface PolicyRule {
  id: string;
  name: string;
  description: string;
  priority: number; // Higher numbers evaluated first
  evaluate: (input: PolicyEvaluationInput) => PolicyDecision | null;
}

export interface PolicyDecision {
  decision: PolicyDecisionType;
  reason: string;
  ruleId?: string;
  evaluatedAt: string;
  requiredApprovers?: string[];
  escalationTarget?: string;
  metadata?: Record<string, unknown>;
}
