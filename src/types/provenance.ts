/**
 * Sovereign Security — Milestone Phase 2A
 * Security Decision Provenance Contracts
 */

import { IdentitySubject } from './identity.js';
import { PolicyContext, PolicyDecisionType } from './policy.js';

export interface SecurityDecisionProvenance {
  decisionId: string;
  correlationId: string;
  timestamp: string;
  actor: {
    id: string;
    type: string;
    roles: string[];
    riskScore: number;
    authMethod?: string;
  };
  resource: string;
  action: string;
  context: PolicyContext;
  riskEvaluation: {
    inputRiskScore: number;
    riskCategory: string;
    calculatedAt: string;
  };
  policyEvaluation: {
    ruleEvaluated?: string;
    priority?: number;
    policyVersion: string;
  };
  decision: PolicyDecisionType;
  reasonCode: string;
  approvalRequirements?: {
    required: boolean;
    requiredApprovers?: string[];
    approvedBy?: string;
    approvedAt?: string;
  };
  executionStatus: 'PENDING' | 'EXECUTED' | 'BLOCKED' | 'FAILED';
  cryptographicSignature?: string;
}

export interface SecurityDecisionInput {
  actor: IdentitySubject;
  resource: string;
  action: string;
  context: PolicyContext;
  riskScore: number;
  correlationId?: string;
}
