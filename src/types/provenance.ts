/**
 * Sovereign Security — Milestone Phase 2A & V1.1 Production Resilience
 * Security Decision Provenance Contracts
 *
 * Implements the full 20-attribute cryptographic provenance schema for zero-trust traceability.
 */

import { IdentitySubject } from './identity.js';
import { PolicyContext, PolicyDecisionType } from './policy.js';

export interface PrecedenceChainEntry {
  ruleId: string;
  name: string;
  priority: number;
  matched: boolean;
  outcome?: string;
}

export interface SecurityDecisionProvenance {
  // 1. decision_id
  decision_id: string;
  decisionId: string; // backwards-compatible alias

  // 2. timestamp (ISO 8601 UTC)
  timestamp: string;

  // 3. policy_version
  policy_version: string;

  // 4. ruleset_hash (SHA-256 of active ruleset)
  ruleset_hash: string;

  // 5. matched_rule_id
  matched_rule_id?: string;

  // 6. input_hash (SHA-256 of normalized input)
  input_hash: string;

  // 7. actor_identity
  actor_identity: {
    id: string;
    type: string;
    roles: string[];
    clearance?: string;
    riskScore: number;
    authMethod?: string;
  };
  actor: {
    id: string;
    type: string;
    roles: string[];
    riskScore: number;
    authMethod?: string;
  }; // backwards-compatible alias

  // 8. action_requested
  action_requested: string;
  action: string; // backwards-compatible alias

  // 9. resource_targeted
  resource_targeted: string;
  resource: string; // backwards-compatible alias

  // 10. context_attributes
  context_attributes: PolicyContext;
  context: PolicyContext; // backwards-compatible alias

  // 11. risk_score_at_decision
  risk_score_at_decision: number;
  riskEvaluation: {
    inputRiskScore: number;
    riskCategory: string;
    calculatedAt: string;
  }; // backwards-compatible alias

  // 12. adversarial_signals_detected
  adversarial_signals_detected: string[];

  // 13. decision (ALLOW, DENY, REQUIRE_APPROVAL, ESCALATE)
  decision: PolicyDecisionType;

  // 14. rationale
  rationale: string;
  reasonCode: string; // backwards-compatible alias

  // 15. precedence_chain (rules evaluated in order with outcome)
  precedence_chain: PrecedenceChainEntry[];

  // 16. approval_requirements
  approval_requirements?: {
    required: boolean;
    requiredApprovers?: string[];
    approvedBy?: string;
    approvedAt?: string;
  };
  approvalRequirements?: {
    required: boolean;
    requiredApprovers?: string[];
    approvedBy?: string;
    approvedAt?: string;
  }; // backwards-compatible alias

  // 17. containment_action_taken
  containment_action_taken?: string;

  // 18. audit_event_id
  audit_event_id?: string;
  correlationId: string; // backwards-compatible alias

  // 19. evaluator_node_id
  evaluator_node_id: string;

  // 20. signature
  signature: string;
  cryptographicSignature?: string; // backwards-compatible alias

  // Legacy structured fields
  policyEvaluation: {
    ruleEvaluated?: string;
    priority?: number;
    policyVersion: string;
  };
  executionStatus: 'PENDING' | 'EXECUTED' | 'BLOCKED' | 'FAILED';
}

export interface SecurityDecisionInput {
  actor: IdentitySubject;
  resource: string;
  action: string;
  context: PolicyContext;
  riskScore: number;
  correlationId?: string;
  adversarialSignals?: string[];
  containmentAction?: string;
  nodeId?: string;
}
