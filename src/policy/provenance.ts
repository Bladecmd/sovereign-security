/**
 * Sovereign Security — Milestone Phase 2A & V1.1 Production Resilience
 * Security Decision Provenance & Policy Boundary Enforcement
 */

import { createHash } from 'node:crypto';
import { AuditService } from '../audit/audit-service.js';
import { StructuredLogger } from '../observability/logger.js';
import { globalMetrics } from '../observability/metrics.js';
import { PolicyEngine } from './engine.js';
import { SecurityDecisionInput, SecurityDecisionProvenance, PrecedenceChainEntry } from '../types/provenance.js';

export interface DecisionEvaluatorOptions {
  policyEngine?: PolicyEngine;
  auditService?: AuditService;
  logger?: StructuredLogger;
  policyVersion?: string;
  nodeId?: string;
}

export class SecurityDecisionPipeline {
  private policyEngine: PolicyEngine;
  private auditService?: AuditService;
  private logger?: StructuredLogger;
  private policyVersion: string;
  private nodeId: string;

  constructor(options: DecisionEvaluatorOptions = {}) {
    this.policyEngine = options.policyEngine || new PolicyEngine();
    this.auditService = options.auditService;
    this.logger = options.logger;
    this.policyVersion = options.policyVersion || '2.0.0-phase2a';
    this.nodeId = options.nodeId || `node-${process.pid || 'core-1'}`;
  }

  public evaluate(input: SecurityDecisionInput): SecurityDecisionProvenance {
    const startTime = performance.now();
    const correlationId = input.correlationId || `dec-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const decisionId = `decision-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const timestamp = new Date().toISOString();

    if (!input.actor?.id || !input.resource || !input.action) {
      throw new Error('Malformed policy input: actor, resource, and action are strictly mandatory');
    }

    let riskCategory = 'LOW';
    if (input.riskScore >= 90) riskCategory = 'CRITICAL';
    else if (input.riskScore >= 70) riskCategory = 'HIGH';
    else if (input.riskScore >= 40) riskCategory = 'MEDIUM';

    // Evaluate against policy engine with precedence chain
    const evalResult = this.policyEngine.evaluateWithPrecedence({
      actor: input.actor,
      resource: input.resource,
      action: input.action,
      context: input.context,
      riskScore: input.riskScore,
    });
    const policyResult = evalResult.decision;
    const precedenceChain: PrecedenceChainEntry[] = evalResult.chain;

    // Ruleset hash (SHA-256 of sorted active rules)
    const rulesetContent = this.policyEngine
      .getRules()
      .map(r => `${r.id}:${r.priority}`)
      .join(';');
    const rulesetHash = createHash('sha256').update(rulesetContent).digest('hex');

    // Input hash (SHA-256 of normalized input)
    const normalizedInput = JSON.stringify({
      actorId: input.actor.id,
      actorType: input.actor.type,
      resource: input.resource,
      action: input.action,
      riskScore: input.riskScore,
      context: input.context,
    });
    const inputHash = createHash('sha256').update(normalizedInput).digest('hex');

    const approvalRequired = policyResult.decision === 'REQUIRE_APPROVAL';
    let executionStatus: 'PENDING' | 'EXECUTED' | 'BLOCKED' | 'FAILED' = 'BLOCKED';

    if (policyResult.decision === 'ALLOW') {
      executionStatus = 'EXECUTED';
    } else if (policyResult.decision === 'REQUIRE_APPROVAL') {
      executionStatus = 'PENDING';
    } else {
      executionStatus = 'BLOCKED';
    }

    const actorIdentity = {
      id: input.actor.id,
      type: input.actor.type,
      roles: input.actor.roles,
      clearance: (input.actor.attributes?.clearance as string) || (input.actor.roles.includes('ADMIN') ? 'TOP_SECRET' : 'STANDARD'),
      riskScore: typeof input.actor.attributes?.riskScore === 'number' ? input.actor.attributes.riskScore : input.riskScore,
      authMethod: input.context.authMethod,
    };

    const approvalRequirements = {
      required: approvalRequired,
      requiredApprovers: policyResult.requiredApprovers,
    };

    // Calculate canonical signature
    const canonicalPayload = JSON.stringify({
      decisionId,
      actorId: actorIdentity.id,
      resource: input.resource,
      action: input.action,
      decision: policyResult.decision,
      reasonCode: policyResult.reason,
      inputHash,
      rulesetHash,
      timestamp,
      nodeId: this.nodeId,
    });
    const signature = createHash('sha256').update(canonicalPayload).digest('hex');

    const provenance: SecurityDecisionProvenance = {
      // 1. decision_id
      decision_id: decisionId,
      decisionId,

      // 2. timestamp
      timestamp,

      // 3. policy_version
      policy_version: this.policyVersion,

      // 4. ruleset_hash
      ruleset_hash: rulesetHash,

      // 5. matched_rule_id
      matched_rule_id: policyResult.ruleId,

      // 6. input_hash
      input_hash: inputHash,

      // 7. actor_identity
      actor_identity: actorIdentity,
      actor: actorIdentity,

      // 8. action_requested
      action_requested: input.action,
      action: input.action,

      // 9. resource_targeted
      resource_targeted: input.resource,
      resource: input.resource,

      // 10. context_attributes
      context_attributes: input.context,
      context: input.context,

      // 11. risk_score_at_decision
      risk_score_at_decision: input.riskScore,
      riskEvaluation: {
        inputRiskScore: input.riskScore,
        riskCategory,
        calculatedAt: timestamp,
      },

      // 12. adversarial_signals_detected
      adversarial_signals_detected: input.adversarialSignals || [],

      // 13. decision
      decision: policyResult.decision,

      // 14. rationale
      rationale: policyResult.reason,
      reasonCode: policyResult.reason,

      // 15. precedence_chain
      precedence_chain: precedenceChain,

      // 16. approval_requirements
      approval_requirements: approvalRequirements,
      approvalRequirements,

      // 17. containment_action_taken
      containment_action_taken: input.containmentAction,

      // 18. audit_event_id
      audit_event_id: correlationId,
      correlationId,

      // 19. evaluator_node_id
      evaluator_node_id: input.nodeId || this.nodeId,

      // 20. signature
      signature,
      cryptographicSignature: signature,

      // Legacy structured fields
      policyEvaluation: {
        ruleEvaluated: policyResult.ruleId,
        priority: precedenceChain.find(c => c.matched)?.priority,
        policyVersion: this.policyVersion,
      },
      executionStatus,
    };

    const duration = performance.now() - startTime;
    globalMetrics.incrementCounter('sovereign_policy_evaluations_total');
    globalMetrics.incrementCounter('sovereign_policy_decisions_total', 1, { outcome: policyResult.decision });
    globalMetrics.observeHistogram('sovereign_policy_evaluation_duration_ms', duration);

    if (this.auditService) {
      this.auditService.append({
        who: input.actor.id,
        what: `DECISION:${policyResult.decision}:${input.action}`,
        where: input.resource,
        why: policyResult.reason,
        result: policyResult.decision === 'ALLOW' ? 'SUCCESS' : 'DENIED',
        details: {
          decisionId,
          correlationId,
          ruleEvaluated: policyResult.ruleId,
          riskScore: input.riskScore,
          signature: provenance.signature,
          inputHash,
          rulesetHash,
        },
      });
    }

    if (this.logger) {
      this.logger.info(
        provenance.actor.id,
        `decision:${policyResult.decision}`,
        correlationId,
        policyResult.decision === 'ALLOW' ? 'SUCCESS' : 'FAILURE',
        { decisionId, action: input.action, resource: input.resource, rule: policyResult.ruleId }
      );
    }

    return provenance;
  }

  public getPolicyEngine(): PolicyEngine {
    return this.policyEngine;
  }
}
