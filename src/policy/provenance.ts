/**
 * Sovereign Security — Milestone Phase 2A
 * Security Decision Provenance & Policy Boundary Enforcement
 */

import { createHash } from 'node:crypto';
import { AuditService } from '../audit/audit-service.js';
import { StructuredLogger } from '../observability/logger.js';
import { globalMetrics } from '../observability/metrics.js';
import { PolicyEngine } from './engine.js';
import { SecurityDecisionInput, SecurityDecisionProvenance } from '../types/provenance.js';

export interface DecisionEvaluatorOptions {
  policyEngine?: PolicyEngine;
  auditService?: AuditService;
  logger?: StructuredLogger;
  policyVersion?: string;
}

export class SecurityDecisionPipeline {
  private policyEngine: PolicyEngine;
  private auditService?: AuditService;
  private logger?: StructuredLogger;
  private policyVersion: string;

  constructor(options: DecisionEvaluatorOptions = {}) {
    this.policyEngine = options.policyEngine || new PolicyEngine();
    this.auditService = options.auditService;
    this.logger = options.logger;
    this.policyVersion = options.policyVersion || '2.0.0-phase2a';
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

    const policyResult = this.policyEngine.evaluate({
      actor: input.actor,
      resource: input.resource,
      action: input.action,
      context: input.context,
      riskScore: input.riskScore,
    });

    const approvalRequired = policyResult.decision === 'REQUIRE_APPROVAL';
    let executionStatus: 'PENDING' | 'EXECUTED' | 'BLOCKED' | 'FAILED' = 'BLOCKED';

    if (policyResult.decision === 'ALLOW') {
      executionStatus = 'EXECUTED';
    } else if (policyResult.decision === 'REQUIRE_APPROVAL') {
      executionStatus = 'PENDING';
    } else {
      executionStatus = 'BLOCKED';
    }

    const provenance: SecurityDecisionProvenance = {
      decisionId,
      correlationId,
      timestamp,
      actor: {
        id: input.actor.id,
        type: input.actor.type,
        roles: input.actor.roles,
        riskScore: typeof input.actor.attributes?.riskScore === 'number' ? input.actor.attributes.riskScore : input.riskScore,
        authMethod: input.context.authMethod,
      },
      resource: input.resource,
      action: input.action,
      context: input.context,
      riskEvaluation: {
        inputRiskScore: input.riskScore,
        riskCategory,
        calculatedAt: timestamp,
      },
      policyEvaluation: {
        ruleEvaluated: policyResult.ruleId,
        policyVersion: this.policyVersion,
      },
      decision: policyResult.decision,
      reasonCode: policyResult.reason,
      approvalRequirements: {
        required: approvalRequired,
        requiredApprovers: policyResult.requiredApprovers,
      },
      executionStatus,
    };

    const canonicalPayload = JSON.stringify({
      decisionId: provenance.decisionId,
      actorId: provenance.actor.id,
      resource: provenance.resource,
      action: provenance.action,
      decision: provenance.decision,
      reasonCode: provenance.reasonCode,
      timestamp: provenance.timestamp,
    });
    provenance.cryptographicSignature = createHash('sha256').update(canonicalPayload).digest('hex');

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
          signature: provenance.cryptographicSignature,
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
