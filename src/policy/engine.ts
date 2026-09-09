/**
 * Sovereign Security — Foundation V0.1
 * Policy Engine Implementation
 * Evaluates actor, resource, action, context, and risk independently from any UI.
 */

import { IdentityAccessEvaluator } from '../identity/rbac.js';
import { Permission } from '../types/identity.js';
import { PolicyDecision, PolicyEvaluationInput, PolicyRule } from '../types/policy.js';

export class PolicyEngine {
  private rules: PolicyRule[] = [];

  constructor() {
    this.registerDefaultRules();
  }

  /**
   * Register a custom policy rule
   */
  public registerRule(rule: PolicyRule): void {
    this.rules.push(rule);
    // Sort descending by priority: highest priority evaluated first
    this.rules.sort((a, b) => b.priority - a.priority);
  }

  /**
   * Clear or reset rules
   */
  public resetRules(): void {
    this.rules = [];
    this.registerDefaultRules();
  }

  /**
   * Evaluate a requested action against all registered policy rules and identity constraints
   */
  public evaluate(input: PolicyEvaluationInput): PolicyDecision {
    const timestamp = new Date().toISOString();

    // 1. Iterate through registered prioritized rules
    for (const rule of this.rules) {
      const decision = rule.evaluate(input);
      if (decision) {
        return decision;
      }
    }

    // 2. Default Zero-Trust Fallback: If no rule permits or matches, deny.
    return {
      decision: 'DENY',
      reason: 'Default zero-trust policy deny: no policy rule explicitly permitted this action.',
      evaluatedAt: timestamp,
    };
  }

  private registerDefaultRules(): void {
    // Rule 1: Extreme Risk Blocker (Priority: 100)
    this.registerRule({
      id: 'RULE_EXTREME_RISK_BLOCK',
      name: 'Extreme Risk Blocker',
      description: 'Automatically blocks any request with a riskScore of 90 or above',
      priority: 100,
      evaluate: (input) => {
        if (input.riskScore >= 90) {
          return {
            decision: 'DENY',
            reason: `Risk score (${input.riskScore}) exceeds maximum permissible threshold (90).`,
            ruleId: 'RULE_EXTREME_RISK_BLOCK',
            evaluatedAt: new Date().toISOString(),
          };
        }
        return null;
      },
    });

    // Rule 2: High Risk Escalation in Production (Priority: 80)
    this.registerRule({
      id: 'RULE_PROD_HIGH_RISK_ESCALATE',
      name: 'Production High Risk Escalation',
      description: 'Escalates high-risk operations (>= 75) executing in production environments',
      priority: 80,
      evaluate: (input) => {
        if (input.context.environment === 'production' && input.riskScore >= 75) {
          return {
            decision: 'ESCALATE',
            reason: `High risk score (${input.riskScore}) in production environment warrants executive escalation.`,
            ruleId: 'RULE_PROD_HIGH_RISK_ESCALATE',
            escalationTarget: 'EXECUTIVE_SECURITY_DESK',
            evaluatedAt: new Date().toISOString(),
          };
        }
        return null;
      },
    });

    // Rule 3: Sensitive Action Approval Requirement (Priority: 70)
    this.registerRule({
      id: 'RULE_SENSITIVE_ACTION_APPROVAL',
      name: 'Sensitive Action Approval Requirement',
      description: 'Requires human-in-the-loop dual approval for destructive or high-impact actions',
      priority: 70,
      evaluate: (input) => {
        const sensitiveActions = [
          'delete_production_database',
          'execute_fund_transfer',
          'revoke_security_certificates',
          'modify_iam_policy',
          'deploy_destructive_infrastructure',
        ];

        if (sensitiveActions.includes(input.action)) {
          return {
            decision: 'REQUIRE_APPROVAL',
            reason: `Action '${input.action}' is classified as sensitive and mandates authorized approval.`,
            ruleId: 'RULE_SENSITIVE_ACTION_APPROVAL',
            requiredApprovers: ['SECURITY_ADMIN', 'EXECUTIVE_APPROVER'],
            evaluatedAt: new Date().toISOString(),
          };
        }
        return null;
      },
    });

    // Rule 4: RBAC & Prohibited Actions Validation (Priority: 50)
    this.registerRule({
      id: 'RULE_RBAC_VERIFICATION',
      name: 'Role-Based Access Control Verification',
      description: 'Enforces least-privilege role permissions and prohibits restricted actions',
      priority: 50,
      evaluate: (input) => {
        // Map common action types to conceptual permissions
        let requiredPermission: Permission = 'READ';
        const actionLower = input.action.toLowerCase();

        if (
          actionLower.startsWith('admin') ||
          actionLower.includes('grant') ||
          actionLower.includes('revoke')
        ) {
          requiredPermission = 'ADMINISTER';
        } else if (
          actionLower.startsWith('write') ||
          actionLower.startsWith('create') ||
          actionLower.startsWith('update')
        ) {
          requiredPermission = 'WRITE';
        } else if (
          actionLower.startsWith('delete') ||
          actionLower.startsWith('exec') ||
          actionLower.startsWith('run') ||
          actionLower.startsWith('deploy')
        ) {
          requiredPermission = 'EXECUTE';
        } else if (actionLower.startsWith('certify') || actionLower.startsWith('approve')) {
          requiredPermission = 'CERTIFY';
        }

        const permCheck = IdentityAccessEvaluator.hasPermission(
          input.actor,
          requiredPermission,
          input.action
        );

        if (!permCheck.granted) {
          return {
            decision: 'DENY',
            reason: permCheck.reason,
            ruleId: 'RULE_RBAC_VERIFICATION',
            evaluatedAt: new Date().toISOString(),
          };
        }

        return null; // Proceed to standard allow
      },
    });

    // Rule 5: Standard Allow for Authorized Operations (Priority: 10)
    this.registerRule({
      id: 'RULE_AUTHORIZED_ALLOW',
      name: 'Authorized Standard Allow',
      description: 'Allows verified actions that have satisfied all RBAC and risk controls',
      priority: 10,
      evaluate: (input) => {
        return {
          decision: 'ALLOW',
          reason: `Action '${input.action}' on resource '${input.resource}' verified and permitted.`,
          ruleId: 'RULE_AUTHORIZED_ALLOW',
          evaluatedAt: new Date().toISOString(),
        };
      },
    });
  }
}
