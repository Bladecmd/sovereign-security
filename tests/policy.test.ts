/**
 * Sovereign Security — Foundation V0.1
 * Policy Engine Tests
 *
 * Covers: ALLOW, DENY, REQUIRE_APPROVAL, ESCALATE
 */

import assert from 'node:assert/strict';
import test, { beforeEach, describe } from 'node:test';
import { PolicyEngine } from '../src/policy/engine.js';
import {
  MOCK_ADMIN_SUBJECT,
  MOCK_EXECUTIVE_SUBJECT,
  MOCK_VEGA_AGENT_SUBJECT,
} from './fixtures/test-events.js';

describe('Policy Engine Multi-Tier Evaluation', () => {
  let engine: PolicyEngine;

  beforeEach(() => {
    engine = new PolicyEngine();
  });

  test('ALLOW: Standard read request by authorized subject', () => {
    const decision = engine.evaluate({
      actor: MOCK_ADMIN_SUBJECT,
      resource: 'api/v1/telemetry/metrics',
      action: 'read_metrics',
      context: {
        environment: 'staging',
        timestamp: new Date().toISOString(),
      },
      riskScore: 15,
    });

    assert.equal(decision.decision, 'ALLOW');
  });

  test('DENY: Blocks request exceeding extreme risk threshold (>= 90)', () => {
    const decision = engine.evaluate({
      actor: MOCK_ADMIN_SUBJECT,
      resource: 'api/v1/iam/roles',
      action: 'grant_full_admin',
      context: {
        environment: 'staging',
        timestamp: new Date().toISOString(),
      },
      riskScore: 95,
    });

    assert.equal(decision.decision, 'DENY');
    assert.match(decision.reason, /exceeds maximum permissible threshold/i);
    assert.equal(decision.ruleId, 'RULE_EXTREME_RISK_BLOCK');
  });

  test('REQUIRE_APPROVAL: Demands dual approval for sensitive financial or destructive actions', () => {
    const decision = engine.evaluate({
      actor: MOCK_ADMIN_SUBJECT,
      resource: 'vault/billing/disbursements',
      action: 'execute_fund_transfer',
      context: {
        environment: 'production',
        timestamp: new Date().toISOString(),
      },
      riskScore: 50,
    });

    assert.equal(decision.decision, 'REQUIRE_APPROVAL');
    assert.ok(decision.requiredApprovers?.includes('EXECUTIVE_APPROVER'));
  });

  test('ESCALATE: Escalates high-risk operations in production environment to Executive desk', () => {
    const decision = engine.evaluate({
      actor: MOCK_EXECUTIVE_SUBJECT,
      resource: 'cluster/nodes/production',
      action: 'read_extended_audit_stream',
      context: {
        environment: 'production',
        timestamp: new Date().toISOString(),
      },
      riskScore: 82, // >= 75 in production
    });

    assert.equal(decision.decision, 'ESCALATE');
    assert.equal(decision.escalationTarget, 'EXECUTIVE_SECURITY_DESK');
  });

  test('DENY: Prohibits restricted actions attempted by AI agent (least privilege)', () => {
    const decision = engine.evaluate({
      actor: MOCK_VEGA_AGENT_SUBJECT,
      resource: 'db/production/users',
      action: 'delete_production_data',
      context: {
        environment: 'production',
        timestamp: new Date().toISOString(),
      },
      riskScore: 40,
    });

    assert.equal(decision.decision, 'DENY');
    assert.match(decision.reason, /prohibited for role 'AGENT'/i);
  });
});
