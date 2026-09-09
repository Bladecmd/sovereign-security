/**
 * Sovereign Security — Foundation V0.1
 * Sovereign OS Integration Adapter Tests
 */

import assert from 'node:assert/strict';
import test, { beforeEach, describe } from 'node:test';
import { SovereignSecurityClient } from '../src/integrations/sovereign-os/client.js';
import {
  MOCK_ADMIN_SUBJECT,
  MOCK_VEGA_AGENT_SUBJECT,
} from './fixtures/test-events.js';

describe('Sovereign OS Integration Client Adapter', () => {
  let client: SovereignSecurityClient;

  beforeEach(() => {
    client = new SovereignSecurityClient({
      sourceId: 'sovereign-os',
      environment: 'production',
    });
  });

  test('emitSecurityEvent(): Ingests valid event and calculates risk if needed', async () => {
    const result = await client.emitSecurityEvent({
      source: 'sovereign-os',
      businessId: 'biz-sovereign-01',
      environment: 'production',
      severity: 'LOW',
      category: 'APPLICATION',
      eventType: 'SYSTEM_HEALTH_CHECK',
      actorId: 'sovereign-daemon',
      resourceId: 'service/health',
      action: 'ping',
      result: 'SUCCESS',
      riskScore: 0, // Auto-calculated
      metadata: { uptimeSeconds: 3600 },
      correlationId: 'corr-health-01',
    });

    assert.ok(result.event.eventId.startsWith('sec-evt-'));
    assert.equal(result.event.result, 'SUCCESS');
    assert.ok(result.event.riskScore >= 0);
  });

  test('checkPolicy(): Evaluates business operations without internal coupling', async () => {
    const decision = await client.checkPolicy({
      actor: MOCK_ADMIN_SUBJECT,
      resource: 'api/v1/users',
      action: 'read_user_profile',
      context: {
        environment: 'production',
        timestamp: new Date().toISOString(),
      },
      riskScore: 20,
    });

    assert.equal(decision.decision, 'ALLOW');
  });

  test('reportSecurityAlert(): Validates and creates a SecurityAlert', async () => {
    const alert = await client.reportSecurityAlert({
      severity: 'MEDIUM',
      category: 'APPLICATION',
      title: 'High Latency Anomaly',
      description: 'API endpoint response duration exceeded threshold',
      sourceEventIds: ['evt-lat-01', 'evt-lat-02'],
      affectedResource: 'api/v1/metrics',
      riskScore: 45,
    });

    assert.ok(alert.alertId.startsWith('alert-'));
    assert.equal(alert.status, 'OPEN');
    assert.equal(alert.severity, 'MEDIUM');
  });

  test('checkAgentPermission(): Evaluates VEGA agent tool permissions', async () => {
    // VEGA reading telemetry -> ALLOW
    const allowed = await client.checkAgentPermission('vega', 'read_business_telemetry');
    assert.equal(allowed.decision, 'ALLOW');

    // VEGA transferring funds -> DENY
    const denied = await client.checkAgentPermission('vega', 'transfer_funds');
    assert.equal(denied.decision, 'DENY');
  });

  test('recordAuditEvent(): Appends an immutable audit log entry', async () => {
    const auditRecord = await client.recordAuditEvent({
      who: MOCK_VEGA_AGENT_SUBJECT.id,
      what: 'DRAFT_BUSINESS_FORECAST',
      where: 'sovereign-os/executive-engine',
      why: 'Monthly revenue forecast generation',
      result: 'SUCCESS',
      details: { model: 'gemini-pro', confidence: 0.94 },
    });

    assert.equal(auditRecord.sequence, 1);
    assert.equal(auditRecord.who, 'agent-vega-01');
    assert.ok(auditRecord.currentHash.length === 64);
  });
});
