/**
 * Sovereign Security — Foundation V0.1
 * Metro Task Force (MTF) Integration Adapter Tests
 */

import assert from 'node:assert/strict';
import test, { beforeEach, describe } from 'node:test';
import { MetroTaskForceAdapter } from '../src/integrations/mtf/adapter.js';
import { ThreatEngine } from '../src/threat/engine.js';

describe('Metro Task Force (MTF) Security Adapter', () => {
  let threatEngine: ThreatEngine;
  let adapter: MetroTaskForceAdapter;

  beforeEach(() => {
    threatEngine = new ThreatEngine();
    adapter = new MetroTaskForceAdapter(threatEngine);
  });

  test('normalizes MTF ADMIN_LOGIN_FAILED into standardized SecurityEvent', () => {
    const raw = {
      eventType: 'ADMIN_LOGIN_FAILED' as const,
      operatorId: 'officer-942',
      unitId: 'cyber-unit-07',
      stationId: 'district-04',
      targetEndpoint: 'mtf/dispatch/admin',
      action: 'authenticate',
      status: 'FAILED' as const,
      clientIp: '198.51.100.44',
      metadata: { attempts: 1 },
    };

    const event = adapter.normalizeMTFEvent(raw);

    assert.equal(event.source, 'metro-task-force');
    assert.equal(event.businessId, 'mtf-hq');
    assert.equal(event.severity, 'HIGH');
    assert.equal(event.category, 'AUTHENTICATION');
    assert.equal(event.actorId, 'officer-942');
    assert.equal(event.result, 'FAILURE');
    assert.ok(event.riskScore >= 70);
    assert.equal(event.metadata['stationId'], 'district-04');
  });

  test('normalizes MTF RATE_LIMIT_TRIGGERED into API SecurityEvent', () => {
    const raw = {
      eventType: 'RATE_LIMIT_TRIGGERED' as const,
      operatorId: 'external-api-client',
      targetEndpoint: 'mtf/api/v1/cases/query',
      action: 'query_cases',
      status: 'DENIED' as const,
      clientIp: '203.0.113.12',
    };

    const event = adapter.normalizeMTFEvent(raw);
    assert.equal(event.category, 'API');
    assert.equal(event.severity, 'MEDIUM');
    assert.equal(event.result, 'DENIED');
  });

  test('normalizes MTF SECRET_EXPOSURE and generates a CRITICAL alert on ingestion', () => {
    const raw = {
      eventType: 'SECRET_EXPOSURE' as const,
      operatorId: 'pipeline-runner',
      targetEndpoint: 'mtf/config/dispatch.env',
      action: 'read_env',
      status: 'FAILED' as const,
      metadata: { leakedClassification: 'API_KEY' },
    };

    const { event, alerts } = adapter.ingest(raw);

    assert.equal(event.category, 'SECRETS');
    assert.equal(event.severity, 'CRITICAL');
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0]?.severity, 'CRITICAL');
    assert.match(alerts[0]?.title || '', /Secret Exposure/i);
  });

  test('normalizes MTF PAYMENT_SECURITY_EVENT and DEPLOYMENT_EVENT', () => {
    const payment = adapter.normalizeMTFEvent({
      eventType: 'PAYMENT_SECURITY_EVENT',
      operatorId: 'procurement-bot',
      targetEndpoint: 'mtf/procurement/payout',
      action: 'execute_payout',
      status: 'FLAGGED',
    });
    assert.equal(payment.severity, 'HIGH');
    assert.equal(payment.result, 'DENIED');

    const deployment = adapter.normalizeMTFEvent({
      eventType: 'DEPLOYMENT_EVENT',
      operatorId: 'deploy-bot',
      targetEndpoint: 'mtf/deploy/cluster',
      action: 'rollout_service',
      status: 'SUCCESS',
    });
    assert.equal(deployment.severity, 'INFO');
    assert.equal(deployment.category, 'DEPLOYMENT');
  });
});
