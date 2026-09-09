/**
 * Sovereign Security — Foundation V0.1
 * Local HTTP API Server & Webhook Ingestion Integration Tests
 */

import assert from 'node:assert/strict';
import { Server } from 'node:http';
import test, { after, before, describe } from 'node:test';
import { startSovereignSecurityServer } from '../src/server/server.js';
import { MOCK_ADMIN_SUBJECT } from './fixtures/test-events.js';

describe('Local HTTP Security API Server & Webhooks', () => {
  let serverInstance: Server;
  let serverPort: number;
  let stopServer: () => Promise<void>;
  let baseUrl: string;

  before(async () => {
    // Start on dynamic / ephemeral port (0)
    const started = await startSovereignSecurityServer({ port: 0 });
    serverInstance = started.server;
    const addr = serverInstance.address();
    serverPort = typeof addr === 'object' && addr ? addr.port : 4000;
    stopServer = started.stop;
    baseUrl = `http://127.0.0.1:${serverPort}`;
  });

  after(async () => {
    if (stopServer) {
      await stopServer();
    }
  });

  test('GET /health returns status UP and service metadata', async () => {
    const res = await fetch(`${baseUrl}/health`);
    assert.equal(res.status, 200);
    const body = (await res.json()) as { status: string; service: string; version: string };
    assert.equal(body.status, 'UP');
    assert.equal(body.service, 'sovereign-security');
    assert.equal(body.version, '0.2.0');
  });

  test('POST /api/v1/events ingests valid SecurityEvent and logs to audit', async () => {
    const res = await fetch(`${baseUrl}/api/v1/events`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        source: 'sovereign-os',
        businessId: 'biz-01',
        environment: 'production',
        severity: 'INFO',
        category: 'AUTHENTICATION',
        eventType: 'ADMIN_LOGIN_SUCCESS',
        actorId: 'usr-admin-01',
        resourceId: 'auth/session',
        action: 'login',
        result: 'SUCCESS',
        riskScore: 10,
        metadata: {},
        correlationId: 'http-test-01',
      }),
    });

    assert.equal(res.status, 201);
    const data = (await res.json()) as { success: boolean; event: { eventId: string } };
    assert.equal(data.success, true);
    assert.ok(data.event.eventId.startsWith('evt-'));
  });

  test('POST /api/v1/policy/evaluate evaluates policy decisions over HTTP', async () => {
    const res = await fetch(`${baseUrl}/api/v1/policy/evaluate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        actor: MOCK_ADMIN_SUBJECT,
        resource: 'api/v1/users',
        action: 'read_user_profile',
        context: {
          environment: 'production',
          timestamp: new Date().toISOString(),
        },
        riskScore: 20,
      }),
    });

    assert.equal(res.status, 200);
    const decision = (await res.json()) as { decision: string };
    assert.equal(decision.decision, 'ALLOW');
  });

  test('POST /api/v1/ai/tool-check verifies agent tool permissions (VEGA rules)', async () => {
    // VEGA reading telemetry -> ALLOW
    const allowedRes = await fetch(`${baseUrl}/api/v1/ai/tool-check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agentId: 'vega',
        toolName: 'read_business_telemetry',
      }),
    });
    assert.equal(allowedRes.status, 200);
    const allowed = (await allowedRes.json()) as { decision: string };
    assert.equal(allowed.decision, 'ALLOW');

    // VEGA transferring funds -> DENY
    const deniedRes = await fetch(`${baseUrl}/api/v1/ai/tool-check`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        agentId: 'vega',
        toolName: 'transfer_funds',
      }),
    });
    assert.equal(deniedRes.status, 200);
    const denied = (await deniedRes.json()) as { decision: string };
    assert.equal(denied.decision, 'DENY');
  });

  test('POST /api/v1/ingest/mtf ingests MTF events and raises alerts on secret exposure', async () => {
    const res = await fetch(`${baseUrl}/api/v1/ingest/mtf`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        eventType: 'SECRET_EXPOSURE',
        operatorId: 'unit-dispatch-9',
        targetEndpoint: 'mtf/config/keys',
        action: 'read_secret',
        status: 'FAILED',
        metadata: { leakedClassification: 'PRIVATE_KEY' },
      }),
    });

    assert.equal(res.status, 201);
    const data = (await res.json()) as {
      success: boolean;
      normalizedEvent: { category: string };
      triggeredAlerts: Array<{ severity: string }>;
    };
    assert.equal(data.success, true);
    assert.equal(data.normalizedEvent.category, 'SECRETS');
    assert.equal(data.triggeredAlerts.length, 1);
    assert.equal(data.triggeredAlerts[0]?.severity, 'CRITICAL');
  });

  test('GET /api/v1/audit/verify confirms unbroken hash-chain integrity', async () => {
    const res = await fetch(`${baseUrl}/api/v1/audit/verify`);
    assert.equal(res.status, 200);
    const verification = (await res.json()) as { isValid: boolean; totalRecords: number };
    assert.equal(verification.isValid, true);
    assert.ok(verification.totalRecords > 0);
  });
});
