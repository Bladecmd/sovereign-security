/**
 * Sovereign Security — Foundation V0.2
 * Security Dashboard & SSE Streaming Integration Tests
 */

import assert from 'node:assert/strict';
import { Server } from 'node:http';
import test, { after, before, describe } from 'node:test';
import { startSovereignSecurityServer } from '../src/server/server.js';

describe('Milestone V0.2: Security Dashboard & Real-Time Triage', () => {
  let serverInstance: Server;
  let serverPort: number;
  let stopServer: () => Promise<void>;
  let baseUrl: string;

  before(async () => {
    const started = await startSovereignSecurityServer({ port: 0 });
    serverInstance = started.server;
    const addr = serverInstance.address();
    serverPort = typeof addr === 'object' && addr ? addr.port : 4001;
    stopServer = started.stop;
    baseUrl = `http://127.0.0.1:${serverPort}`;
  });

  after(async () => {
    if (stopServer) {
      await stopServer();
    }
  });

  test('GET / and GET /dashboard serve valid dashboard HTML', async () => {
    const rootRes = await fetch(`${baseUrl}/`);
    assert.equal(rootRes.status, 200);
    assert.match(rootRes.headers.get('content-type') || '', /text\/html/);
    const rootHtml = await rootRes.text();
    assert.match(rootHtml, /SOVEREIGN SECURITY/i);
    assert.match(rootHtml, /Operations Dashboard V0.2/i);

    const dashRes = await fetch(`${baseUrl}/dashboard`);
    assert.equal(dashRes.status, 200);
    const dashHtml = await dashRes.text();
    assert.match(dashHtml, /Live Security Alerts & Triage Workspace/i);
  });

  test('GET /api/v1/telemetry/stats returns aggregate metrics', async () => {
    const res = await fetch(`${baseUrl}/api/v1/telemetry/stats`);
    assert.equal(res.status, 200);
    const stats = (await res.json()) as {
      totalEvents: number;
      openAlerts: number;
      averageRiskScore: number;
      auditChainValid: boolean;
      alertsBySeverity: Record<string, number>;
    };

    assert.equal(typeof stats.totalEvents, 'number');
    assert.equal(typeof stats.openAlerts, 'number');
    assert.equal(typeof stats.averageRiskScore, 'number');
    assert.equal(stats.auditChainValid, true);
    assert.ok('CRITICAL' in stats.alertsBySeverity);
  });

  test('POST /api/v1/alerts/:id/triage updates alert status across lifecycle', async () => {
    // 1. Create a test alert
    const createRes = await fetch(`${baseUrl}/api/v1/alerts`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        alertId: 'alt-triage-101',
        createdAt: new Date().toISOString(),
        severity: 'HIGH',
        category: 'AUTHENTICATION',
        title: 'Suspicious Login Sequence',
        description: 'Multiple failed attempts followed by unfamiliar user agent',
        sourceEventIds: ['evt-src-01'],
        affectedResource: 'auth/login',
        riskScore: 78,
        status: 'OPEN',
      }),
    });
    assert.equal(createRes.status, 201);

    // 2. Triage to ACKNOWLEDGED
    const ackRes = await fetch(`${baseUrl}/api/v1/alerts/alt-triage-101/triage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        status: 'ACKNOWLEDGED',
        assignedTo: 'sec-analyst-vega',
      }),
    });
    assert.equal(ackRes.status, 200);
    const ackBody = (await ackRes.json()) as { success: boolean; alert: { status: string; assignedTo: string } };
    assert.equal(ackBody.alert.status, 'ACKNOWLEDGED');
    assert.equal(ackBody.alert.assignedTo, 'sec-analyst-vega');

    // 3. Triage to CONTAINED
    const containRes = await fetch(`${baseUrl}/api/v1/alerts/alt-triage-101/triage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        status: 'CONTAINED',
        resolution: 'Target user session terminated. Password reset forced.',
      }),
    });
    assert.equal(containRes.status, 200);
    const containBody = (await containRes.json()) as { alert: { status: string; resolution: string } };
    assert.equal(containBody.alert.status, 'CONTAINED');
    assert.match(containBody.alert.resolution, /session terminated/);

    // 4. Triage to RESOLVED
    const resolveRes = await fetch(`${baseUrl}/api/v1/alerts/alt-triage-101/triage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        status: 'RESOLVED',
        resolution: 'Incident fully mitigated.',
      }),
    });
    assert.equal(resolveRes.status, 200);
    const resolveBody = (await resolveRes.json()) as { alert: { status: string; resolvedAt: string } };
    assert.equal(resolveBody.alert.status, 'RESOLVED');
    assert.ok(resolveBody.alert.resolvedAt);
  });

  test('GET /api/v1/events/stream establishes SSE connection', async () => {
    const controller = new AbortController();
    const sseRes = await fetch(`${baseUrl}/api/v1/events/stream`, {
      signal: controller.signal,
    });

    assert.equal(sseRes.status, 200);
    assert.match(sseRes.headers.get('content-type') || '', /text\/event-stream/);

    // Cleanly abort connection
    controller.abort();
  });
});
