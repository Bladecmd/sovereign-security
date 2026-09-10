/**
 * Sovereign Security — Phase 2C
 * Security Operations Center (SOC) V2 Operational Interface Tests
 * 
 * Tests:
 * 1. UI Serving & 9 Panels Verification
 * 2. API Endpoints (Overview, Fleet Posture, Alerts, Agent Command, Containment, Forensics, Compliance, Audit, Health)
 * 3. Authorisation Guardrails (Fail-Closed, 401/403 on unauthenticated/unauthorized actions)
 * 4. Audit Trail Generation & Cryptographic SHA-256 Hash Chain Verification
 * 5. Forensics Correlation-Chain Trace (SecurityEvent -> Alert -> PolicyDecision -> Containment -> Resolution)
 */

import assert from 'node:assert/strict';
import { Server } from 'node:http';
import test, { after, before, describe } from 'node:test';
import { startSovereignSecurityServer } from '../src/server/server.js';

describe('Phase 2C: Security Operations Center V2 Interface & Control Plane', () => {
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

  // =========================================================================
  // 1. UI TESTS: Dashboard Serving, 9 Panels, and Security Badges
  // =========================================================================
  describe('1. UI Serving & 9 Panels Structure', () => {
    test('GET / and GET /dashboard serve valid SOC V2 HTML with all 9 operational panels', async () => {
      const res = await fetch(`${baseUrl}/dashboard`);
      assert.equal(res.status, 200);
      assert.match(res.headers.get('content-type') || '', /text\/html/);
      const html = await res.text();

      // Brand and Version Header
      assert.match(html, /SOVEREIGN SECURITY/i);
      assert.match(html, /Operations Dashboard V0.2 \/ SOC V2/i);
      assert.match(html, /Live Security Alerts & Triage Workspace/i);

      // Verify all 9 panel identifiers exist
      assert.match(html, /panel-overview/i);
      assert.match(html, /id="fleet"/i);
      assert.match(html, /id="alerts"/i);
      assert.match(html, /id="agents"/i);
      assert.match(html, /id="containment"/i);
      assert.match(html, /id="forensics"/i);
      assert.match(html, /id="compliance"/i);
      assert.match(html, /id="audit"/i);
      assert.match(html, /id="health"/i);

      // Verify compliance disclaimer exists
      assert.match(html, /INTERNAL EVIDENCE MAPPING DISCLAIMER/i);
      assert.match(html, /NOT constitute a formal third-party accredited audit/i);

      // Verify policy-gated containment release modal controls exist
      assert.match(html, /modal-caller-id/i);
      assert.match(html, /modal-operator-role/i);
      assert.match(html, /modal-release-reason/i);
      assert.match(html, /modal-confirm-check/i);
    });

    test('GET /favicon.svg and GET /favicon.ico serve valid Sovereign Security favicon', async () => {
      const resSvg = await fetch(`${baseUrl}/favicon.svg`);
      assert.equal(resSvg.status, 200);
      assert.match(resSvg.headers.get('content-type') || '', /image\/svg\+xml/);
      const svgText = await resSvg.text();
      assert.match(svgText, /<svg/);

      const resIco = await fetch(`${baseUrl}/favicon.ico`);
      assert.equal(resIco.status, 200);
      assert.match(resIco.headers.get('content-type') || '', /image\/svg\+xml/);
    });
  });

  // =========================================================================
  // 2. API TESTS: 9 Operational Endpoints
  // =========================================================================
  describe('2. Operational API Endpoints', () => {
    test('GET /api/v1/soc/overview returns comprehensive system defense metrics', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soc/overview`);
      assert.equal(res.status, 200);
      const data = (await res.json()) as any;

      assert.ok(['OPTIMAL', 'ELEVATED', 'DEGRADED', 'INCIDENT_ACTIVE'].includes(data.status));
      assert.equal(typeof data.totalEvents, 'number');
      assert.ok(data.alerts);
      assert.equal(typeof data.alerts.total, 'number');
      assert.equal(typeof data.alerts.bySeverity.CRITICAL, 'number');
      assert.ok(data.containment);
      assert.equal(typeof data.containment.activeCount, 'number');
      assert.ok(data.auditLedger);
      assert.equal(data.auditLedger.integrityValid, true);
      assert.ok(data.fleet);
      assert.equal(data.fleet.totalEntities, 5);
      assert.equal(data.subsystems.POLICY_ENGINE, 'ACTIVE');
      assert.equal(data.subsystems.AI_SECURITY_GATEWAY, 'ACTIVE');
    });

    test('GET /api/v1/soc/fleet-posture returns discrete connection status and real control counts (no arbitrary percentages)', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soc/fleet-posture`);
      assert.equal(res.status, 200);
      const data = (await res.json()) as any;

      assert.equal(data.entities.length, 5);
      const names = data.entities.map((e: any) => e.displayName);
      assert.ok(names.includes('Sovereign OS'));
      assert.ok(names.includes('MTF'));
      assert.ok(names.includes('Compliance Labs'));
      assert.ok(names.includes('AudioBlue'));
      assert.ok(names.includes('GriDD Corp'));

      for (const entity of data.entities) {
        // Must be one of the four discrete status states
        assert.ok(['CONNECTED', 'DEGRADED', 'OFFLINE', 'UNKNOWN'].includes(entity.status));
        // Control and evidence counts must be concrete integers
        assert.equal(typeof entity.controlCount, 'number');
        assert.equal(typeof entity.evidenceCount, 'number');
        assert.ok(entity.controlCount > 0);
        assert.ok(entity.evidenceCount > 0);
        // Must NOT contain arbitrary hardcoded percentage strings like '98%', '95%', '100%'
        assert.equal(typeof entity.score, 'undefined');
        assert.equal(typeof entity.percentage, 'undefined');
      }
    });

    test('GET /api/v1/soc/compliance-evidence returns required labels without claiming formal certification', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soc/compliance-evidence`);
      assert.equal(res.status, 200);
      const data = (await res.json()) as any;

      assert.match(data.disclaimer, /NOT represent a formal third-party accredited certification/i);
      assert.ok(data.evidenceItems.length > 0);

      const validLabels = [
        'IMPLEMENTED',
        'PARTIAL',
        'NOT IMPLEMENTED',
        'EVIDENCE AVAILABLE',
        'EXTERNALLY VALIDATED',
      ];

      for (const item of data.evidenceItems) {
        assert.ok(validLabels.includes(item.status), `Invalid status label: ${item.status}`);
        assert.equal(item.isFormalCertification, false);
        assert.ok(item.evidenceSource);
        assert.ok(item.controlId);
        assert.ok(item.framework);
      }

      // Verify frameworks represented
      const frameworks = new Set(data.evidenceItems.map((i: any) => i.framework));
      assert.ok(frameworks.has('NIST_SP_800_207'));
      assert.ok(frameworks.has('SOC2_TYPE_II'));
      assert.ok(frameworks.has('ISO_IEC_27001_2022'));
    });

    test('GET /api/v1/audit/ledger provides read-only inspection with SHA-256 verification', async () => {
      const res = await fetch(`${baseUrl}/api/v1/audit/ledger?limit=10`);
      assert.equal(res.status, 200);
      const data = (await res.json()) as any;

      assert.equal(data.readOnly, true);
      assert.equal(typeof data.totalRecords, 'number');
      assert.equal(data.verification.isValid, true);
      assert.ok(Array.isArray(data.records));

      if (data.records.length > 0) {
        const first = data.records[0];
        assert.equal(typeof first.sequence, 'number');
        assert.ok(first.currentHash);
        assert.ok(first.previousHash);
        assert.ok(first.who);
        assert.ok(first.what);
        assert.ok(first.result);
      }
    });

    test('GET /api/v1/soc/system-health returns process health, memory, and component readiness', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soc/system-health`);
      assert.equal(res.status, 200);
      const data = (await res.json()) as any;

      assert.equal(data.status, 'HEALTHY');
      assert.equal(typeof data.uptimeSeconds, 'number');
      assert.equal(typeof data.memoryUsage.heapUsedMB, 'number');
      assert.equal(data.components.POLICY_ENGINE, 'READY');
      assert.equal(data.components.AI_SECURITY_GATEWAY, 'READY');
      assert.equal(data.auditChainValid, true);
    });

    test('POST /api/v1/alerts supports status lifecycle and correlationId filtering', async () => {
      const corrId = `corr-test-${Date.now()}`;
      const alertId = `alt-soc-${Date.now()}`;

      // Create alert with correlationId
      const createRes = await fetch(`${baseUrl}/api/v1/alerts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alertId,
          createdAt: new Date().toISOString(),
          severity: 'HIGH',
          category: 'AUTHORIZATION',
          title: 'Unauthorized Model Tool Invocation Attempt',
          description: 'Model attempted execution of privileged system shell without clearance',
          sourceEventIds: ['evt-tool-01'],
          affectedResource: 'tools/system_exec',
          riskScore: 82,
          status: 'OPEN',
          correlationId: corrId,
        }),
      });
      assert.equal(createRes.status, 201);

      // Filter alerts by correlationId
      const filterRes = await fetch(`${baseUrl}/api/v1/alerts?correlationId=${corrId}`);
      assert.equal(filterRes.status, 200);
      const filterData = (await filterRes.json()) as any;
      assert.equal(filterData.count, 1);
      assert.equal(filterData.alerts[0].alertId, alertId);
      assert.equal(filterData.alerts[0].correlationId, corrId);

      // Triage alert to INVESTIGATING
      const triageRes = await fetch(`${baseUrl}/api/v1/alerts/${alertId}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: 'INVESTIGATING',
          callerId: 'sec-analyst-vega',
          resolution: 'Investigating anomalous tool arguments against tool permission registry',
        }),
      });
      assert.equal(triageRes.status, 200);
      const triageData = (await triageRes.json()) as any;
      assert.equal(triageData.alert.status, 'INVESTIGATING');
    });
  });

  // =========================================================================
  // 3. AUTHORISATION TESTS: Fail-Closed Zero-Trust Enforcement
  // =========================================================================
  describe('3. Authorisation & Policy Guardrails', () => {
    let testQuarantineId: string;

    before(async () => {
      // Create a quarantine target to test releases against
      const qRes = await fetch(`${baseUrl}/api/v1/agents/containment/quarantine`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetType: 'ACTOR',
          targetId: 'rogue-service-actor-99',
          reason: 'Excessive high-risk operations in production',
          ttlMs: 3600000,
        }),
      });
      assert.equal(qRes.status, 201);
      const qData = (await qRes.json()) as any;
      testQuarantineId = qData.quarantineRecord.quarantineId;
    });

    test('Containment release rejects unauthenticated requests (missing callerId)', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soc/containment/release`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          quarantineId: testQuarantineId,
          reason: 'Attempted release without identity',
          confirmed: true,
        }),
      });
      assert.equal(res.status, 401);
      const data = (await res.json()) as any;
      assert.equal(data.error, 'AUTHENTICATION_REQUIRED');
    });

    test('Containment release rejects requests missing justification reason', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soc/containment/release`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          quarantineId: testQuarantineId,
          callerId: 'sec-admin-01',
          role: 'SOC_ADMIN',
          reason: '   ', // Blank reason
          confirmed: true,
        }),
      });
      assert.equal(res.status, 400);
      const data = (await res.json()) as any;
      assert.equal(data.error, 'JUSTIFICATION_REQUIRED');
    });

    test('Containment release rejects unconfirmed requests (confirmed: false)', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soc/containment/release`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          quarantineId: testQuarantineId,
          callerId: 'sec-admin-01',
          role: 'SOC_ADMIN',
          reason: 'Legitimate service restarted',
          confirmed: false,
        }),
      });
      assert.equal(res.status, 400);
      const data = (await res.json()) as any;
      assert.equal(data.error, 'CONFIRMATION_REQUIRED');
    });

    test('Containment release strictly DENIES unauthorized role via PolicyEngine', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soc/containment/release`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          quarantineId: testQuarantineId,
          callerId: 'guest-user-01',
          role: 'UNPRIVILEGED_GUEST',
          reason: 'Trying to unblock service',
          confirmed: true,
        }),
      });
      assert.equal(res.status, 403);
      const data = (await res.json()) as any;
      assert.equal(data.error, 'AUTHORIZATION_DENIED');
      assert.equal(data.decision.decision, 'DENY');
    });

    test('Containment release SUCCEEDS for authorized operator (SOC_ADMIN) with valid audit event', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soc/containment/release`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          quarantineId: testQuarantineId,
          callerId: 'sec-admin-01',
          role: 'SOC_ADMIN',
          reason: 'Host remediated, anomalous credentials revoked, malware scrubbed.',
          confirmed: true,
        }),
      });
      assert.equal(res.status, 200);
      const data = (await res.json()) as any;
      assert.equal(data.success, true);
      assert.equal(data.quarantineId, testQuarantineId);
      assert.equal(data.releasedBy, 'sec-admin-01');
      assert.ok(data.decisionId);

      // Verify quarantine is no longer active
      const activeRes = await fetch(`${baseUrl}/api/v1/agents/containment/active`);
      const activeData = (await activeRes.json()) as any;
      assert.ok(!activeData.quarantines.some((q: any) => q.quarantineId === testQuarantineId));
    });

    test('Agent command rejects unauthorized guest role', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soc/agents/command`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          command: 'TRIAGE_ALERT',
          callerId: 'guest-user',
          role: 'UNPRIVILEGED_GUEST',
        }),
      });
      assert.equal(res.status, 403);
      const data = (await res.json()) as any;
      assert.equal(data.error, 'AUTHORIZATION_DENIED');
    });

    test('Agent command permits authorized operator to sync baselines', async () => {
      const res = await fetch(`${baseUrl}/api/v1/soc/agents/command`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          command: 'POSTURE_SYNC',
          callerId: 'sec-lead-vega',
          role: 'SECURITY_LEAD',
          reason: 'Periodic manual baseline sync from SOC command',
        }),
      });
      assert.equal(res.status, 200);
      const data = (await res.json()) as any;
      assert.equal(data.success, true);
      assert.equal(data.command, 'POSTURE_SYNC');
      assert.equal(data.result.synced, true);
    });
  });

  // =========================================================================
  // 4. AUDIT TESTS: Immutable Ledger & Cryptographic Verification
  // =========================================================================
  describe('4. Audit Trail Generation & Hash-Chain Integrity', () => {
    test('Every dashboard action generates a valid cryptographic audit record', async () => {
      const auditRes = await fetch(`${baseUrl}/api/v1/audit/ledger?limit=50`);
      assert.equal(auditRes.status, 200);
      const auditData = (await auditRes.json()) as any;

      const actions = auditData.records.map((r: any) => r.what);
      // Verify actions executed in earlier tests are recorded
      assert.ok(actions.some((a: string) => a.includes('soc.containment.release')));
      assert.ok(actions.some((a: string) => a.includes('soc.containment.release_denied')));
      assert.ok(actions.some((a: string) => a.includes('TRIAGE_ALERT')));
      assert.ok(actions.some((a: string) => a.includes('soc.agent.command')));

      // Cryptographic integrity must be unbroken
      const verifyRes = await fetch(`${baseUrl}/api/v1/audit/verify`);
      assert.equal(verifyRes.status, 200);
      const verifyData = (await verifyRes.json()) as any;
      assert.equal(verifyData.isValid, true);
      assert.equal(typeof verifyData.totalRecords, 'number');
      assert.ok(verifyData.totalRecords > 0);
    });
  });

  // =========================================================================
  // 5. FORENSICS TESTS: Full Correlation-Chain Tracing
  // =========================================================================
  describe('5. Forensics Correlation-Chain Tracing', () => {
    test('Traces complete causality chain: SecurityEvent -> Alert -> PolicyDecision -> Containment -> Resolution', async () => {
      const corrId = `corr-chain-${Date.now()}`;
      const eventId = `evt-chain-${Date.now()}`;
      const alertId = `alt-chain-${Date.now()}`;

      // 1. Ingest SecurityEvent
      const eventRes = await fetch(`${baseUrl}/api/v1/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          eventId,
          eventType: 'BRUTE_FORCE_ATTACK',
          severity: 'HIGH',
          category: 'AUTHENTICATION',
          action: 'auth:login_attempt',
          actorId: 'attacker-ip-192.168.1.50',
          resourceId: 'auth/login',
          result: 'DENIED',
          businessId: 'SOVEREIGN_OS_CORE',
          environment: 'production',
          correlationId: corrId,
        }),
      });
      assert.equal(eventRes.status, 201);

      // 2. Create Alert for this incident
      const alertRes = await fetch(`${baseUrl}/api/v1/alerts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          alertId,
          createdAt: new Date().toISOString(),
          severity: 'CRITICAL',
          category: 'AUTHENTICATION',
          title: 'Automated Credential Stuffing Attack',
          description: 'Rapid sequential authentication failures detected from single origin',
          sourceEventIds: [eventId],
          affectedResource: 'auth/login',
          actorId: 'attacker-ip-192.168.1.50',
          riskScore: 92,
          status: 'OPEN',
          correlationId: corrId,
        }),
      });
      assert.equal(alertRes.status, 201);

      // 3. Quarantine the attacker IP
      const qRes = await fetch(`${baseUrl}/api/v1/agents/containment/quarantine`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetType: 'IP',
          targetId: '192.168.1.50',
          reason: 'Credential attack defense isolation',
          metadata: { correlationId: corrId },
        }),
      });
      assert.equal(qRes.status, 201);
      const qData = (await qRes.json()) as any;
      const qId = qData.quarantineRecord.quarantineId;

      // 4. Release Quarantine after incident mitigation
      const releaseRes = await fetch(`${baseUrl}/api/v1/soc/containment/release`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          quarantineId: qId,
          callerId: 'sec-admin-01',
          role: 'SOC_ADMIN',
          reason: 'WAF rules deployed, IP isolation safe to decommission',
          confirmed: true,
        }),
      });
      assert.equal(releaseRes.status, 200);

      // 5. Resolve Alert
      const triageRes = await fetch(`${baseUrl}/api/v1/alerts/${alertId}/triage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          status: 'RESOLVED',
          assignedTo: 'sec-analyst-vega',
          resolution: 'Incident fully mitigated via WAF rule and credential rotation',
        }),
      });
      assert.equal(triageRes.status, 200);

      // 6. Query Forensics Trace Endpoint
      const traceRes = await fetch(`${baseUrl}/api/v1/forensics/trace/${corrId}`);
      assert.equal(traceRes.status, 200);
      const trace = (await traceRes.json()) as any;

      assert.equal(trace.correlationId, corrId);
      assert.ok(trace.securityEvents.some((e: any) => e.eventId === eventId));
      assert.ok(trace.alerts.some((a: any) => a.alertId === alertId));
      assert.ok(trace.containment.length > 0);
      assert.ok(trace.resolutions.length > 0);
      assert.equal(trace.chainComplete, true);
    });
  });
});