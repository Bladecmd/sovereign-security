/**
 * Sovereign Security — Milestone V0.7
 * Autonomous Security Agents Test Suite
 */

import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { SentinelAgent } from '../src/agents/sentinel.js';
import { ContainmentAgent } from '../src/agents/containment.js';
import { ForensicsAgent } from '../src/agents/forensics.js';
import { AgentCoordinator } from '../src/agents/coordinator.js';
import { AuditService } from '../src/audit/audit-service.js';
import { SecurityAlert } from '../src/types/alerts.js';
import { SecurityEvent } from '../src/types/events.js';

describe('Milestone V0.7: Autonomous Security Agents', () => {
  const createMockAlert = (overrides: Partial<SecurityAlert> = {}): SecurityAlert => ({
    alertId: `alt-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
    title: 'Suspicious Administrative Access Attempt',
    description: 'Multiple failed privileged actions detected.',
    severity: 'HIGH',
    status: 'OPEN',
    actorId: 'bad-actor-99',
    tenantId: 'sovereign-corp',
    sourceEventIds: ['evt-1', 'evt-2'],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    ...overrides,
  });

  describe('Sentinel Agent: 24/7 Automated Alert Triage & Noise Suppression', () => {
    let sentinel: SentinelAgent;

    beforeEach(() => {
      sentinel = new SentinelAgent({
        testActorPrefixes: ['test-', 'synthetic-', 'probe-'],
      });
    });

    it('suppresses alerts triggered by synthetic test actors or probe suites', () => {
      const testAlert = createMockAlert({
        actorId: 'test-runner-alpha',
        title: 'High Frequency API Hits (Synthetic)',
      });

      const triage = sentinel.triageAlert(testAlert);

      assert.equal(triage.decision, 'SUPPRESS');
      assert.equal(triage.recommendedSeverity, 'LOW');
      assert.ok(triage.confidence >= 0.9);
      assert.equal(triage.matchedRule, 'FALSE_POSITIVE_SYNTHETIC_SUPPRESSION');
    });

    it('recommends immediate containment for critical secret exposures or brute force attacks', () => {
      const criticalAlert = createMockAlert({
        title: 'CRITICAL_ALERT: Secret Exposure Detected in Service Logs',
        severity: 'CRITICAL',
        actorId: 'compromised-service-account',
      });

      const triage = sentinel.triageAlert(criticalAlert);

      assert.equal(triage.decision, 'CONTAIN');
      assert.equal(triage.recommendedSeverity, 'CRITICAL');
      assert.ok(triage.confidence >= 0.95);
      assert.equal(triage.matchedRule, 'CRITICAL_THREAT_AUTO_CONTAINMENT');
    });

    it('escalates alerts when repeated threat activity is correlated for the same actor', () => {
      const actor = 'persistent-adversary';
      const priorAlert1 = createMockAlert({ alertId: 'alert-p1', actorId: actor, title: 'Auth Failure 1' });
      const priorAlert2 = createMockAlert({ alertId: 'alert-p2', actorId: actor, title: 'Auth Failure 2' });

      sentinel.registerAlert(priorAlert1);
      sentinel.registerAlert(priorAlert2);

      const incomingAlert = createMockAlert({
        alertId: 'alert-p3',
        actorId: actor,
        title: 'Suspicious API Mutation',
        severity: 'MEDIUM',
      });

      const triage = sentinel.triageAlert(incomingAlert);

      assert.equal(triage.decision, 'ESCALATE');
      assert.equal(triage.recommendedSeverity, 'HIGH');
      assert.ok(triage.correlatedAlertIds.includes('alert-p1'));
      assert.ok(triage.correlatedAlertIds.includes('alert-p2'));
      assert.equal(triage.matchedRule, 'MULTI_ALERT_REPETITION_ESCALATION');
    });

    it('clusters multiple alerts into correlated incident groups', () => {
      const alerts: SecurityAlert[] = [
        createMockAlert({ alertId: 'a1', actorId: 'hacker-x', severity: 'HIGH' }),
        createMockAlert({ alertId: 'a2', actorId: 'hacker-x', severity: 'CRITICAL' }),
        createMockAlert({ alertId: 'a3', actorId: 'contractor-y', severity: 'LOW' }),
      ];

      const clusters = sentinel.correlateIncidents(alerts);

      assert.equal(clusters.length, 2);
      const hackerCluster = clusters.find((c) => c.primaryActorId === 'hacker-x');
      assert.ok(hackerCluster);
      assert.equal(hackerCluster.alertIds.length, 2);
      assert.equal(hackerCluster.severity, 'CRITICAL');
    });
  });

  describe('Containment Agent: Automated Defensive Isolation & Rollback', () => {
    let containment: ContainmentAgent;
    let audit: AuditService;

    beforeEach(() => {
      audit = new AuditService();
      containment = new ContainmentAgent({ auditService: audit, defaultTtlMs: 3600000 });
    });

    it('applies quarantine to an actor and records cryptographic audit record', () => {
      const res = containment.quarantine({
        targetType: 'ACTOR',
        targetId: 'threat-actor-404',
        reason: 'Confirmed credential stuffing attack',
        initiatedBy: 'sentinel-automation',
      });

      assert.equal(res.success, true);
      assert.equal(res.quarantineRecord.targetId, 'threat-actor-404');
      assert.equal(res.quarantineRecord.isActive, true);

      // Verify status check
      assert.equal(containment.isQuarantined('threat-actor-404', 'ACTOR'), true);
      assert.equal(containment.isQuarantined('unrelated-actor', 'ACTOR'), false);

      // Verify audit logging
      const records = audit.getRecords();
      assert.ok(records.some((r) => r.what.includes('containment.quarantine_applied:ACTOR:threat-actor-404')));
      assert.equal(audit.verifyIntegrity().isValid, true);
    });

    it('reversibly releases an active quarantine upon incident resolution', () => {
      const quarantineResult = containment.quarantine({
        targetType: 'ACTOR',
        targetId: 'cleared-actor-5',
        reason: 'Temporary quarantine pending triage',
      });

      const quarantineId = quarantineResult.quarantineRecord.quarantineId;
      assert.equal(containment.isQuarantined('cleared-actor-5'), true);

      // Release quarantine
      const released = containment.release(
        quarantineId,
        'security-lead-admin',
        'False alarm verified by operations team.'
      );

      assert.equal(released, true);
      assert.equal(containment.isQuarantined('cleared-actor-5'), false);

      const record = containment.getQuarantineById(quarantineId);
      assert.equal(record?.isActive, false);
      assert.equal(record?.releasedBy, 'security-lead-admin');
      assert.ok(record?.releasedAt);
    });

    it('automatically treats expired quarantines as inactive', () => {
      // 10ms TTL
      containment.quarantine({
        targetType: 'IP',
        targetId: '192.168.1.100',
        reason: 'Rate limit breach',
        ttlMs: -1000, // already expired
      });

      assert.equal(containment.isQuarantined('192.168.1.100', 'IP'), false);
    });
  });

  describe('Forensics Agent: Timeline Reconstruction & Root Cause Analysis', () => {
    let forensics: ForensicsAgent;
    let audit: AuditService;

    beforeEach(() => {
      audit = new AuditService();
      forensics = new ForensicsAgent({ auditService: audit });
    });

    it('reconstructs an end-to-end timeline from audit records and security events', () => {
      const actor = 'investigated-actor';

      audit.append({
        who: actor,
        what: 'auth.login_attempt',
        where: 'sovereign-auth-service',
        why: 'User login request',
        result: 'FAILURE',
        details: { reason: 'bad_credentials' },
      });

      const event: SecurityEvent = {
        eventId: 'evt-test-1',
        timestamp: new Date().toISOString(),
        correlationId: 'corr-test',
        source: 'mtf-gateway',
        actorId: actor,
        category: 'AUTHENTICATION',
        severity: 'MEDIUM',
        riskScore: 60,
        action: 'auth.failed_attempt',
        status: 'FAILED',
        metadata: { clientIp: '10.0.0.1' },
      };

      forensics.registerEvents([event]);

      const timeline = forensics.reconstructTimeline({ actorId: actor });

      assert.ok(timeline.length >= 2);
      assert.equal(timeline[0]!.actorId, actor);
      assert.ok(timeline.some((t) => t.type === 'AUDIT'));
      assert.ok(timeline.some((t) => t.type === 'EVENT'));
    });

    it('synthesizes a comprehensive Root Cause Analysis (RCA) report', () => {
      const alert = createMockAlert({
        title: 'Brute Force Attack Detected',
        severity: 'CRITICAL',
        actorId: 'adversary-007',
      });

      const rca = forensics.generateRCAReport(alert);

      assert.ok(rca.reportId.startsWith('rca-'));
      assert.equal(rca.incidentId, alert.alertId);
      assert.equal(rca.patientZero, 'adversary-007');
      assert.ok(rca.rootCauseHypothesis.includes('Credential attack'));
      assert.ok(rca.recommendedMitigations.length >= 3);
      assert.ok(rca.recommendedMitigations.some((m) => m.includes('Containment quarantine')));
      assert.ok(rca.blastRadius.affectedActors.includes('adversary-007'));
    });
  });

  describe('Agent Coordinator: End-to-End Autonomous Orchestration', () => {
    it('executes full incident workflow: Triage -> Containment -> Forensics RCA', async () => {
      const audit = new AuditService();
      const coordinator = new AgentCoordinator({ auditService: audit });

      const criticalAlert = createMockAlert({
        title: 'Secret Exposure Detected: Database Root Credential Leaked',
        severity: 'CRITICAL',
        actorId: 'rogue-bot-42',
      });

      const result = await coordinator.processAlert({
        alert: criticalAlert,
        autoContain: true,
      });

      assert.equal(result.alertId, criticalAlert.alertId);
      assert.equal(result.status, 'CONTAINED');
      assert.equal(result.triage.decision, 'CONTAIN');
      assert.ok(result.containment);
      assert.equal(result.containment?.success, true);
      assert.equal(result.containment?.quarantineRecord.targetId, 'rogue-bot-42');
      assert.ok(result.rcaReport);
      assert.equal(result.rcaReport?.patientZero, 'rogue-bot-42');

      // Verify containment status is live
      assert.equal(coordinator.getContainment().isQuarantined('rogue-bot-42'), true);

      // Verify audit trail captures the coordinated orchestration
      const records = audit.getRecords();
      assert.ok(records.some((r) => r.what.includes('incident.coordinated_response')));
      assert.equal(audit.verifyIntegrity().isValid, true);
    });
  });
});
