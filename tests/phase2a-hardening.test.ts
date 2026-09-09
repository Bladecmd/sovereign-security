import test, { describe } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, unlinkSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { PersistentAuditLedger } from '../src/audit/persistent-storage.js';
import { SecurityDecisionPipeline } from '../src/policy/provenance.js';
import { ContainmentAgent } from '../src/agents/containment.js';
import { startSovereignSecurityServer } from '../src/server/server.js';
import { IdentitySubject } from '../src/types/identity.js';

describe('Phase 2A: Production Hardening & Zero-Trust Runtime', () => {

  describe('Workstream 4: Persistent Append-Only Audit Ledger', () => {
    const testLedgerPath = join(tmpdir(), 'test-audit-ledger-' + Date.now() + '.jsonl');

    test('cold start initializes clean ledger on disk', () => {
      if (existsSync(testLedgerPath)) unlinkSync(testLedgerPath);
      const ledger = new PersistentAuditLedger(testLedgerPath);
      const initResult = ledger.initialize();

      assert.equal(initResult.isValid, true);
      assert.equal(initResult.totalRecords, 0);
      assert.equal(existsSync(testLedgerPath), false);
    });

    test('appends records with valid SHA-256 hash chaining and persists to disk', () => {
      const ledger = new PersistentAuditLedger(testLedgerPath);
      ledger.initialize();

      const r1 = ledger.append({
        who: 'admin-01',
        what: 'USER_LOGIN',
        where: '/auth/login',
        why: 'Operator sign-in',
        result: 'SUCCESS',
        details: { ip: '192.168.1.100' },
      });

      const r2 = ledger.append({
        who: 'service-mtf',
        what: 'INGEST_TELEMETRY',
        where: '/api/v1/ingest/mtf',
        why: 'Sync events',
        result: 'SUCCESS',
        details: { eventCount: 15 },
      });

      assert.equal(r1.sequence, 1);
      assert.equal(r2.sequence, 2);
      assert.equal(r2.previousHash, r1.currentHash);
      assert.equal(existsSync(testLedgerPath), true);

      const diskLines = readFileSync(testLedgerPath, 'utf-8').trim().split('\n');
      assert.equal(diskLines.length, 2);
    });

    test('crash recovery: reopens file and verifies hash-chain integrity', () => {
      const restartedLedger = new PersistentAuditLedger(testLedgerPath);
      const verification = restartedLedger.initialize();

      assert.equal(verification.isValid, true);
      assert.equal(verification.totalRecords, 2);
      assert.equal(restartedLedger.getRecords().length, 2);
    });

    test('tamper detection: detects record modification on disk', () => {
      const tamperedPath = join(tmpdir(), 'test-tampered-ledger-' + Date.now() + '.jsonl');
      const ledger = new PersistentAuditLedger(tamperedPath);
      ledger.initialize();

      ledger.append({
        who: 'legit-user',
        what: 'VIEW_RESOURCES',
        where: '/data',
        why: 'Normal operation',
        result: 'SUCCESS',
        details: {},
      });

      const raw = readFileSync(tamperedPath, 'utf-8');
      const modified = raw.replace('legit-user', 'malicious-attacker');
      writeFileSync(tamperedPath, modified, 'utf-8');

      const tamperedLedger = new PersistentAuditLedger(tamperedPath);
      const verification = tamperedLedger.initialize();

      assert.equal(verification.isValid, false);
      assert.ok(verification.error?.includes('Data tamper detected') || verification.error?.includes('checksum'));

      assert.throws(() => {
        tamperedLedger.append({
          who: 'user-02',
          what: 'TRY_APPEND',
          where: '/test',
          why: 'Test',
          result: 'SUCCESS',
          details: {},
        });
      }, /Cannot append to compromised audit ledger/);

      if (existsSync(tamperedPath)) unlinkSync(tamperedPath);
    });

    test('concurrency: supports 20 rapid concurrent appends without breaking sequence or hash chain', async () => {
      const concurrentPath = join(tmpdir(), 'test-concurrent-ledger-' + Date.now() + '.jsonl');
      const ledger = new PersistentAuditLedger(concurrentPath);
      ledger.initialize();

      const promises: Promise<void>[] = [];
      for (let i = 0; i < 20; i++) {
        promises.push(
          new Promise<void>((resolve) => {
            ledger.append({
              who: 'worker-' + i,
              what: 'CONCURRENT_ACTION_' + i,
              where: '/parallel',
              why: 'Stress testing',
              result: 'SUCCESS',
              details: { index: i },
            });
            resolve();
          })
        );
      }

      await Promise.all(promises);

      const verification = ledger.verifyIntegrity();
      assert.equal(verification.isValid, true);
      assert.equal(verification.totalRecords, 20);

      const reloaded = new PersistentAuditLedger(concurrentPath);
      assert.equal(reloaded.initialize().isValid, true);

      if (existsSync(concurrentPath)) unlinkSync(concurrentPath);
      if (existsSync(testLedgerPath)) unlinkSync(testLedgerPath);
    });
  });

  describe('Workstream 5 & 6: Security Decision Provenance & Policy Boundary', () => {
    const pipeline = new SecurityDecisionPipeline();

    const testActor: IdentitySubject = {
      id: 'usr-analyst-01',
      type: 'AGENT',
      name: 'Security Analyst Bot',
      roles: ['AGENT'],
      organizationId: 'org-sovereign',
    };

    test('ALLOW: Produces complete provenance record with cryptographic signature', () => {
      const provenance = pipeline.evaluate({
        actor: testActor,
        resource: 'sovereign.telemetry.events',
        action: 'read_events',
        riskScore: 20,
        context: {
          environment: 'production',
          timestamp: new Date().toISOString(),
          authMethod: 'mTLS',
        },
      });

      assert.ok(provenance.decisionId.startsWith('decision-'));
      assert.equal(provenance.decision, 'ALLOW');
      assert.equal(provenance.executionStatus, 'EXECUTED');
      assert.equal(provenance.riskEvaluation.riskCategory, 'LOW');
      assert.equal(provenance.policyEvaluation.policyVersion, '2.0.0-phase2a');
      assert.ok(provenance.cryptographicSignature);
      assert.equal(provenance.cryptographicSignature.length, 64);
    });

    test('DENY: Blocks extreme risk operations (>=90) and seals provenance', () => {
      const provenance = pipeline.evaluate({
        actor: testActor,
        resource: 'sovereign.core.database',
        action: 'read_database',
        riskScore: 95,
        context: {
          environment: 'production',
          timestamp: new Date().toISOString(),
        },
      });

      assert.equal(provenance.decision, 'DENY');
      assert.equal(provenance.executionStatus, 'BLOCKED');
      assert.equal(provenance.riskEvaluation.riskCategory, 'CRITICAL');
      assert.ok(provenance.reasonCode.includes('exceeds maximum permissible threshold'));
    });

    test('REQUIRE_APPROVAL: Sensitive actions mandate dual approvers with status PENDING', () => {
      const provenance = pipeline.evaluate({
        actor: { ...testActor, type: 'ADMIN', roles: ['ADMIN'] },
        resource: 'sovereign.financial.vault',
        action: 'execute_fund_transfer',
        riskScore: 40,
        context: {
          environment: 'production',
          timestamp: new Date().toISOString(),
        },
      });

      assert.equal(provenance.decision, 'REQUIRE_APPROVAL');
      assert.equal(provenance.executionStatus, 'PENDING');
      assert.equal(provenance.approvalRequirements?.required, true);
      assert.deepEqual(provenance.approvalRequirements?.requiredApprovers, ['SECURITY_ADMIN', 'EXECUTIVE_APPROVER']);
    });

    test('ESCALATE: Production high-risk operations escalate to executive security desk', () => {
      const provenance = pipeline.evaluate({
        actor: testActor,
        resource: 'sovereign.config.network',
        action: 'read_config',
        riskScore: 80,
        context: {
          environment: 'production',
          timestamp: new Date().toISOString(),
        },
      });

      assert.equal(provenance.decision, 'ESCALATE');
      assert.equal(provenance.executionStatus, 'BLOCKED');
      assert.ok(provenance.reasonCode.includes('executive escalation'));
    });
  });

  describe('Workstream 7: Containment Safety & Fail-Safe TTL', () => {
    test('enforces fail-safe TTL and prevents unbounded quarantine', () => {
      const agent = new ContainmentAgent({ defaultTtlMs: 1000, maxTtlMs: 5000 });

      const result = agent.quarantine({
        targetType: 'ACTOR',
        targetId: 'rogue-actor-01',
        reason: 'Credential compromise detected',
        ttlMs: 10 * 24 * 60 * 60 * 1000,
      });

      assert.equal(result.success, true);
      assert.equal(result.quarantineRecord.status, 'ACTIVE');

      const expires = new Date(result.quarantineRecord.expiresAt).getTime();
      const created = new Date(result.quarantineRecord.createdAt).getTime();
      assert.ok(expires - created <= 5000, 'TTL must be clamped to maxTtlMs');
      assert.equal(agent.isQuarantined('rogue-actor-01'), true);
    });

    test('automatically transitions to EXPIRED once TTL passes', async () => {
      const agent = new ContainmentAgent({ defaultTtlMs: 50 });

      agent.quarantine({
        targetType: 'IP',
        targetId: '198.51.100.22',
        reason: 'Brute force attack',
      });

      assert.equal(agent.isQuarantined('198.51.100.22'), true);

      await new Promise((r) => setTimeout(r, 70));

      assert.equal(agent.isQuarantined('198.51.100.22'), false);
      assert.equal(agent.getActiveQuarantines().length, 0);
    });

    test('releases quarantine with auditable justification and authorized identity', () => {
      const agent = new ContainmentAgent();
      const { quarantineRecord } = agent.quarantine({
        targetType: 'SERVICE',
        targetId: 'compromised-microservice',
        reason: 'Anomalous egress traffic',
      });

      assert.equal(agent.isQuarantined('compromised-microservice'), true);

      const released = agent.release(
        quarantineRecord.quarantineId,
        'incident-commander-01',
        'Payload sanitized and patched in container build v1.2'
      );

      assert.equal(released, true);
      assert.equal(agent.isQuarantined('compromised-microservice'), false);

      const record = agent.getQuarantineById(quarantineRecord.quarantineId);
      assert.equal(record?.status, 'RELEASED');
      assert.equal(record?.releasedBy, 'incident-commander-01');
      assert.ok(record?.releasedAt);
    });
  });

  describe('Workstream 2 & 3: Production Observability & Telemetry Endpoints', () => {
    let stopServer: () => Promise<void>;
    const port = 4199;
    const baseUrl = 'http://127.0.0.1:' + port;

    test.before(async () => {
      const serverInstance = await startSovereignSecurityServer({ port });
      stopServer = serverInstance.stop;
    });

    test.after(async () => {
      if (stopServer) await stopServer();
    });

    test('GET /health returns process liveness and memory sane status', async () => {
      const res = await fetch(baseUrl + '/health');
      assert.equal(res.status, 200);
      const data = (await res.json()) as any;
      assert.equal(data.status, 'UP');
      assert.ok(data.uptimeSeconds >= 0);
      assert.ok(data.memory.heapUsedMB > 0);
    });

    test('GET /ready returns readiness check including audit ledger integrity', async () => {
      const res = await fetch(baseUrl + '/ready');
      assert.equal(res.status, 200);
      const data = (await res.json()) as any;
      assert.equal(data.ready, true);
      assert.equal(data.checks.policyEngine, 'READY');
      assert.equal(data.checks.auditLedger, 'VERIFIED');
      assert.equal(data.checks.threatEngine, 'READY');
    });

    test('GET /metrics provides RFC-compliant Prometheus exposition format', async () => {
      const res = await fetch(baseUrl + '/metrics');
      assert.equal(res.status, 200);
      assert.ok(res.headers.get('content-type')?.includes('text/plain'));
      const text = await res.text();

      assert.ok(text.includes('# HELP sovereign_policy_evaluations_total'));
      assert.ok(text.includes('# TYPE sovereign_policy_evaluations_total counter'));
      assert.ok(text.includes('# HELP sovereign_process_uptime_seconds'));
      assert.ok(text.includes('# TYPE sovereign_process_uptime_seconds gauge'));
      assert.ok(text.includes('# HELP sovereign_policy_evaluation_duration_ms'));
      assert.ok(text.includes('# TYPE sovereign_policy_evaluation_duration_ms histogram'));

      assert.equal(text.includes('password'), false);
      assert.equal(text.includes('secret'), false);
      assert.equal(text.includes('API_KEY'), false);
    });

    test('POST /api/v1/decisions/evaluate executes provenance-sealed decision over HTTP', async () => {
      const res = await fetch(baseUrl + '/api/v1/decisions/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          actor: {
            id: 'actor-api-test',
            type: 'ADMIN',
            name: 'API Test Admin',
            roles: ['ADMIN'],
            organizationId: 'org-sovereign',
          },
          resource: 'sovereign.api.cluster',
          action: 'read_cluster_status',
          riskScore: 15,
          context: {
            environment: 'production',
            timestamp: new Date().toISOString(),
          },
        }),
      });

      assert.equal(res.status, 200);
      const decision = (await res.json()) as any;
      assert.equal(decision.decision, 'ALLOW');
      assert.equal(decision.executionStatus, 'EXECUTED');
      assert.ok(decision.cryptographicSignature);
    });
  });
});
