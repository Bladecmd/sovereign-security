import test, { describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { EcosystemAuthenticator, EcosystemCredentials } from '../src/integrations/auth/credentials.js';
import { SovereignSecurityClient } from '../src/integrations/sovereign-os/client.js';
import { MetroTaskForceAdapter } from '../src/integrations/mtf/adapter.js';
import { ComplianceLabsAdapter } from '../src/integrations/compliance-labs/adapter.js';
import { AudioBlueCIControls } from '../src/integrations/audioblue/ci-controls.js';
import { GriDDCorpAdapter, SecurityAlertService } from '../src/integrations/gridd-corp/adapter.js';
import { AuditService } from '../src/audit/audit-service.js';

describe('Phase 2B: Ecosystem Fleet Wiring Test Suite', () => {
  let auditService: AuditService;
  let alertService: SecurityAlertService;

  beforeEach(() => {
    auditService = new AuditService();
    alertService = new SecurityAlertService();
  });

  describe('1. Mutual Authentication & Anti-Replay', () => {
    test('authenticates valid registered ecosystem entities', () => {
      const validCreds: EcosystemCredentials = {
        serviceId: 'sovereign-os',
        businessId: 'sovereign-core-hq',
        environment: 'production',
        apiKey: 'sec_key_sovereign_os_prod_secret',
        timestamp: new Date().toISOString(),
        nonce: `nonce-${Math.random()}`,
      };

      const result = EcosystemAuthenticator.verifyCredentials(validCreds);
      assert.equal(result.authenticated, true);
      assert.ok(result.entityName?.includes('Sovereign OS'));
    });

    test('rejects unverified or unknown ecosystem entities', () => {
      const rogueCreds: EcosystemCredentials = {
        serviceId: 'rogue-entity',
        businessId: 'unknown-corp',
        environment: 'production',
        apiKey: 'bad_key',
        timestamp: new Date().toISOString(),
        nonce: `nonce-${Math.random()}`,
      };

      const result = EcosystemAuthenticator.verifyCredentials(rogueCreds);
      assert.equal(result.authenticated, false);
      assert.equal(result.errorCode, 'UNKNOWN_SERVICE');
    });

    test('rejects mismatched businessId bindings', () => {
      const spoofedCreds: EcosystemCredentials = {
        serviceId: 'sovereign-os',
        businessId: 'imposter-corp',
        environment: 'production',
        apiKey: 'key',
        timestamp: new Date().toISOString(),
        nonce: `nonce-${Math.random()}`,
      };

      const result = EcosystemAuthenticator.verifyCredentials(spoofedCreds);
      assert.equal(result.authenticated, false);
      assert.equal(result.errorCode, 'UNKNOWN_BUSINESS');
    });

    test('detects and rejects replayed nonces', () => {
      const nonce = `test-nonce-${Date.now()}`;
      const creds: EcosystemCredentials = {
        serviceId: 'metro-task-force',
        businessId: 'mtf-hq',
        environment: 'production',
        apiKey: 'sec_key_mtf_telemetry_prod_secret',
        timestamp: new Date().toISOString(),
        nonce,
      };

      const firstAttempt = EcosystemAuthenticator.verifyCredentials(creds);
      assert.equal(firstAttempt.authenticated, true);

      const replayAttempt = EcosystemAuthenticator.verifyCredentials(creds);
      assert.equal(replayAttempt.authenticated, false);
      assert.equal(replayAttempt.errorCode, 'REPLAY_DETECTED');
    });

    test('rejects expired timestamps beyond clock skew threshold', () => {
      const expiredTimestamp = new Date(Date.now() - 10 * 60 * 1000).toISOString();
      const creds: EcosystemCredentials = {
        serviceId: 'compliance-labs',
        businessId: 'compliance-labs-inc',
        environment: 'production',
        apiKey: 'sec_key_compliance_labs_audit_secret',
        timestamp: expiredTimestamp,
        nonce: `nonce-${Math.random()}`,
      };

      const result = EcosystemAuthenticator.verifyCredentials(creds);
      assert.equal(result.authenticated, false);
      assert.equal(result.errorCode, 'EXPIRED_TIMESTAMP');
    });
  });

  describe('2. Sovereign OS & VEGA Mediation', () => {
    let client: SovereignSecurityClient;

    beforeEach(() => {
      client = new SovereignSecurityClient({
        auditService,
      });
    });

    test('evaluates and permits authorized VEGA tool calls with tamper-evident audit record', async () => {
      let executorCalled = false;
      const result = await client.invokeVegaTool({
        agentId: 'vega',
        toolName: 'read_business_telemetry',
        parameters: { maxLines: 100 },
        executor: async () => {
          executorCalled = true;
          return { lines: 100 };
        },
      });

      assert.equal(result.permitted, true);
      assert.equal(executorCalled, true);
      assert.ok(result.auditRecord);
      assert.ok(result.auditRecord.what.includes('VEGA_TOOL_EXECUTED'));
      assert.ok(result.securityEvent);
    });

    test('fails closed and prevents VEGA from executing unauthorized or high-risk tools', async () => {
      let executorCalled = false;
      const result = await client.invokeVegaTool({
        agentId: 'vega',
        toolName: 'transfer_funds',
        parameters: { amount: 1000000 },
        executor: async () => {
          executorCalled = true;
        },
      });

      assert.equal(result.permitted, false);
      assert.equal(executorCalled, false);
      assert.ok(result.rejectionReason);
    });

    test('mediates executive actions and creates correlation trail', async () => {
      let actionExecuted = false;
      const result = await client.evaluateExecutiveAction({
        executiveId: 'ciso-officer',
        action: 'isolate-network-segment',
        resource: 'subnet-10-core',
        executor: () => {
          actionExecuted = true;
          return { isolated: true };
        },
      });

      assert.equal(result.permitted, true);
      assert.equal(actionExecuted, true);
      assert.ok(result.auditRecord);
      assert.ok(result.securityEvent?.correlationId.includes('corr-exec'));
    });

    test('audits privileged config changes and sensitive data access', async () => {
      const cfgResult = await client.evaluateConfigChange(
        'admin-01',
        'auth.mfa.required',
        false,
        true
      );
      assert.equal(cfgResult.permitted, true);
      assert.ok(cfgResult.auditRecord.what.includes('CONFIG_CHANGE_APPLIED'));

      const dataResult = await client.evaluateDataAccess(
        'analyst-01',
        'customer-pii-vault',
        'RESTRICTED'
      );
      assert.equal(dataResult.permitted, true);
      assert.ok(dataResult.auditRecord.what.includes('DATA_ACCESS_GRANTED'));
    });
  });

  describe('3. Metro Task Force (MTF) Telemetry Ingestion', () => {
    let adapter: MetroTaskForceAdapter;

    beforeEach(() => {
      adapter = new MetroTaskForceAdapter();
    });

    test('ingests valid MTF security telemetry with mutual auth', () => {
      const creds: EcosystemCredentials = {
        serviceId: 'metro-task-force',
        businessId: 'mtf-hq',
        environment: 'production',
        apiKey: 'sec_key_mtf_telemetry_prod_secret',
        timestamp: new Date().toISOString(),
        nonce: `mtf-nonce-${Math.random()}`,
      };

      const result = adapter.ingestWithCredentials(
        {
          eventType: 'ADMIN_LOGIN_FAILED',
          operatorId: 'unknown-attacker',
          targetEndpoint: '/api/v1/mtf/auth',
          action: 'login',
          status: 'FAILED',
          clientIp: '198.51.100.1',
        },
        creds
      );

      assert.equal(result.accepted, true);
      assert.ok(result.event);
      assert.equal(result.event.category, 'AUTHENTICATION');
      assert.equal(result.event.severity, 'HIGH');
    });

    test('strictly rejects pure business operations telemetry', () => {
      const creds: EcosystemCredentials = {
        serviceId: 'metro-task-force',
        businessId: 'mtf-hq',
        environment: 'production',
        apiKey: 'sec_key_mtf_telemetry_prod_secret',
        timestamp: new Date().toISOString(),
        nonce: `mtf-nonce-${Math.random()}`,
      };

      const result = adapter.ingestWithCredentials(
        {
          eventType: 'PATROL_LOCATION_PING',
          operatorId: 'unit-44',
          targetEndpoint: '/mtf/dispatch/gps',
          action: 'ping',
          status: 'SUCCESS',
        },
        creds
      );

      assert.equal(result.accepted, false);
      assert.ok(result.rejectedReason?.includes('operational business telemetry'));
    });
  });

  describe('4. Compliance Labs Adapter & Verifiable Evidence', () => {
    let adapter: ComplianceLabsAdapter;

    beforeEach(() => {
      auditService = new AuditService();
      auditService.append({
        who: 'system-init',
        what: 'GENESIS_BLOCK',
        where: 'core',
        why: 'init',
        result: 'SUCCESS',
      });
      adapter = new ComplianceLabsAdapter(auditService);
    });

    test('generates verifiable evidence bundles without synthetic compliance data', () => {
      const creds: EcosystemCredentials = {
        serviceId: 'compliance-labs',
        businessId: 'compliance-labs-inc',
        environment: 'production',
        apiKey: 'sec_key_compliance_labs_audit_secret',
        timestamp: new Date().toISOString(),
        nonce: `comp-nonce-${Math.random()}`,
      };

      const result = adapter.generateVerifiableEvidenceBundle(
        {
          framework: 'SOC2_TYPE_II',
          requestedBy: 'auditor-jane',
          auditScope: 'Q3-2026-Platform',
        },
        creds
      );

      assert.equal(result.success, true);
      assert.ok(result.bundle);
      assert.equal(result.bundle.verifiedAuditTrail.chainValid, true);
      assert.ok(result.bundle.verifiedAuditTrail.recordCount > 0);
      assert.equal(result.bundle.attestation.framework, 'SOC2_TYPE_II');
    });
  });

  describe('5. AudioBlue CI/CD Pre-Commit & Build Controls', () => {
    let ciControls: AudioBlueCIControls;

    beforeEach(() => {
      ciControls = new AudioBlueCIControls({ auditService });
    });

    test('passes build gate when no secrets or CVEs are present', () => {
      const result = ciControls.evaluateBuildGate({
        repoName: 'audioblue-web',
        commitSha: 'c0ffee123',
        sourceFiles: [
          { filename: 'index.ts', content: 'console.log("Clean code");' },
        ],
        manifest: {
          name: 'audioblue-web',
          version: '1.0.0',
          dependencies: {
            lodash: '4.17.21',
          },
        },
      });

      assert.equal(result.status, 'PASSED');
      assert.equal(result.secretScan.passed, true);
      assert.ok(result.sbom);
    });

    test('blocks build when exposed secret token is detected', () => {
      const result = ciControls.evaluateBuildGate({
        repoName: 'audioblue-backend',
        commitSha: 'badsha456',
        sourceFiles: [
          {
            filename: 'config.ts',
            content: 'const API_KEY = "ghp_123456789012345678901234567890123456";',
          },
        ],
      });

      assert.equal(result.status, 'BLOCKED');
      assert.equal(result.secretScan.passed, false);
      assert.ok(result.reason.includes('Build gate failed'));
    });

    test('permits emergency bypass ONLY with valid authorization and tamper-evident audit record', () => {
      const result = ciControls.evaluateBuildGate({
        repoName: 'audioblue-hotfix',
        commitSha: 'emerg789',
        sourceFiles: [
          {
            filename: 'auth.ts',
            content: 'const SECRET = "ghp_123456789012345678901234567890123456";',
          },
        ],
        bypassRequested: {
          authorizedBy: 'vp-engineering',
          justificationTicket: 'INCIDENT-9912-P0-PRODUCTION-OUTAGE',
          approved: true,
        },
      });

      assert.equal(result.status, 'BYPASS_APPROVED');
      assert.ok(result.auditTrailId);

      const allRecords = auditService.getRecords();
      const auditRecord = allRecords.find((r) => r.auditId === result.auditTrailId);
      assert.ok(auditRecord);
      assert.equal(auditRecord.what, 'AUDIOBLUE_CI_EMERGENCY_BYPASS');
      assert.equal(auditRecord.details.justificationTicket, 'INCIDENT-9912-P0-PRODUCTION-OUTAGE');
    });
  });

  describe('6. GriDD Corp Posture Aggregation & Fleet Governance', () => {
    let adapter: GriDDCorpAdapter;

    beforeEach(() => {
      adapter = new GriDDCorpAdapter(alertService, auditService);
    });

    test('retrieves genuine fleet posture without synthetic metrics', () => {
      // Add real alert
      alertService.createAlert({
        title: 'Critical Outage Alert',
        severity: 'CRITICAL',
        category: 'APPLICATION',
        description: 'Test critical alert',
      });

      const creds: EcosystemCredentials = {
        serviceId: 'gridd-corp',
        businessId: 'gridd-holding-corp',
        environment: 'production',
        apiKey: 'sec_key_gridd_corp_governance_secret',
        timestamp: new Date().toISOString(),
        nonce: `gridd-nonce-${Math.random()}`,
      };

      const result = adapter.getFleetPostureSummary(creds);
      assert.equal(result.success, true);
      assert.equal(result.posture?.totalActiveAlerts, 1);
      assert.equal(result.posture?.alertsBySeverity.critical, 1);
      assert.equal(result.posture?.authorizedEntitiesReporting.length, 5);
    });

    test('forwards high severity alerts to GriDD Corp board feed', () => {
      alertService.createAlert({
        title: 'High severity intrusion attempt',
        severity: 'HIGH',
        category: 'AUTHENTICATION',
        description: 'High alert',
      });

      const creds: EcosystemCredentials = {
        serviceId: 'gridd-corp',
        businessId: 'gridd-holding-corp',
        environment: 'production',
        apiKey: 'sec_key_gridd_corp_governance_secret',
        timestamp: new Date().toISOString(),
        nonce: `gridd-nonce-${Math.random()}`,
      };

      const result = adapter.getHighSeverityAlertsForForwarding(creds);
      assert.equal(result.success, true);
      assert.equal(result.forwarding?.forwardedCount, 1);
      assert.equal(result.forwarding?.alerts[0].severity, 'HIGH');
    });
  });
});
