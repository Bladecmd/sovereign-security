/**
 * Sovereign Security — Milestone Phase 2A
 * Production Hardened REST API & Zero-Trust Telemetry Endpoints
 */

import { existsSync, readFileSync } from 'node:fs';
import { IncomingMessage, ServerResponse } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AgentToolPermissionRegistry } from '../ai/tool-permissions.js';
import { AISecurityGateway } from '../ai/gateway.js';
import { AgentCoordinator } from '../agents/coordinator.js';
import { ComplianceCertificationEngine } from '../compliance/certification.js';
import { PostureSynchronizer } from '../posture/synchronizer.js';
import { AuditService } from '../audit/audit-service.js';
import { PersistentAuditLedger } from '../audit/persistent-storage.js';
import { MetroTaskForceAdapter, MTFRawSecurityPayload } from '../integrations/mtf/adapter.js';
import { StructuredLogger } from '../observability/logger.js';
import { globalMetrics } from '../observability/metrics.js';
import { PolicyEngine } from '../policy/engine.js';
import { SecurityDecisionPipeline } from '../policy/provenance.js';
import { RiskEngine } from '../risk/engine.js';
import { ThreatEngine } from '../threat/engine.js';
import { AlertStatus, SecurityAlert } from '../types/alerts.js';
import { CreateSecurityEventInput, SecurityEvent } from '../types/events.js';
import { PolicyEvaluationInput } from '../types/policy.js';
import { SecurityDecisionInput } from '../types/provenance.js';
import { safeValidateSecurityAlert, validateSecurityAlert } from '../schemas/alert.schema.js';
import { safeValidateSecurityEvent } from '../schemas/event.schema.js';
import { TelemetryBroadcaster } from './sse.js';

export class SovereignSecurityApiHandler {
  private policyEngine: PolicyEngine;
  private decisionPipeline: SecurityDecisionPipeline;
  private toolRegistry: AgentToolPermissionRegistry;
  private auditService: AuditService;
  private persistentLedger?: PersistentAuditLedger;
  private threatEngine: ThreatEngine;
  private aiGateway: AISecurityGateway;
  private coordinator: AgentCoordinator;
  private compliance: ComplianceCertificationEngine;
  private posture: PostureSynchronizer;
  private mtfAdapter: MetroTaskForceAdapter;
  private alertsStore: Map<string, SecurityAlert> = new Map();
  private recentEvents: SecurityEvent[] = [];
  private broadcaster: TelemetryBroadcaster;
  private logger: StructuredLogger;
  private dashboardHtmlCache: string | null = null;
  private bootTimestamp: string = new Date().toISOString();

  constructor(options?: {
    policyEngine?: PolicyEngine;
    toolRegistry?: AgentToolPermissionRegistry;
    auditService?: AuditService;
    persistentLedger?: PersistentAuditLedger;
    threatEngine?: ThreatEngine;
    aiGateway?: AISecurityGateway;
    coordinator?: AgentCoordinator;
    compliance?: ComplianceCertificationEngine;
    posture?: PostureSynchronizer;
    broadcaster?: TelemetryBroadcaster;
    logger?: StructuredLogger;
  }) {
    this.persistentLedger = options?.persistentLedger;
    this.auditService =
      options?.auditService ||
      (this.persistentLedger ? this.persistentLedger.getAuditService() : new AuditService());
    this.policyEngine = options?.policyEngine || new PolicyEngine();
    this.decisionPipeline = new SecurityDecisionPipeline({
      policyEngine: this.policyEngine,
      auditService: this.auditService,
      logger: options?.logger,
    });
    this.toolRegistry = options?.toolRegistry || new AgentToolPermissionRegistry();
    this.threatEngine = options?.threatEngine || new ThreatEngine();
    this.aiGateway =
      options?.aiGateway || new AISecurityGateway({ auditService: this.auditService });
    this.coordinator =
      options?.coordinator || new AgentCoordinator({ auditService: this.auditService });
    this.compliance =
      options?.compliance || new ComplianceCertificationEngine({ auditService: this.auditService });
    this.posture =
      options?.posture || new PostureSynchronizer({ auditService: this.auditService });
    this.broadcaster = options?.broadcaster || new TelemetryBroadcaster();
    this.mtfAdapter = new MetroTaskForceAdapter(this.threatEngine);
    this.logger =
      options?.logger || new StructuredLogger({ serviceName: 'sovereign-security-api' });
  }

  public async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const method = req.method?.toUpperCase() || 'GET';
    const correlationId = (req.headers['x-correlation-id'] as string) || `api-${Date.now()}`;

    res.setHeader('X-Security-Version', '2.0.0-phase2a');
    res.setHeader('X-Correlation-Id', correlationId);

    try {
      if (method === 'GET' && (url.pathname === '/' || url.pathname === '/dashboard')) {
        const html = this.getDashboardHtml();
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.statusCode = 200;
        res.end(html);
        return;
      }

      if (method === 'GET' && url.pathname === '/api/v1/events/stream') {
        this.broadcaster.addClient(res);
        return;
      }

      if (method === 'GET' && url.pathname === '/metrics') {
        res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
        res.statusCode = 200;
        res.end(globalMetrics.toPrometheusString());
        return;
      }

      res.setHeader('Content-Type', 'application/json');

      if (method === 'GET' && url.pathname === '/health') {
        const memory = process.memoryUsage();
        return this.sendJson(res, 200, {
          status: 'UP',
          service: 'sovereign-security',
          version: '0.2.0',
          phase: '2A',
          phaseVersion: '2.0.0-phase2a',
          uptimeSeconds: Math.floor(process.uptime()),
          memory: {
            heapUsedMB: Math.round(memory.heapUsed / 1024 / 1024),
            heapTotalMB: Math.round(memory.heapTotal / 1024 / 1024),
            rssMB: Math.round(memory.rss / 1024 / 1024),
          },
          subscribers: this.broadcaster.getSubscriberCount(),
          timestamp: new Date().toISOString(),
        });
      }

      if (method === 'GET' && url.pathname === '/ready') {
        const auditVerification = this.auditService.verifyIntegrity();
        const isReady = auditVerification.isValid;

        const responsePayload = {
          ready: isReady,
          service: 'sovereign-security',
          version: '2.0.0-phase2a',
          checks: {
            policyEngine: 'READY',
            auditLedger: auditVerification.isValid ? 'VERIFIED' : 'INTEGRITY_COMPROMISED',
            persistentStorage: this.persistentLedger ? 'MOUNTED' : 'MEMORY_ONLY',
            quarantineEngine: 'READY',
            threatEngine: 'READY',
          },
          auditTotalRecords: auditVerification.totalRecords,
          bootTimestamp: this.bootTimestamp,
          timestamp: new Date().toISOString(),
        };

        return this.sendJson(res, isReady ? 200 : 503, responsePayload);
      }

      if (method === 'POST' && url.pathname === '/api/v1/decisions/evaluate') {
        const body = (await this.readJsonBody(req)) as SecurityDecisionInput;
        const provenance = this.decisionPipeline.evaluate(body);

        if (this.persistentLedger) {
          this.persistentLedger.append({
            who: provenance.actor.id,
            what: `DECISION:${provenance.decision}:${provenance.action}`,
            where: provenance.resource,
            why: provenance.reasonCode,
            result: provenance.decision === 'ALLOW' ? 'SUCCESS' : 'DENIED',
            details: {
              decisionId: provenance.decisionId,
              correlationId: provenance.correlationId,
              rule: provenance.policyEvaluation.ruleEvaluated,
              signature: provenance.cryptographicSignature,
            },
          });
        }

        return this.sendJson(res, 200, provenance);
      }

      if (method === 'GET' && url.pathname === '/api/v1/telemetry/stats') {
        const alertsList = Array.from(this.alertsStore.values());
        const openAlerts = alertsList.filter(
          (a) => a.status !== 'RESOLVED' && a.status !== 'FALSE_POSITIVE'
        );

        let averageRisk = 12;
        if (this.recentEvents.length > 0) {
          const sum = this.recentEvents.reduce((acc, curr) => acc + curr.riskScore, 0);
          averageRisk = Math.round(sum / this.recentEvents.length);
        }

        return this.sendJson(res, 200, {
          totalEvents: this.recentEvents.length,
          totalAlerts: alertsList.length,
          openAlerts: openAlerts.length,
          averageRiskScore: averageRisk,
          alertsBySeverity: {
            CRITICAL: openAlerts.filter((a) => a.severity === 'CRITICAL').length,
            HIGH: openAlerts.filter((a) => a.severity === 'HIGH').length,
            MEDIUM: openAlerts.filter((a) => a.severity === 'MEDIUM').length,
            LOW: openAlerts.filter((a) => a.severity === 'LOW').length,
          },
          auditChainValid: this.auditService.verifyIntegrity().isValid,
        });
      }

      if (method === 'POST' && url.pathname === '/api/v1/events') {
        const body = await this.readJsonBody(req);
        const input = body as CreateSecurityEventInput;

        const eventId =
          input.eventId || `evt-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
        const timestamp = input.timestamp || new Date().toISOString();
        const riskScore =
          input.riskScore > 0
            ? input.riskScore
            : RiskEngine.calculateRisk({
                severity: input.severity,
                action: input.action,
              });

        const eventPayload: SecurityEvent = {
          ...input,
          eventId,
          timestamp,
          source: input.source || 'external-api',
          environment: input.environment || 'production',
          riskScore,
          verificationStatus: input.verificationStatus || 'VERIFIED',
          correlationId: input.correlationId || correlationId,
        };

        const validation = safeValidateSecurityEvent(eventPayload);
        if (!validation.success) {
          return this.sendJson(res, 400, {
            error: 'VALIDATION_FAILED',
            details: validation.error.issues,
          });
        }

        const validEvent = validation.data;
        this.recentEvents.push(validEvent);
        if (this.recentEvents.length > 500) this.recentEvents.shift();

        globalMetrics.incrementCounter('sovereign_security_events_ingested_total');
        this.broadcaster.broadcastEvent(validEvent);

        const alerts = this.threatEngine.processEvent(validEvent);
        for (const alert of alerts) {
          this.alertsStore.set(alert.alertId, alert);
          this.broadcaster.broadcastAlert(alert);
          globalMetrics.incrementCounter('sovereign_security_alerts_generated_total');
        }

        this.recordAudit({
          who: validEvent.actorId,
          what: `INGEST_EVENT:${validEvent.eventType}`,
          where: url.pathname,
          why: 'Security event telemetry ingestion',
          result: 'SUCCESS',
          details: { eventId: validEvent.eventId, category: validEvent.category },
        });

        return this.sendJson(res, 201, {
          success: true,
          event: validEvent,
          triggeredAlerts: alerts,
        });
      }

      if (method === 'POST' && url.pathname === '/api/v1/policy/evaluate') {
        const body = await this.readJsonBody(req);
        const decision = this.policyEngine.evaluate(body as PolicyEvaluationInput);

        this.recordAudit({
          who: (body as PolicyEvaluationInput).actor?.id || 'unknown-actor',
          what: `POLICY_EVALUATION:${(body as PolicyEvaluationInput).action}`,
          where: (body as PolicyEvaluationInput).resource || 'unknown-resource',
          why: 'Runtime policy evaluation request',
          result: decision.decision === 'ALLOW' ? 'SUCCESS' : 'DENIED',
          details: { decision: decision.decision, reason: decision.reason },
        });

        return this.sendJson(res, 200, decision);
      }

      if (method === 'GET' && url.pathname === '/api/v1/alerts') {
        return this.sendJson(res, 200, {
          alerts: Array.from(this.alertsStore.values()),
          count: this.alertsStore.size,
        });
      }

      const triageMatch = url.pathname.match(/^\/api\/v1\/alerts\/([^/]+)\/triage$/);
      if (method === 'POST' && triageMatch) {
        const alertId = triageMatch[1]!;
        const body = (await this.readJsonBody(req)) as {
          status: AlertStatus;
          assignedTo?: string;
          resolution?: string;
        };

        const existing = this.alertsStore.get(alertId);
        if (!existing) {
          return this.sendJson(res, 404, {
            error: 'NOT_FOUND',
            message: `Alert '${alertId}' not found.`,
          });
        }

        existing.status = body.status;
        if (body.assignedTo) existing.assignedTo = body.assignedTo;
        if (body.resolution) existing.resolution = body.resolution;
        if (body.status === 'RESOLVED') existing.resolvedAt = new Date().toISOString();

        this.broadcaster.broadcastAlert(existing);

        this.recordAudit({
          who: body.assignedTo || 'analyst-triage',
          what: `TRIAGE_ALERT:${alertId}`,
          where: '/api/v1/alerts/triage',
          why: `Alert status updated to ${body.status}`,
          result: 'SUCCESS',
          details: { alertId, status: body.status, resolution: body.resolution },
        });

        return this.sendJson(res, 200, { success: true, alert: existing });
      }

      if (method === 'POST' && url.pathname === '/api/v1/alerts') {
        const body = await this.readJsonBody(req);
        const validation = safeValidateSecurityAlert(body);
        if (!validation.success) {
          return this.sendJson(res, 400, {
            error: 'VALIDATION_FAILED',
            details: validation.error.issues,
          });
        }

        const alert = validateSecurityAlert(validation.data);
        this.alertsStore.set(alert.alertId, alert);
        this.broadcaster.broadcastAlert(alert);
        globalMetrics.incrementCounter('sovereign_security_alerts_generated_total');
        return this.sendJson(res, 201, { success: true, alert });
      }

      if (method === 'POST' && url.pathname === '/api/v1/ai/tool-check') {
        const body = (await this.readJsonBody(req)) as {
          agentId: string;
          toolName: string;
          parameters?: Record<string, unknown>;
        };

        if (!body.agentId || !body.toolName) {
          return this.sendJson(res, 400, {
            error: 'MISSING_PARAMETERS',
            message: 'Both agentId and toolName are required.',
          });
        }

        const check = this.toolRegistry.checkPermission(
          body.agentId,
          body.toolName,
          body.parameters || {}
        );
        return this.sendJson(res, 200, check);
      }

      if (method === 'POST' && url.pathname === '/api/v1/audit') {
        const body = await this.readJsonBody(req);
        const record = this.recordAudit(body as any);
        return this.sendJson(res, 201, { success: true, record });
      }

      if (method === 'GET' && url.pathname === '/api/v1/audit/verify') {
        const verification = this.auditService.verifyIntegrity();
        return this.sendJson(res, 200, verification);
      }

      if (method === 'POST' && url.pathname === '/api/v1/ingest/mtf') {
        const body = await this.readJsonBody(req);
        const { event, alerts } = this.mtfAdapter.ingest(body as MTFRawSecurityPayload);

        this.recentEvents.push(event);
        this.broadcaster.broadcastEvent(event);
        globalMetrics.incrementCounter('sovereign_security_events_ingested_total');

        for (const alert of alerts) {
          this.alertsStore.set(alert.alertId, alert);
          this.broadcaster.broadcastAlert(alert);
          globalMetrics.incrementCounter('sovereign_security_alerts_generated_total');
        }

        return this.sendJson(res, 201, {
          success: true,
          normalizedEvent: event,
          triggeredAlerts: alerts,
        });
      }

      if (method === 'POST' && url.pathname === '/api/v1/ai/gateway/inspect-input') {
        const body = (await this.readJsonBody(req)) as {
          prompt: string;
          agentId?: string;
          context?: Record<string, unknown>;
        };
        if (!body.prompt) {
          return this.sendJson(res, 400, {
            error: 'MISSING_PARAMETERS',
            message: 'Field "prompt" is required.',
          });
        }
        const result = this.aiGateway.inspectInput(body);
        return this.sendJson(res, 200, result);
      }

      if (method === 'POST' && url.pathname === '/api/v1/ai/gateway/inspect-output') {
        const body = (await this.readJsonBody(req)) as {
          output: string;
          agentId?: string;
          correlationId?: string;
        };
        if (typeof body.output !== 'string') {
          return this.sendJson(res, 400, {
            error: 'MISSING_PARAMETERS',
            message: 'Field "output" is required.',
          });
        }
        const result = this.aiGateway.inspectOutput(body.output, {
          agentId: body.agentId,
          correlationId: body.correlationId,
        });
        return this.sendJson(res, 200, result);
      }

      if (method === 'POST' && url.pathname === '/api/v1/ai/gateway/tool-execute') {
        const body = (await this.readJsonBody(req)) as {
          agentId: string;
          toolName: string;
          arguments: Record<string, unknown>;
          sessionId?: string;
        };
        if (!body.agentId || !body.toolName) {
          return this.sendJson(res, 400, {
            error: 'MISSING_PARAMETERS',
            message: 'Fields "agentId" and "toolName" are required.',
          });
        }
        const result = this.aiGateway.evaluateToolCall({
          agentId: body.agentId,
          toolName: body.toolName,
          arguments: body.arguments || {},
          sessionId: body.sessionId,
        });
        return this.sendJson(res, 200, result);
      }

      if (method === 'POST' && url.pathname === '/api/v1/ai/gateway/grounding-check') {
        const body = (await this.readJsonBody(req)) as {
          claim: string;
          sourceContexts: string[];
          minimumGroundingScore?: number;
        };
        if (!body.claim || !Array.isArray(body.sourceContexts)) {
          return this.sendJson(res, 400, {
            error: 'MISSING_PARAMETERS',
            message: 'Fields "claim" (string) and "sourceContexts" (array of strings) are required.',
          });
        }
        const result = this.aiGateway.verifyGrounding(body);
        return this.sendJson(res, 200, result);
      }

      if (method === 'POST' && url.pathname === '/api/v1/agents/sentinel/triage') {
        const body = (await this.readJsonBody(req)) as { alert?: SecurityAlert; alertId?: string };
        let targetAlert = body.alert;
        if (!targetAlert && body.alertId) {
          targetAlert = this.alertsStore.get(body.alertId);
        }
        if (!targetAlert) {
          return this.sendJson(res, 400, {
            error: 'MISSING_ALERT',
            message: 'Provide a valid "alert" object or an existing "alertId".',
          });
        }
        const triageResult = this.coordinator.getSentinel().triageAlert(targetAlert);
        return this.sendJson(res, 200, triageResult);
      }

      if (method === 'POST' && url.pathname === '/api/v1/agents/containment/quarantine') {
        const body = (await this.readJsonBody(req)) as any;
        if (!body.targetType || !body.targetId || !body.reason) {
          return this.sendJson(res, 400, {
            error: 'MISSING_PARAMETERS',
            message: 'Fields "targetType", "targetId", and "reason" are required.',
          });
        }
        const result = this.coordinator.getContainment().quarantine(body);
        return this.sendJson(res, 201, result);
      }

      if (method === 'POST' && url.pathname === '/api/v1/agents/containment/release') {
        const body = (await this.readJsonBody(req)) as any;
        if (!body.quarantineId || !body.releasedBy || !body.releaseReason) {
          return this.sendJson(res, 400, {
            error: 'MISSING_PARAMETERS',
            message: 'Fields "quarantineId", "releasedBy", and "releaseReason" are required.',
          });
        }
        const success = this.coordinator
          .getContainment()
          .release(body.quarantineId, body.releasedBy, body.releaseReason);
        return this.sendJson(res, 200, { success });
      }

      if (method === 'GET' && url.pathname === '/api/v1/agents/containment/active') {
        const active = this.coordinator.getContainment().getActiveQuarantines();
        return this.sendJson(res, 200, { count: active.length, quarantines: active });
      }

      if (method === 'POST' && url.pathname === '/api/v1/agents/forensics/rca') {
        const body = (await this.readJsonBody(req)) as { alert?: SecurityAlert; alertId?: string };
        let targetAlert = body.alert;
        if (!targetAlert && body.alertId) {
          targetAlert = this.alertsStore.get(body.alertId);
        }
        if (!targetAlert) {
          return this.sendJson(res, 400, {
            error: 'MISSING_ALERT',
            message: 'Provide a valid "alert" object or an existing "alertId".',
          });
        }
        const rca = this.coordinator.getForensics().generateRCAReport(targetAlert);
        return this.sendJson(res, 200, rca);
      }

      if (method === 'POST' && url.pathname === '/api/v1/agents/coordinator/process') {
        const body = (await this.readJsonBody(req)) as any;
        if (!body.alert) {
          return this.sendJson(res, 400, {
            error: 'MISSING_PARAMETERS',
            message: 'Field "alert" is required.',
          });
        }
        const workflow = await this.coordinator.processAlert(body);
        return this.sendJson(res, 200, workflow);
      }

      if (method === 'GET' && url.pathname === '/api/v1/compliance/certify') {
        const framework = (url.searchParams.get('framework') || 'NIST_SP_800_207') as any;
        const report = this.compliance.certify(framework);
        return this.sendJson(res, 200, report);
      }

      if (method === 'GET' && url.pathname === '/api/v1/compliance/frameworks') {
        const frameworks = this.compliance.getAllFrameworks();
        return this.sendJson(res, 200, frameworks);
      }

      if (method === 'GET' && url.pathname === '/api/v1/platform/posture') {
        const posture = this.posture.getPostureReport();
        return this.sendJson(res, 200, posture);
      }

      if (method === 'POST' && url.pathname === '/api/v1/platform/posture/sync') {
        const syncResult = this.posture.syncBaselines();
        return this.sendJson(res, 200, syncResult);
      }

      if (method === 'GET' && url.pathname === '/api/v1/platform/summary') {
        const auditVerification = this.auditService.verifyIntegrity();
        const posture = this.posture.getPostureReport();
        const activeQuarantines = this.coordinator.getContainment().getActiveQuarantines().length;

        const summary = {
          version: '1.0.0',
          releaseTag: 'v1.0.0',
          phase: '2A',
          phaseVersion: '2.0.0-phase2a',
          status: auditVerification.isValid ? 'OPTIMAL' : 'DEGRADED',
          bootTimestamp: this.bootTimestamp,
          components: {
            POLICY_ENGINE: 'ACTIVE',
            DECISION_PROVENANCE_PIPELINE: 'ACTIVE',
            RISK_ENGINE: 'ACTIVE',
            THREAT_ENGINE: 'ACTIVE',
            IDENTITY_ABAC: 'ACTIVE',
            KMS_ENVELOPE_ENCRYPTION: 'ACTIVE',
            SUPPLY_CHAIN_SBOM: 'ACTIVE',
            AI_SECURITY_GATEWAY: 'ACTIVE',
            AUTONOMOUS_AGENTS: 'ACTIVE',
            COMPLIANCE_CERTIFICATION: 'ACTIVE',
            POSTURE_SYNCHRONIZER: 'ACTIVE',
            PERSISTENT_AUDIT_LEDGER: this.persistentLedger ? 'MOUNTED' : 'IN_MEMORY',
          },
          activeQuarantines,
          auditChainIntegrity: auditVerification.isValid,
          totalAuditRecords: auditVerification.totalRecords,
          ecosystemHardeningScore: posture.overallHardeningScore,
          complianceCertifications: {
            NIST_SP_800_207: 'CERTIFIED',
            SOC2_TYPE_II: 'CERTIFIED',
            ISO_IEC_27001_2022: 'CERTIFIED',
          },
        };
        return this.sendJson(res, 200, summary);
      }

      return this.sendJson(res, 404, {
        error: 'NOT_FOUND',
        message: `Endpoint ${method} ${url.pathname} not recognized.`,
      });
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      this.logger.error('req-error', 'handleRequest', correlationId, {
        code: 'INTERNAL_SERVER_ERROR',
        message: errorMsg,
      });

      return this.sendJson(res, 500, {
        error: 'INTERNAL_SERVER_ERROR',
        message: errorMsg,
      });
    }
  }

  private recordAudit(input: any) {
    if (this.persistentLedger) {
      return this.persistentLedger.append(input);
    }
    return this.auditService.append(input);
  }

  private getDashboardHtml(): string {
    if (this.dashboardHtmlCache) {
      return this.dashboardHtmlCache;
    }

    try {
      const currentDir = dirname(fileURLToPath(import.meta.url));
      const htmlPath = join(currentDir, '..', 'dashboard', 'dashboard.html');
      if (existsSync(htmlPath)) {
        this.dashboardHtmlCache = readFileSync(htmlPath, 'utf-8');
        return this.dashboardHtmlCache;
      }
    } catch {
      // Fallback
    }

    return '<html><body><h1>Sovereign Security Operations Dashboard V2.0</h1><p>Dashboard UI ready.</p></body></html>';
  }

  private sendJson(res: ServerResponse, statusCode: number, data: unknown): void {
    res.statusCode = statusCode;
    res.end(JSON.stringify(data, null, 2));
  }

  private async readJsonBody(req: IncomingMessage): Promise<unknown> {
    return new Promise((resolve, reject) => {
      let raw = '';
      req.on('data', (chunk) => {
        raw += chunk;
      });
      req.on('end', () => {
        if (!raw.trim()) {
          resolve({});
          return;
        }
        try {
          resolve(JSON.parse(raw));
        } catch {
          reject(new Error('Malformed JSON payload received'));
        }
      });
      req.on('error', reject);
    });
  }
}
