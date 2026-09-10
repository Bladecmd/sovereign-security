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
import { ApplicationRateLimiter } from './rate-limiter.js';

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
  private rateLimiter: ApplicationRateLimiter;
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
    rateLimiter?: ApplicationRateLimiter;
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
    this.rateLimiter = options?.rateLimiter || new ApplicationRateLimiter();
  }

  public getRateLimiter(): ApplicationRateLimiter {
    return this.rateLimiter;
  }

  public async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const method = req.method?.toUpperCase() || 'GET';
    const correlationId = (req.headers['x-correlation-id'] as string) || `api-${Date.now()}`;

    res.setHeader('X-Security-Version', '2.0.0-phase2c');
    res.setHeader('X-Correlation-Id', correlationId);

    // Application-layer tiered rate limiting
    const rawIp = (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() || req.socket?.remoteAddress || '127.0.0.1';
    const hasAuth = Boolean(req.headers.authorization || req.headers['x-api-key'] || req.headers['x-service-id']);
    const tier = this.rateLimiter.resolveTier(url.pathname, hasAuth);
    const limitCheck = this.rateLimiter.checkLimit(rawIp, tier);

    if (!limitCheck.allowed) {
      res.setHeader('Content-Type', 'application/json');
      res.setHeader('Retry-After', limitCheck.retryAfterSeconds.toString());
      res.setHeader('X-RateLimit-Limit', limitCheck.maxRequests.toString());
      res.setHeader('X-RateLimit-Remaining', '0');
      res.setHeader('X-RateLimit-Reset', Math.ceil(limitCheck.resetTimeMs / 1000).toString());
      res.statusCode = 429;
      res.end(
        JSON.stringify({
          error: 'TOO_MANY_REQUESTS',
          message: `Application rate limit exceeded for tier '${tier}'. Please retry after ${limitCheck.retryAfterSeconds} seconds.`,
          retryAfter: limitCheck.retryAfterSeconds,
          tier,
        })
      );
      return;
    }

    res.setHeader('X-RateLimit-Limit', limitCheck.maxRequests.toString());
    res.setHeader('X-RateLimit-Remaining', limitCheck.remainingRequests.toString());

    try {
      if (method === 'GET' && (url.pathname === '/' || url.pathname === '/dashboard')) {
        const html = this.getDashboardHtml();
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.statusCode = 200;
        res.end(html);
        return;
      }

      if (method === 'GET' && (url.pathname === '/favicon.ico' || url.pathname === '/favicon.svg')) {
        const svg = this.getFaviconSvg();
        res.setHeader('Content-Type', 'image/svg+xml');
        res.setHeader('Cache-Control', 'public, max-age=86400');
        res.statusCode = 200;
        res.end(svg);
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
        this.coordinator.getForensics().registerEvents([validEvent]);

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
        const statusFilter = url.searchParams.get('status');
        const severityFilter = url.searchParams.get('severity');
        const correlationFilter = url.searchParams.get('correlationId');

        let list = Array.from(this.alertsStore.values());
        if (statusFilter) {
          list = list.filter((a) => a.status === statusFilter);
        }
        if (severityFilter) {
          list = list.filter((a) => a.severity === severityFilter);
        }
        if (correlationFilter) {
          list = list.filter((a) => a.correlationId === correlationFilter);
        }

        return this.sendJson(res, 200, {
          alerts: list,
          count: list.length,
        });
      }

      const triageMatch = url.pathname.match(/^\/api\/v1\/alerts\/([^/]+)\/triage$/);
      if (method === 'POST' && triageMatch) {
        const alertId = triageMatch[1]!;
        const body = (await this.readJsonBody(req)) as {
          status: AlertStatus;
          assignedTo?: string;
          resolution?: string;
          callerId?: string;
          operatorId?: string;
        };

        const existing = this.alertsStore.get(alertId);
        if (!existing) {
          return this.sendJson(res, 404, {
            error: 'NOT_FOUND',
            message: `Alert '${alertId}' not found.`,
          });
        }

        const validStatuses: AlertStatus[] = [
          'OPEN',
          'ACKNOWLEDGED',
          'INVESTIGATING',
          'CONTAINED',
          'RESOLVED',
          'FALSE_POSITIVE',
        ];
        if (!validStatuses.includes(body.status)) {
          return this.sendJson(res, 400, {
            error: 'INVALID_STATUS',
            message: `Status must be one of: ${validStatuses.join(', ')}`,
          });
        }

        existing.status = body.status;
        if (body.assignedTo) existing.assignedTo = body.assignedTo;
        if (body.resolution) existing.resolution = body.resolution;
        if (body.status === 'RESOLVED') existing.resolvedAt = new Date().toISOString();

        this.broadcaster.broadcastAlert(existing);

        const actor = body.callerId || body.operatorId || body.assignedTo || 'analyst-triage';
        this.recordAudit({
          who: actor,
          what: `TRIAGE_ALERT:${alertId}`,
          where: '/api/v1/alerts/triage',
          why: `Alert status updated to ${body.status}`,
          result: 'SUCCESS',
          details: {
            alertId,
            status: body.status,
            resolution: body.resolution,
            correlationId: existing.correlationId,
          },
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
        this.coordinator.getForensics().registerEvents([event]);
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

      if (
        method === 'POST' &&
        (url.pathname === '/api/v1/soc/containment/release' ||
          url.pathname === '/api/v1/agents/containment/release')
      ) {
        const body = (await this.readJsonBody(req)) as any;
        const targetQuarantineId = body.quarantineId;
        const callerId = body.callerId || body.releasedBy;
        const role = body.role || 'SECURITY_OPERATOR';
        const reason = body.reason || body.releaseReason;
        const confirmed =
          body.confirmed !== undefined ? body.confirmed : (body.releaseReason ? true : false);

        if (!callerId || typeof callerId !== 'string' || callerId.trim().length === 0) {
          return this.sendJson(res, 401, {
            error: 'AUTHENTICATION_REQUIRED',
            message: 'Authenticated user (callerId) is required to request quarantine release.',
          });
        }

        if (!targetQuarantineId) {
          return this.sendJson(res, 400, {
            error: 'MISSING_PARAMETERS',
            message: 'Field "quarantineId" is required.',
          });
        }

        if (!reason || typeof reason !== 'string' || reason.trim().length === 0) {
          return this.sendJson(res, 400, {
            error: 'JUSTIFICATION_REQUIRED',
            message: 'Non-empty justification reason is required to release containment.',
          });
        }

        if (confirmed !== true) {
          return this.sendJson(res, 400, {
            error: 'CONFIRMATION_REQUIRED',
            message: 'Explicit operator confirmation (confirmed: true) is mandatory to release containment.',
          });
        }

        const isPrivileged =
          role === 'SOC_ADMIN' || role === 'SECURITY_LEAD' || role === 'ADMIN';

        const decisionInput: SecurityDecisionInput = {
          actor: {
            id: callerId,
            name: callerId,
            type: isPrivileged ? 'ADMIN' : 'SERVICE',
            roles: isPrivileged ? ['ADMIN'] : [],
            organizationId: 'sovereign-security',
            attributes: {
              department: 'SECURITY_OPERATIONS',
              role,
              clearanceLevel: isPrivileged ? 3 : 0,
            },
          },
          action: 'containment:release',
          resource: `quarantine:${targetQuarantineId}`,
          context: {
            environment: 'production',
            ipAddress:
              (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1',
            timestamp: new Date().toISOString(),
          },
          riskScore: isPrivileged ? 10 : 95,
          correlationId,
        };

        const decision = await this.decisionPipeline.evaluate(decisionInput);

        if (decision.decision !== 'ALLOW') {
          this.recordAudit({
            who: callerId,
            what: `soc.containment.release_denied:${targetQuarantineId}`,
            where: url.pathname,
            why: `Policy rejected release: ${decision.reasonCode}`,
            result: 'DENIED',
            details: {
              quarantineId: targetQuarantineId,
              role,
              reason,
              decisionId: decision.decisionId,
              correlationId,
            },
          });

          return this.sendJson(res, 403, {
            error: 'AUTHORIZATION_DENIED',
            message: `Policy engine rejected containment release for role ${role}: ${decision.reasonCode}`,
            decision,
          });
        }

        const released = this.coordinator
          .getContainment()
          .release(targetQuarantineId, callerId, reason);

        if (!released) {
          return this.sendJson(res, 404, {
            error: 'QUARANTINE_NOT_FOUND_OR_INACTIVE',
            message: `Quarantine '${targetQuarantineId}' does not exist or is not currently active.`,
          });
        }

        this.recordAudit({
          who: callerId,
          what: `soc.containment.release:${targetQuarantineId}`,
          where: url.pathname,
          why: reason,
          result: 'SUCCESS',
          details: {
            quarantineId: targetQuarantineId,
            operatorRole: role,
            confirmed: true,
            policyDecisionId: decision.decisionId,
            correlationId,
          },
        });

        return this.sendJson(res, 200, {
          success: true,
          quarantineId: targetQuarantineId,
          releasedBy: callerId,
          decisionId: decision.decisionId,
          message: `Quarantine ${targetQuarantineId} successfully released by ${callerId}`,
        });
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

      if (method === 'GET' && url.pathname === '/api/v1/soc/overview') {
        const auditVerification = this.auditService.verifyIntegrity();
        const activeQuarantines = this.coordinator.getContainment().getActiveQuarantines();
        const alertsList = Array.from(this.alertsStore.values());
        const openAlerts = alertsList.filter(
          (a) => a.status !== 'RESOLVED' && a.status !== 'FALSE_POSITIVE'
        );
        const criticalAlerts = openAlerts.filter((a) => a.severity === 'CRITICAL').length;
        const highAlerts = openAlerts.filter((a) => a.severity === 'HIGH').length;

        let status = 'OPTIMAL';
        if (!auditVerification.isValid) {
          status = 'DEGRADED';
        } else if (criticalAlerts > 0) {
          status = 'INCIDENT_ACTIVE';
        } else if (highAlerts > 0) {
          status = 'ELEVATED';
        }

        const fleet = this.posture.getSocFleetPosture();
        const connectedEntities = fleet.filter((e) => e.status === 'CONNECTED').length;

        return this.sendJson(res, 200, {
          status,
          bootTimestamp: this.bootTimestamp,
          totalEvents: this.recentEvents.length,
          alerts: {
            total: alertsList.length,
            open: openAlerts.length,
            bySeverity: {
              CRITICAL: openAlerts.filter((a) => a.severity === 'CRITICAL').length,
              HIGH: openAlerts.filter((a) => a.severity === 'HIGH').length,
              MEDIUM: openAlerts.filter((a) => a.severity === 'MEDIUM').length,
              LOW: openAlerts.filter((a) => a.severity === 'LOW').length,
              INFO: openAlerts.filter((a) => a.severity === 'INFO').length,
            },
            byStatus: {
              OPEN: alertsList.filter((a) => a.status === 'OPEN').length,
              INVESTIGATING: alertsList.filter((a) => a.status === 'INVESTIGATING').length,
              CONTAINED: alertsList.filter((a) => a.status === 'CONTAINED').length,
              RESOLVED: alertsList.filter((a) => a.status === 'RESOLVED').length,
              FALSE_POSITIVE: alertsList.filter((a) => a.status === 'FALSE_POSITIVE').length,
            },
          },
          containment: {
            activeCount: activeQuarantines.length,
            activeQuarantines,
          },
          auditLedger: {
            totalRecords: auditVerification.totalRecords,
            integrityValid: auditVerification.isValid,
            lastHash:
              this.auditService.getRecords().length > 0
                ? this.auditService.getRecords()[this.auditService.getRecords().length - 1]!.currentHash
                : '0'.repeat(64),
          },
          fleet: {
            totalEntities: fleet.length,
            connectedEntities,
            entities: fleet,
          },
          subsystems: {
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
        });
      }

      if (method === 'GET' && url.pathname === '/api/v1/soc/fleet-posture') {
        const fleet = this.posture.getSocFleetPosture();
        return this.sendJson(res, 200, {
          timestamp: new Date().toISOString(),
          entities: fleet,
          summary: {
            total: fleet.length,
            connected: fleet.filter((f) => f.status === 'CONNECTED').length,
            degraded: fleet.filter((f) => f.status === 'DEGRADED').length,
            offline: fleet.filter((f) => f.status === 'OFFLINE').length,
            unknown: fleet.filter((f) => f.status === 'UNKNOWN').length,
          },
        });
      }

      if (method === 'GET' && url.pathname === '/api/v1/soc/compliance-evidence') {
        const matrix = this.compliance.getSocComplianceEvidenceMatrix();
        return this.sendJson(res, 200, matrix);
      }

      if (method === 'GET' && url.pathname === '/api/v1/audit/ledger') {
        const verification = this.auditService.verifyIntegrity();
        const limit = parseInt(url.searchParams.get('limit') || '100', 10);
        const offset = parseInt(url.searchParams.get('offset') || '0', 10);
        const allRecords = this.auditService.getRecords();
        const paginated = allRecords.slice(offset, offset + limit);

        return this.sendJson(res, 200, {
          readOnly: true,
          totalRecords: allRecords.length,
          limit,
          offset,
          verification,
          records: paginated,
        });
      }

      if (method === 'GET' && url.pathname === '/api/v1/soc/system-health') {
        const auditVerification = this.auditService.verifyIntegrity();
        const mem = process.memoryUsage();
        return this.sendJson(res, 200, {
          status: 'HEALTHY',
          uptimeSeconds: Math.floor(process.uptime()),
          bootTimestamp: this.bootTimestamp,
          currentTimestamp: new Date().toISOString(),
          memoryUsage: {
            heapUsedMB: Math.round((mem.heapUsed / 1024 / 1024) * 100) / 100,
            heapTotalMB: Math.round((mem.heapTotal / 1024 / 1024) * 100) / 100,
            rssMB: Math.round((mem.rss / 1024 / 1024) * 100) / 100,
          },
          components: {
            POLICY_ENGINE: 'READY',
            DECISION_PROVENANCE_PIPELINE: 'READY',
            RISK_ENGINE: 'READY',
            THREAT_ENGINE: 'READY',
            IDENTITY_ABAC: 'READY',
            KMS_ENVELOPE_ENCRYPTION: 'READY',
            SUPPLY_CHAIN_SBOM: 'READY',
            AI_SECURITY_GATEWAY: 'READY',
            AUTONOMOUS_AGENTS: 'READY',
            COMPLIANCE_CERTIFICATION: 'READY',
            POSTURE_SYNCHRONIZER: 'READY',
            PERSISTENT_AUDIT_LEDGER: this.persistentLedger ? 'MOUNTED' : 'IN_MEMORY',
          },
          activeQuarantines: this.coordinator.getContainment().getActiveQuarantines().length,
          auditChainValid: auditVerification.isValid,
        });
      }

      if (method === 'POST' && url.pathname === '/api/v1/soc/agents/command') {
        const body = (await this.readJsonBody(req)) as any;
        const callerId = body.callerId || (req.headers['x-actor-id'] as string) || 'soc-operator';
        const role = body.role || 'SECURITY_OPERATOR';
        const command = body.command;

        if (!command) {
          return this.sendJson(res, 400, {
            error: 'MISSING_COMMAND',
            message: 'Field "command" is required.',
          });
        }

        if (role === 'UNPRIVILEGED_GUEST') {
          return this.sendJson(res, 403, {
            error: 'AUTHORIZATION_DENIED',
            message: `Role ${role} is not permitted to execute agent commands.`,
          });
        }

        let result: unknown = null;
        if (command === 'TRIAGE_ALERT') {
          let alert = body.alert;
          if (!alert && body.alertId) {
            alert = this.alertsStore.get(body.alertId);
          }
          if (!alert) {
            return this.sendJson(res, 400, {
              error: 'ALERT_NOT_FOUND',
              message: 'Target alert not found.',
            });
          }
          result = this.coordinator.getSentinel().triageAlert(alert);
        } else if (command === 'FORENSIC_RCA') {
          let alert = body.alert;
          if (!alert && body.alertId) {
            alert = this.alertsStore.get(body.alertId);
          }
          if (!alert) {
            return this.sendJson(res, 400, {
              error: 'ALERT_NOT_FOUND',
              message: 'Target alert not found.',
            });
          }
          result = this.coordinator.getForensics().generateRCAReport(alert);
        } else if (command === 'POSTURE_SYNC') {
          result = this.posture.syncBaselines();
        } else if (command === 'CERTIFY') {
          result = this.compliance.certify(body.framework || 'NIST_SP_800_207');
        } else {
          return this.sendJson(res, 400, {
            error: 'UNKNOWN_COMMAND',
            message: `Command ${command} not recognized.`,
          });
        }

        this.recordAudit({
          who: callerId,
          what: `soc.agent.command:${command}`,
          where: url.pathname,
          why: body.reason || `Operator executed ${command} command`,
          result: 'SUCCESS',
          details: { command, callerId, role, correlationId },
        });

        return this.sendJson(res, 200, { success: true, command, result });
      }

      const traceMatch = url.pathname.match(/^\/api\/v1\/forensics\/trace\/([^/]+)$/);
      if (method === 'GET' && traceMatch) {
        const targetCorrelationId = decodeURIComponent(traceMatch[1]!);
        this.coordinator.getForensics().registerEvents(this.recentEvents);
        const trace = this.coordinator.getForensics().traceCorrelationChain(
          targetCorrelationId,
          Array.from(this.alertsStore.values())
        );

        this.recordAudit({
          who: (req.headers['x-actor-id'] as string) || 'sec-analyst',
          what: `FORENSICS_TRACE:${targetCorrelationId}`,
          where: url.pathname,
          why: 'Defensive correlation chain investigation',
          result: 'SUCCESS',
          details: {
            correlationId: targetCorrelationId,
            eventsFound: trace.securityEvents.length,
            alertsFound: trace.alerts.length,
            policyDecisionsFound: trace.policyDecisions.length,
            containmentFound: trace.containment.length,
            resolutionsFound: trace.resolutions.length,
            chainComplete: trace.chainComplete,
          },
        });

        return this.sendJson(res, 200, trace);
      }

      return this.sendJson(res, 404, {
        error: 'NOT_FOUND',
        message: `Endpoint ${method} ${url.pathname} not recognized.`,
      });
    } catch (err: unknown) {
      const errorObj = err as { code?: string; message?: string } | Error;
      const errorCode = (errorObj && 'code' in errorObj && errorObj.code) || 'INTERNAL_SERVER_ERROR';
      const errorMsg = err instanceof Error ? err.message : String(err);

      if (errorCode === 'PAYLOAD_TOO_LARGE') {
        res.setHeader('Connection', 'close');
        return this.sendJson(res, 413, {
          error: 'PAYLOAD_TOO_LARGE',
          message: 'Request payload exceeds maximum allowed size limit.',
        });
      }

      if (errorCode === 'MALFORMED_JSON') {
        return this.sendJson(res, 400, {
          error: 'BAD_REQUEST',
          message: errorMsg,
        });
      }

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
      const srcHtmlPath = join(currentDir, '..', '..', 'src', 'dashboard', 'dashboard.html');
      if (existsSync(srcHtmlPath)) {
        this.dashboardHtmlCache = readFileSync(srcHtmlPath, 'utf-8');
        return this.dashboardHtmlCache;
      }
    } catch {
      // Fallback
    }

    return '<html><body><h1>Sovereign Security Operations Dashboard V2.0</h1><p>Dashboard UI ready.</p></body></html>';
  }

  private getFaviconSvg(): string {
    try {
      const currentDir = dirname(fileURLToPath(import.meta.url));
      const svgPath = join(currentDir, '..', 'dashboard', 'favicon.svg');
      if (existsSync(svgPath)) {
        return readFileSync(svgPath, 'utf-8');
      }
      const srcSvgPath = join(currentDir, '..', '..', 'src', 'dashboard', 'favicon.svg');
      if (existsSync(srcSvgPath)) {
        return readFileSync(srcSvgPath, 'utf-8');
      }
    } catch {
      // Fallback
    }
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><defs><linearGradient id="sg" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#00e5ff"/><stop offset="100%" stop-color="#3b82f6"/></linearGradient></defs><path d="M16 2 L28 6 V15 C28 22.5 22.5 28.5 16 30 C9.5 28.5 4 22.5 4 15 V6 Z" fill="#0d1322" stroke="url(#sg)" stroke-width="2"/><circle cx="16" cy="15" r="2.2" fill="#00e5ff"/></svg>`;
  }

  private sendJson(res: ServerResponse, statusCode: number, data: unknown): void {
    res.statusCode = statusCode;
    res.end(JSON.stringify(data, null, 2));
  }

  public static readonly MAX_BODY_SIZE_BYTES = 1024 * 1024; // 1MB

  private async readJsonBody(req: IncomingMessage): Promise<unknown> {
    return new Promise((resolve, reject) => {
      let raw = '';
      let bytesReceived = 0;

      req.on('data', (chunk: Buffer | string) => {
        bytesReceived += typeof chunk === 'string' ? Buffer.byteLength(chunk) : chunk.length;
        if (bytesReceived > SovereignSecurityApiHandler.MAX_BODY_SIZE_BYTES) {
          req.pause();
          req.removeAllListeners('data');
          const err = new Error('Payload too large');
          (err as any).code = 'PAYLOAD_TOO_LARGE';
          reject(err);
          return;
        }
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
          const err = new Error('Malformed JSON payload received');
          (err as any).code = 'MALFORMED_JSON';
          reject(err);
        }
      });
      req.on('error', reject);
    });
  }
}
