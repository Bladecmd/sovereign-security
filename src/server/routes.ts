/**
 * Sovereign Security — Foundation V0.2
 * Local HTTP API Server & Webhook Ingestion Routes with Real-Time Dashboard & SSE
 *
 * Exposes RESTful endpoints for live webhook emissions, policy evaluations, and dashboard:
 * - GET  / & /dashboard
 * - GET  /api/v1/events/stream (SSE)
 * - GET  /api/v1/telemetry/stats
 * - POST /api/v1/events
 * - POST /api/v1/policy/evaluate
 * - POST /api/v1/alerts
 * - GET  /api/v1/alerts
 * - POST /api/v1/alerts/:id/triage
 * - POST /api/v1/ai/tool-check
 * - POST /api/v1/audit
 * - GET  /api/v1/audit/verify
 * - POST /api/v1/ingest/mtf
 * - GET  /health
 */

import { existsSync, readFileSync } from 'node:fs';
import { IncomingMessage, ServerResponse } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AgentToolPermissionRegistry } from '../ai/tool-permissions.js';
import { AuditService } from '../audit/audit-service.js';
import { MetroTaskForceAdapter, MTFRawSecurityPayload } from '../integrations/mtf/adapter.js';
import { StructuredLogger } from '../observability/logger.js';
import { PolicyEngine } from '../policy/engine.js';
import { RiskEngine } from '../risk/engine.js';
import { ThreatEngine } from '../threat/engine.js';
import { AlertStatus, SecurityAlert } from '../types/alerts.js';
import { CreateSecurityEventInput, SecurityEvent } from '../types/events.js';
import { PolicyEvaluationInput } from '../types/policy.js';
import { safeValidateSecurityAlert, validateSecurityAlert } from '../schemas/alert.schema.js';
import { safeValidateSecurityEvent } from '../schemas/event.schema.js';
import { TelemetryBroadcaster } from './sse.js';

export class SovereignSecurityApiHandler {
  private policyEngine: PolicyEngine;
  private toolRegistry: AgentToolPermissionRegistry;
  private auditService: AuditService;
  private threatEngine: ThreatEngine;
  private mtfAdapter: MetroTaskForceAdapter;
  private alertsStore: Map<string, SecurityAlert> = new Map();
  private recentEvents: SecurityEvent[] = [];
  private broadcaster: TelemetryBroadcaster;
  private logger: StructuredLogger;
  private dashboardHtmlCache: string | null = null;

  constructor(options?: {
    policyEngine?: PolicyEngine;
    toolRegistry?: AgentToolPermissionRegistry;
    auditService?: AuditService;
    threatEngine?: ThreatEngine;
    broadcaster?: TelemetryBroadcaster;
    logger?: StructuredLogger;
  }) {
    this.policyEngine = options?.policyEngine || new PolicyEngine();
    this.toolRegistry = options?.toolRegistry || new AgentToolPermissionRegistry();
    this.auditService = options?.auditService || new AuditService();
    this.threatEngine = options?.threatEngine || new ThreatEngine();
    this.broadcaster = options?.broadcaster || new TelemetryBroadcaster();
    this.mtfAdapter = new MetroTaskForceAdapter(this.threatEngine);
    this.logger =
      options?.logger || new StructuredLogger({ serviceName: 'sovereign-security-api' });
  }

  public async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const method = req.method?.toUpperCase() || 'GET';
    const correlationId = (req.headers['x-correlation-id'] as string) || `api-${Date.now()}`;

    res.setHeader('X-Security-Version', '0.2.0');
    res.setHeader('X-Correlation-Id', correlationId);

    try {
      // 1. Dashboard UI
      if (method === 'GET' && (url.pathname === '/' || url.pathname === '/dashboard')) {
        const html = this.getDashboardHtml();
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.statusCode = 200;
        res.end(html);
        return;
      }

      // 2. Server-Sent Events (SSE) Live Stream
      if (method === 'GET' && url.pathname === '/api/v1/events/stream') {
        this.broadcaster.addClient(res);
        return;
      }

      // JSON endpoints default header
      res.setHeader('Content-Type', 'application/json');

      // 3. Health Check
      if (method === 'GET' && url.pathname === '/health') {
        return this.sendJson(res, 200, {
          status: 'UP',
          service: 'sovereign-security',
          version: '0.2.0',
          subscribers: this.broadcaster.getSubscriberCount(),
          timestamp: new Date().toISOString(),
        });
      }

      // 4. Telemetry Stats & Ecosystem Risk Summary
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

      // 5. Ingest Normalized SecurityEvent
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

        // Broadcast to dashboard
        this.broadcaster.broadcastEvent(validEvent);

        const alerts = this.threatEngine.processEvent(validEvent);
        for (const alert of alerts) {
          this.alertsStore.set(alert.alertId, alert);
          this.broadcaster.broadcastAlert(alert);
        }

        // Record in audit log
        this.auditService.append({
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

      // 6. Evaluate Policy
      if (method === 'POST' && url.pathname === '/api/v1/policy/evaluate') {
        const body = await this.readJsonBody(req);
        const decision = this.policyEngine.evaluate(body as PolicyEvaluationInput);

        this.auditService.append({
          who: (body as PolicyEvaluationInput).actor?.id || 'unknown-actor',
          what: `POLICY_EVALUATION:${(body as PolicyEvaluationInput).action}`,
          where: (body as PolicyEvaluationInput).resource || 'unknown-resource',
          why: 'Runtime policy evaluation request',
          result: decision.decision === 'ALLOW' ? 'SUCCESS' : 'DENIED',
          details: { decision: decision.decision, reason: decision.reason },
        });

        return this.sendJson(res, 200, decision);
      }

      // 7. List Active Alerts
      if (method === 'GET' && url.pathname === '/api/v1/alerts') {
        return this.sendJson(res, 200, {
          alerts: Array.from(this.alertsStore.values()),
          count: this.alertsStore.size,
        });
      }

      // 8. Triage an Alert (Status Update)
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

        this.auditService.append({
          who: body.assignedTo || 'analyst-triage',
          what: `TRIAGE_ALERT:${alertId}`,
          where: '/api/v1/alerts/triage',
          why: `Alert status updated to ${body.status}`,
          result: 'SUCCESS',
          details: { alertId, status: body.status, resolution: body.resolution },
        });

        return this.sendJson(res, 200, { success: true, alert: existing });
      }

      // 9. Ingest Security Alert Directly
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
        return this.sendJson(res, 201, { success: true, alert });
      }

      // 10. Check AI Agent Tool Permissions
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

      // 11. Append Audit Record
      if (method === 'POST' && url.pathname === '/api/v1/audit') {
        const body = await this.readJsonBody(req);
        const record = this.auditService.append(body as any);
        return this.sendJson(res, 201, { success: true, record });
      }

      // 12. Verify Audit Log Hash Chain Integrity
      if (method === 'GET' && url.pathname === '/api/v1/audit/verify') {
        const verification = this.auditService.verifyIntegrity();
        return this.sendJson(res, 200, verification);
      }

      // 13. Ingest Metro Task Force (MTF) Event Webhook
      if (method === 'POST' && url.pathname === '/api/v1/ingest/mtf') {
        const body = await this.readJsonBody(req);
        const { event, alerts } = this.mtfAdapter.ingest(body as MTFRawSecurityPayload);

        this.recentEvents.push(event);
        this.broadcaster.broadcastEvent(event);

        for (const alert of alerts) {
          this.alertsStore.set(alert.alertId, alert);
          this.broadcaster.broadcastAlert(alert);
        }

        return this.sendJson(res, 201, {
          success: true,
          normalizedEvent: event,
          triggeredAlerts: alerts,
        });
      }

      // 404 Route Not Found
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
      // Fallback if bundled
    }

    return '<html><body><h1>Sovereign Security Operations Dashboard V0.2</h1><p>Dashboard UI ready.</p></body></html>';
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
