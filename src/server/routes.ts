/**
 * Sovereign Security — Foundation V0.1
 * Local HTTP API Server & Webhook Ingestion Routes
 *
 * Exposes RESTful endpoints for live webhook emissions and policy evaluations:
 * - POST /api/v1/events
 * - POST /api/v1/policy/evaluate
 * - POST /api/v1/alerts
 * - GET  /api/v1/alerts
 * - POST /api/v1/ai/tool-check
 * - POST /api/v1/audit
 * - GET  /api/v1/audit/verify
 * - POST /api/v1/ingest/mtf
 * - GET  /health
 */

import { IncomingMessage, ServerResponse } from 'node:http';
import { AgentToolPermissionRegistry } from '../ai/tool-permissions.js';
import { AuditService } from '../audit/audit-service.js';
import { MetroTaskForceAdapter, MTFRawSecurityPayload } from '../integrations/mtf/adapter.js';
import { StructuredLogger } from '../observability/logger.js';
import { PolicyEngine } from '../policy/engine.js';
import { RiskEngine } from '../risk/engine.js';
import { ThreatEngine } from '../threat/engine.js';
import { SecurityAlert } from '../types/alerts.js';
import { CreateSecurityEventInput, SecurityEvent } from '../types/events.js';
import { PolicyEvaluationInput } from '../types/policy.js';
import { safeValidateSecurityAlert, validateSecurityAlert } from '../schemas/alert.schema.js';
import { safeValidateSecurityEvent } from '../schemas/event.schema.js';

export class SovereignSecurityApiHandler {
  private policyEngine: PolicyEngine;
  private toolRegistry: AgentToolPermissionRegistry;
  private auditService: AuditService;
  private threatEngine: ThreatEngine;
  private mtfAdapter: MetroTaskForceAdapter;
  private alertsStore: Map<string, SecurityAlert> = new Map();
  private logger: StructuredLogger;

  constructor(options?: {
    policyEngine?: PolicyEngine;
    toolRegistry?: AgentToolPermissionRegistry;
    auditService?: AuditService;
    threatEngine?: ThreatEngine;
    logger?: StructuredLogger;
  }) {
    this.policyEngine = options?.policyEngine || new PolicyEngine();
    this.toolRegistry = options?.toolRegistry || new AgentToolPermissionRegistry();
    this.auditService = options?.auditService || new AuditService();
    this.threatEngine = options?.threatEngine || new ThreatEngine();
    this.mtfAdapter = new MetroTaskForceAdapter(this.threatEngine);
    this.logger =
      options?.logger || new StructuredLogger({ serviceName: 'sovereign-security-api' });
  }

  public async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const method = req.method?.toUpperCase() || 'GET';
    const correlationId = (req.headers['x-correlation-id'] as string) || `api-${Date.now()}`;

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('X-Security-Version', '0.1.0');
    res.setHeader('X-Correlation-Id', correlationId);

    try {
      // 1. Health Check
      if (method === 'GET' && url.pathname === '/health') {
        return this.sendJson(res, 200, {
          status: 'UP',
          service: 'sovereign-security',
          version: '0.1.0',
          timestamp: new Date().toISOString(),
        });
      }

      // 2. Ingest Normalized SecurityEvent
      if (method === 'POST' && url.pathname === '/api/v1/events') {
        const body = await this.readJsonBody(req);
        const input = body as CreateSecurityEventInput;

        const eventId = input.eventId || `evt-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
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

        const alerts = this.threatEngine.processEvent(validation.data);
        for (const alert of alerts) {
          this.alertsStore.set(alert.alertId, alert);
        }

        // Record in audit log
        this.auditService.append({
          who: validation.data.actorId,
          what: `INGEST_EVENT:${validation.data.eventType}`,
          where: url.pathname,
          why: 'Security event telemetry ingestion',
          result: 'SUCCESS',
          details: { eventId: validation.data.eventId, category: validation.data.category },
        });

        return this.sendJson(res, 201, {
          success: true,
          event: validation.data,
          triggeredAlerts: alerts,
        });
      }

      // 3. Evaluate Policy
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

      // 4. List Active Alerts
      if (method === 'GET' && url.pathname === '/api/v1/alerts') {
        return this.sendJson(res, 200, {
          alerts: Array.from(this.alertsStore.values()),
          count: this.alertsStore.size,
        });
      }

      // 5. Ingest Security Alert Directly
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
        return this.sendJson(res, 201, { success: true, alert });
      }

      // 6. Check AI Agent Tool Permissions
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

      // 7. Append Audit Record
      if (method === 'POST' && url.pathname === '/api/v1/audit') {
        const body = await this.readJsonBody(req);
        const record = this.auditService.append(body as any);
        return this.sendJson(res, 201, { success: true, record });
      }

      // 8. Verify Audit Log Hash Chain Integrity
      if (method === 'GET' && url.pathname === '/api/v1/audit/verify') {
        const verification = this.auditService.verifyIntegrity();
        return this.sendJson(res, 200, verification);
      }

      // 9. Ingest Metro Task Force (MTF) Event Webhook
      if (method === 'POST' && url.pathname === '/api/v1/ingest/mtf') {
        const body = await this.readJsonBody(req);
        const { event, alerts } = this.mtfAdapter.ingest(body as MTFRawSecurityPayload);

        for (const alert of alerts) {
          this.alertsStore.set(alert.alertId, alert);
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
