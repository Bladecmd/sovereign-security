/**
 * Sovereign Security — Foundation V0.1
 * Sovereign OS Integration Adapter (SovereignSecurityClient)
 *
 * Provides a clean, decoupled API client for Sovereign OS to communicate with
 * Sovereign Security without coupling internal databases or schemas.
 */

import { AgentToolPermissionRegistry } from '../../ai/tool-permissions.js';
import { AuditService } from '../../audit/audit-service.js';
import { PolicyEngine } from '../../policy/engine.js';
import { RiskEngine } from '../../risk/engine.js';
import { ThreatEngine } from '../../threat/engine.js';
import { CreateSecurityAlertInput, SecurityAlert } from '../../types/alerts.js';
import { ToolPermissionCheck } from '../../types/ai-security.js';
import { AuditRecord, CreateAuditRecordInput } from '../../types/audit.js';
import { CreateSecurityEventInput, SecurityEvent } from '../../types/events.js';
import { PolicyDecision, PolicyEvaluationInput } from '../../types/policy.js';
import { validateSecurityAlert } from '../../schemas/alert.schema.js';
import { validateSecurityEvent } from '../../schemas/event.schema.js';

export interface SovereignSecurityClientConfig {
  sourceId?: string;
  environment?: string;
  policyEngine?: PolicyEngine;
  toolRegistry?: AgentToolPermissionRegistry;
  auditService?: AuditService;
  threatEngine?: ThreatEngine;
}

export class SovereignSecurityClient {
  private sourceId: string;
  private environment: string;
  private policyEngine: PolicyEngine;
  private toolRegistry: AgentToolPermissionRegistry;
  private auditService: AuditService;
  private threatEngine: ThreatEngine;

  constructor(config: SovereignSecurityClientConfig = {}) {
    this.sourceId = config.sourceId || 'sovereign-os';
    this.environment = config.environment || 'production';
    this.policyEngine = config.policyEngine || new PolicyEngine();
    this.toolRegistry = config.toolRegistry || new AgentToolPermissionRegistry();
    this.auditService = config.auditService || new AuditService();
    this.threatEngine = config.threatEngine || new ThreatEngine();
  }

  /**
   * Emit a normalized SecurityEvent from Sovereign OS
   */
  public async emitSecurityEvent(input: CreateSecurityEventInput): Promise<{
    event: SecurityEvent;
    triggeredAlerts: SecurityAlert[];
  }> {
    const eventId = input.eventId || `sec-evt-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
    const timestamp = input.timestamp || new Date().toISOString();
    const verificationStatus = input.verificationStatus || 'VERIFIED';

    // Auto-calculate risk score if 0 or default
    const calculatedRisk =
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
      source: input.source || this.sourceId,
      environment: input.environment || this.environment,
      riskScore: calculatedRisk,
      verificationStatus,
    };

    // Runtime schema validation
    const validated = validateSecurityEvent(eventPayload);

    // Threat engine processing
    const triggeredAlerts = this.threatEngine.processEvent(validated);

    return {
      event: validated,
      triggeredAlerts,
    };
  }

  /**
   * Evaluate a requested business action against security policies
   */
  public async checkPolicy(input: PolicyEvaluationInput): Promise<PolicyDecision> {
    return this.policyEngine.evaluate(input);
  }

  /**
   * Report an operational security alert from Sovereign OS
   */
  public async reportSecurityAlert(input: CreateSecurityAlertInput): Promise<SecurityAlert> {
    const alertId = input.alertId || `alert-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const createdAt = input.createdAt || new Date().toISOString();
    const status = input.status || 'OPEN';

    const alertPayload: SecurityAlert = {
      ...input,
      alertId,
      createdAt,
      status,
    };

    return validateSecurityAlert(alertPayload);
  }

  /**
   * Check whether an AI agent (e.g. VEGA) has permission to invoke a tool
   */
  public async checkAgentPermission(
    agentId: string,
    toolName: string,
    parameters: Record<string, unknown> = {}
  ): Promise<ToolPermissionCheck> {
    return this.toolRegistry.checkPermission(agentId, toolName, parameters);
  }

  /**
   * Record an immutable audit log entry for sensitive Sovereign OS operations
   */
  public async recordAuditEvent(input: CreateAuditRecordInput): Promise<AuditRecord> {
    return this.auditService.append(input);
  }
}
