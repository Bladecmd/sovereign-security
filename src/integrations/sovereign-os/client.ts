/**
 * Sovereign Security — Phase 2B: Ecosystem Fleet Wiring
 * Sovereign OS Security Mediation Client (SovereignSecurityClient)
 *
 * Mediates all security-sensitive interactions from Sovereign OS:
 * - Executive action policy checks
 * - VEGA tool invocation (strictly mediated - VEGA never directly executes privileged tools)
 * - Privileged configuration changes
 * - Sensitive data access
 * - External API actions
 * - Agent actions
 *
 * Correlation Pipeline:
 * VEGA tool call / Exec Action -> Policy Evaluation -> Decision (ALLOW/DENY/APPROVAL/ESCALATE)
 * -> Execution only if allowed -> SecurityEvent emitted -> Tamper-evident Audit Ledger record.
 */

import { AgentToolPermissionRegistry } from '../../ai/tool-permissions.js';
import { AuditService } from '../../audit/audit-service.js';
import { SecurityDecisionPipeline } from '../../policy/provenance.js';
import { RiskEngine } from '../../risk/engine.js';
import { ThreatEngine } from '../../threat/engine.js';
import { CreateSecurityAlertInput, SecurityAlert } from '../../types/alerts.js';
import { ToolPermissionCheck } from '../../types/ai-security.js';
import { AuditRecord, CreateAuditRecordInput } from '../../types/audit.js';
import { CreateSecurityEventInput, SecurityEvent } from '../../types/events.js';
import { IdentitySubject } from '../../types/identity.js';
import { PolicyDecision, PolicyEvaluationInput } from '../../types/policy.js';
import { validateSecurityAlert } from '../../schemas/alert.schema.js';
import { validateSecurityEvent } from '../../schemas/event.schema.js';
import { EcosystemAuthenticator, EcosystemCredentials } from '../auth/credentials.js';

export interface SovereignSecurityClientConfig {
  sourceId?: string;
  businessId?: string;
  environment?: string;
  apiKey?: string;
  toolRegistry?: AgentToolPermissionRegistry;
  auditService?: AuditService;
  threatEngine?: ThreatEngine;
  decisionPipeline?: SecurityDecisionPipeline;
}

export interface VegaToolInvocationRequest {
  agentId: string; // e.g. 'vega' or 'vega-ops'
  toolName: string;
  parameters: Record<string, unknown>;
  correlationId?: string;
  executor: () => Promise<unknown> | unknown;
}

export interface VegaToolInvocationResult {
  permitted: boolean;
  decision: PolicyDecision;
  executionResult?: unknown;
  securityEvent?: SecurityEvent;
  auditRecord?: AuditRecord;
  rejectionReason?: string;
}

export interface ExecutiveActionRequest {
  executiveId: string;
  action: string;
  resource: string;
  parameters?: Record<string, unknown>;
  correlationId?: string;
  executor?: () => Promise<unknown> | unknown;
}

export class SovereignSecurityClient {
  private sourceId: string;
  private businessId: string;
  private environment: string;
  private apiKey: string;
  private toolRegistry: AgentToolPermissionRegistry;
  private auditService: AuditService;
  private threatEngine: ThreatEngine;
  private decisionPipeline: SecurityDecisionPipeline;

  constructor(config: SovereignSecurityClientConfig = {}) {
    this.sourceId = config.sourceId || 'sovereign-os';
    this.businessId = config.businessId || 'sovereign-core-hq';
    this.environment = config.environment || 'production';
    this.apiKey = config.apiKey || 'sec_key_sovereign_os_prod_secret';
    this.toolRegistry = config.toolRegistry || new AgentToolPermissionRegistry();
    this.auditService = config.auditService || new AuditService();
    this.threatEngine = config.threatEngine || new ThreatEngine();
    this.decisionPipeline = config.decisionPipeline || new SecurityDecisionPipeline({
      auditService: this.auditService,
    });
  }

  public generateCredentials(): EcosystemCredentials {
    return {
      serviceId: this.sourceId,
      businessId: this.businessId,
      environment: this.environment,
      apiKey: this.apiKey,
      timestamp: new Date().toISOString(),
      nonce: `non-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
    };
  }

  /**
   * Mediates VEGA AI tool invocation.
   * VEGA must NOT directly execute privileged tools.
   */
  public async invokeVegaTool(request: VegaToolInvocationRequest): Promise<VegaToolInvocationResult> {
    const correlationId = request.correlationId || `corr-vega-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const creds = this.generateCredentials();
    const auth = EcosystemAuthenticator.verifyCredentials(creds);

    if (!auth.authenticated) {
      return {
        permitted: false,
        decision: {
          decision: 'DENY',
          reason: `Ecosystem authentication failed: ${auth.errorMessage}`,
          evaluatedAt: new Date().toISOString(),
        },
        rejectionReason: `AUTH_FAILED: ${auth.errorMessage}`,
      };
    }

    // Check agent tool permissions registry
    const permCheck = await this.toolRegistry.checkPermission(
      request.agentId,
      request.toolName,
      request.parameters
    );

    if (permCheck.decision !== 'ALLOW') {
      const audit = this.auditService.append({
        who: request.agentId,
        what: `VEGA_TOOL_BLOCKED:${request.toolName}`,
        where: `sovereign-os/tools/${request.toolName}`,
        why: permCheck.reason,
        result: 'DENIED',
        details: { parameters: request.parameters, correlationId },
      });

      return {
        permitted: false,
        decision: {
          decision: permCheck.decision,
          reason: permCheck.reason,
          evaluatedAt: new Date().toISOString(),
        },
        rejectionReason: permCheck.reason,
        auditRecord: audit,
      };
    }

    // Evaluate via Zero-Trust Decision Pipeline
    const actorSubject: IdentitySubject = {
      id: request.agentId,
      type: 'AGENT',
      name: `AI Agent (${request.agentId})`,
      roles: ['AGENT'],
      organizationId: this.businessId,
    };

    const provenance = this.decisionPipeline.evaluate({
      actor: actorSubject,
      action: `tool:${request.toolName}`,
      resource: `ai-tool/${request.toolName}`,
      context: {
        environment: this.environment,
        timestamp: new Date().toISOString(),
        metadata: {
          agentId: request.agentId,
          parameters: request.parameters,
          correlationId,
        },
      },
      riskScore: 10,
      correlationId,
    });

    const isAllowed = provenance.decision === 'ALLOW';

    if (!isAllowed) {
      const audit = this.auditService.append({
        who: request.agentId,
        what: `VEGA_TOOL_DENIED_BY_POLICY:${request.toolName}`,
        where: `sovereign-os/tools/${request.toolName}`,
        why: provenance.reasonCode,
        result: 'DENIED',
        details: {
          decisionId: provenance.decisionId,
          parameters: request.parameters,
          correlationId,
        },
      });

      return {
        permitted: false,
        decision: {
          decision: provenance.decision,
          reason: provenance.reasonCode,
          evaluatedAt: provenance.timestamp,
        },
        rejectionReason: provenance.reasonCode,
        auditRecord: audit,
      };
    }

    // Policy permitted: execute executor
    let executionResult: unknown;
    try {
      executionResult = await request.executor();
    } catch (err: any) {
      const audit = this.auditService.append({
        who: request.agentId,
        what: `VEGA_TOOL_EXECUTION_FAILED:${request.toolName}`,
        where: `sovereign-os/tools/${request.toolName}`,
        why: err?.message || 'Execution error',
        result: 'FAILURE',
        details: { error: String(err), correlationId },
      });

      return {
        permitted: true,
        decision: {
          decision: provenance.decision,
          reason: provenance.reasonCode,
          evaluatedAt: provenance.timestamp,
        },
        rejectionReason: `EXECUTION_FAILED: ${err?.message}`,
        auditRecord: audit,
      };
    }

    // Emit SecurityEvent
    const { event } = await this.emitSecurityEvent({
      source: this.sourceId,
      businessId: this.businessId,
      environment: this.environment,
      eventType: 'AI_TOOL_EXECUTION',
      riskScore: 10,
      actorId: request.agentId,
      action: `execute-tool:${request.toolName}`,
      resourceId: `tool/${request.toolName}`,
      category: 'AI_SECURITY',
      severity: 'LOW',
      result: 'SUCCESS',
      correlationId,
      metadata: {
        parameters: request.parameters,
        decisionId: provenance.decisionId,
      },
    });

    // Record immutable audit ledger entry
    const audit = this.auditService.append({
      who: request.agentId,
      what: `VEGA_TOOL_EXECUTED:${request.toolName}`,
      where: `sovereign-os/tools/${request.toolName}`,
      why: 'Authorized by Policy Engine and AI Tool Permission Registry',
      result: 'SUCCESS',
      details: {
        decisionId: provenance.decisionId,
        eventId: event.eventId,
        correlationId,
      },
    });

    return {
      permitted: true,
      decision: {
        decision: provenance.decision,
        reason: provenance.reasonCode,
        evaluatedAt: provenance.timestamp,
      },
      executionResult,
      securityEvent: event,
      auditRecord: audit,
    };
  }

  /**
   * Mediates Executive Actions requested by leadership or administrative components
   */
  public async evaluateExecutiveAction(request: ExecutiveActionRequest): Promise<{
    permitted: boolean;
    decision: PolicyDecision;
    result?: unknown;
    auditRecord?: AuditRecord;
    securityEvent?: SecurityEvent;
  }> {
    const correlationId = request.correlationId || `corr-exec-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    
    const actorSubject: IdentitySubject = {
      id: request.executiveId,
      type: 'EXECUTIVE',
      name: `Executive Leader (${request.executiveId})`,
      roles: ['EXECUTIVE'],
      organizationId: this.businessId,
    };

    const provenance = this.decisionPipeline.evaluate({
      actor: actorSubject,
      action: request.action,
      resource: request.resource,
      context: {
        environment: this.environment,
        timestamp: new Date().toISOString(),
        metadata: {
          ...request.parameters,
          correlationId,
        },
      },
      riskScore: 25,
      correlationId,
    });

    const isAllowed = provenance.decision === 'ALLOW';

    if (!isAllowed) {
      const audit = this.auditService.append({
        who: request.executiveId,
        what: `EXECUTIVE_ACTION_BLOCKED:${request.action}`,
        where: request.resource,
        why: provenance.reasonCode,
        result: 'DENIED',
        details: { decisionId: provenance.decisionId, correlationId },
      });

      return {
        permitted: false,
        decision: {
          decision: provenance.decision,
          reason: provenance.reasonCode,
          evaluatedAt: provenance.timestamp,
        },
        auditRecord: audit,
      };
    }

    let result: unknown;
    if (request.executor) {
      result = await request.executor();
    }

    const { event } = await this.emitSecurityEvent({
      source: this.sourceId,
      businessId: this.businessId,
      environment: this.environment,
      eventType: 'EXECUTIVE_ACTION_EXECUTION',
      riskScore: 25,
      actorId: request.executiveId,
      action: request.action,
      resourceId: request.resource,
      category: 'AUTHORIZATION',
      severity: 'MEDIUM',
      result: 'SUCCESS',
      correlationId,
      metadata: {
        decisionId: provenance.decisionId,
        parameters: request.parameters,
      },
    });

    const audit = this.auditService.append({
      who: request.executiveId,
      what: `EXECUTIVE_ACTION_EXECUTED:${request.action}`,
      where: request.resource,
      why: provenance.reasonCode,
      result: 'SUCCESS',
      details: {
        decisionId: provenance.decisionId,
        eventId: event.eventId,
        correlationId,
      },
    });

    return {
      permitted: true,
      decision: {
        decision: provenance.decision,
        reason: provenance.reasonCode,
        evaluatedAt: provenance.timestamp,
      },
      result,
      auditRecord: audit,
      securityEvent: event,
    };
  }

  /**
   * Evaluates Privileged Configuration Changes
   */
  public async evaluateConfigChange(
    actorId: string,
    settingKey: string,
    oldValue: unknown,
    newValue: unknown
  ): Promise<{ permitted: boolean; decision: PolicyDecision; auditRecord: AuditRecord }> {
    const correlationId = `corr-cfg-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    const actorSubject: IdentitySubject = {
      id: actorId,
      type: 'ADMIN',
      name: `Administrator (${actorId})`,
      roles: ['ADMIN'],
      organizationId: this.businessId,
    };

    const provenance = this.decisionPipeline.evaluate({
      actor: actorSubject,
      action: 'modify-config',
      resource: `config/${settingKey}`,
      context: {
        environment: this.environment,
        timestamp: new Date().toISOString(),
        metadata: { settingKey, oldValue, newValue, correlationId },
      },
      riskScore: 30,
      correlationId,
    });

    const isAllowed = provenance.decision === 'ALLOW';

    const audit = this.auditService.append({
      who: actorId,
      what: `CONFIG_CHANGE_${isAllowed ? 'APPLIED' : 'REJECTED'}:${settingKey}`,
      where: `system/config/${settingKey}`,
      why: provenance.reasonCode,
      result: isAllowed ? 'SUCCESS' : 'DENIED',
      details: {
        settingKey,
        oldValue,
        newValue,
        decisionId: provenance.decisionId,
        correlationId,
      },
    });

    return {
      permitted: isAllowed,
      decision: {
        decision: provenance.decision,
        reason: provenance.reasonCode,
        evaluatedAt: provenance.timestamp,
      },
      auditRecord: audit,
    };
  }

  /**
   * Evaluates Sensitive Data Access
   */
  public async evaluateDataAccess(
    actorId: string,
    datasetId: string,
    classification: string
  ): Promise<{ permitted: boolean; decision: PolicyDecision; auditRecord: AuditRecord }> {
    const correlationId = `corr-data-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    const actorSubject: IdentitySubject = {
      id: actorId,
      type: 'ADMIN',
      name: `Security Analyst (${actorId})`,
      roles: ['ADMIN'],
      organizationId: this.businessId,
    };

    const provenance = this.decisionPipeline.evaluate({
      actor: actorSubject,
      action: 'read-sensitive-data',
      resource: `data/${datasetId}`,
      context: {
        environment: this.environment,
        timestamp: new Date().toISOString(),
        metadata: { datasetId, classification, correlationId },
      },
      riskScore: 20,
      correlationId,
    });

    const isAllowed = provenance.decision === 'ALLOW';

    const audit = this.auditService.append({
      who: actorId,
      what: `DATA_ACCESS_${isAllowed ? 'GRANTED' : 'DENIED'}:${datasetId}`,
      where: `datasets/${datasetId}`,
      why: provenance.reasonCode,
      result: isAllowed ? 'SUCCESS' : 'DENIED',
      details: {
        datasetId,
        classification,
        decisionId: provenance.decisionId,
        correlationId,
      },
    });

    return {
      permitted: isAllowed,
      decision: {
        decision: provenance.decision,
        reason: provenance.reasonCode,
        evaluatedAt: provenance.timestamp,
      },
      auditRecord: audit,
    };
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

    const validated = validateSecurityEvent(eventPayload);
    const triggeredAlerts = this.threatEngine.processEvent(validated);

    return {
      event: validated,
      triggeredAlerts,
    };
  }

  public async checkPolicy(input: PolicyEvaluationInput): Promise<PolicyDecision> {
    const provenance = this.decisionPipeline.evaluate({
      ...input,
      correlationId: `chk-pol-${Date.now()}`,
    });
    return {
      decision: provenance.decision,
      reason: provenance.reasonCode,
      evaluatedAt: provenance.timestamp,
    };
  }

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

  public async checkAgentPermission(
    agentId: string,
    toolName: string,
    parameters: Record<string, unknown> = {}
  ): Promise<ToolPermissionCheck> {
    return this.toolRegistry.checkPermission(agentId, toolName, parameters);
  }

  public async recordAuditEvent(input: CreateAuditRecordInput): Promise<AuditRecord> {
    return this.auditService.append(input);
  }
}
