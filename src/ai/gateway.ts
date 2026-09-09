/**
 * Sovereign Security — Milestone V0.6
 * AI Security Gateway Orchestrator
 */

import {
  AIGatewayInspectionRequest,
  AIGatewayInspectionResult,
  GroundingCheckRequest,
  GroundingCheckResult,
  ModelArmorResult,
  ToolExecutionRequest,
  ToolExecutionResult,
} from '../types/ai-gateway.js';
import { PromptInjectionDetector } from './prompt-injection.js';
import { ModelArmorFilter, ModelArmorOptions } from './model-armor.js';
import { AgentSandboxRuntime } from './agent-sandbox.js';
import { SemanticGroundingGuard } from './grounding.js';
import { AuditService } from '../audit/audit-service.js';

export interface AISecurityGatewayOptions {
  modelArmorOptions?: ModelArmorOptions;
  auditService?: AuditService;
}

export class AISecurityGateway {
  private promptDetector: PromptInjectionDetector;
  private modelArmor: ModelArmorFilter;
  private sandbox: AgentSandboxRuntime;
  private groundingGuard: SemanticGroundingGuard;
  private auditService?: AuditService;

  constructor(options: AISecurityGatewayOptions = {}) {
    this.promptDetector = new PromptInjectionDetector();
    this.modelArmor = new ModelArmorFilter(options.modelArmorOptions);
    this.sandbox = new AgentSandboxRuntime();
    this.groundingGuard = new SemanticGroundingGuard();
    this.auditService = options.auditService;
  }

  public getPromptDetector(): PromptInjectionDetector {
    return this.promptDetector;
  }

  public getModelArmor(): ModelArmorFilter {
    return this.modelArmor;
  }

  public getSandbox(): AgentSandboxRuntime {
    return this.sandbox;
  }

  public getGroundingGuard(): SemanticGroundingGuard {
    return this.groundingGuard;
  }

  /**
   * Evaluates inbound prompt before LLM processing
   */
  public inspectInput(request: AIGatewayInspectionRequest): AIGatewayInspectionResult {
    const correlationId = `ai-gw-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const analysis = this.promptDetector.detect(request.prompt);

    const allowed = analysis.action === 'ALLOW' || analysis.action === 'SANITIZE';
    const riskScore = Math.round(analysis.confidence * 100);

    if (this.auditService && !allowed) {
      this.auditService.append({
        who: request.agentId || 'anonymous-ai-client',
        what: 'ai.prompt_injection_blocked',
        where: 'sovereign-ai-gateway/production',
        why: 'Enforce zero-trust adversarial prompt defense',
        result: 'FAILURE',
        details: {
          riskLevel: analysis.riskLevel,
          confidence: analysis.confidence,
          matchedPatterns: analysis.matchedPatterns,
          correlationId,
        },
      });
    }

    return {
      allowed,
      action: analysis.action,
      promptAnalysis: analysis,
      riskScore,
      correlationId,
    };
  }

  /**
   * Evaluates outbound LLM generation before delivery to client
   */
  public inspectOutput(output: string, context?: { agentId?: string; correlationId?: string }): ModelArmorResult {
    const result = this.modelArmor.inspect(output);

    if (this.auditService && !result.clean) {
      this.auditService.append({
        who: context?.agentId || 'llm-output-filter',
        what: 'ai.model_armor_sanitized',
        where: 'sovereign-ai-gateway/production',
        why: 'Prevent secret, canary, and PII exfiltration from model output',
        result: result.action === 'BLOCK' ? 'FAILURE' : 'SUCCESS',
        details: {
          action: result.action,
          violationsCount: result.violations.length,
          violationTypes: result.violations.map((v) => v.type),
          correlationId: context?.correlationId || `armor-${Date.now()}`,
        },
      });
    }

    return result;
  }

  /**
   * Evaluates agent tool execution against sandbox and quotas
   */
  public evaluateToolCall(request: ToolExecutionRequest): ToolExecutionResult {
    return this.sandbox.evaluateToolExecution(request);
  }

  /**
   * Verifies factual grounding of generated response against source references
   */
  public verifyGrounding(request: GroundingCheckRequest): GroundingCheckResult {
    return this.groundingGuard.verifyGrounding(request);
  }
}
