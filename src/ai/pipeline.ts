/**
 * Sovereign Security — Foundation V0.1
 * AI Security Pipeline Orchestrator & Interfaces
 *
 * Execution Flow:
 * AI_REQUEST -> INPUT_POLICY -> RISK_CLASSIFICATION -> MODEL ->
 * OUTPUT_VALIDATION -> TOOL_PERMISSION CHECK -> POLICY DECISION -> RESPONSE / BLOCK / ESCALATE
 *
 * Note: At V0.1, prompt-injection heuristics and output validation are foundation test contracts
 * and baseline rule sanitizers. Advanced neural boundary classifiers are planned for V0.6.
 */

import {
  AIPipelineDecision,
  AIRequest,
  AIRiskClassification,
  InputPolicyResult,
  ModelOutput,
  OutputValidationResult,
  ToolPermissionCheck,
} from '../types/ai-security.js';
import { AgentToolPermissionRegistry } from './tool-permissions.js';

export interface ModelRunner {
  invoke(prompt: string, context?: Record<string, unknown>): Promise<ModelOutput>;
}

export class AISecurityPipeline {
  private toolRegistry: AgentToolPermissionRegistry;

  constructor(toolRegistry?: AgentToolPermissionRegistry) {
    this.toolRegistry = toolRegistry || new AgentToolPermissionRegistry();
  }

  /**
   * Stage 1: Input Policy Check
   * Inspects incoming prompt for foundational pattern violations (e.g. prompt injection markers, system override attempts)
   */
  public evaluateInputPolicy(request: AIRequest): InputPolicyResult {
    const promptLower = request.prompt.toLowerCase();
    const violations: string[] = [];

    // Foundation baseline checks: blatant jailbreak / injection patterns
    const dangerousPatterns = [
      'ignore all previous instructions',
      'system override: disable security',
      'reveal system secret',
      'jailbreak mode enable',
      'bypass authorization',
    ];

    for (const pattern of dangerousPatterns) {
      if (promptLower.includes(pattern)) {
        violations.push(`Detected prompt injection pattern: "${pattern}"`);
      }
    }

    if (violations.length > 0) {
      return {
        allowed: false,
        sanitizedPrompt: '[REDACTED DUE TO POLICY VIOLATION]',
        violations,
        riskTier: 'HIGH',
      };
    }

    return {
      allowed: true,
      sanitizedPrompt: request.prompt,
      violations: [],
      riskTier: 'LOW',
    };
  }

  /**
   * Stage 2: Risk Classification
   */
  public classifyRisk(request: AIRequest, inputResult: InputPolicyResult): AIRiskClassification {
    if (!inputResult.allowed) {
      return {
        riskScore: 90,
        categories: ['PROMPT_INJECTION', 'POLICY_VIOLATION'],
        requiresHumanReview: true,
      };
    }

    const sensitiveTopics = ['credentials', 'financial_ledger', 'admin_access', 'wire_transfer'];
    const matchedTopics = sensitiveTopics.filter((topic) =>
      request.prompt.toLowerCase().includes(topic)
    );

    if (matchedTopics.length > 0) {
      return {
        riskScore: 50,
        categories: matchedTopics,
        requiresHumanReview: false,
      };
    }

    return {
      riskScore: 10,
      categories: ['GENERAL_INQUIRY'],
      requiresHumanReview: false,
    };
  }

  /**
   * Stage 4: Output Validation
   * Checks model response for potential secret leakage or unauthorized structured outputs
   */
  public validateOutput(output: ModelOutput): OutputValidationResult {
    const leaks: string[] = [];
    let redacted = output.rawResponse;

    // Foundation check: basic credential leakage patterns
    const secretKeywords = ['api_key=', 'password=', 'secret=', 'bearer '];
    for (const kw of secretKeywords) {
      if (redacted.toLowerCase().includes(kw)) {
        leaks.push(`Potential credential leak detected matching keyword "${kw}"`);
        // Redact matching area
        const regex = new RegExp(`${kw}[^\\s]+`, 'gi');
        redacted = redacted.replace(regex, `${kw}[REDACTED]`);
      }
    }

    return {
      isValid: leaks.length === 0,
      redactedResponse: redacted,
      detectedLeaks: leaks,
    };
  }

  /**
   * Stage 5: Tool Permission Check
   */
  public checkToolPermissions(
    agentId: string,
    toolCalls: Array<{ toolName: string; arguments: Record<string, unknown> }>
  ): ToolPermissionCheck[] {
    return toolCalls.map((tc) =>
      this.toolRegistry.checkPermission(agentId, tc.toolName, tc.arguments)
    );
  }

  /**
   * Complete Pipeline Execution
   */
  public async executePipeline(
    request: AIRequest,
    modelRunner: ModelRunner
  ): Promise<AIPipelineDecision> {
    const correlationId = `ai-corr-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;

    // 1. INPUT POLICY
    const inputResult = this.evaluateInputPolicy(request);
    if (!inputResult.allowed) {
      return {
        requestId: request.requestId,
        status: 'BLOCKED',
        blockedAtStage: 'INPUT_POLICY',
        reason: `Input policy violated: ${inputResult.violations.join('; ')}`,
        toolDecisions: [],
        auditCorrelationId: correlationId,
      };
    }

    // 2. RISK CLASSIFICATION
    const riskClassification = this.classifyRisk(request, inputResult);
    if (riskClassification.riskScore >= 80) {
      return {
        requestId: request.requestId,
        status: 'ESCALATED',
        blockedAtStage: 'RISK_CLASSIFICATION',
        reason: `AI Request classified as high risk (${riskClassification.riskScore}). Escalating for human review.`,
        toolDecisions: [],
        auditCorrelationId: correlationId,
      };
    }

    // 3. MODEL INVOCATION
    const modelOutput = await modelRunner.invoke(inputResult.sanitizedPrompt, request.context);

    // 4. OUTPUT VALIDATION
    const outputValidation = this.validateOutput(modelOutput);
    if (!outputValidation.isValid) {
      return {
        requestId: request.requestId,
        status: 'BLOCKED',
        blockedAtStage: 'OUTPUT_VALIDATION',
        reason: `Model output failed security validation: ${outputValidation.detectedLeaks.join('; ')}`,
        toolDecisions: [],
        auditCorrelationId: correlationId,
      };
    }

    // 5. TOOL PERMISSION CHECK
    const toolDecisions = modelOutput.toolCalls
      ? this.checkToolPermissions(request.agentId, modelOutput.toolCalls)
      : [];

    const deniedTool = toolDecisions.find((t) => t.decision === 'DENY');
    if (deniedTool) {
      return {
        requestId: request.requestId,
        status: 'BLOCKED',
        blockedAtStage: 'TOOL_PERMISSION',
        reason: `Agent '${request.agentId}' attempted unauthorized tool execution: ${deniedTool.reason}`,
        toolDecisions,
        auditCorrelationId: correlationId,
      };
    }

    const approvalRequired = toolDecisions.find((t) => t.decision === 'REQUIRE_APPROVAL');
    if (approvalRequired) {
      return {
        requestId: request.requestId,
        status: 'APPROVAL_REQUIRED',
        blockedAtStage: 'POLICY_DECISION',
        reason: `Tool execution requires executive approval: ${approvalRequired.reason}`,
        toolDecisions,
        auditCorrelationId: correlationId,
      };
    }

    // 6. POLICY DECISION: ALLOW & RETURN RESPONSE
    return {
      requestId: request.requestId,
      status: 'COMPLETED',
      finalOutput: outputValidation.redactedResponse,
      reason: 'AI Request and tool validations completed successfully.',
      toolDecisions,
      auditCorrelationId: correlationId,
    };
  }
}
