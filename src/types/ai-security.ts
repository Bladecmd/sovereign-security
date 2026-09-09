/**
 * Sovereign Security — Foundation V0.1
 * AI Security Pipeline & Tool Permission Types
 */

import { PolicyDecisionType } from './policy.js';

export interface AIRequest {
  requestId: string;
  agentId: string;
  prompt: string;
  context?: Record<string, unknown>;
  targetModel?: string;
  timestamp: string;
}

export interface InputPolicyResult {
  allowed: boolean;
  sanitizedPrompt: string;
  violations: string[];
  riskTier: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
}

export interface AIRiskClassification {
  riskScore: number; // 0 - 100
  categories: string[];
  requiresHumanReview: boolean;
}

export interface ModelOutput {
  rawResponse: string;
  toolCalls?: Array<{
    toolName: string;
    arguments: Record<string, unknown>;
  }>;
}

export interface OutputValidationResult {
  isValid: boolean;
  redactedResponse: string;
  detectedLeaks: string[];
}

export interface ToolPermissionCheck {
  agentId: string;
  toolName: string;
  parameters: Record<string, unknown>;
  decision: PolicyDecisionType;
  reason: string;
}

export interface AIPipelineDecision {
  requestId: string;
  status: 'COMPLETED' | 'BLOCKED' | 'ESCALATED' | 'APPROVAL_REQUIRED';
  finalOutput?: string;
  blockedAtStage?:
    | 'INPUT_POLICY'
    | 'RISK_CLASSIFICATION'
    | 'OUTPUT_VALIDATION'
    | 'TOOL_PERMISSION'
    | 'POLICY_DECISION';
  reason: string;
  toolDecisions: ToolPermissionCheck[];
  auditCorrelationId: string;
}

export interface ToolPermissionRule {
  toolName: string;
  action: 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL';
  maxParameters?: Record<string, unknown>;
  reason?: string;
}

export interface AgentToolPolicy {
  agentId: string;
  agentName: string;
  description: string;
  defaultAction: 'DENY' | 'ALLOW';
  allowedTools: string[];
  deniedTools: string[];
  approvalRequiredTools: string[];
  parameterConstraints?: Record<string, (params: Record<string, unknown>) => boolean>;
}
