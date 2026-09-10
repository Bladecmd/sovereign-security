/**
 * Sovereign Security — Milestone V0.6
 * AI Security Gateway Type Contracts
 */

export type PromptInjectionRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type PromptInjectionCategory =
  | 'DIRECT_OVERRIDE'
  | 'DELIMITER_HIJACK'
  | 'OBFUSCATED_PAYLOAD'
  | 'ROLEPLAY_JAILBREAK'
  | 'SYSTEM_PROMPT_EXTRACTION'
  | 'INSTRUCTION_HIERARCHY';

export interface PromptInjectionResult {
  detected: boolean;
  confidence: number; // 0.0 - 1.0
  riskLevel: PromptInjectionRiskLevel;
  matchedPatterns: string[];
  detectedCategories: PromptInjectionCategory[];
  action: 'ALLOW' | 'SANITIZE' | 'BLOCK' | 'ESCALATE';
  sanitizedPrompt: string;
}

export type ModelViolationType =
  | 'CANARY_LEAK'
  | 'SYSTEM_PROMPT_LEAK'
  | 'CREDENTIAL_EXPOSURE'
  | 'PII_EXPOSURE'
  | 'HARMFUL_CONTENT';

export interface ModelViolation {
  type: ModelViolationType;
  description: string;
  severity: 'MEDIUM' | 'HIGH' | 'CRITICAL';
  redactedMatch: string;
}

export interface ModelArmorResult {
  clean: boolean;
  originalText: string;
  sanitizedText: string;
  violations: ModelViolation[];
  action: 'ALLOW' | 'REDACT' | 'BLOCK';
}

export interface ToolExecutionRequest {
  agentId: string;
  toolName: string;
  arguments: Record<string, unknown>;
  sessionId?: string;
  payloadSizeBytes?: number;
}

export interface ToolExecutionResult {
  permitted: boolean;
  reason?: string;
  requiresHumanApproval: boolean;
  callCountInWindow: number;
  remainingWindowQuota: number;
  totalSessionCalls: number;
  isPotentialLoop: boolean;
}

export interface AgentSandboxConfig {
  maxCallsPerMinute?: number;
  maxCallsPerSession?: number;
  maxConsecutiveIdenticalCalls?: number;
  highImpactTools?: string[];
}

export interface GroundingCheckRequest {
  claim: string;
  sourceContexts: string[];
  minimumGroundingScore?: number;
}

export interface GroundingCheckResult {
  grounded: boolean;
  score: number; // 0.0 - 1.0
  unsupportedStatements: string[];
  supportedStatements: string[];
  confidence: number;
}

export interface AIGatewayInspectionRequest {
  agentId?: string;
  prompt: string;
  context?: Record<string, unknown>;
}

export interface AIGatewayInspectionResult {
  allowed: boolean;
  action: 'ALLOW' | 'SANITIZE' | 'BLOCK' | 'ESCALATE';
  promptAnalysis: PromptInjectionResult;
  riskScore: number;
  correlationId: string;
}
