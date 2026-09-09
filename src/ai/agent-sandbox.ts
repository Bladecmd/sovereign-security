/**
 * Sovereign Security — Milestone V0.6
 * Autonomous Agent Sandbox & Tool Execution Guard
 */

import {
  AgentSandboxConfig,
  ToolExecutionRequest,
  ToolExecutionResult,
} from '../types/ai-gateway.js';

interface CallRecord {
  timestamp: number;
  toolName: string;
  argumentsHash: string;
}

export class AgentSandboxRuntime {
  private config: Required<AgentSandboxConfig>;
  // Map of agentId -> CallRecord[]
  private callHistory: Map<string, CallRecord[]> = new Map();
  // Map of sessionId -> total call count
  private sessionCounts: Map<string, number> = new Map();

  constructor(config: AgentSandboxConfig = {}) {
    this.config = {
      maxCallsPerMinute: config.maxCallsPerMinute ?? 20,
      maxCallsPerSession: config.maxCallsPerSession ?? 100,
      maxConsecutiveIdenticalCalls: config.maxConsecutiveIdenticalCalls ?? 3,
      highImpactTools: config.highImpactTools ?? [
        'execute_sql_mutation',
        'update_iam_roles',
        'terminate_instances',
        'transfer_funds',
        'deploy_production_code',
        'revoke_all_tokens',
        'modify_firewall_rules',
      ],
    };
  }

  private hashArguments(args: Record<string, unknown>): string {
    return JSON.stringify(args, Object.keys(args).sort());
  }

  /**
   * Evaluates a requested tool execution against sandbox guardrails
   */
  public evaluateToolExecution(request: ToolExecutionRequest): ToolExecutionResult {
    const now = Date.now();
    const windowMs = 60 * 1000;
    const { agentId, toolName, arguments: args, sessionId = 'default-session' } = request;

    // 1. Retrieve & prune call history for agent
    let history = this.callHistory.get(agentId) || [];
    history = history.filter((record) => now - record.timestamp < windowMs);
    this.callHistory.set(agentId, history);

    const callCountInWindow = history.length;
    const remainingWindowQuota = Math.max(0, this.config.maxCallsPerMinute - callCountInWindow);

    // 2. Check Session Total Quota
    const currentSessionTotal = (this.sessionCounts.get(sessionId) || 0) + 1;
    if (currentSessionTotal > this.config.maxCallsPerSession) {
      return {
        permitted: false,
        reason: `Session tool quota exceeded (${currentSessionTotal} > ${this.config.maxCallsPerSession}). Execution halted to prevent runaway billing.`,
        requiresHumanApproval: false,
        callCountInWindow,
        remainingWindowQuota,
        totalSessionCalls: currentSessionTotal - 1,
        isPotentialLoop: false,
      };
    }

    // 3. Check Sliding Window Rate Limit
    if (callCountInWindow >= this.config.maxCallsPerMinute) {
      return {
        permitted: false,
        reason: `Agent rate limit exceeded (${callCountInWindow} calls in 60s window, max ${this.config.maxCallsPerMinute}).`,
        requiresHumanApproval: false,
        callCountInWindow,
        remainingWindowQuota: 0,
        totalSessionCalls: currentSessionTotal - 1,
        isPotentialLoop: false,
      };
    }

    // 4. Runaway Recursive Loop Detection
    const currentHash = this.hashArguments(args);
    let consecutiveIdentical = 0;
    for (let i = history.length - 1; i >= 0; i--) {
      const prev = history[i];
      if (prev && prev.toolName === toolName && prev.argumentsHash === currentHash) {
        consecutiveIdentical++;
      } else {
        break;
      }
    }

    const isPotentialLoop = consecutiveIdentical >= this.config.maxConsecutiveIdenticalCalls - 1;
    if (isPotentialLoop) {
      return {
        permitted: false,
        reason: `Potential infinite loop detected: Tool '${toolName}' called ${consecutiveIdentical + 1} times consecutively with identical arguments.`,
        requiresHumanApproval: false,
        callCountInWindow,
        remainingWindowQuota,
        totalSessionCalls: currentSessionTotal - 1,
        isPotentialLoop: true,
      };
    }

    // 5. High-Impact Gated Action Check
    const requiresHumanApproval = this.config.highImpactTools.includes(toolName);

    // Record the call
    history.push({
      timestamp: now,
      toolName,
      argumentsHash: currentHash,
    });
    this.sessionCounts.set(sessionId, currentSessionTotal);

    if (requiresHumanApproval) {
      return {
        permitted: false,
        reason: `Tool '${toolName}' is designated HIGH-IMPACT and requires human executive authorization before execution.`,
        requiresHumanApproval: true,
        callCountInWindow: callCountInWindow + 1,
        remainingWindowQuota: Math.max(0, remainingWindowQuota - 1),
        totalSessionCalls: currentSessionTotal,
        isPotentialLoop: false,
      };
    }

    return {
      permitted: true,
      requiresHumanApproval: false,
      callCountInWindow: callCountInWindow + 1,
      remainingWindowQuota: Math.max(0, remainingWindowQuota - 1),
      totalSessionCalls: currentSessionTotal,
      isPotentialLoop: false,
    };
  }

  /**
   * Reset stats for testing / new sessions
   */
  public resetAgentHistory(agentId?: string): void {
    if (agentId) {
      this.callHistory.delete(agentId);
    } else {
      this.callHistory.clear();
      this.sessionCounts.clear();
    }
  }
}
