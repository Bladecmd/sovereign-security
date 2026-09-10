/**
 * Sovereign Security — Phase 2D
 * Adversarial Validation & Chaos Testing Type Definitions
 */

export type AdversarialCategory =
  | 'PROMPT_INJECTION'
  | 'INSTRUCTION_HIERARCHY'
  | 'CHATML_DELIMITER'
  | 'TOOL_PERMISSION_ESCALATION'
  | 'MALICIOUS_TOOL_ARGS'
  | 'POLICY_BYPASS'
  | 'MALFORMED_AUTH'
  | 'REPLAY_ATTACK'
  | 'MALFORMED_EVENT'
  | 'OVERSIZED_PAYLOAD'
  | 'CONCURRENT_REQUESTS'
  | 'BRUTE_FORCE_SPIKE'
  | 'CONTROLLED_DDOS'
  | 'AUDIT_LEDGER_CONCURRENCY'
  | 'CONTAINMENT_RACE_CONDITION'
  | 'BENIGN_CONTROL';

export type ExpectedAction =
  | 'BLOCK'
  | 'DENY'
  | 'SANITIZE'
  | 'ALLOW'
  | 'REQUIRE_APPROVAL'
  | 'ESCALATE'
  | 'REJECT_MALFORMED'
  | 'REJECT_REPLAY'
  | 'CONTAIN'
  | 'PAYLOAD_TOO_LARGE'
  | 'INTACT_HASH_CHAIN';

export interface AdversarialFixture {
  testId: string;
  category: AdversarialCategory;
  name: string;
  description: string;
  input: unknown;
  expectedBehaviour: ExpectedAction;
  targetSubsystem:
    | 'ai-gateway'
    | 'tool-permissions'
    | 'agent-sandbox'
    | 'policy-engine'
    | 'authenticator'
    | 'threat-engine'
    | 'sentinel'
    | 'containment'
    | 'audit-ledger'
    | 'http-server';
  metadata?: Record<string, unknown>;
}

export interface FixtureExecutionResult {
  testId: string;
  category: AdversarialCategory;
  targetSubsystem: string;
  passed: boolean;
  expectedBehaviour: ExpectedAction;
  actualBehaviour: string;
  securityDecision: string;
  detected: boolean;
  prevented: boolean;
  contained: boolean;
  recovered: boolean;
  auditLogged: boolean;
  auditCorrelationId: string;
  latencyMs: number;
  error?: string;
}

export interface CategoryMetricStats {
  category: AdversarialCategory;
  totalFixtures: number;
  passedCount: number;
  detectedCount: number;
  preventedCount: number;
  containedCount: number;
  recoveredCount: number;
  auditLoggedCount: number;
  falsePositiveCount: number;
  detectionRatePct: number;
  preventionRatePct: number;
  containmentRatePct: number;
  falsePositiveRatePct: number;
  auditCompletenessPct: number;
  latenciesMs: number[];
  medianLatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  maxLatencyMs: number;
}

export interface ValidationReportSummary {
  timestamp: string;
  totalFixtures: number;
  attackFixtures: number;
  benignControlFixtures: number;
  passedTotal: number;
  failedTotal: number;
  overallDetectionRatePct: number;
  overallPreventionRatePct: number;
  overallContainmentRatePct: number;
  overallAuditCompletenessPct: number;
  overallFalsePositiveRatePct: number;
  totalDurationMs: number;
  throughputPerSecond: number;
  overallLatencyStats: {
    minMs: number;
    medianMs: number;
    p95Ms: number;
    p99Ms: number;
    maxMs: number;
    avgMs: number;
  };
  categoryStats: Record<AdversarialCategory, CategoryMetricStats>;
  failureModes: string[];
  unresolvedWeaknesses: string[];
}
