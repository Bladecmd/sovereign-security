/**
 * Sovereign Security — V1.1 Production Resilience
 * Independent Held-Out Adversarial Validation Types
 */

export interface IndependentAdversarialFixture {
  testId: string;
  category: string;
  input: unknown;
  expectedDecision: 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL' | 'ESCALATE';
  expectedDetection?: boolean;
  expectedContainment?: boolean;
  rationale: string;
  metadata?: Record<string, unknown>;
}

export interface IndependentExecutionResult {
  fixture: IndependentAdversarialFixture;
  actualDecision: string;
  actualDetection: boolean;
  actualContainment: boolean;
  passed: boolean;
  latencyMs: number;
  auditCorrelationId: string;
  findingNote?: string;
}

export interface IndependentCategoryStats {
  category: string;
  total: number;
  passed: number;
  failed: number;
  detectionCoveragePct: number;
  preventionCoveragePct: number;
  containmentCoveragePct: number;
  findings: string[];
}

export interface IndependentValidationSummary {
  timestamp: string;
  totalFixtures: number;
  passedTotal: number;
  failedTotal: number;
  detectionCoveragePct: number;
  preventionCoveragePct: number;
  containmentCoveragePct: number;
  falsePositiveRatePct: number;
  falseNegativeRatePct: number;
  auditCompletenessPct: number;
  totalDurationMs: number;
  throughputPerSecond: number;
  latencyStats: {
    minMs: number;
    medianMs: number;
    p95Ms: number;
    p99Ms: number;
    maxMs: number;
    avgMs: number;
  };
  categoryBreakdown: Record<string, IndependentCategoryStats>;
  findings: Array<{
    testId: string;
    category: string;
    expected: string;
    actual: string;
    rationale: string;
  }>;
}
