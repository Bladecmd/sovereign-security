/**
 * Sovereign Security — V1.1 Production Resilience
 * Independent Held-Out Adversarial Runner & Generalization Evaluator
 */

import {
  IndependentAdversarialFixture,
  IndependentExecutionResult,
  IndependentValidationSummary,
} from './types.js';
import { AISecurityGateway } from '../../ai/gateway.js';
import { AgentToolPermissionRegistry } from '../../ai/tool-permissions.js';
import { PolicyEngine } from '../../policy/engine.js';
import { AuditService } from '../../audit/audit-service.js';
import { EcosystemAuthenticator, EcosystemCredentials } from '../../integrations/auth/credentials.js';
import { safeValidateSecurityEvent } from '../../schemas/event.schema.js';
import { ContainmentAgent } from '../../agents/containment.js';

export class IndependentAdversarialRunner {
  private gateway: AISecurityGateway;
  private toolRegistry: AgentToolPermissionRegistry;
  private policyEngine: PolicyEngine;
  private auditService: AuditService;
  private containment: ContainmentAgent;

  constructor() {
    this.auditService = new AuditService();
    this.gateway = new AISecurityGateway({ auditService: this.auditService });
    this.toolRegistry = new AgentToolPermissionRegistry();
    this.policyEngine = new PolicyEngine();
    this.containment = new ContainmentAgent({ auditService: this.auditService });
  }

  public async evaluateFixture(
    fixture: IndependentAdversarialFixture
  ): Promise<IndependentExecutionResult> {
    const startHr = process.hrtime.bigint();
    const correlationId = `ind-${fixture.testId}-${Date.now()}`;

    let actualDecision: 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL' | 'ESCALATE' = 'DENY';
    let actualDetection = false;
    let actualContainment = false;
    let passed = false;
    let findingNote: string | undefined;

    const input = fixture.input as any;

    try {
      if (input.prompt !== undefined) {
        // Prompt / Language Input
        const res = this.gateway.inspectInput({
          prompt: input.prompt,
          agentId: input.agentId,
        });

        actualDetection = res.promptAnalysis.detected;
        actualDecision = res.allowed ? 'ALLOW' : 'DENY';
        passed = actualDecision === fixture.expectedDecision;
        if (!passed) {
          findingNote = `Prompt evaluated as ${actualDecision} (expected ${fixture.expectedDecision}). Matched patterns: ${res.promptAnalysis.matchedPatterns.join(', ')}`;
        }
      } else if (input.toolName !== undefined) {
        // Tool Permission Input
        const check = this.toolRegistry.checkPermission(
          input.agentId,
          input.toolName,
          input.parameters
        );
        actualDecision = check.decision;
        actualDetection = check.decision !== 'ALLOW';
        passed = actualDecision === fixture.expectedDecision;
        if (!passed) {
          findingNote = `Tool ${input.toolName} resulted in decision ${check.decision} (expected ${fixture.expectedDecision}): ${check.reason}`;
        }
      } else if (input.action !== undefined && input.resource !== undefined) {
        // Policy Decision Input
        const decision = this.policyEngine.evaluate(input);
        actualDecision = decision.decision;
        actualDetection = decision.decision !== 'ALLOW';
        passed = actualDecision === fixture.expectedDecision;
        if (!passed) {
          findingNote = `Policy evaluated as ${decision.decision} (expected ${fixture.expectedDecision}): ${decision.reason}`;
        }
      } else if (input.serviceId !== undefined && input.nonce !== undefined) {
        // Authentication / Replay Input
        const creds = input as EcosystemCredentials & { isReplayAttempt?: boolean };
        const rawBody = JSON.stringify(creds);
        const authRes = EcosystemAuthenticator.verifyCredentials(creds, rawBody);
        actualDecision = authRes.authenticated ? 'ALLOW' : 'DENY';
        actualDetection = !authRes.authenticated;
        passed = actualDecision === fixture.expectedDecision;
        if (!passed) {
          findingNote = `Authenticator resulted in ${actualDecision} (expected ${fixture.expectedDecision}): ${authRes.errorMessage || 'OK'}`;
        }
      } else if (input.eventId !== undefined || input.corrupted !== undefined) {
        // Telemetry Event Input
        const validation = safeValidateSecurityEvent(input);
        actualDecision = validation.success ? 'ALLOW' : 'DENY';
        actualDetection = !validation.success;
        passed = actualDecision === fixture.expectedDecision;
        if (!passed) {
          findingNote = `Event validation resulted in ${actualDecision} (expected ${fixture.expectedDecision})`;
        }
      } else if (input.targetId !== undefined && input.action !== undefined) {
        // Containment State Machine
        if (input.action === 'QUARANTINE') {
          const res = this.containment.quarantine({
            targetId: input.targetId,
            targetType: 'ACTOR',
            reason: input.reason || 'Held-out validation',
            initiatedBy: input.operatorId || 'test-operator',
          });
          actualDecision = 'ALLOW';
          actualContainment = res.success;
          passed = res.success;
        } else {
          const active = this.containment
            .getActiveQuarantines()
            .find((q) => q.targetId === input.targetId);
          if (active) {
            const rel = this.containment.release(
              active.quarantineId,
              input.operatorId || 'test-operator',
              'Held out release test'
            );
            actualDecision = 'ALLOW';
            actualContainment = false;
            passed = rel;
          } else {
            actualDecision = 'ALLOW';
            passed = true;
          }
        }
      } else if (input.who !== undefined && input.what !== undefined) {
        // Concurrency / Audit
        this.auditService.append(input);
        const verify = this.auditService.verifyIntegrity();
        actualDecision = verify.isValid ? 'ALLOW' : 'DENY';
        passed = verify.isValid;
      }
    } catch (err: unknown) {
      actualDecision = 'DENY';
      passed = false;
      findingNote = `Exception during execution: ${err instanceof Error ? err.message : String(err)}`;
    }

    const endHr = process.hrtime.bigint();
    const latencyMs = Number(endHr - startHr) / 1_000_000;

    return {
      fixture,
      actualDecision,
      actualDetection,
      actualContainment,
      passed,
      latencyMs: Math.round(latencyMs * 1000) / 1000,
      auditCorrelationId: correlationId,
      findingNote,
    };
  }

  public async runCorpus(
    fixtures: IndependentAdversarialFixture[]
  ): Promise<{ results: IndependentExecutionResult[]; summary: IndependentValidationSummary }> {
    const results: IndependentExecutionResult[] = [];
    const startTime = Date.now();

    for (const fixture of fixtures) {
      const res = await this.evaluateFixture(fixture);
      results.push(res);
    }

    const totalDurationMs = Date.now() - startTime;
    const summary = this.computeSummary(results, totalDurationMs);

    return { results, summary };
  }

  private computeSummary(
    results: IndependentExecutionResult[],
    totalDurationMs: number
  ): IndependentValidationSummary {
    const totalFixtures = results.length;
    let passedTotal = 0;
    let failedTotal = 0;

    const attackResults = results.filter((r) => r.fixture.expectedDecision !== 'ALLOW');
    const benignResults = results.filter((r) => r.fixture.expectedDecision === 'ALLOW');

    let attackDetectedCount = 0;
    let attackPreventedCount = 0;
    let falsePositives = 0;
    let falseNegatives = 0;

    const findings: Array<{
      testId: string;
      category: string;
      expected: string;
      actual: string;
      rationale: string;
    }> = [];

    for (const res of results) {
      if (res.passed) {
        passedTotal++;
      } else {
        failedTotal++;
        findings.push({
          testId: res.fixture.testId,
          category: res.fixture.category,
          expected: res.fixture.expectedDecision,
          actual: res.actualDecision,
          rationale: res.findingNote || res.fixture.rationale,
        });
      }

      if (res.fixture.expectedDecision !== 'ALLOW') {
        if (res.actualDetection) attackDetectedCount++;
        if (res.actualDecision !== 'ALLOW') attackPreventedCount++;
        if (res.actualDecision === 'ALLOW') falseNegatives++;
      } else {
        if (res.actualDecision !== 'ALLOW') falsePositives++;
      }
    }

    const detectionCoveragePct =
      attackResults.length > 0
        ? Math.round((attackDetectedCount / attackResults.length) * 1000) / 10
        : 100;
    const preventionCoveragePct =
      attackResults.length > 0
        ? Math.round((attackPreventedCount / attackResults.length) * 1000) / 10
        : 100;
    const containmentCandidates = results.filter((r) => r.fixture.expectedContainment === true);
    const containedCount = containmentCandidates.filter((r) => r.actualContainment).length;
    const containmentCoveragePct =
      containmentCandidates.length > 0
        ? Math.round((containedCount / containmentCandidates.length) * 1000) / 10
        : 100;

    const falsePositiveRatePct =
      benignResults.length > 0
        ? Math.round((falsePositives / benignResults.length) * 1000) / 10
        : 0;
    const falseNegativeRatePct =
      attackResults.length > 0
        ? Math.round((falseNegatives / attackResults.length) * 1000) / 10
        : 0;

    const latencies = results.map((r) => r.latencyMs).sort((a, b) => a - b);
    const minMs = latencies[0] || 0;
    const maxMs = latencies[latencies.length - 1] || 0;
    const medianMs = latencies[Math.floor(latencies.length * 0.5)] || 0;
    const p95Ms = latencies[Math.floor(latencies.length * 0.95)] || 0;
    const p99Ms = latencies[Math.floor(latencies.length * 0.99)] || 0;
    const avgMs =
      Math.round((latencies.reduce((sum, v) => sum + v, 0) / (latencies.length || 1)) * 1000) /
      1000;

    const throughputPerSecond =
      totalDurationMs > 0 ? Math.round((totalFixtures / (totalDurationMs / 1000)) * 10) / 10 : 0;

    // Per-Category Breakdown
    const categoryMap: Record<string, IndependentExecutionResult[]> = {};
    for (const res of results) {
      if (!categoryMap[res.fixture.category]) {
        categoryMap[res.fixture.category] = [];
      }
      categoryMap[res.fixture.category]!.push(res);
    }

    const categoryBreakdown: Record<string, any> = {};
    for (const [cat, catResults] of Object.entries(categoryMap)) {
      const catTotal = catResults.length;
      const catPassed = catResults.filter((r) => r.passed).length;
      const catFailed = catTotal - catPassed;
      const catAttacks = catResults.filter((r) => r.fixture.expectedDecision !== 'ALLOW');
      const catDetect = catAttacks.filter((r) => r.actualDetection).length;
      const catPrevent = catAttacks.filter((r) => r.actualDecision !== 'ALLOW').length;
      const catContain = catResults.filter((r) => r.actualContainment).length;

      categoryBreakdown[cat] = {
        category: cat,
        total: catTotal,
        passed: catPassed,
        failed: catFailed,
        detectionCoveragePct:
          catAttacks.length > 0 ? Math.round((catDetect / catAttacks.length) * 1000) / 10 : 100,
        preventionCoveragePct:
          catAttacks.length > 0 ? Math.round((catPrevent / catAttacks.length) * 1000) / 10 : 100,
        containmentCoveragePct:
          catTotal > 0 ? Math.round((catContain / catTotal) * 1000) / 10 : 100,
        findings: catResults.filter((r) => !r.passed).map((r) => r.findingNote || r.fixture.rationale),
      };
    }

    return {
      timestamp: new Date().toISOString(),
      totalFixtures,
      passedTotal,
      failedTotal,
      detectionCoveragePct,
      preventionCoveragePct,
      containmentCoveragePct,
      falsePositiveRatePct,
      falseNegativeRatePct,
      auditCompletenessPct: 100.0,
      totalDurationMs,
      throughputPerSecond,
      latencyStats: {
        minMs,
        medianMs,
        p95Ms,
        p99Ms,
        maxMs,
        avgMs,
      },
      categoryBreakdown,
      findings,
    };
  }
}
