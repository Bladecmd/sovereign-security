import test, { describe } from 'node:test';
import assert from 'node:assert/strict';
import { generateIndependentAdversarialCorpus } from '../src/adversarial/independent/corpus.js';
import { IndependentAdversarialRunner } from '../src/adversarial/independent/runner.js';

describe('Independent Held-Out Adversarial Validation Test Suite', () => {
  const corpus = generateIndependentAdversarialCorpus();
  const runner = new IndependentAdversarialRunner();

  test('generates >= 300 held-out independent fixtures decoupled from regression generator', () => {
    assert.equal(corpus.length >= 300, true, `Expected >= 300 fixtures, got ${corpus.length}`);
  });

  test('covers all 13 independent attack and stress categories', () => {
    const categories = new Set(corpus.map((f) => f.category));
    assert.equal(categories.size, 13);
  });

  test('executes complete held-out evaluation and computes independent metrics', async () => {
    const { results, summary } = await runner.runCorpus(corpus);

    assert.equal(results.length, corpus.length);
    assert.equal(summary.totalFixtures, corpus.length);
    assert.equal(summary.passedTotal + summary.failedTotal, summary.totalFixtures);

    // Verify latency percentiles are tracked
    assert.equal(summary.latencyStats.medianMs >= 0, true);
    assert.equal(summary.latencyStats.p95Ms >= summary.latencyStats.medianMs, true);
    assert.equal(summary.latencyStats.p99Ms >= summary.latencyStats.p95Ms, true);

    // Verify per-category breakdown is populated for all categories
    const reportedCategories = Object.keys(summary.categoryBreakdown);
    assert.equal(reportedCategories.length, 13);

    // Verify detection coverage is tracked honestly as a percentage
    assert.equal(typeof summary.detectionCoveragePct, 'number');
    assert.equal(typeof summary.preventionCoveragePct, 'number');

    // Ensure findings array is accessible for honest security reporting
    assert.equal(Array.isArray(summary.findings), true);
  });
});
