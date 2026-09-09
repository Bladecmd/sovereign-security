/**
 * Sovereign Security — Foundation V0.1
 * Risk Engine Deterministic Scoring Tests
 */

import assert from 'node:assert/strict';
import test, { describe } from 'node:test';
import { RiskEngine } from '../src/risk/engine.js';

describe('Deterministic Risk Scoring Engine', () => {
  test('calculates base risk for standard read operations', () => {
    const score = RiskEngine.calculateRisk({
      severity: 'INFO',
      action: 'read_dashboard',
      assetCriticality: 'MEDIUM',
    });

    assert.ok(score >= 0 && score <= 20);
  });

  test('amplifies risk score for administrative actions on mission-critical assets', () => {
    const standardScore = RiskEngine.calculateRisk({
      severity: 'HIGH',
      action: 'read_logs',
      assetCriticality: 'MEDIUM',
    });

    const highCriticalityAdminScore = RiskEngine.calculateRisk({
      severity: 'HIGH',
      action: 'admin_modify_policy',
      assetCriticality: 'MISSION_CRITICAL',
    });

    assert.ok(highCriticalityAdminScore > standardScore);
  });

  test('adjusts risk score based on authentication state', () => {
    const unauthenticatedScore = RiskEngine.calculateRisk({
      severity: 'MEDIUM',
      action: 'query_api',
      authState: 'UNAUTHENTICATED',
    });

    const mfaScore = RiskEngine.calculateRisk({
      severity: 'MEDIUM',
      action: 'query_api',
      authState: 'MFA_VERIFIED',
    });

    assert.ok(unauthenticatedScore > mfaScore);
  });

  test('increases risk score with repetition/frequency', () => {
    const singleFailure = RiskEngine.calculateRisk({
      severity: 'HIGH',
      action: 'authenticate',
      repetitionCount: 1,
    });

    const repeatedFailures = RiskEngine.calculateRisk({
      severity: 'HIGH',
      action: 'authenticate',
      repetitionCount: 5,
    });

    assert.ok(repeatedFailures > singleFailure);
  });

  test('strictly clamps score to 0 - 100 range', () => {
    const extremeMax = RiskEngine.calculateRisk({
      severity: 'CRITICAL',
      action: 'drop_database_root_admin',
      assetCriticality: 'MISSION_CRITICAL',
      authState: 'UNAUTHENTICATED',
      repetitionCount: 20,
    });

    assert.equal(extremeMax, 100);

    const extremeMin = RiskEngine.calculateRisk({
      severity: 'INFO',
      action: 'read_status',
      assetCriticality: 'LOW',
      authState: 'CERTIFICATE_BOUND',
    });

    assert.ok(extremeMin >= 0);
  });
});
