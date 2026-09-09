/**
 * Sovereign Security — Foundation V0.1
 * SecurityEvent Schema & Validation Tests
 */

import assert from 'node:assert/strict';
import test, { describe } from 'node:test';
import {
  safeValidateSecurityEvent,
  validateSecurityEvent,
} from '../src/schemas/event.schema.js';
import { VALID_SECURITY_EVENT } from './fixtures/test-events.js';

describe('SecurityEvent Schema & Contract Validation', () => {
  test('successfully validates a well-formed SecurityEvent', () => {
    const validated = validateSecurityEvent(VALID_SECURITY_EVENT);
    assert.equal(validated.eventId, 'evt-test-1001');
    assert.equal(validated.severity, 'INFO');
    assert.equal(validated.category, 'AUTHENTICATION');
    assert.equal(validated.result, 'SUCCESS');
    assert.equal(validated.riskScore, 10);
    assert.equal(validated.verificationStatus, 'VERIFIED');
  });

  test('rejects events with invalid timestamp format', () => {
    const invalidEvent = {
      ...VALID_SECURITY_EVENT,
      timestamp: 'not-a-valid-iso-date',
    };
    const result = safeValidateSecurityEvent(invalidEvent);
    assert.equal(result.success, false);
    if (!result.success) {
      assert.match(result.error.issues[0]?.message || '', /ISO 8601/i);
    }
  });

  test('rejects events with out-of-bounds riskScore', () => {
    const invalidEventHigh = {
      ...VALID_SECURITY_EVENT,
      riskScore: 105,
    };
    const invalidEventLow = {
      ...VALID_SECURITY_EVENT,
      riskScore: -5,
    };

    assert.equal(safeValidateSecurityEvent(invalidEventHigh).success, false);
    assert.equal(safeValidateSecurityEvent(invalidEventLow).success, false);
  });

  test('rejects events with unsupported severity or category', () => {
    const invalidSeverity = {
      ...VALID_SECURITY_EVENT,
      severity: 'SUPER_CRITICAL',
    };
    const invalidCategory = {
      ...VALID_SECURITY_EVENT,
      category: 'MARKETING',
    };

    assert.equal(safeValidateSecurityEvent(invalidSeverity).success, false);
    assert.equal(safeValidateSecurityEvent(invalidCategory).success, false);
  });

  test('requires mandatory correlationId and actorId', () => {
    const missingActor = {
      ...VALID_SECURITY_EVENT,
      actorId: '',
    };
    assert.equal(safeValidateSecurityEvent(missingActor).success, false);
  });
});
