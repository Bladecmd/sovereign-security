/**
 * Sovereign Security — Foundation V0.1
 * SecurityAlert Schema & Lifecycle Tests
 */

import assert from 'node:assert/strict';
import test, { describe } from 'node:test';
import {
  safeValidateSecurityAlert,
  validateSecurityAlert,
} from '../src/schemas/alert.schema.js';
import { VALID_SECURITY_ALERT } from './fixtures/test-events.js';

describe('SecurityAlert Schema & Validation', () => {
  test('validates a properly formatted SecurityAlert', () => {
    const alert = validateSecurityAlert(VALID_SECURITY_ALERT);
    assert.equal(alert.alertId, 'alt-test-5001');
    assert.equal(alert.severity, 'HIGH');
    assert.equal(alert.category, 'AUTHENTICATION');
    assert.equal(alert.status, 'OPEN');
    assert.equal(alert.sourceEventIds.length, 1);
  });

  test('rejects alert without source event IDs', () => {
    const invalidAlert = {
      ...VALID_SECURITY_ALERT,
      sourceEventIds: [],
    };
    const result = safeValidateSecurityAlert(invalidAlert);
    assert.equal(result.success, false);
  });

  test('supports alert status updates across incident lifecycle', () => {
    const acknowledged = validateSecurityAlert({
      ...VALID_SECURITY_ALERT,
      status: 'ACKNOWLEDGED',
      assignedTo: 'sec-analyst-09',
    });
    assert.equal(acknowledged.status, 'ACKNOWLEDGED');
    assert.equal(acknowledged.assignedTo, 'sec-analyst-09');

    const resolved = validateSecurityAlert({
      ...VALID_SECURITY_ALERT,
      status: 'RESOLVED',
      assignedTo: 'sec-analyst-09',
      resolution: 'Source IP blocked at perimeter firewall. No credentials compromised.',
      resolvedAt: '2026-09-09T12:30:00.000Z',
    });
    assert.equal(resolved.status, 'RESOLVED');
    assert.ok(resolved.resolvedAt);
  });
});
