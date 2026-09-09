/**
 * Sovereign Security — Foundation V0.1
 * Identity & RBAC Tests
 */

import assert from 'node:assert/strict';
import test, { describe } from 'node:test';
import { IdentityAccessEvaluator } from '../src/identity/rbac.js';
import {
  MOCK_ADMIN_SUBJECT,
  MOCK_EXECUTIVE_SUBJECT,
  MOCK_SERVICE_SUBJECT,
  MOCK_VEGA_AGENT_SUBJECT,
} from './fixtures/test-events.js';

describe('Identity & RBAC Least-Privilege Evaluator', () => {
  test('grants ADMIN permissions according to least privilege', () => {
    const readCheck = IdentityAccessEvaluator.hasPermission(MOCK_ADMIN_SUBJECT, 'READ');
    assert.equal(readCheck.granted, true);

    const adminCheck = IdentityAccessEvaluator.hasPermission(MOCK_ADMIN_SUBJECT, 'ADMINISTER');
    assert.equal(adminCheck.granted, true);

    // ADMIN cannot certify executive financial reports without executive role
    const certifyCheck = IdentityAccessEvaluator.hasPermission(
      MOCK_ADMIN_SUBJECT,
      'CERTIFY',
      'certify_financial_reports'
    );
    assert.equal(certifyCheck.granted, false);
  });

  test('grants EXECUTIVE certification permissions but restricts raw infrastructure modifications', () => {
    const certifyCheck = IdentityAccessEvaluator.hasPermission(MOCK_EXECUTIVE_SUBJECT, 'CERTIFY');
    assert.equal(certifyCheck.granted, true);

    const infraCheck = IdentityAccessEvaluator.hasPermission(
      MOCK_EXECUTIVE_SUBJECT,
      'WRITE',
      'direct_infrastructure_modification'
    );
    assert.equal(infraCheck.granted, false);
  });

  test('restricts AGENT from unauthorized or destructive operations', () => {
    const readCheck = IdentityAccessEvaluator.hasPermission(MOCK_VEGA_AGENT_SUBJECT, 'READ');
    assert.equal(readCheck.granted, true);

    // AGENT strictly blocked from fund transfers
    const transferCheck = IdentityAccessEvaluator.hasPermission(
      MOCK_VEGA_AGENT_SUBJECT,
      'EXECUTE',
      'transfer_funds'
    );
    assert.equal(transferCheck.granted, false);

    // AGENT strictly blocked from deleting production data
    const deleteCheck = IdentityAccessEvaluator.hasPermission(
      MOCK_VEGA_AGENT_SUBJECT,
      'EXECUTE',
      'delete_production_data'
    );
    assert.equal(deleteCheck.granted, false);
  });

  test('denies ungranted permissions by default (Zero-Trust)', () => {
    const serviceAdminCheck = IdentityAccessEvaluator.hasPermission(
      MOCK_SERVICE_SUBJECT,
      'ADMINISTER'
    );
    assert.equal(serviceAdminCheck.granted, false);
  });
});
