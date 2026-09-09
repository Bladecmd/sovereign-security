/**
 * Sovereign Security — Foundation V0.1
 * Audit Foundation & Cryptographic Hash Chain Tests
 */

import assert from 'node:assert/strict';
import test, { beforeEach, describe } from 'node:test';
import { AuditService } from '../src/audit/audit-service.js';

describe('Append-Oriented Cryptographic Audit Service', () => {
  let auditService: AuditService;

  beforeEach(() => {
    auditService = new AuditService();
  });

  test('creates audit records capturing who, what, when, where, why, result', () => {
    const record = auditService.append({
      who: 'usr-admin-01',
      what: 'UPDATE_FIREWALL_RULE',
      where: 'perimeter-gateway-01',
      why: 'Ticket SEC-409: Block malicious CIDR block',
      result: 'SUCCESS',
      details: { cidr: '198.51.100.0/24', action: 'DROP' },
    });

    assert.equal(record.sequence, 1);
    assert.equal(record.who, 'usr-admin-01');
    assert.equal(record.what, 'UPDATE_FIREWALL_RULE');
    assert.equal(record.where, 'perimeter-gateway-01');
    assert.equal(record.why, 'Ticket SEC-409: Block malicious CIDR block');
    assert.equal(record.result, 'SUCCESS');
    assert.ok(record.currentHash.length === 64);
    assert.equal(record.previousHash, '0'.repeat(64)); // Genesis hash
  });

  test('successfully verifies integrity of multiple sequentially appended records', () => {
    for (let i = 1; i <= 5; i++) {
      auditService.append({
        who: `agent-0${i}`,
        what: `EXECUTE_TASK_${i}`,
        where: 'worker-cluster-01',
        why: `Scheduled task ${i}`,
        result: 'SUCCESS',
        details: { taskId: i },
      });
    }

    const verification = auditService.verifyIntegrity();
    assert.equal(verification.isValid, true);
    assert.equal(verification.totalRecords, 5);
    assert.equal(verification.tamperedIndex, undefined);
  });

  test('detects content tampering in an audit record', () => {
    auditService.append({
      who: 'usr-analyst-01',
      what: 'VIEW_AUDIT_LOGS',
      where: 'admin-portal',
      why: 'Routine check',
      result: 'SUCCESS',
      details: { page: 1 },
    });

    const secondRecord = auditService.append({
      who: 'usr-admin-02',
      what: 'TRANSFER_ROLES',
      where: 'iam-service',
      why: 'Promotion',
      result: 'SUCCESS',
      details: { grantedRole: 'AUDITOR' },
    });

    // Directly tamper with the second record in memory
    // @ts-expect-error - Simulating adversarial in-memory modification
    secondRecord.details = { grantedRole: 'FULL_ADMIN_SUPERUSER' };

    const verification = auditService.verifyIntegrity();
    assert.equal(verification.isValid, false);
    assert.equal(verification.tamperedIndex, 1);
    assert.match(verification.error || '', /Data tamper detected/i);
  });

  test('detects broken hash linkage if a record is injected or deleted', () => {
    auditService.append({
      who: 'usr-1',
      what: 'ACTION_1',
      where: 'srv',
      why: 'why-1',
      result: 'SUCCESS',
      details: {},
    });

    const record2 = auditService.append({
      who: 'usr-2',
      what: 'ACTION_2',
      where: 'srv',
      why: 'why-2',
      result: 'SUCCESS',
      details: {},
    });

    // Corrupt previousHash pointer
    // @ts-expect-error - Simulating adversarial hash break
    record2.previousHash = 'bad'.repeat(21) + 'b';

    const verification = auditService.verifyIntegrity();
    assert.equal(verification.isValid, false);
    assert.equal(verification.tamperedIndex, 1);
    assert.match(verification.error || '', /Hash chain break/i);
  });
});
