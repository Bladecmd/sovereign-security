/**
 * Sovereign Security — Foundation V0.1
 * Append-Oriented Cryptographic Audit Service
 *
 * Implements:
 * - who, what, when, where, why, result record architecture
 * - SHA-256 cryptographic hash-chaining across sequentially appended records
 * - Complete chain tamper-verification engine
 */

import { createHash } from 'node:crypto';
import {
  AuditRecord,
  AuditVerificationResult,
  CreateAuditRecordInput,
} from '../types/audit.js';

export class AuditService {
  private chain: AuditRecord[] = [];
  private readonly genesisHash = '0'.repeat(64);

  constructor(initialRecords: AuditRecord[] = []) {
    if (initialRecords.length > 0) {
      this.chain = [...initialRecords];
    }
  }

  /**
   * Append a new audit record to the tamper-evident chain
   */
  public append(input: CreateAuditRecordInput): AuditRecord {
    const sequence = this.chain.length + 1;
    const auditId = input.auditId || `audit-${Date.now()}-${sequence}`;
    const when = input.when || new Date().toISOString();
    const previousHash =
      this.chain.length === 0
        ? this.genesisHash
        : this.chain[this.chain.length - 1]!.currentHash;

    const payloadToHash = this.serializeForHash({
      sequence,
      auditId,
      who: input.who,
      what: input.what,
      when,
      where: input.where,
      why: input.why,
      result: input.result,
      details: input.details,
      previousHash,
    });

    const currentHash = this.computeSha256(payloadToHash);

    const record: AuditRecord = {
      sequence,
      auditId,
      who: input.who,
      what: input.what,
      when,
      where: input.where,
      why: input.why,
      result: input.result,
      details: input.details,
      previousHash,
      currentHash,
    };

    this.chain.push(record);
    return record;
  }

  /**
   * Retrieve all audit records
   */
  public getRecords(): readonly AuditRecord[] {
    return this.chain;
  }

  /**
   * Verify the cryptographic integrity of the entire audit chain
   */
  public verifyIntegrity(): AuditVerificationResult {
    if (this.chain.length === 0) {
      return { isValid: true, totalRecords: 0 };
    }

    let expectedPreviousHash = this.genesisHash;

    for (let i = 0; i < this.chain.length; i++) {
      const record = this.chain[i]!;

      // 1. Check sequence number continuity
      if (record.sequence !== i + 1) {
        return {
          isValid: false,
          totalRecords: this.chain.length,
          tamperedIndex: i,
          tamperedRecordId: record.auditId,
          error: `Sequence mismatch at index ${i}. Expected ${i + 1}, found ${record.sequence}.`,
        };
      }

      // 2. Check previous hash linkage
      if (record.previousHash !== expectedPreviousHash) {
        return {
          isValid: false,
          totalRecords: this.chain.length,
          tamperedIndex: i,
          tamperedRecordId: record.auditId,
          error: `Hash chain break at index ${i}. Record's previousHash does not match computed hash of prior record.`,
        };
      }

      // 3. Recalculate and check record's currentHash
      const payloadToHash = this.serializeForHash({
        sequence: record.sequence,
        auditId: record.auditId,
        who: record.who,
        what: record.what,
        when: record.when,
        where: record.where,
        why: record.why,
        result: record.result,
        details: record.details,
        previousHash: record.previousHash,
      });

      const recomputedHash = this.computeSha256(payloadToHash);
      if (recomputedHash !== record.currentHash) {
        return {
          isValid: false,
          totalRecords: this.chain.length,
          tamperedIndex: i,
          tamperedRecordId: record.auditId,
          error: `Data tamper detected in record ${record.auditId} at index ${i}. Hash checksum does not match content.`,
        };
      }

      expectedPreviousHash = record.currentHash;
    }

    return {
      isValid: true,
      totalRecords: this.chain.length,
    };
  }

  private computeSha256(data: string): string {
    return createHash('sha256').update(data).digest('hex');
  }

  private serializeForHash(data: {
    sequence: number;
    auditId: string;
    who: string;
    what: string;
    when: string;
    where: string;
    why: string;
    result: string;
    details: Record<string, unknown>;
    previousHash: string;
  }): string {
    // Deterministic key sorting for canonical hashing
    return JSON.stringify({
      sequence: data.sequence,
      auditId: data.auditId,
      who: data.who,
      what: data.what,
      when: data.when,
      where: data.where,
      why: data.why,
      result: data.result,
      details: this.sortObjectKeys(data.details),
      previousHash: data.previousHash,
    });
  }

  private sortObjectKeys(obj: unknown): unknown {
    if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) {
      return obj;
    }
    const sorted: Record<string, unknown> = {};
    const keys = Object.keys(obj as Record<string, unknown>).sort();
    for (const key of keys) {
      sorted[key] = this.sortObjectKeys((obj as Record<string, unknown>)[key]);
    }
    return sorted;
  }
}
