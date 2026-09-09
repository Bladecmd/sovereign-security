/**
 * Sovereign Security — Milestone Phase 2A
 * Persistent Append-Only Audit Ledger
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { AuditRecord, AuditVerificationResult, CreateAuditRecordInput } from '../types/audit.js';
import { AuditService } from './audit-service.js';
import { globalMetrics } from '../observability/metrics.js';

export class PersistentAuditLedger {
  private filePath: string;
  private memoryService: AuditService;
  private isInitialized: boolean = false;

  constructor(filePath: string) {
    this.filePath = filePath;
    this.memoryService = new AuditService();
  }

  public initialize(): AuditVerificationResult {
    const dir = dirname(this.filePath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }

    if (!existsSync(this.filePath)) {
      this.isInitialized = true;
      globalMetrics.setGauge('sovereign_audit_ledger_integrity_status', 1);
      globalMetrics.setGauge('sovereign_audit_ledger_records', 0);
      return { isValid: true, totalRecords: 0 };
    }

    const content = readFileSync(this.filePath, 'utf-8');
    const lines = content.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);

    const restoredRecords: AuditRecord[] = [];
    for (let i = 0; i < lines.length; i++) {
      try {
        const record = JSON.parse(lines[i]!) as AuditRecord;
        restoredRecords.push(record);
      } catch (err) {
        globalMetrics.setGauge('sovereign_audit_ledger_integrity_status', 0);
        return {
          isValid: false,
          totalRecords: i,
          tamperedIndex: i,
          error: `Corrupt JSON line at index ${i}: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    }

    this.memoryService = new AuditService(restoredRecords);
    const verify = this.memoryService.verifyIntegrity();

    globalMetrics.setGauge('sovereign_audit_ledger_integrity_status', verify.isValid ? 1 : 0);
    globalMetrics.setGauge('sovereign_audit_ledger_records', verify.totalRecords);

    if (!verify.isValid) {
      this.isInitialized = false;
      return verify;
    }

    this.isInitialized = true;
    return verify;
  }

  public append(input: CreateAuditRecordInput): AuditRecord {
    if (!this.isInitialized) {
      const initResult = this.initialize();
      if (!initResult.isValid) {
        throw new Error(`Cannot append to compromised audit ledger: ${initResult.error}`);
      }
    }

    const record = this.memoryService.append(input);
    const serializedLine = JSON.stringify(record) + '\n';
    appendFileSync(this.filePath, serializedLine, { encoding: 'utf-8' });

    globalMetrics.incrementCounter('sovereign_audit_records_persisted_total');
    globalMetrics.setGauge('sovereign_audit_ledger_records', this.memoryService.getRecords().length);

    return record;
  }

  public getRecords(): readonly AuditRecord[] {
    return this.memoryService.getRecords();
  }

  public verifyIntegrity(): AuditVerificationResult {
    return this.memoryService.verifyIntegrity();
  }

  public getAuditService(): AuditService {
    return this.memoryService;
  }
}
