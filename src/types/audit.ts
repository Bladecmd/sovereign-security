/**
 * Sovereign Security — Foundation V0.1
 * Audit Foundation Types (Who, What, When, Where, Why, Result)
 * Append-oriented audit record with cryptographic hash-chaining verification
 */

export interface AuditRecord {
  sequence: number;
  auditId: string;
  who: string; // Actor ID / System ID / Agent ID
  what: string; // Operation / Action performed
  when: string; // ISO 8601 UTC timestamp
  where: string; // Service / Host / Environment / Endpoint
  why: string; // Intent / Business Reason / Ticket ID / Policy rationale
  result: 'SUCCESS' | 'FAILURE' | 'DENIED' | 'ERROR';
  details: Record<string, unknown>;
  previousHash: string; // Hash of previous audit record in chain
  currentHash: string; // SHA-256 hash of this record's canonical representation
}

export type CreateAuditRecordInput = Omit<
  AuditRecord,
  'sequence' | 'auditId' | 'when' | 'previousHash' | 'currentHash'
> & {
  auditId?: string;
  when?: string;
};

export interface AuditVerificationResult {
  isValid: boolean;
  totalRecords: number;
  tamperedIndex?: number;
  tamperedRecordId?: string;
  error?: string;
}
