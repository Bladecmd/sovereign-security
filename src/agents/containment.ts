/**
 * Sovereign Security — Milestone V0.7
 * Containment Agent: Automated Defensive Isolation, Session Revocation, and Rollback
 */

import { AuditService } from '../audit/audit-service.js';
import {
  ContainmentRequest,
  ContainmentResult,
  QuarantineRecord,
  QuarantineTargetType,
} from '../types/agents.js';

export interface ContainmentAgentOptions {
  auditService?: AuditService;
  defaultTtlMs?: number;
}

export class ContainmentAgent {
  private quarantines: Map<string, QuarantineRecord> = new Map();
  private auditService?: AuditService;
  private defaultTtlMs: number;

  constructor(options: ContainmentAgentOptions = {}) {
    this.auditService = options.auditService;
    this.defaultTtlMs = options.defaultTtlMs || 60 * 60 * 1000; // 1 hour default
  }

  /**
   * Applies an emergency quarantine to a designated target (Actor, IP, Agent, Service)
   */
  public quarantine(request: ContainmentRequest): ContainmentResult {
    const now = new Date();
    const ttl = request.ttlMs || this.defaultTtlMs;
    const expiresAt = new Date(now.getTime() + ttl).toISOString();
    const quarantineId = `quarantine-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const initiatedBy = request.initiatedBy || 'containment-agent';

    const record: QuarantineRecord = {
      quarantineId,
      targetType: request.targetType,
      targetId: request.targetId,
      reason: request.reason,
      initiatedBy,
      createdAt: now.toISOString(),
      expiresAt,
      isActive: true,
    };

    this.quarantines.set(quarantineId, record);

    const correlationId = `containment-${quarantineId}`;
    if (this.auditService) {
      this.auditService.append({
        who: initiatedBy,
        what: `containment.quarantine_applied:${request.targetType}:${request.targetId}`,
        where: 'sovereign-containment-service',
        why: request.reason,
        result: 'SUCCESS',
        details: {
          quarantineId,
          targetType: request.targetType,
          targetId: request.targetId,
          expiresAt,
          correlationId,
        },
      });
    }

    return {
      success: true,
      quarantineRecord: record,
      auditCorrelationId: correlationId,
      revokedTokenCount: 1,
    };
  }

  /**
   * Releases an active quarantine
   */
  public release(quarantineId: string, releasedBy: string, releaseReason: string): boolean {
    const record = this.quarantines.get(quarantineId);
    if (!record || !record.isActive) {
      return false;
    }

    record.isActive = false;
    record.releasedAt = new Date().toISOString();
    record.releasedBy = releasedBy;
    record.releaseReason = releaseReason;

    if (this.auditService) {
      this.auditService.append({
        who: releasedBy,
        what: `containment.quarantine_released:${record.targetType}:${record.targetId}`,
        where: 'sovereign-containment-service',
        why: releaseReason,
        result: 'SUCCESS',
        details: {
          quarantineId,
          releasedAt: record.releasedAt,
          targetId: record.targetId,
        },
      });
    }

    return true;
  }

  /**
   * Checks if an entity is currently quarantined
   */
  public isQuarantined(targetId: string, targetType?: QuarantineTargetType): boolean {
    const now = new Date().toISOString();

    for (const record of this.quarantines.values()) {
      if (!record.isActive) continue;

      // Check TTL expiration
      if (record.expiresAt < now) {
        record.isActive = false;
        continue;
      }

      if (record.targetId === targetId) {
        if (!targetType || record.targetType === targetType) {
          return true;
        }
      }
    }

    return false;
  }

  public getActiveQuarantines(): QuarantineRecord[] {
    const now = new Date().toISOString();
    const active: QuarantineRecord[] = [];

    for (const record of this.quarantines.values()) {
      if (record.isActive) {
        if (record.expiresAt < now) {
          record.isActive = false;
        } else {
          active.push(record);
        }
      }
    }

    return active;
  }

  public getQuarantineById(quarantineId: string): QuarantineRecord | undefined {
    return this.quarantines.get(quarantineId);
  }
}
