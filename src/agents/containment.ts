/**
 * Sovereign Security — Milestone Phase 2A
 * Containment Agent: Automated Defensive Isolation, Fail-Safe TTL, and Auditable Release
 */

import { AuditService } from '../audit/audit-service.js';
import { globalMetrics } from '../observability/metrics.js';
import {
  ContainmentRequest,
  ContainmentResult,
  QuarantineRecord,
  QuarantineTargetType,
} from '../types/agents.js';

export interface ContainmentAgentOptions {
  auditService?: AuditService;
  defaultTtlMs?: number;
  maxTtlMs?: number;
}

export class ContainmentAgent {
  private quarantines: Map<string, QuarantineRecord> = new Map();
  private auditService?: AuditService;
  private defaultTtlMs: number;
  private maxTtlMs: number;

  constructor(options: ContainmentAgentOptions = {}) {
    this.auditService = options.auditService;
    this.defaultTtlMs = options.defaultTtlMs || 60 * 60 * 1000; // 1 hour default
    this.maxTtlMs = options.maxTtlMs || 24 * 60 * 60 * 1000; // 24 hours max fail-safe
  }

  public quarantine(request: ContainmentRequest): ContainmentResult {
    const now = new Date();
    const requestedTtl = request.ttlMs || this.defaultTtlMs;
    const effectiveTtl = Math.min(requestedTtl, this.maxTtlMs);
    const expiresAt = new Date(now.getTime() + effectiveTtl).toISOString();
    const quarantineId = `quarantine-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const initiatedBy = request.initiatedBy || 'containment-agent';

    const record: QuarantineRecord = {
      quarantineId,
      targetType: request.targetType,
      targetId: request.targetId,
      reason: request.reason,
      status: 'ACTIVE',
      initiatedBy,
      createdAt: now.toISOString(),
      expiresAt,
      isActive: true,
      metadata: request.metadata,
    };

    this.quarantines.set(quarantineId, record);

    globalMetrics.incrementCounter('sovereign_containment_quarantines_total');
    globalMetrics.setGauge('sovereign_active_quarantines', this.getActiveQuarantines().length);

    const correlationId =
      (request.metadata?.correlationId as string) ||
      (request.metadata?.traceCorrelationId as string) ||
      `containment-${quarantineId}`;
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

  public release(quarantineId: string, releasedBy: string, releaseReason: string): boolean {
    const record = this.quarantines.get(quarantineId);
    if (!record || record.status !== 'ACTIVE') {
      return false;
    }

    record.isActive = false;
    record.status = 'RELEASED';
    record.releasedAt = new Date().toISOString();
    record.releasedBy = releasedBy;
    record.releaseReason = releaseReason;

    globalMetrics.incrementCounter('sovereign_containment_releases_total');
    globalMetrics.setGauge('sovereign_active_quarantines', this.getActiveQuarantines().length);

    const correlationId =
      (record.metadata?.correlationId as string) ||
      (record.metadata?.traceCorrelationId as string) ||
      `containment-${quarantineId}`;

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
          correlationId,
        },
      });
    }

    return true;
  }

  public isQuarantined(targetId: string, targetType?: QuarantineTargetType): boolean {
    const now = new Date().toISOString();

    for (const record of this.quarantines.values()) {
      if (record.status !== 'ACTIVE') continue;

      if (record.expiresAt < now) {
        record.isActive = false;
        record.status = 'EXPIRED';
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
      if (record.status === 'ACTIVE') {
        if (record.expiresAt < now) {
          record.isActive = false;
          record.status = 'EXPIRED';
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
