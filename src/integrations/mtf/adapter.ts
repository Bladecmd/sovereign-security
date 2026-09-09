/**
 * Sovereign Security — Foundation V0.1
 * Metro Task Force (MTF) Integration Adapter
 *
 * Ingests MTF telemetry and normalizes MTF-specific domain events into standard SecurityEvents.
 * Does not duplicate MTF business logic.
 */

import { RiskEngine } from '../../risk/engine.js';
import { ThreatEngine } from '../../threat/engine.js';
import { SecurityAlert } from '../../types/alerts.js';
import {
  SecurityCategory,
  SecurityEvent,
  SecurityResult,
  SecuritySeverity,
} from '../../types/events.js';
import { validateSecurityEvent } from '../../schemas/event.schema.js';

export type MTFEventType =
  | 'ADMIN_LOGIN_FAILED'
  | 'ADMIN_LOGIN_SUCCESS'
  | 'RATE_LIMIT_TRIGGERED'
  | 'PERMISSION_DENIED'
  | 'SUSPICIOUS_API_ACTIVITY'
  | 'SECRET_EXPOSURE'
  | 'DEPLOYMENT_EVENT'
  | 'PAYMENT_SECURITY_EVENT';

export interface MTFRawSecurityPayload {
  eventId?: string;
  eventType: MTFEventType;
  timestamp?: string;
  unitId?: string; // MTF Unit or Officer identifier
  stationId?: string;
  operatorId: string;
  targetEndpoint: string;
  action: string;
  status: 'SUCCESS' | 'FAILED' | 'DENIED' | 'FLAGGED';
  clientIp?: string;
  metadata?: Record<string, unknown>;
  correlationId?: string;
}

export class MetroTaskForceAdapter {
  private threatEngine: ThreatEngine;

  constructor(threatEngine?: ThreatEngine) {
    this.threatEngine = threatEngine || new ThreatEngine();
  }

  /**
   * Normalize an incoming MTF event into a standardized SecurityEvent
   */
  public normalizeMTFEvent(payload: MTFRawSecurityPayload): SecurityEvent {
    const timestamp = payload.timestamp || new Date().toISOString();
    const eventId = payload.eventId || `mtf-evt-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const correlationId =
      payload.correlationId || `corr-mtf-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;

    const { severity, category, result } = this.mapMTFEventDetails(payload);

    const riskScore = RiskEngine.calculateRisk({
      severity,
      action: payload.action,
      authState: payload.eventType === 'ADMIN_LOGIN_FAILED' ? 'UNAUTHENTICATED' : undefined,
    });

    const normalized: SecurityEvent = {
      eventId,
      timestamp,
      source: 'metro-task-force',
      businessId: 'mtf-hq',
      environment: (payload.metadata?.['env'] as string) || 'production',
      severity,
      category,
      eventType: payload.eventType,
      actorId: payload.operatorId || payload.unitId || 'anonymous-mtf-actor',
      resourceId: payload.targetEndpoint,
      action: payload.action,
      result,
      riskScore,
      verificationStatus: 'VERIFIED',
      metadata: {
        unitId: payload.unitId,
        stationId: payload.stationId,
        clientIp: payload.clientIp,
        ...(payload.metadata || {}),
      },
      correlationId,
    };

    return validateSecurityEvent(normalized);
  }

  /**
   * Ingest and evaluate an MTF event, generating alerts if threat rules trigger
   */
  public ingest(payload: MTFRawSecurityPayload): {
    event: SecurityEvent;
    alerts: SecurityAlert[];
  } {
    const normalized = this.normalizeMTFEvent(payload);
    const alerts = this.threatEngine.processEvent(normalized);
    return { event: normalized, alerts };
  }

  private mapMTFEventDetails(payload: MTFRawSecurityPayload): {
    severity: SecuritySeverity;
    category: SecurityCategory;
    result: SecurityResult;
  } {
    switch (payload.eventType) {
      case 'ADMIN_LOGIN_FAILED':
        return { severity: 'HIGH', category: 'AUTHENTICATION', result: 'FAILURE' };
      case 'ADMIN_LOGIN_SUCCESS':
        return { severity: 'INFO', category: 'AUTHENTICATION', result: 'SUCCESS' };
      case 'RATE_LIMIT_TRIGGERED':
        return { severity: 'MEDIUM', category: 'API', result: 'DENIED' };
      case 'PERMISSION_DENIED':
        return { severity: 'MEDIUM', category: 'AUTHORIZATION', result: 'DENIED' };
      case 'SUSPICIOUS_API_ACTIVITY':
        return { severity: 'HIGH', category: 'API', result: 'DENIED' };
      case 'SECRET_EXPOSURE':
        return { severity: 'CRITICAL', category: 'SECRETS', result: 'FAILURE' };
      case 'DEPLOYMENT_EVENT':
        return { severity: 'INFO', category: 'DEPLOYMENT', result: 'SUCCESS' };
      case 'PAYMENT_SECURITY_EVENT':
        return { severity: 'HIGH', category: 'APPLICATION', result: payload.status === 'SUCCESS' ? 'SUCCESS' : 'DENIED' };
      default:
        return { severity: 'LOW', category: 'APPLICATION', result: 'SUCCESS' };
    }
  }
}
