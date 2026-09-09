/**
 * Sovereign Security — Phase 2B: Ecosystem Fleet Wiring
 * Metro Task Force (MTF) Integration Adapter
 *
 * Ingests MTF security telemetry and normalizes MTF-specific domain events into
 * standard SecurityEvents.
 *
 * STRICT BOUNDARY RULES:
 * - Ingests authorized security-relevant events:
 *   - Authentication anomalies & admin login failures
 *   - Brute force spikes
 *   - Privileged operations & permission denials
 *   - Secrets exposure & API rate limiting
 * - Rejects pure business operations telemetry (e.g. dispatch tickets, patrol assignments,
 *   vehicle telemetry, routine status updates) to prevent security ledger pollution.
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
import { EcosystemAuthenticator, EcosystemCredentials } from '../auth/credentials.js';

export type MTFSecurityEventType =
  | 'ADMIN_LOGIN_FAILED'
  | 'ADMIN_LOGIN_SUCCESS'
  | 'RATE_LIMIT_TRIGGERED'
  | 'PERMISSION_DENIED'
  | 'SUSPICIOUS_API_ACTIVITY'
  | 'SECRET_EXPOSURE'
  | 'DEPLOYMENT_EVENT'
  | 'PAYMENT_SECURITY_EVENT';

export const REJECTED_BUSINESS_TELEMETRY = [
  'PATROL_LOCATION_PING',
  'DISPATCH_TICKET_CREATED',
  'OFFICER_STATUS_UPDATE',
  'VEHICLE_TELEMETRY',
  'EVIDENCE_ITEM_CHECKOUT',
  'ROUTINE_RADIO_LOG',
] as const;

export type MTFRejectedBusinessEventType = (typeof REJECTED_BUSINESS_TELEMETRY)[number];

export interface MTFRawSecurityPayload {
  eventId?: string;
  eventType: string; // evaluated against security vs business lists
  timestamp?: string;
  unitId?: string;
  stationId?: string;
  operatorId: string;
  targetEndpoint: string;
  action: string;
  status: 'SUCCESS' | 'FAILED' | 'DENIED' | 'FLAGGED';
  clientIp?: string;
  metadata?: Record<string, unknown>;
  correlationId?: string;
}

export interface MTFIngestResult {
  accepted: boolean;
  event?: SecurityEvent;
  alerts: SecurityAlert[];
  rejectedReason?: string;
}

export class MetroTaskForceAdapter {
  private threatEngine: ThreatEngine;

  constructor(threatEngine?: ThreatEngine) {
    this.threatEngine = threatEngine || new ThreatEngine();
  }

  /**
   * Evaluates if event is authorized security telemetry or rejected business data
   */
  public isSecurityRelevantEvent(eventType: string): boolean {
    const validSecurityEvents: string[] = [
      'ADMIN_LOGIN_FAILED',
      'ADMIN_LOGIN_SUCCESS',
      'RATE_LIMIT_TRIGGERED',
      'PERMISSION_DENIED',
      'SUSPICIOUS_API_ACTIVITY',
      'SECRET_EXPOSURE',
      'DEPLOYMENT_EVENT',
      'PAYMENT_SECURITY_EVENT',
    ];
    return validSecurityEvents.includes(eventType);
  }

  /**
   * Ingest and evaluate an MTF event, strictly enforcing mutual auth and telemetry boundaries
   */
  public ingestWithCredentials(
    payload: MTFRawSecurityPayload,
    credentials: EcosystemCredentials
  ): MTFIngestResult {
    // 1. Verify ecosystem mutual authentication
    const auth = EcosystemAuthenticator.verifyCredentials(credentials);
    if (!auth.authenticated) {
      return {
        accepted: false,
        alerts: [],
        rejectedReason: `ECOSYSTEM_AUTH_FAILED: ${auth.errorMessage}`,
      };
    }

    // 2. Reject pure business operations telemetry
    if (!this.isSecurityRelevantEvent(payload.eventType)) {
      return {
        accepted: false,
        alerts: [],
        rejectedReason: `TELEMETRY_REJECTED: Event type '${payload.eventType}' is operational business telemetry and not authorized for security event ledger.`,
      };
    }

    // 3. Normalize and process through ThreatEngine
    const normalized = this.normalizeMTFEvent(payload as MTFRawSecurityPayload & { eventType: MTFSecurityEventType });
    const alerts = this.threatEngine.processEvent(normalized);

    return {
      accepted: true,
      event: normalized,
      alerts,
    };
  }

  /**
   * Normalize an incoming MTF event into a standardized SecurityEvent
   */
  public normalizeMTFEvent(payload: MTFRawSecurityPayload & { eventType: MTFSecurityEventType }): SecurityEvent {
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
   * Backward-compatible ingest for existing test suites
   */
  public ingest(payload: MTFRawSecurityPayload): {
    event: SecurityEvent;
    alerts: SecurityAlert[];
  } {
    const normalized = this.normalizeMTFEvent(payload as any);
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
        return { severity: 'HIGH', category: 'AUTHORIZATION', result: 'DENIED' };
      case 'SUSPICIOUS_API_ACTIVITY':
        return { severity: 'CRITICAL', category: 'API', result: 'DENIED' };
      case 'SECRET_EXPOSURE':
        return { severity: 'CRITICAL', category: 'SECRETS', result: 'FAILURE' };
      case 'DEPLOYMENT_EVENT':
        return { severity: 'INFO', category: 'DEPLOYMENT', result: 'SUCCESS' };
      case 'PAYMENT_SECURITY_EVENT':
        return { severity: 'HIGH', category: 'APPLICATION', result: 'DENIED' };
      default:
        return { severity: 'MEDIUM', category: 'APPLICATION', result: 'DENIED' };
    }
  }
}
