/**
 * Sovereign Security — Phase 2B: Ecosystem Fleet Wiring
 * GriDD Corp Integration Adapter
 *
 * Provides group-level security governance and fleet posture feeds to GriDD Corp:
 * - Genuine aggregated fleet security posture (active alerts, risk distribution, audit counts)
 * - Zero synthetic compliance percentages or fabricated telemetry
 * - Real-time forwarding of CRITICAL and HIGH severity alerts
 * - Audit bundle exports for group-level oversight
 */

import { AuditService } from '../../audit/audit-service.js';
import { CreateSecurityAlertInput, SecurityAlert } from '../../types/alerts.js';
import { validateSecurityAlert } from '../../schemas/alert.schema.js';
import { EcosystemAuthenticator, EcosystemCredentials } from '../auth/credentials.js';

export interface GriDDFleetPostureSummary {
  reportedAt: string;
  totalActiveAlerts: number;
  alertsBySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  totalAuditRecords: number;
  auditLedgerIntegrity: boolean;
  authorizedEntitiesReporting: readonly string[];
}

export interface GriDDFleetAlertForwardingResult {
  forwardedCount: number;
  alerts: SecurityAlert[];
  dispatchedAt: string;
}

export class SecurityAlertService {
  private alerts: Map<string, SecurityAlert> = new Map();

  public createAlert(input: Partial<CreateSecurityAlertInput> & { title: string; severity?: any; category?: any; description?: string }): SecurityAlert {
    const alertId = input.alertId || `alt-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
    const createdAt = input.createdAt || new Date().toISOString();
    const alert: SecurityAlert = {
      alertId,
      createdAt,
      severity: input.severity || 'MEDIUM',
      category: input.category || 'APPLICATION',
      title: input.title,
      description: input.description || input.title,
      sourceEventIds: input.sourceEventIds || [`evt-${Date.now()}`],
      affectedResource: input.affectedResource || 'system',
      riskScore: input.riskScore ?? 50,
      status: input.status || 'OPEN',
      actorId: input.actorId,
      tenantId: input.tenantId,
      assignedTo: input.assignedTo,
      resolution: input.resolution,
      resolvedAt: input.resolvedAt,
    };

    const validated = validateSecurityAlert(alert);
    this.alerts.set(validated.alertId, validated);
    return validated;
  }

  public listAlerts(filter?: { severity?: string; status?: string }): SecurityAlert[] {
    let result = Array.from(this.alerts.values());
    if (filter?.severity) {
      result = result.filter((a) => a.severity === filter.severity);
    }
    if (filter?.status) {
      result = result.filter((a) => a.status === filter.status);
    }
    return result;
  }

  public getAlert(alertId: string): SecurityAlert | undefined {
    return this.alerts.get(alertId);
  }
}

export class GriDDCorpAdapter {
  private alertService: SecurityAlertService;
  private auditService: AuditService;

  constructor(alertService?: SecurityAlertService, auditService?: AuditService) {
    this.alertService = alertService || new SecurityAlertService();
    this.auditService = auditService || new AuditService();
  }

  public getAlertService(): SecurityAlertService {
    return this.alertService;
  }

  /**
   * Retrieves genuine fleet governance posture summary for GriDD Corp
   */
  public getFleetPostureSummary(credentials: EcosystemCredentials): {
    success: boolean;
    posture?: GriDDFleetPostureSummary;
    error?: string;
  } {
    const auth = EcosystemAuthenticator.verifyCredentials(credentials);
    if (!auth.authenticated) {
      return {
        success: false,
        error: `ECOSYSTEM_AUTH_FAILED: ${auth.errorMessage}`,
      };
    }

    const openAlerts = this.alertService.listAlerts({ status: 'OPEN' });
    const severityCount = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    for (const alert of openAlerts) {
      const sev = alert.severity?.toLowerCase() as keyof typeof severityCount;
      if (severityCount[sev] !== undefined) {
        severityCount[sev]++;
      }
    }

    const auditRecords = this.auditService.getRecords();
    const integrity = this.auditService.verifyIntegrity();

    return {
      success: true,
      posture: {
        reportedAt: new Date().toISOString(),
        totalActiveAlerts: openAlerts.length,
        alertsBySeverity: severityCount,
        totalAuditRecords: auditRecords.length,
        auditLedgerIntegrity: integrity.isValid,
        authorizedEntitiesReporting: EcosystemAuthenticator.getAuthorizedEntities(),
      },
    };
  }

  /**
   * Forwards high-severity (CRITICAL and HIGH) security alerts to GriDD Corp board/CISO dashboard
   */
  public getHighSeverityAlertsForForwarding(credentials: EcosystemCredentials): {
    success: boolean;
    forwarding?: GriDDFleetAlertForwardingResult;
    error?: string;
  } {
    const auth = EcosystemAuthenticator.verifyCredentials(credentials);
    if (!auth.authenticated) {
      return {
        success: false,
        error: `ECOSYSTEM_AUTH_FAILED: ${auth.errorMessage}`,
      };
    }

    const criticals = this.alertService.listAlerts({ severity: 'CRITICAL', status: 'OPEN' });
    const highs = this.alertService.listAlerts({ severity: 'HIGH', status: 'OPEN' });
    const combined = [...criticals, ...highs];

    return {
      success: true,
      forwarding: {
        forwardedCount: combined.length,
        alerts: combined,
        dispatchedAt: new Date().toISOString(),
      },
    };
  }
}
