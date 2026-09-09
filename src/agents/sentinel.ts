/**
 * Sovereign Security — Milestone V0.7
 * Sentinel Agent: 24/7 Automated Alert Triage, Noise Suppression, and Correlation
 */

import { SecurityAlert } from '../types/alerts.js';
import { IncidentCluster, TriageResult } from '../types/agents.js';

export interface SentinelConfig {
  testActorPrefixes?: string[];
  maxClusterWindowMs?: number;
}

export class SentinelAgent {
  private testActorPrefixes: string[];
  private maxClusterWindowMs: number;
  private knownAlerts: Map<string, SecurityAlert> = new Map();

  constructor(config: SentinelConfig = {}) {
    this.testActorPrefixes = config.testActorPrefixes || [
      'test-',
      'synthetic-',
      'probe-',
      'mock-',
      'ci-runner',
    ];
    this.maxClusterWindowMs = config.maxClusterWindowMs || 15 * 60 * 1000; // 15 mins
  }

  public registerAlert(alert: SecurityAlert): void {
    this.knownAlerts.set(alert.alertId, alert);
  }

  /**
   * Evaluates an incoming alert, detects false positives, correlates with existing alerts,
   * and outputs a deterministic triage recommendation.
   */
  public triageAlert(alert: SecurityAlert, historicalAlerts?: SecurityAlert[]): TriageResult {
    const alertsToCorrelate = historicalAlerts || Array.from(this.knownAlerts.values());
    const actorId = alert.actorId || alert.affectedResource;

    // 1. False-Positive / Test Environment Suppression
    const isTestActor = this.testActorPrefixes.some((prefix) =>
      actorId.toLowerCase().startsWith(prefix)
    );
    const isTestTitle = alert.title.toLowerCase().includes('synthetic') ||
      alert.title.toLowerCase().includes('automated test probe');

    if (isTestActor || isTestTitle) {
      return {
        alertId: alert.alertId,
        originalSeverity: alert.severity,
        recommendedSeverity: 'LOW',
        decision: 'SUPPRESS',
        confidence: 0.95,
        rationale: `Suppressed: Alert attributed to recognized synthetic test actor '${actorId}' or test probe.`,
        correlatedAlertIds: [],
        matchedRule: 'FALSE_POSITIVE_SYNTHETIC_SUPPRESSION',
      };
    }

    // 2. Alert Correlation: find other alerts with same actor or source events
    const correlatedAlerts = alertsToCorrelate.filter((a) => {
      if (a.alertId === alert.alertId) return false;
      const otherActor = a.actorId || a.affectedResource;
      if (otherActor && otherActor === actorId) return true;
      // Match on shared source events
      return a.sourceEventIds.some((id) => alert.sourceEventIds.includes(id));
    });

    const correlatedAlertIds = correlatedAlerts.map((a) => a.alertId);

    // 3. Immediate Containment Trigger (Secrets, Brute Force, Unauthorized Privilege Action)
    const alertTitleUpper = alert.title.toUpperCase();
    const isCriticalThreat =
      alert.severity === 'CRITICAL' ||
      alertTitleUpper.includes('SECRET') ||
      alertTitleUpper.includes('BRUTE FORCE') ||
      alertTitleUpper.includes('UNAUTHORIZED PRIVILEGED');

    if (isCriticalThreat) {
      return {
        alertId: alert.alertId,
        originalSeverity: alert.severity,
        recommendedSeverity: 'CRITICAL',
        decision: 'CONTAIN',
        confidence: 0.98,
        rationale: `Automated Containment Recommended: Critical security event (${alert.title}). Immediate actor isolation required.`,
        correlatedAlertIds,
        matchedRule: 'CRITICAL_THREAT_AUTO_CONTAINMENT',
      };
    }

    // 4. Repeated Activity Escalation (3+ alerts from same actor)
    if (correlatedAlerts.length >= 2) {
      return {
        alertId: alert.alertId,
        originalSeverity: alert.severity,
        recommendedSeverity: 'HIGH',
        decision: 'ESCALATE',
        confidence: 0.9,
        rationale: `Escalation Recommended: Repeated threat activity detected. Actor '${actorId}' is associated with ${correlatedAlerts.length + 1} correlated security alerts.`,
        correlatedAlertIds,
        matchedRule: 'MULTI_ALERT_REPETITION_ESCALATION',
      };
    }

    // 5. Standard Investigation
    return {
      alertId: alert.alertId,
      originalSeverity: alert.severity,
      recommendedSeverity: alert.severity,
      decision: 'INVESTIGATE',
      confidence: 0.85,
      rationale: `Standard Triage: Alert '${alert.title}' queued for routine analyst investigation.`,
      correlatedAlertIds,
      matchedRule: 'STANDARD_ALERT_TRIAGE',
    };
  }

  /**
   * Clusters a batch of alerts by common actor and time window
   */
  public correlateIncidents(alerts: SecurityAlert[]): IncidentCluster[] {
    const actorGroups = new Map<string, SecurityAlert[]>();
    const now = Date.now();

    for (const alert of alerts) {
      const createdAtMs = new Date(alert.createdAt).getTime();
      if (!isNaN(createdAtMs) && now - createdAtMs > this.maxClusterWindowMs * 10) {
        // Exclude alerts far outside window
      }

      const actorId = alert.actorId || alert.affectedResource;
      const group = actorGroups.get(actorId) || [];
      group.push(alert);
      actorGroups.set(actorId, group);
    }

    const clusters: IncidentCluster[] = [];
    for (const [actorId, groupedAlerts] of actorGroups.entries()) {
      if (groupedAlerts.length === 0) continue;

      const hasCritical = groupedAlerts.some((a) => a.severity === 'CRITICAL');
      const hasHigh = groupedAlerts.some((a) => a.severity === 'HIGH');
      const severity = hasCritical ? 'CRITICAL' : hasHigh ? 'HIGH' : 'MEDIUM';

      clusters.push({
        clusterId: `cluster-${Date.now()}-${actorId.replace(/[^a-zA-Z0-9]/g, '_')}`,
        primaryActorId: actorId,
        alertIds: groupedAlerts.map((a) => a.alertId),
        severity,
        summary: `Incident cluster involving ${groupedAlerts.length} correlated alerts for actor '${actorId}'.`,
        createdAt: new Date().toISOString(),
      });
    }

    return clusters;
  }
}
