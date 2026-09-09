/**
 * Sovereign Security — Milestone V0.7
 * Forensics Agent: Incident Timeline Reconstruction & Root Cause Analysis (RCA)
 */

import { AuditService } from '../audit/audit-service.js';
import { SecurityAlert } from '../types/alerts.js';
import { SecurityEvent } from '../types/events.js';
import { BlastRadius, RCAReport, TimelineEvent } from '../types/agents.js';

export interface ForensicsAgentOptions {
  auditService?: AuditService;
}

export class ForensicsAgent {
  private auditService?: AuditService;
  private securityEvents: SecurityEvent[] = [];

  constructor(options: ForensicsAgentOptions = {}) {
    this.auditService = options.auditService;
  }

  public registerEvents(events: SecurityEvent[]): void {
    this.securityEvents.push(...events);
  }

  /**
   * Reconstructs an end-to-end chronological timeline of all actions around an incident
   */
  public reconstructTimeline(options: {
    actorId?: string;
    correlationId?: string;
    since?: string;
    until?: string;
  } = {}): TimelineEvent[] {
    const timeline: TimelineEvent[] = [];

    // 1. Ingest from Audit Log
    if (this.auditService) {
      const records = this.auditService.getRecords();
      for (const record of records) {
        if (options.actorId && record.who !== options.actorId) {
          // Check if actorId matches inside details
          const detailActor = record.details?.targetId || record.details?.actorId;
          if (detailActor !== options.actorId) continue;
        }

        if (options.correlationId) {
          const recordCorr = record.details?.correlationId;
          if (recordCorr !== options.correlationId) continue;
        }

        if (options.since && record.when < options.since) continue;
        if (options.until && record.when > options.until) continue;

        timeline.push({
          timestamp: record.when,
          type: 'AUDIT',
          actorId: record.who,
          action: record.what,
          service: record.where,
          details: record.details,
          hash: record.currentHash,
        });
      }
    }

    // 2. Ingest from Security Events
    for (const evt of this.securityEvents) {
      if (options.actorId && evt.actorId !== options.actorId) continue;
      if (options.correlationId && evt.correlationId !== options.correlationId) continue;
      if (options.since && evt.timestamp < options.since) continue;
      if (options.until && evt.timestamp > options.until) continue;

      timeline.push({
        timestamp: evt.timestamp,
        type: 'EVENT',
        actorId: evt.actorId,
        action: evt.action,
        service: evt.source,
        details: {
          category: evt.category,
          severity: evt.severity,
          riskScore: evt.riskScore,
          metadata: evt.metadata,
        },
      });
    }

    // Sort chronologically ascending
    return timeline.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  }

  /**
   * Synthesizes a Root Cause Analysis (RCA) report
   */
  public generateRCAReport(alert: SecurityAlert, explicitTimeline?: TimelineEvent[]): RCAReport {
    const timeline =
      explicitTimeline ||
      this.reconstructTimeline({
        actorId: alert.actorId || alert.affectedResource,
      });

    // Determine Patient Zero (primary compromised actor, excluding automated responders)
    const initialActor = alert.actorId || alert.affectedResource;
    const suspectEvent = timeline.find(
      (e) => e.actorId === initialActor || !e.action.startsWith('containment.')
    );
    const patientZero = suspectEvent ? suspectEvent.actorId : initialActor;
    const initialVector =
      timeline.length > 0
        ? `${timeline[0]!.action} via ${timeline[0]!.service}`
        : `${alert.title} (${alert.severity})`;

    // Calculate Blast Radius
    const actors = new Set<string>([alert.actorId || alert.affectedResource]);
    const services = new Set<string>();
    const resources = new Set<string>();

    for (const item of timeline) {
      if (item.actorId) actors.add(item.actorId);
      if (item.service) services.add(item.service);
      const target = item.details?.resource || item.details?.targetId || item.details?.targetEndpoint;
      if (typeof target === 'string') resources.add(target);
    }

    const blastRadius: BlastRadius = {
      affectedActors: Array.from(actors),
      affectedServices: Array.from(services),
      impactedResources: Array.from(resources),
    };

    // Formulate Root Cause Hypothesis
    let rootCauseHypothesis = 'Anomalous activity pattern detected requiring investigation.';
    const alertTitle = alert.title.toLowerCase();

    if (alertTitle.includes('brute force') || alertTitle.includes('login')) {
      rootCauseHypothesis = `Credential attack: Excessive authentication failures from actor '${patientZero}' indicate credential stuffing or brute-force attempt.`;
    } else if (alertTitle.includes('secret') || alertTitle.includes('leak')) {
      rootCauseHypothesis = `Secret exposure: Credential or cryptographic token inadvertently exposed in unencrypted channel or service log.`;
    } else if (alertTitle.includes('prompt injection') || alertTitle.includes('ai')) {
      rootCauseHypothesis = `Adversarial AI manipulation: Untrusted input attempted delimiter hijacking or instruction override against model endpoints.`;
    } else if (alertTitle.includes('privilege') || alertTitle.includes('unauthorized')) {
      rootCauseHypothesis = `Unauthorized privilege escalation: Subject attempted access to restricted capability without matching clearance or policy authorization.`;
    }

    // Recommended Mitigations
    const mitigations: string[] = [
      `Enforce immediate session revocation for actor '${patientZero}'.`,
      `Audit all permissions and role assignments associated with affected resources.`,
      `Review access policies across services: ${Array.from(services).join(', ') || 'N/A'}.`,
    ];

    if (alert.severity === 'CRITICAL') {
      mitigations.unshift('Execute automated Containment quarantine immediately.');
      mitigations.push('Mandate hardware token (FIDO2 / WebAuthn) step-up for any subsequent login.');
    }

    return {
      reportId: `rca-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      incidentId: alert.alertId,
      generatedAt: new Date().toISOString(),
      summary: `Forensic RCA Report for Incident '${alert.title}' (Severity: ${alert.severity})`,
      initialVector,
      patientZero,
      timeline,
      blastRadius,
      rootCauseHypothesis,
      recommendedMitigations: mitigations,
    };
  }

  /**
   * Traces the complete defensive correlation chain:
   * SecurityEvent -> Alert -> PolicyDecision -> Containment -> Resolution
   * using correlationId
   */
  public traceCorrelationChain(
    correlationId: string,
    allAlerts: SecurityAlert[] = []
  ): {
    correlationId: string;
    securityEvents: SecurityEvent[];
    alerts: SecurityAlert[];
    policyDecisions: Array<{
      action: string;
      who: string;
      result: string;
      timestamp: string;
      hash?: string;
      details?: Record<string, unknown>;
    }>;
    containment: Array<{
      action: string;
      who: string;
      result: string;
      timestamp: string;
      details?: Record<string, unknown>;
    }>;
    resolutions: Array<{
      action: string;
      who: string;
      timestamp: string;
      details?: Record<string, unknown>;
    }>;
    chainComplete: boolean;
  } {
    // 1. Trace SecurityEvents matching correlationId
    const matchedEvents = this.securityEvents.filter(
      (e) => e.correlationId === correlationId
    );
    const matchedEventIds = new Set(matchedEvents.map((e) => e.eventId));

    // 2. Trace Alerts matching correlationId or referencing matched event IDs
    const matchedAlerts = allAlerts.filter(
      (a) =>
        a.correlationId === correlationId ||
        a.sourceEventIds.some((id) => matchedEventIds.has(id))
    );
    const matchedAlertIds = new Set(matchedAlerts.map((a) => a.alertId));

    // 3. Trace PolicyDecisions, Containment, and Resolutions from audit records
    const policyDecisions: Array<{
      action: string;
      who: string;
      result: string;
      timestamp: string;
      hash?: string;
      details?: Record<string, unknown>;
    }> = [];

    const containment: Array<{
      action: string;
      who: string;
      result: string;
      timestamp: string;
      details?: Record<string, unknown>;
    }> = [];

    const resolutions: Array<{
      action: string;
      who: string;
      timestamp: string;
      details?: Record<string, unknown>;
    }> = [];

    if (this.auditService) {
      const records = this.auditService.getRecords();
      for (const record of records) {
        const recordCorr =
          record.details?.correlationId ||
          record.details?.auditCorrelationId ||
          record.details?.traceCorrelationId;

        const isRelated =
          recordCorr === correlationId ||
          (record.details?.alertId && matchedAlertIds.has(record.details.alertId as string)) ||
          (record.details?.targetId &&
            matchedAlerts.some(
              (a) =>
                a.affectedResource === record.details?.targetId ||
                a.actorId === record.details?.targetId
            ));

        if (!isRelated) continue;

        if (
          record.what.startsWith('POLICY_') ||
          record.what.startsWith('policy.') ||
          record.what.includes('DECISION') ||
          record.what.includes('PROVENANCE') ||
          record.where.includes('policy')
        ) {
          policyDecisions.push({
            action: record.what,
            who: record.who,
            result: record.result,
            timestamp: record.when,
            hash: record.currentHash,
            details: record.details,
          });
        } else if (
          record.what.startsWith('containment.quarantine_applied') ||
          record.what.includes('quarantine')
        ) {
          containment.push({
            action: record.what,
            who: record.who,
            result: record.result,
            timestamp: record.when,
            details: record.details,
          });
        } else if (
          record.what.startsWith('containment.quarantine_released') ||
          record.what.includes('release') ||
          record.what.includes('RESOLV') ||
          record.what.includes('TRIAGE')
        ) {
          resolutions.push({
            action: record.what,
            who: record.who,
            timestamp: record.when,
            details: record.details,
          });
        }
      }
    }

    // Also check for alert resolutions
    for (const alert of matchedAlerts) {
      if (alert.status === 'RESOLVED' || alert.status === 'CONTAINED') {
        const existing = resolutions.some(
          (r) => r.details?.alertId === alert.alertId
        );
        if (!existing) {
          resolutions.push({
            action: `ALERT_RESOLVED:${alert.status}`,
            who: alert.assignedTo || 'security-operator',
            timestamp: alert.resolvedAt || alert.createdAt,
            details: {
              alertId: alert.alertId,
              status: alert.status,
              resolution: alert.resolution,
            },
          });
        }
      }
    }

    const chainComplete =
      matchedEvents.length > 0 &&
      (matchedAlerts.length > 0 || policyDecisions.length > 0 || containment.length > 0);

    return {
      correlationId,
      securityEvents: matchedEvents,
      alerts: matchedAlerts,
      policyDecisions,
      containment,
      resolutions,
      chainComplete,
    };
  }
}

