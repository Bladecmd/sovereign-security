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
}
