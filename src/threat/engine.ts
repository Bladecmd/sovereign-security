/**
 * Sovereign Security — Foundation V0.1
 * Threat Engine Foundation (Deterministic Detection Rules)
 *
 * Evaluates normalized SecurityEvents and generates SecurityAlerts.
 * Purely defensive: no offensive scanning or unauthorized intrusion capabilities.
 */

import { SecurityAlert } from '../types/alerts.js';
import { SecurityEvent } from '../types/events.js';

export interface ThreatRule {
  ruleId: string;
  name: string;
  description: string;
  evaluate: (events: SecurityEvent[], context?: Record<string, unknown>) => SecurityAlert | null;
}

export class ThreatEngine {
  private rules: ThreatRule[] = [];
  private eventHistory: SecurityEvent[] = [];
  private readonly maxHistorySize: number;

  constructor(maxHistorySize: number = 1000) {
    this.maxHistorySize = maxHistorySize;
    this.registerDefaultRules();
  }

  /**
   * Register a custom defensive threat detection rule
   */
  public registerRule(rule: ThreatRule): void {
    this.rules.push(rule);
  }

  /**
   * Process a new incoming SecurityEvent, store in history, and evaluate against threat rules
   */
  public processEvent(event: SecurityEvent): SecurityAlert[] {
    this.eventHistory.push(event);
    if (this.eventHistory.length > this.maxHistorySize) {
      this.eventHistory.shift();
    }

    const generatedAlerts: SecurityAlert[] = [];

    for (const rule of this.rules) {
      const alert = rule.evaluate(this.eventHistory);
      if (alert) {
        generatedAlerts.push(alert);
      }
    }

    return generatedAlerts;
  }

  /**
   * Clear event history (used between test runs)
   */
  public clearHistory(): void {
    this.eventHistory = [];
  }

  /**
   * Register default deterministic detection rules
   */
  private registerDefaultRules(): void {
    // Threat Rule 1: Brute Force / Repeated Failed Login Detection
    this.registerRule({
      ruleId: 'THREAT_BRUTE_FORCE_AUTH',
      name: 'Repeated Failed Login Detector',
      description: 'Generates a HIGH alert if failed login attempts exceed threshold (>= 5 in sliding window)',
      evaluate: (events) => {
        const currentEvent = events[events.length - 1];
        if (!currentEvent || currentEvent.eventType !== 'ADMIN_LOGIN_FAILED') {
          return null;
        }

        // Count failed logins for the same actor or resource in the last 10 minutes
        const windowMs = 10 * 60 * 1000;
        const eventTime = new Date(currentEvent.timestamp).getTime();
        const failedEvents = events.filter((e) => {
          if (e.eventType !== 'ADMIN_LOGIN_FAILED') return false;
          if (e.actorId !== currentEvent.actorId && e.resourceId !== currentEvent.resourceId) return false;
          const t = new Date(e.timestamp).getTime();
          return eventTime - t >= 0 && eventTime - t <= windowMs;
        });

        if (failedEvents.length >= 5) {
          return {
            alertId: `alert-bf-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
            createdAt: new Date().toISOString(),
            severity: 'HIGH',
            category: 'AUTHENTICATION',
            title: 'Multiple Failed Authentication Attempts Detected',
            description: `Actor '${currentEvent.actorId}' failed authentication ${failedEvents.length} times within the detection window against '${currentEvent.resourceId}'.`,
            sourceEventIds: failedEvents.map((e) => e.eventId),
            affectedResource: currentEvent.resourceId,
            riskScore: 80,
            status: 'OPEN',
          };
        }

        return null;
      },
    });

    // Threat Rule 2: Unauthorized Privileged Action
    this.registerRule({
      ruleId: 'THREAT_UNAUTHORIZED_PRIVILEGED_ACTION',
      name: 'Unauthorized Privileged Action Detector',
      description: 'Generates a CRITICAL alert if an unauthorized actor attempts privileged or destructive actions',
      evaluate: (events) => {
        const currentEvent = events[events.length - 1];
        if (!currentEvent) return null;

        const privilegedActions = [
          'delete_production_data',
          'drop_table',
          'export_credentials',
          'grant_admin_role',
          'deploy_destructive_infrastructure',
        ];

        const isPrivilegedAction = privilegedActions.some((pa) =>
          currentEvent.action.toLowerCase().includes(pa)
        );

        if (isPrivilegedAction && (currentEvent.result === 'DENIED' || currentEvent.result === 'FAILURE')) {
          return {
            alertId: `alert-priv-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
            createdAt: new Date().toISOString(),
            severity: 'CRITICAL',
            category: 'AUTHORIZATION',
            title: 'Unauthorized Privileged Action Blocked',
            description: `Actor '${currentEvent.actorId}' attempted prohibited privileged action '${currentEvent.action}' on resource '${currentEvent.resourceId}'.`,
            sourceEventIds: [currentEvent.eventId],
            affectedResource: currentEvent.resourceId,
            riskScore: 95,
            status: 'OPEN',
          };
        }

        return null;
      },
    });

    // Threat Rule 3: Secret Exposure Incident
    this.registerRule({
      ruleId: 'THREAT_SECRET_EXPOSURE',
      name: 'Secret Exposure Incident Detector',
      description: 'Generates a CRITICAL alert upon any secret exposure event',
      evaluate: (events) => {
        const currentEvent = events[events.length - 1];
        if (!currentEvent) return null;

        if (currentEvent.eventType === 'SECRET_EXPOSURE' || currentEvent.category === 'SECRETS') {
          return {
            alertId: `alert-sec-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
            createdAt: new Date().toISOString(),
            severity: 'CRITICAL',
            category: 'SECRETS',
            title: 'Credential or Secret Exposure Detected',
            description: `Potential secret exposure event recorded from source '${currentEvent.source}' on resource '${currentEvent.resourceId}'. Immediate rotation advised.`,
            sourceEventIds: [currentEvent.eventId],
            affectedResource: currentEvent.resourceId,
            riskScore: 98,
            status: 'OPEN',
          };
        }

        return null;
      },
    });
  }
}
