/**
 * Sovereign Security — Milestone V0.7
 * Autonomous Security Agents Type Contracts
 */

import { AlertStatus, SecurityAlert } from './alerts.js';
import { SecuritySeverity } from './events.js';

export type TriageDecision =
  | 'ESCALATE'
  | 'CONTAIN'
  | 'INVESTIGATE'
  | 'SUPPRESS'
  | 'AUTO_RESOLVE';

export interface TriageResult {
  alertId: string;
  originalSeverity: SecuritySeverity;
  recommendedSeverity: SecuritySeverity;
  decision: TriageDecision;
  confidence: number; // 0.0 - 1.0
  rationale: string;
  correlatedAlertIds: string[];
  matchedRule?: string;
}

export interface IncidentCluster {
  clusterId: string;
  primaryActorId: string;
  alertIds: string[];
  severity: SecuritySeverity;
  summary: string;
  createdAt: string;
}

export type QuarantineTargetType = 'ACTOR' | 'IP' | 'AGENT' | 'SERVICE';

export interface QuarantineRecord {
  quarantineId: string;
  targetType: QuarantineTargetType;
  targetId: string;
  reason: string;
  initiatedBy: string;
  createdAt: string;
  expiresAt: string;
  isActive: boolean;
  releasedAt?: string;
  releasedBy?: string;
  releaseReason?: string;
}

export interface ContainmentRequest {
  targetType: QuarantineTargetType;
  targetId: string;
  reason: string;
  ttlMs?: number;
  initiatedBy?: string;
}

export interface ContainmentResult {
  success: boolean;
  quarantineRecord: QuarantineRecord;
  auditCorrelationId: string;
  revokedTokenCount?: number;
}

export interface TimelineEvent {
  timestamp: string;
  type: 'EVENT' | 'ALERT' | 'AUDIT' | 'CONTAINMENT';
  actorId: string;
  action: string;
  service: string;
  details: Record<string, unknown>;
  hash?: string;
}

export interface BlastRadius {
  affectedActors: string[];
  affectedServices: string[];
  impactedResources: string[];
}

export interface RCAReport {
  reportId: string;
  incidentId: string;
  generatedAt: string;
  summary: string;
  initialVector: string;
  patientZero: string;
  timeline: TimelineEvent[];
  blastRadius: BlastRadius;
  rootCauseHypothesis: string;
  recommendedMitigations: string[];
}

export interface IncidentWorkflowRequest {
  alert: SecurityAlert;
  autoContain?: boolean;
}

export interface IncidentWorkflowResult {
  alertId: string;
  status: AlertStatus;
  triage: TriageResult;
  containment?: ContainmentResult;
  rcaReport?: RCAReport;
}
