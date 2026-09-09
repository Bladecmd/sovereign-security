/**
 * Sovereign Security — Foundation V0.1
 * Normalized SecurityAlert Schema & Types
 */

import { SecurityCategory, SecuritySeverity } from './events.js';

export type AlertStatus =
  | 'OPEN'
  | 'ACKNOWLEDGED'
  | 'INVESTIGATING'
  | 'CONTAINED'
  | 'RESOLVED'
  | 'FALSE_POSITIVE';

export interface SecurityAlert {
  alertId: string;
  createdAt: string; // ISO 8601 UTC
  severity: SecuritySeverity;
  category: SecurityCategory;
  title: string;
  description: string;
  sourceEventIds: string[];
  affectedResource: string;
  riskScore: number; // 0 - 100
  status: AlertStatus;
  assignedTo?: string; // Analyst ID or Automated Response Handler
  resolution?: string; // Explanation of resolution or containment
  resolvedAt?: string; // ISO 8601 UTC
}

export type CreateSecurityAlertInput = Omit<SecurityAlert, 'alertId' | 'createdAt' | 'status'> & {
  alertId?: string;
  createdAt?: string;
  status?: AlertStatus;
};
