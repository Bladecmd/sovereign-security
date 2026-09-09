/**
 * Sovereign Security — Foundation V0.1
 * Deterministic Risk Scoring Engine
 *
 * Computes normalized 0-100 risk scores based on:
 * - Event Severity
 * - Asset Criticality
 * - Authentication State
 * - Action Sensitivity
 * - Frequency / Repetition Multipliers
 */

import { SecuritySeverity } from '../types/events.js';

export type AssetCriticality = 'LOW' | 'MEDIUM' | 'HIGH' | 'MISSION_CRITICAL';

export type AuthenticationState =
  | 'UNAUTHENTICATED'
  | 'ANONYMOUS'
  | 'PASSWORD_ONLY'
  | 'MFA_VERIFIED'
  | 'CERTIFICATE_BOUND';

export interface RiskEvaluationFactors {
  severity: SecuritySeverity;
  assetCriticality?: AssetCriticality;
  authState?: AuthenticationState;
  action: string;
  repetitionCount?: number; // Count of occurrences in current window
}

export class RiskEngine {
  private static readonly SEVERITY_BASE_SCORES: Record<SecuritySeverity, number> = {
    INFO: 5,
    LOW: 20,
    MEDIUM: 45,
    HIGH: 75,
    CRITICAL: 95,
  };

  private static readonly ASSET_CRITICALITY_MULTIPLIERS: Record<AssetCriticality, number> = {
    LOW: 0.85,
    MEDIUM: 1.0,
    HIGH: 1.25,
    MISSION_CRITICAL: 1.5,
  };

  private static readonly AUTH_STATE_ADJUSTMENTS: Record<AuthenticationState, number> = {
    UNAUTHENTICATED: 30,
    ANONYMOUS: 25,
    PASSWORD_ONLY: 10,
    MFA_VERIFIED: -15,
    CERTIFICATE_BOUND: -20,
  };

  /**
   * Calculate a deterministic risk score between 0 and 100.
   */
  public static calculateRisk(factors: RiskEvaluationFactors): number {
    // 1. Base score from severity
    let score = this.SEVERITY_BASE_SCORES[factors.severity] ?? 30;

    // 2. Action sensitivity modifier
    const actionLower = factors.action.toLowerCase();
    if (
      actionLower.includes('admin') ||
      actionLower.includes('root') ||
      actionLower.includes('iam')
    ) {
      score += 20;
    } else if (
      actionLower.includes('delete') ||
      actionLower.includes('drop') ||
      actionLower.includes('purge')
    ) {
      score += 15;
    } else if (
      actionLower.includes('transfer') ||
      actionLower.includes('payout') ||
      actionLower.includes('billing')
    ) {
      score += 15;
    } else if (actionLower.includes('write') || actionLower.includes('update')) {
      score += 5;
    }

    // 3. Asset Criticality adjustment
    const criticality = factors.assetCriticality ?? 'MEDIUM';
    const multiplier = this.ASSET_CRITICALITY_MULTIPLIERS[criticality];
    score = score * multiplier;

    // 4. Authentication State adjustment
    if (factors.authState) {
      score += this.AUTH_STATE_ADJUSTMENTS[factors.authState];
    }

    // 5. Repetition / Frequency Multiplier
    if (factors.repetitionCount && factors.repetitionCount > 1) {
      // Add compounding factor up to +25
      const frequencyBump = Math.min(25, (factors.repetitionCount - 1) * 5);
      score += frequencyBump;
    }

    // 6. Clamp to 0 - 100 integer range
    return Math.round(Math.max(0, Math.min(100, score)));
  }
}
