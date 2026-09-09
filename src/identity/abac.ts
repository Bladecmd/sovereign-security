/**
 * Sovereign Security — Milestone V0.3
 * Attribute-Based Access Control (ABAC) Engine
 *
 * Dynamically evaluates access requests using multi-dimensional attribute matrices:
 * - Subject attributes (clearance level, department, tenant, device posture, hardware key)
 * - Resource attributes (classification tier, tenant, required clearance, department boundary, geofencing)
 * - Environmental attributes (fleet threat level, origin country, time)
 */

import { ABACEvaluationInput, ABACPolicyDecision } from '../types/identity.js';

export class ABACEvaluator {
  /**
   * Evaluate multi-attribute access control conditions
   */
  public static evaluate(input: ABACEvaluationInput): ABACPolicyDecision {
    const { subjectAttrs, resourceAttrs, envAttrs } = input;

    // 1. Device Posture Quarantine Check
    if (subjectAttrs.devicePosture === 'QUARANTINED') {
      return {
        allowed: false,
        reason: 'Device posture is QUARANTINED. Access blocked under Zero-Trust endpoint policy.',
      };
    }

    // 2. Multi-Tenant Boundary Isolation
    if (subjectAttrs.tenantId !== resourceAttrs.tenantId) {
      return {
        allowed: false,
        reason: `Cross-tenant access violation: subject tenant '${subjectAttrs.tenantId}' cannot access resource owned by tenant '${resourceAttrs.tenantId}'.`,
      };
    }

    // 3. Security Clearance Level Evaluation
    if (subjectAttrs.clearanceLevel < resourceAttrs.requiredClearance) {
      return {
        allowed: false,
        reason: `Insufficient security clearance: subject level ${subjectAttrs.clearanceLevel} is lower than resource requirement ${resourceAttrs.requiredClearance}.`,
      };
    }

    // 4. Department Boundary Isolation
    if (
      resourceAttrs.restrictedToDepartments &&
      resourceAttrs.restrictedToDepartments.length > 0 &&
      !resourceAttrs.restrictedToDepartments.includes(subjectAttrs.department)
    ) {
      return {
        allowed: false,
        reason: `Department restriction: subject department '${subjectAttrs.department}' is not authorized for resource (authorized: ${resourceAttrs.restrictedToDepartments.join(', ')}).`,
      };
    }

    // 5. Geo-Fencing Constraints
    if (
      resourceAttrs.geoFenceAllowed &&
      resourceAttrs.geoFenceAllowed.length > 0 &&
      envAttrs.countryCode &&
      !resourceAttrs.geoFenceAllowed.includes(envAttrs.countryCode)
    ) {
      return {
        allowed: false,
        reason: `Geographic fencing violation: access origin '${envAttrs.countryCode}' is not in the permitted geofence (${resourceAttrs.geoFenceAllowed.join(', ')}).`,
      };
    }

    // 6. High/Critical Fleet Threat Level Elevation
    if (
      envAttrs.currentFleetThreatLevel === 'CRITICAL' &&
      subjectAttrs.clearanceLevel < 4 &&
      input.action.toLowerCase() !== 'read'
    ) {
      return {
        allowed: false,
        reason: 'Fleet threat level is CRITICAL: mutating actions restricted to Level 4+ executive/admin personnel.',
      };
    }

    // 7. Step-Up Hardware Security Token (FIDO2) Requirement
    if (
      (resourceAttrs.classification === 'TOP_SECRET' ||
        resourceAttrs.classification === 'RESTRICTED') &&
      !subjectAttrs.hardwareTokenBound
    ) {
      return {
        allowed: false,
        reason: `Access to ${resourceAttrs.classification} data mandates physical hardware token step-up authentication.`,
        requiredStepUp: 'HARDWARE_TOKEN',
      };
    }

    return {
      allowed: true,
      reason: 'ABAC conditions verified: clearance, tenant, device posture, and departmental policies satisfied.',
    };
  }
}
