/**
 * Sovereign Security — Foundation V0.1
 * RBAC & Least Privilege Identity Evaluator
 */

import { IdentitySubject, Permission, Role, RoleDefinition } from '../types/identity.js';

export const ROLE_DEFINITIONS: Record<Role, RoleDefinition> = {
  ADMIN: {
    role: 'ADMIN',
    description: 'System and platform administration with operational configuration authority',
    allowedPermissions: ['READ', 'WRITE', 'EXECUTE', 'ADMINISTER'],
    restrictedActions: ['certify_financial_reports', 'override_executive_veto'],
  },
  EXECUTIVE: {
    role: 'EXECUTIVE',
    description: 'Executive leadership with certification and strategic governance authority',
    allowedPermissions: ['READ', 'CERTIFY'],
    restrictedActions: ['direct_infrastructure_modification', 'modify_system_credentials'],
  },
  SYSTEM: {
    role: 'SYSTEM',
    description: 'Core automated background services and orchestrators',
    allowedPermissions: ['READ', 'WRITE', 'EXECUTE'],
    restrictedActions: ['administer_user_roles', 'certify_financial_reports'],
  },
  AGENT: {
    role: 'AGENT',
    description: 'Autonomous or semi-autonomous AI agents (strictly bounded least-privilege)',
    allowedPermissions: ['READ', 'EXECUTE'],
    restrictedActions: [
      'transfer_funds',
      'delete_production_data',
      'modify_security_policies',
      'deploy_destructive_infrastructure',
      'export_raw_credentials',
    ],
  },
  SERVICE: {
    role: 'SERVICE',
    description: 'Scoped machine-to-machine integrations and external microservices',
    allowedPermissions: ['READ', 'EXECUTE'],
    restrictedActions: ['administer_user_roles', 'certify_financial_reports'],
  },
};

export class IdentityAccessEvaluator {
  /**
   * Determine whether a subject has permission to execute an action.
   * Least-privilege by default: returns false unless explicitly authorized.
   */
  public static hasPermission(
    subject: IdentitySubject,
    requiredPermission: Permission,
    actionName?: string
  ): { granted: boolean; reason: string } {
    // 1. Check explicit subject restrictions
    if (actionName) {
      for (const role of subject.roles) {
        const def = ROLE_DEFINITIONS[role];
        if (def?.restrictedActions && def.restrictedActions.includes(actionName)) {
          return {
            granted: false,
            reason: `Action '${actionName}' is strictly prohibited for role '${role}' under least-privilege policy.`,
          };
        }
      }
    }

    // 2. Check explicit direct permissions attached to the subject
    if (subject.explicitPermissions && subject.explicitPermissions.includes(requiredPermission)) {
      return {
        granted: true,
        reason: `Permission '${requiredPermission}' granted via explicit subject permission.`,
      };
    }

    // 3. Check role-based permission inheritance
    for (const role of subject.roles) {
      const def = ROLE_DEFINITIONS[role];
      if (def && def.allowedPermissions.includes(requiredPermission)) {
        return {
          granted: true,
          reason: `Permission '${requiredPermission}' granted via role '${role}'.`,
        };
      }
    }

    return {
      granted: false,
      reason: `Subject '${subject.id}' (${subject.roles.join(', ')}) lacks required permission '${requiredPermission}'.`,
    };
  }
}
