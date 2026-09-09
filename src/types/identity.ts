/**
 * Sovereign Security — Foundation V0.1
 * Identity & Access Management (RBAC / Least Privilege) Types
 */

export type Role = 'ADMIN' | 'EXECUTIVE' | 'SYSTEM' | 'AGENT' | 'SERVICE';

export type Permission = 'READ' | 'WRITE' | 'EXECUTE' | 'CERTIFY' | 'ADMINISTER';

export interface IdentitySubject {
  id: string;
  type: Role;
  name: string;
  roles: Role[];
  explicitPermissions?: Permission[];
  organizationId: string;
  attributes?: Record<string, unknown>;
}

export interface RoleDefinition {
  role: Role;
  description: string;
  allowedPermissions: readonly Permission[];
  restrictedActions?: readonly string[];
}
