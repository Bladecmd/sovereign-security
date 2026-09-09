/**
 * Sovereign Security — Milestone V0.3
 * Multi-Tenant Partition & Boundary Governance
 *
 * Enforces strict cryptographic isolation between Sovereign ecosystem tenants.
 * Prohibits cross-tenant data leakage unless explicitly permitted by mutual federation trust agreements.
 */

export interface TenantFederationAgreement {
  agreementId: string;
  sourceTenantId: string;
  targetTenantId: string;
  allowedResources: string[];
  expiresAt: string;
}

export class TenantBoundaryGovernor {
  private federationAgreements: Map<string, TenantFederationAgreement> = new Map();

  /**
   * Register a mutual cross-tenant federation agreement
   */
  public registerFederationAgreement(agreement: TenantFederationAgreement): void {
    const key = `${agreement.sourceTenantId}:${agreement.targetTenantId}`;
    this.federationAgreements.set(key, agreement);
  }

  /**
   * Validate whether source tenant is permitted to access a target tenant's resource
   */
  public canAccessTenantResource(
    sourceTenantId: string,
    targetTenantId: string,
    resourceId: string
  ): { allowed: boolean; reason: string } {
    // 1. Same tenant is always allowed within boundary
    if (sourceTenantId === targetTenantId) {
      return {
        allowed: true,
        reason: 'Intra-tenant access authorized.',
      };
    }

    // 2. Check for active cross-tenant federation agreement
    const key = `${sourceTenantId}:${targetTenantId}`;
    const agreement = this.federationAgreements.get(key);

    if (!agreement) {
      return {
        allowed: false,
        reason: `Zero-Trust Boundary Deny: No federation trust agreement exists between tenant '${sourceTenantId}' and '${targetTenantId}'.`,
      };
    }

    // 3. Check expiration
    if (Date.now() > new Date(agreement.expiresAt).getTime()) {
      return {
        allowed: false,
        reason: `Federation agreement between '${sourceTenantId}' and '${targetTenantId}' has expired.`,
      };
    }

    // 4. Check resource scope
    const isResourceAllowed =
      agreement.allowedResources.includes('*') ||
      agreement.allowedResources.some((ar) => resourceId.startsWith(ar));

    if (!isResourceAllowed) {
      return {
        allowed: false,
        reason: `Resource '${resourceId}' is not authorized under the federation agreement between '${sourceTenantId}' and '${targetTenantId}'.`,
      };
    }

    return {
      allowed: true,
      reason: `Cross-tenant access authorized under federation agreement '${agreement.agreementId}'.`,
    };
  }
}
