/**
 * Sovereign Security — Milestone V0.3
 * Just-In-Time (JIT) Ephemeral Privilege Escalation Manager
 *
 * Provides time-bounded, audited temporary elevation for incident containment
 * and emergency maintenance operations. Enforces TTL auto-expiry.
 */

import { JITGrant, JITRequest, Permission, Role } from '../types/identity.js';

export class JITPrivilegeManager {
  private requests: Map<string, JITRequest> = new Map();
  private grants: Map<string, JITGrant> = new Map();

  /**
   * Submit an ephemeral privilege escalation request
   */
  public requestElevation(params: {
    subjectId: string;
    targetRole: Role;
    elevatedPermissions: Permission[];
    justificationTicket: string;
    durationMinutes: number;
  }): JITRequest {
    const requestId = `jit-req-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    const duration = Math.max(5, Math.min(60, params.durationMinutes)); // Clamp 5 - 60 min

    const req: JITRequest = {
      requestId,
      subjectId: params.subjectId,
      targetRole: params.targetRole,
      elevatedPermissions: params.elevatedPermissions,
      justificationTicket: params.justificationTicket,
      durationMinutes: duration,
      requestedAt: new Date().toISOString(),
      status: 'PENDING',
    };

    this.requests.set(requestId, req);
    return req;
  }

  /**
   * Approve a pending JIT request and issue an active, time-bounded grant
   */
  public approveElevation(requestId: string, approvedBy: string): JITGrant {
    const req = this.requests.get(requestId);
    if (!req) {
      throw new Error(`JIT Request '${requestId}' not found.`);
    }

    if (req.status !== 'PENDING') {
      throw new Error(`Cannot approve JIT Request '${requestId}' with status '${req.status}'.`);
    }

    const grantId = `jit-grant-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`;
    const now = Date.now();
    const expiresAt = new Date(now + req.durationMinutes * 60 * 1000).toISOString();

    const grant: JITGrant = {
      grantId,
      requestId,
      subjectId: req.subjectId,
      grantedRole: req.targetRole,
      grantedPermissions: req.elevatedPermissions,
      approvedBy,
      issuedAt: new Date(now).toISOString(),
      expiresAt,
      status: 'ACTIVE',
    };

    req.status = 'APPROVED';
    this.grants.set(grantId, grant);
    return grant;
  }

  /**
   * Retrieve any currently active JIT grant for a given subject (accounting for TTL)
   */
  public getActiveGrantForSubject(subjectId: string): JITGrant | null {
    this.expireOutdatedGrants();

    for (const grant of this.grants.values()) {
      if (grant.subjectId === subjectId && grant.status === 'ACTIVE') {
        const now = new Date().getTime();
        const exp = new Date(grant.expiresAt).getTime();
        if (now < exp) {
          return grant;
        } else {
          grant.status = 'EXPIRED';
        }
      }
    }

    return null;
  }

  /**
   * Explicitly revoke an active grant
   */
  public revokeGrant(grantId: string): JITGrant {
    const grant = this.grants.get(grantId);
    if (!grant) {
      throw new Error(`Grant '${grantId}' not found.`);
    }

    grant.status = 'REVOKED';
    return grant;
  }

  /**
   * Scan and expire grants that have exceeded their TTL
   */
  public expireOutdatedGrants(): void {
    const now = new Date().getTime();
    for (const grant of this.grants.values()) {
      if (grant.status === 'ACTIVE' && now >= new Date(grant.expiresAt).getTime()) {
        grant.status = 'EXPIRED';
      }
    }
  }

  public listActiveGrants(): JITGrant[] {
    this.expireOutdatedGrants();
    return Array.from(this.grants.values()).filter((g) => g.status === 'ACTIVE');
  }
}
