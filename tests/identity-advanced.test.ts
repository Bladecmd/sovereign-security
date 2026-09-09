/**
 * Sovereign Security — Milestone V0.3
 * Advanced Identity (ABAC, JIT, WebAuthn, Multi-Tenant) Tests
 */

import assert from 'node:assert/strict';
import test, { beforeEach, describe } from 'node:test';
import { ABACEvaluator } from '../src/identity/abac.js';
import { JITPrivilegeManager } from '../src/identity/jit.js';
import { TenantBoundaryGovernor } from '../src/identity/tenant.js';
import { WebAuthnStepUpValidator } from '../src/identity/webauthn.js';
import { ABACEvaluationInput, IdentitySubject } from '../src/types/identity.js';

describe('Milestone V0.3: Advanced Identity Governance', () => {
  const mockSubject: IdentitySubject = {
    id: 'usr-analyst-44',
    type: 'ADMIN',
    name: 'Senior Threat Analyst',
    roles: ['ADMIN'],
    organizationId: 'org-sovereign-hq',
  };

  describe('Attribute-Based Access Control (ABAC)', () => {
    test('ALLOW: Subject with required clearance and matching tenant is permitted', () => {
      const input: ABACEvaluationInput = {
        subject: mockSubject,
        subjectAttrs: {
          clearanceLevel: 3,
          department: 'CYBER_DEFENSE',
          tenantId: 'sovereign-os',
          devicePosture: 'MANAGED_SECURE',
          mfaVerified: true,
          hardwareTokenBound: true,
        },
        resourceAttrs: {
          resourceId: 'data/cyber/threat_intel',
          tenantId: 'sovereign-os',
          classification: 'CONFIDENTIAL',
          requiredClearance: 3,
          restrictedToDepartments: ['CYBER_DEFENSE', 'EXECUTIVE_DESK'],
          geoFenceAllowed: ['US', 'EU', 'GB'],
        },
        envAttrs: {
          timestamp: new Date().toISOString(),
          ipAddress: '198.51.100.10',
          countryCode: 'US',
          currentFleetThreatLevel: 'GUARDED',
        },
        action: 'read',
      };

      const result = ABACEvaluator.evaluate(input);
      assert.equal(result.allowed, true);
    });

    test('DENY: Blocks request if device posture is QUARANTINED', () => {
      const input: ABACEvaluationInput = {
        subject: mockSubject,
        subjectAttrs: {
          clearanceLevel: 5,
          department: 'CYBER_DEFENSE',
          tenantId: 'sovereign-os',
          devicePosture: 'QUARANTINED',
          mfaVerified: true,
        },
        resourceAttrs: {
          resourceId: 'data/telemetry',
          tenantId: 'sovereign-os',
          classification: 'INTERNAL',
          requiredClearance: 1,
        },
        envAttrs: {
          timestamp: new Date().toISOString(),
          ipAddress: '198.51.100.10',
          currentFleetThreatLevel: 'LOW',
        },
        action: 'read',
      };

      const result = ABACEvaluator.evaluate(input);
      assert.equal(result.allowed, false);
      assert.match(result.reason, /QUARANTINED/);
    });

    test('DENY: Blocks cross-tenant access without federation agreement', () => {
      const input: ABACEvaluationInput = {
        subject: mockSubject,
        subjectAttrs: {
          clearanceLevel: 4,
          department: 'DISPATCH',
          tenantId: 'metro-task-force',
          devicePosture: 'MANAGED_SECURE',
          mfaVerified: true,
        },
        resourceAttrs: {
          resourceId: 'vault/billing/payouts',
          tenantId: 'sovereign-os', // Different tenant
          classification: 'CONFIDENTIAL',
          requiredClearance: 2,
        },
        envAttrs: {
          timestamp: new Date().toISOString(),
          ipAddress: '198.51.100.10',
          currentFleetThreatLevel: 'LOW',
        },
        action: 'read',
      };

      const result = ABACEvaluator.evaluate(input);
      assert.equal(result.allowed, false);
      assert.match(result.reason, /Cross-tenant access violation/);
    });

    test('DENY & STEP-UP: Demands physical hardware key for TOP_SECRET resources', () => {
      const input: ABACEvaluationInput = {
        subject: mockSubject,
        subjectAttrs: {
          clearanceLevel: 5,
          department: 'CYBER_DEFENSE',
          tenantId: 'sovereign-os',
          devicePosture: 'MANAGED_SECURE',
          mfaVerified: true,
          hardwareTokenBound: false, // Lacks hardware token assertion
        },
        resourceAttrs: {
          resourceId: 'vault/master_keys',
          tenantId: 'sovereign-os',
          classification: 'TOP_SECRET',
          requiredClearance: 5,
        },
        envAttrs: {
          timestamp: new Date().toISOString(),
          ipAddress: '198.51.100.10',
          currentFleetThreatLevel: 'LOW',
        },
        action: 'read',
      };

      const result = ABACEvaluator.evaluate(input);
      assert.equal(result.allowed, false);
      assert.equal(result.requiredStepUp, 'HARDWARE_TOKEN');
      assert.match(result.reason, /mandates physical hardware token/);
    });
  });

  describe('Just-In-Time (JIT) Ephemeral Privilege Escalation', () => {
    let jitManager: JITPrivilegeManager;

    beforeEach(() => {
      jitManager = new JITPrivilegeManager();
    });

    test('full lifecycle: request elevation, approve, retrieve active grant, and expire', () => {
      // 1. Submit request
      const req = jitManager.requestElevation({
        subjectId: 'usr-analyst-44',
        targetRole: 'ADMIN',
        elevatedPermissions: ['ADMINISTER', 'WRITE'],
        justificationTicket: 'INCIDENT-892',
        durationMinutes: 15,
      });

      assert.equal(req.status, 'PENDING');
      assert.equal(req.durationMinutes, 15);

      // 2. Approve request
      const grant = jitManager.approveElevation(req.requestId, 'usr-exec-01');
      assert.equal(grant.status, 'ACTIVE');
      assert.equal(grant.grantedRole, 'ADMIN');
      assert.ok(grant.expiresAt > grant.issuedAt);

      // 3. Active grant lookup
      const active = jitManager.getActiveGrantForSubject('usr-analyst-44');
      assert.ok(active);
      assert.equal(active.grantId, grant.grantId);

      // 4. Revocation
      jitManager.revokeGrant(grant.grantId);
      const afterRevoke = jitManager.getActiveGrantForSubject('usr-analyst-44');
      assert.equal(afterRevoke, null);
    });
  });

  describe('Hardware Token (WebAuthn / FIDO2) Step-Up Validator', () => {
    let validator: WebAuthnStepUpValidator;

    beforeEach(() => {
      validator = new WebAuthnStepUpValidator();
    });

    test('generates single-use cryptographic challenge and verifies valid assertion', () => {
      const challenge = validator.generateChallenge('usr-analyst-44', 'rotate_keys');
      assert.ok(challenge.challengeId.startsWith('chal-'));
      assert.equal(challenge.nonce.length, 64);

      const verifyResult = validator.verifyAssertion({
        challengeId: challenge.challengeId,
        subjectId: 'usr-analyst-44',
        credentialId: 'yubikey-fido2-cred-991',
        clientDataJSON: '{"type":"webauthn.get"}',
        authenticatorData: 'auth_data_mock_bytes',
        signature: 'valid_ecdsa_signature_mock_1234567890',
      });

      assert.equal(verifyResult.verified, true);

      // Replay attempt must fail
      const replayResult = validator.verifyAssertion({
        challengeId: challenge.challengeId,
        subjectId: 'usr-analyst-44',
        credentialId: 'yubikey-fido2-cred-991',
        clientDataJSON: '{"type":"webauthn.get"}',
        authenticatorData: 'auth_data_mock_bytes',
        signature: 'valid_ecdsa_signature_mock_1234567890',
      });

      assert.equal(replayResult.verified, false);
      assert.match(replayResult.reason, /replay protection/i);
    });
  });

  describe('Tenant Boundary Governor & Cross-Tenant Isolation', () => {
    let governor: TenantBoundaryGovernor;

    beforeEach(() => {
      governor = new TenantBoundaryGovernor();
    });

    test('allows intra-tenant access, denies cross-tenant access without federation', () => {
      // Intra-tenant
      const sameTenant = governor.canAccessTenantResource(
        'sovereign-os',
        'sovereign-os',
        'api/users'
      );
      assert.equal(sameTenant.allowed, true);

      // Cross-tenant without agreement
      const crossTenant = governor.canAccessTenantResource(
        'metro-task-force',
        'sovereign-os',
        'api/users'
      );
      assert.equal(crossTenant.allowed, false);
      assert.match(crossTenant.reason, /No federation trust agreement exists/);
    });

    test('allows cross-tenant access when explicit federation agreement exists', () => {
      governor.registerFederationAgreement({
        agreementId: 'fed-mtf-sos-01',
        sourceTenantId: 'metro-task-force',
        targetTenantId: 'sovereign-os',
        allowedResources: ['telemetry/incidents', 'shared/cases'],
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
      });

      const allowedResource = governor.canAccessTenantResource(
        'metro-task-force',
        'sovereign-os',
        'telemetry/incidents/stream'
      );
      assert.equal(allowedResource.allowed, true);

      const blockedResource = governor.canAccessTenantResource(
        'metro-task-force',
        'sovereign-os',
        'vault/internal_passwords'
      );
      assert.equal(blockedResource.allowed, false);
    });
  });
});
