/**
 * Sovereign Security — Foundation V0.1
 * Test Fixtures (Synthetic Mock Data Only)
 *
 * All identifiers, IPs, and attributes are artificial test fixtures.
 */

import { IdentitySubject } from '../../src/types/identity.js';
import { CreateSecurityEventInput, SecurityEvent } from '../../src/types/events.js';
import { CreateSecurityAlertInput, SecurityAlert } from '../../src/types/alerts.js';

export const MOCK_ADMIN_SUBJECT: IdentitySubject = {
  id: 'usr-admin-01',
  type: 'ADMIN',
  name: 'Security Administrator',
  roles: ['ADMIN'],
  organizationId: 'org-sovereign-hq',
  attributes: { clearance: 'LEVEL_5' },
};

export const MOCK_EXECUTIVE_SUBJECT: IdentitySubject = {
  id: 'usr-exec-01',
  type: 'EXECUTIVE',
  name: 'Chief Executive Officer',
  roles: ['EXECUTIVE'],
  organizationId: 'org-sovereign-hq',
};

export const MOCK_VEGA_AGENT_SUBJECT: IdentitySubject = {
  id: 'agent-vega-01',
  type: 'AGENT',
  name: 'VEGA Autonomous Analyst',
  roles: ['AGENT'],
  organizationId: 'org-sovereign-hq',
};

export const MOCK_SERVICE_SUBJECT: IdentitySubject = {
  id: 'svc-billing-01',
  type: 'SERVICE',
  name: 'Billing Integration Service',
  roles: ['SERVICE'],
  organizationId: 'org-sovereign-hq',
};

export const VALID_SECURITY_EVENT: SecurityEvent = {
  eventId: 'evt-test-1001',
  timestamp: '2026-09-09T12:00:00.000Z',
  source: 'sovereign-os',
  businessId: 'biz-sovereign-01',
  environment: 'production',
  severity: 'INFO',
  category: 'AUTHENTICATION',
  eventType: 'ADMIN_LOGIN_SUCCESS',
  actorId: 'usr-admin-01',
  resourceId: 'api/v1/auth/login',
  action: 'authenticate',
  result: 'SUCCESS',
  riskScore: 10,
  verificationStatus: 'VERIFIED',
  metadata: { ip: '127.0.0.1', authType: 'mfa' },
  correlationId: 'corr-test-001',
};

export const AUTH_FAILURE_EVENT_INPUT: CreateSecurityEventInput = {
  eventId: 'evt-test-1002',
  source: 'sovereign-os',
  businessId: 'biz-sovereign-01',
  environment: 'production',
  severity: 'HIGH',
  category: 'AUTHENTICATION',
  eventType: 'ADMIN_LOGIN_FAILED',
  actorId: 'unauthorized-intruder',
  resourceId: 'api/v1/admin/dashboard',
  action: 'authenticate',
  result: 'FAILURE',
  riskScore: 75,
  metadata: { ip: '192.0.2.1', failureReason: 'INVALID_CREDENTIALS' },
  correlationId: 'corr-test-002',
};

export const VALID_SECURITY_ALERT: SecurityAlert = {
  alertId: 'alt-test-5001',
  createdAt: '2026-09-09T12:05:00.000Z',
  severity: 'HIGH',
  category: 'AUTHENTICATION',
  title: 'Repeated Login Failure Alert',
  description: 'Multiple failed login attempts detected against admin endpoint',
  sourceEventIds: ['evt-test-1002'],
  affectedResource: 'api/v1/admin/dashboard',
  riskScore: 80,
  status: 'OPEN',
};
