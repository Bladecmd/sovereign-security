/**
 * Sovereign Security — Foundation V0.1
 * Threat Engine Detection Rule Tests
 */

import assert from 'node:assert/strict';
import test, { beforeEach, describe } from 'node:test';
import { ThreatEngine } from '../src/threat/engine.js';
import { SecurityEvent } from '../src/types/events.js';

describe('Threat Engine Deterministic Detection Rules', () => {
  let threatEngine: ThreatEngine;

  beforeEach(() => {
    threatEngine = new ThreatEngine();
  });

  test('generates HIGH alert when failed login attempts reach threshold (>= 5)', () => {
    const baseTimestamp = new Date('2026-09-09T14:00:00.000Z').getTime();

    // Ingest 4 failed attempts: should not alert yet
    for (let i = 0; i < 4; i++) {
      const event: SecurityEvent = {
        eventId: `evt-fail-${i}`,
        timestamp: new Date(baseTimestamp + i * 1000).toISOString(),
        source: 'sovereign-os',
        businessId: 'biz-01',
        environment: 'production',
        severity: 'HIGH',
        category: 'AUTHENTICATION',
        eventType: 'ADMIN_LOGIN_FAILED',
        actorId: 'attacker-ip-1',
        resourceId: 'auth/admin/login',
        action: 'authenticate',
        result: 'FAILURE',
        riskScore: 75,
        verificationStatus: 'VERIFIED',
        metadata: {},
        correlationId: `corr-${i}`,
      };
      const alerts = threatEngine.processEvent(event);
      assert.equal(alerts.length, 0);
    }

    // 5th failed attempt: threshold reached, triggers alert
    const fifthEvent: SecurityEvent = {
      eventId: 'evt-fail-4',
      timestamp: new Date(baseTimestamp + 5000).toISOString(),
      source: 'sovereign-os',
      businessId: 'biz-01',
      environment: 'production',
      severity: 'HIGH',
      category: 'AUTHENTICATION',
      eventType: 'ADMIN_LOGIN_FAILED',
      actorId: 'attacker-ip-1',
      resourceId: 'auth/admin/login',
      action: 'authenticate',
      result: 'FAILURE',
      riskScore: 75,
      verificationStatus: 'VERIFIED',
      metadata: {},
      correlationId: 'corr-4',
    };

    const alerts = threatEngine.processEvent(fifthEvent);
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0]?.severity, 'HIGH');
    assert.equal(alerts[0]?.category, 'AUTHENTICATION');
    assert.equal(alerts[0]?.sourceEventIds.length, 5);
  });

  test('generates CRITICAL alert upon blocked unauthorized privileged action', () => {
    const privilegedEvent: SecurityEvent = {
      eventId: 'evt-priv-01',
      timestamp: new Date().toISOString(),
      source: 'sovereign-os',
      businessId: 'biz-01',
      environment: 'production',
      severity: 'CRITICAL',
      category: 'AUTHORIZATION',
      eventType: 'PERMISSION_DENIED',
      actorId: 'unauthorized-user',
      resourceId: 'db/production/ledger',
      action: 'delete_production_data',
      result: 'DENIED',
      riskScore: 95,
      verificationStatus: 'VERIFIED',
      metadata: {},
      correlationId: 'corr-priv-01',
    };

    const alerts = threatEngine.processEvent(privilegedEvent);
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0]?.severity, 'CRITICAL');
    assert.match(alerts[0]?.title || '', /Unauthorized Privileged Action Blocked/i);
    assert.equal(alerts[0]?.affectedResource, 'db/production/ledger');
  });

  test('generates CRITICAL alert on secret exposure events', () => {
    const secretEvent: SecurityEvent = {
      eventId: 'evt-sec-01',
      timestamp: new Date().toISOString(),
      source: 'metro-task-force',
      businessId: 'mtf-01',
      environment: 'production',
      severity: 'CRITICAL',
      category: 'SECRETS',
      eventType: 'SECRET_EXPOSURE',
      actorId: 'dev-operator',
      resourceId: 'config/keys/jwt',
      action: 'export_key',
      result: 'FAILURE',
      riskScore: 98,
      verificationStatus: 'VERIFIED',
      metadata: {},
      correlationId: 'corr-sec-01',
    };

    const alerts = threatEngine.processEvent(secretEvent);
    assert.equal(alerts.length, 1);
    assert.equal(alerts[0]?.severity, 'CRITICAL');
    assert.equal(alerts[0]?.category, 'SECRETS');
  });
});
