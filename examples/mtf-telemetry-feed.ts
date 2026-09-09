/**
 * Sovereign Security — Phase 2B Example
 * Metro Task Force (MTF) Telemetry Ingestion Example
 *
 * Demonstrates:
 * 1. Mutual authentication with MTF credentials
 * 2. Ingestion of security events (e.g. brute force, admin login failed)
 * 3. Strict rejection of business telemetry (e.g. patrol location pings)
 */

import { EcosystemCredentials } from '../src/integrations/auth/credentials.js';
import { MetroTaskForceAdapter } from '../src/integrations/mtf/adapter.js';

async function main() {
  console.log('--- METRO TASK FORCE TELEMETRY FEED DEMO ---');
  const adapter = new MetroTaskForceAdapter();

  const validCreds: EcosystemCredentials = {
    serviceId: 'metro-task-force',
    businessId: 'mtf-hq',
    environment: 'production',
    apiKey: 'sec_key_mtf_telemetry_prod_secret',
    timestamp: new Date().toISOString(),
    nonce: `mtf-nonce-${Date.now()}`,
  };

  // 1. Ingest Security-Relevant Event
  console.log('\n1. Ingesting Security Event (ADMIN_LOGIN_FAILED)...');
  const secResult = adapter.ingestWithCredentials(
    {
      eventType: 'ADMIN_LOGIN_FAILED',
      operatorId: 'unknown-intruder',
      targetEndpoint: '/api/v1/mtf/admin/login',
      action: 'admin-login',
      status: 'FAILED',
      clientIp: '198.51.100.44',
      metadata: { attempts: 5 },
    },
    validCreds
  );

  console.log('Accepted:', secResult.accepted);
  console.log('Normalized Event ID:', secResult.event?.eventId);
  console.log('Risk Score:', secResult.event?.riskScore);

  // 2. Attempt to Send Pure Business Telemetry
  console.log('\n2. Attempting to Ingest Pure Business Telemetry (PATROL_LOCATION_PING)...');
  const busCreds: EcosystemCredentials = {
    ...validCreds,
    nonce: `mtf-nonce-bus-${Date.now()}`,
  };

  const busResult = adapter.ingestWithCredentials(
    {
      eventType: 'PATROL_LOCATION_PING',
      operatorId: 'officer-104',
      targetEndpoint: '/mtf/fleet/gps',
      action: 'location-update',
      status: 'SUCCESS',
      metadata: { latitude: 40.7128, longitude: -74.006 },
    },
    busCreds
  );

  console.log('Accepted:', busResult.accepted);
  console.log('Rejected Reason:', busResult.rejectedReason);

  console.log('\n--- MTF TELEMETRY FEED DEMO COMPLETED ---');
}

main().catch(console.error);
