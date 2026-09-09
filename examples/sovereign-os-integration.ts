/**
 * Sovereign Security — Phase 2B Example
 * Sovereign OS Integration Example
 *
 * Demonstrates:
 * 1. VEGA tool execution through SovereignSecurityClient
 * 2. Executive action check & correlation chaining
 * 3. Configuration change & sensitive data access mediation
 * 4. Audit ledger verification
 */

import { SovereignSecurityClient } from '../src/integrations/sovereign-os/client.js';

async function main() {
  console.log('--- SOVEREIGN OS INTEGRATION DEMO ---');
  const client = new SovereignSecurityClient({
    sourceId: 'sovereign-os',
    businessId: 'sovereign-core-hq',
    environment: 'production',
  });

  // 1. Mediated VEGA tool execution
  console.log('\n1. Mediating VEGA tool execution...');
  const vegaResult = await client.invokeVegaTool({
    agentId: 'vega',
    toolName: 'read_business_telemetry',
    parameters: { lines: 50 },
    executor: async () => {
      return { status: 'OK', linesRetrieved: 50 };
    },
  });

  console.log('VEGA Invocation Permitted:', vegaResult.permitted);
  console.log('Decision:', vegaResult.decision.decision);
  console.log('Audit Record ID:', vegaResult.auditRecord?.auditId);

  // 2. Executive action
  console.log('\n2. Evaluating Executive Action...');
  const execResult = await client.evaluateExecutiveAction({
    executiveId: 'commander-01',
    action: 'rotate-encryption-keys',
    resource: 'system/kms/fleet-keys',
    parameters: { keyAlgorithm: 'AES-256-GCM' },
    executor: () => ({ status: 'ROTATED' }),
  });

  console.log('Executive Action Permitted:', execResult.permitted);
  console.log('Executive Action Result:', execResult.result);
  console.log('Executive Audit Record ID:', execResult.auditRecord?.auditId);

  // 3. Sensitive Data Access
  console.log('\n3. Evaluating Sensitive Data Access...');
  const dataResult = await client.evaluateDataAccess(
    'analyst-42',
    'financial-records-q3',
    'CONFIDENTIAL'
  );
  console.log('Data Access Permitted:', dataResult.permitted);
  console.log('Decision Reason:', dataResult.decision.reason);

  console.log('\n--- SOVEREIGN OS INTEGRATION COMPLETED ---');
}

main().catch(console.error);
