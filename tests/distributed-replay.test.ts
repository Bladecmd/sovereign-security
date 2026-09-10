import test, { describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  EcosystemAuthenticator,
  EcosystemCredentials,
} from '../src/integrations/auth/credentials.js';
import {
  InMemoryReplayProtectionStore,
  DistributedReplayProtectionStore,
} from '../src/integrations/auth/replay-store.js';

describe('Distributed Replay Protection & Concurrency Test Suite', () => {
  beforeEach(() => {
    EcosystemAuthenticator.resetReplayStore();
  });

  const createValidCreds = (nonce: string, offsetMs = 0): EcosystemCredentials => {
    const timestamp = new Date(Date.now() + offsetMs).toISOString();
    return {
      serviceId: 'sovereign-os',
      businessId: 'sovereign-core-hq',
      environment: 'production',
      apiKey: 'sec_key_sovereign_os_prod_secret',
      timestamp,
      nonce,
    };
  };

  describe('1. InMemoryReplayProtectionStore', () => {
    test('evicts LRU entries when max capacity is reached', () => {
      const store = new InMemoryReplayProtectionStore(3);
      store.record('nonce-1', 60_000);
      store.record('nonce-2', 60_000);
      store.record('nonce-3', 60_000);

      assert.equal(store.has('nonce-1'), true);
      assert.equal(store.has('nonce-2'), true);
      assert.equal(store.has('nonce-3'), true);

      // Adding 4th should evict the oldest (nonce-1)
      store.record('nonce-4', 60_000);
      assert.equal(store.has('nonce-1'), false);
      assert.equal(store.has('nonce-4'), true);
    });

    test('reports health metrics accurately', () => {
      const store = new InMemoryReplayProtectionStore(10);
      store.record('health-test', 60_000);
      const health = store.health();
      assert.equal(health.healthy, true);
      assert.equal(health.entryCount, 1);
      assert.equal(health.mode, 'in-memory-lru');
    });
  });

  describe('2. Multi-Instance Distributed Replay Protection', () => {
    test('detects replay across simulated distinct cluster instances sharing backing storage', async () => {
      const sharedClusterBacking = new Map<string, number>();

      const instanceAStore = new DistributedReplayProtectionStore({ sharedBackend: sharedClusterBacking });
      const instanceBStore = new DistributedReplayProtectionStore({ sharedBackend: sharedClusterBacking });
      const instanceCStore = new DistributedReplayProtectionStore({ sharedBackend: sharedClusterBacking });

      const creds = createValidCreds('shared-tx-nonce-999');

      // Instance A processes the original request
      const resA = await EcosystemAuthenticator.verifyCredentialsAsync(creds, undefined, instanceAStore);
      assert.equal(resA.authenticated, true);

      // Replay attack routed to Instance B
      const resB = await EcosystemAuthenticator.verifyCredentialsAsync(creds, undefined, instanceBStore);
      assert.equal(resB.authenticated, false);
      assert.equal(resB.errorCode, 'REPLAY_DETECTED');

      // Replay attack routed to Instance C
      const resC = await EcosystemAuthenticator.verifyCredentialsAsync(creds, undefined, instanceCStore);
      assert.equal(resC.authenticated, false);
      assert.equal(resC.errorCode, 'REPLAY_DETECTED');
    });

    test('handles atomic race conditions across concurrent nodes, allowing only one consumer', async () => {
      const sharedClusterBacking = new Map<string, number>();
      const nodeCount = 10;
      const nodes = Array.from({ length: nodeCount }, () =>
        new DistributedReplayProtectionStore({ sharedBackend: sharedClusterBacking })
      );

      const targetNonce = 'race-condition-nonce-42';
      const creds = createValidCreds(targetNonce);

      // Fire 10 concurrent requests across 10 nodes with the same nonce
      const results = await Promise.all(
        nodes.map(node => EcosystemAuthenticator.verifyCredentialsAsync(creds, undefined, node))
      );

      const successful = results.filter(r => r.authenticated);
      const replayed = results.filter(r => !r.authenticated && r.errorCode === 'REPLAY_DETECTED');

      assert.equal(successful.length, 1);
      assert.equal(replayed.length, nodeCount - 1);
    });

    test('enforces fail-closed security when distributed store is unhealthy or partitioned', async () => {
      const failedStore = new DistributedReplayProtectionStore({ simulateFailure: true });
      const creds = createValidCreds('fail-closed-nonce');

      // Asynchronous check must fail closed
      const res = await EcosystemAuthenticator.verifyCredentialsAsync(creds, undefined, failedStore);
      assert.equal(res.authenticated, false);
      assert.equal(res.errorCode, 'REPLAY_STORE_UNAVAILABLE');
      assert.match(res.errorMessage || '', /fail-closed/);
    });

    test('enforces fail-closed when synchronous verification receives an async store', () => {
      const asyncStore = new DistributedReplayProtectionStore();
      const creds = createValidCreds('sync-misuse-nonce');

      const res = EcosystemAuthenticator.verifyCredentials(creds, undefined, asyncStore);
      assert.equal(res.authenticated, false);
      assert.equal(res.errorCode, 'REPLAY_STORE_UNAVAILABLE');
      assert.match(res.errorMessage || '', /requires EcosystemAuthenticator.verifyCredentialsAsync\(\)/);
    });
  });
});
