import test, { describe, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { IncomingMessage, ServerResponse } from 'node:http';
import { ApplicationRateLimiter } from '../src/server/rate-limiter.js';
import { SovereignSecurityApiHandler } from '../src/server/routes.js';

describe('Application-Layer Rate Limiting Test Suite', () => {
  let rateLimiter: ApplicationRateLimiter;

  beforeEach(() => {
    rateLimiter = new ApplicationRateLimiter({
      tiers: {
        UNAUTHENTICATED: { maxRequests: 5, windowMs: 10_000, burstAllowance: 2 },
        AUTHENTICATED: { maxRequests: 20, windowMs: 10_000, burstAllowance: 5 },
        SENSITIVE: { maxRequests: 2, windowMs: 10_000, burstAllowance: 1 },
      },
      maxTrackedEntries: 100,
    });
  });

  describe('1. Sliding Window & Burst Behavior', () => {
    test('permits requests within base limit plus burst allowance', () => {
      const ip = '192.168.1.100';
      // Limit is 5 + 2 burst = 7 total allowed
      for (let i = 0; i < 7; i++) {
        const res = rateLimiter.checkLimit(ip, 'UNAUTHENTICATED');
        assert.equal(res.allowed, true);
        assert.equal(res.currentRequests, i + 1);
      }

      // 8th request breaches burst allowance
      const blocked = rateLimiter.checkLimit(ip, 'UNAUTHENTICATED');
      assert.equal(blocked.allowed, false);
      assert.equal(blocked.remainingRequests, 0);
      assert.equal(blocked.retryAfterSeconds > 0, true);
    });

    test('calculates accurate Retry-After seconds based on oldest window entry', () => {
      const ip = '10.0.0.5';
      const startTime = 1_000_000;

      // Fill sensitive limit (2 + 1 = 3 requests)
      rateLimiter.checkLimit(ip, 'SENSITIVE', startTime);
      rateLimiter.checkLimit(ip, 'SENSITIVE', startTime + 1000);
      rateLimiter.checkLimit(ip, 'SENSITIVE', startTime + 2000);

      // 4th request at startTime + 3000
      const blocked = rateLimiter.checkLimit(ip, 'SENSITIVE', startTime + 3000);
      assert.equal(blocked.allowed, false);
      // Window is 10s from first entry (startTime: 1,000,000 + 10,000 = 1,010,000)
      // Current time is 1,003,000 -> 7,000ms remaining = 7 seconds
      assert.equal(blocked.retryAfterSeconds, 7);
    });
  });

  describe('2. Multi-Tiered Quotas', () => {
    test('enforces distinct quotas across unauthenticated, authenticated, and sensitive tiers', () => {
      const client = 'client-tier-test';

      // Sensitive tier allows only 3 (2 + 1)
      assert.equal(rateLimiter.checkLimit(client, 'SENSITIVE').allowed, true);
      assert.equal(rateLimiter.checkLimit(client, 'SENSITIVE').allowed, true);
      assert.equal(rateLimiter.checkLimit(client, 'SENSITIVE').allowed, true);
      assert.equal(rateLimiter.checkLimit(client, 'SENSITIVE').allowed, false);

      // Authenticated tier for the same client still has its own higher quota
      for (let i = 0; i < 15; i++) {
        assert.equal(rateLimiter.checkLimit(client, 'AUTHENTICATED').allowed, true);
      }
    });

    test('resolves appropriate tier based on request URL and auth headers', () => {
      assert.equal(rateLimiter.resolveTier('/health', false), 'UNAUTHENTICATED');
      assert.equal(rateLimiter.resolveTier('/api/v1/events', false), 'UNAUTHENTICATED');
      assert.equal(rateLimiter.resolveTier('/api/v1/events', true), 'AUTHENTICATED');
      assert.equal(rateLimiter.resolveTier('/api/v1/agents/containment', true), 'SENSITIVE');
      assert.equal(rateLimiter.resolveTier('/api/v1/policy/rules', false), 'SENSITIVE');
    });
  });

  describe('3. Memory Bounding & High-Cardinality IP Spray Defense', () => {
    test('evicts stale window buckets on periodic cleanup', () => {
      const now = 5_000_000;
      rateLimiter.checkLimit('ip-1', 'UNAUTHENTICATED', now);
      rateLimiter.checkLimit('ip-2', 'UNAUTHENTICATED', now);
      assert.equal(rateLimiter.getTrackedCount(), 2);

      // Advance time beyond windowMs (10,000ms)
      const evicted = rateLimiter.cleanExpired(now + 15_000);
      assert.equal(evicted, 2);
      assert.equal(rateLimiter.getTrackedCount(), 0);
    });

    test('caps tracked entries under high-cardinality spoofed IP flood', () => {
      const boundedLimiter = new ApplicationRateLimiter({
        maxTrackedEntries: 50,
      });

      // Flood with 200 distinct spoofed IPs
      for (let i = 0; i < 200; i++) {
        boundedLimiter.checkLimit(`10.99.${Math.floor(i / 256)}.${i % 256}`, 'UNAUTHENTICATED');
      }

      // Tracked entries must remain bounded
      assert.equal(boundedLimiter.getTrackedCount() <= 60, true);
    });
  });

  describe('4. Server HTTP Integration & 429 Response Format', () => {
    test('returns HTTP 429 with Retry-After header and JSON payload when limit breached', async () => {
      const serverLimiter = new ApplicationRateLimiter({
        tiers: {
          UNAUTHENTICATED: { maxRequests: 1, windowMs: 10_000, burstAllowance: 0 },
        },
      });

      const handler = new SovereignSecurityApiHandler({
        rateLimiter: serverLimiter,
      });

      // Mock request helper
      const createMockReqRes = (urlPath: string, ip: string) => {
        const req = new EventEmitter() as any;
        req.url = urlPath;
        req.method = 'GET';
        req.headers = {
          host: 'localhost:3000',
          'x-forwarded-for': ip,
        };
        req.socket = { remoteAddress: ip };

        let statusCode = 200;
        const headers: Record<string, string> = {};
        let body = '';

        const res = {
          setHeader: (name: string, val: string) => {
            headers[name.toLowerCase()] = val;
          },
          writeHead: (code: number, hdrs?: Record<string, string>) => {
            statusCode = code;
            if (hdrs) Object.assign(headers, hdrs);
          },
          get statusCode() {
            return statusCode;
          },
          set statusCode(val: number) {
            statusCode = val;
          },
          end: (chunk?: string) => {
            if (chunk) body += chunk;
          },
          headers,
          getBody: () => body,
        } as any;

        return { req, res };
      };

      // 1st request should succeed (200)
      const req1 = createMockReqRes('/health', '172.16.0.1');
      await handler.handleRequest(req1.req, req1.res);
      assert.equal(req1.res.statusCode, 200);
      assert.equal(req1.res.headers['x-ratelimit-remaining'], '0');

      // 2nd request should receive 429 Too Many Requests
      const req2 = createMockReqRes('/health', '172.16.0.1');
      await handler.handleRequest(req2.req, req2.res);
      assert.equal(req2.res.statusCode, 429);
      assert.equal(req2.res.headers['retry-after'] !== undefined, true);
      const parsedBody = JSON.parse(req2.res.getBody());
      assert.equal(parsedBody.error, 'TOO_MANY_REQUESTS');
      assert.equal(parsedBody.tier, 'UNAUTHENTICATED');
      assert.equal(parsedBody.retryAfter > 0, true);
    });
  });
});
