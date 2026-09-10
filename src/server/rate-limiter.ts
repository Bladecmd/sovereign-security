/**
 * Sovereign Security — V1.1 Production Resilience Candidate
 * Application-Layer Rate Limiter with Sliding Window, Tiered Quotas & Memory Bounding
 *
 * Mitigates DDoS-like spikes and high-cardinality spoofed-IP attacks at the application tier.
 * Returns HTTP 429 Too Many Requests with compliant Retry-After headers.
 */

export type RateLimitTier = 'UNAUTHENTICATED' | 'AUTHENTICATED' | 'SENSITIVE';

export interface RateLimitTierConfig {
  maxRequests: number;
  windowMs: number;
  burstAllowance: number;
}

export interface RateLimiterOptions {
  tiers?: Partial<Record<RateLimitTier, RateLimitTierConfig>>;
  maxTrackedEntries?: number;
  cleanupIntervalMs?: number;
}

export interface RateLimitResult {
  allowed: boolean;
  tier: RateLimitTier;
  currentRequests: number;
  maxRequests: number;
  remainingRequests: number;
  retryAfterSeconds: number;
  resetTimeMs: number;
}

interface WindowBucket {
  timestamps: number[];
  lastAccess: number;
}

export class ApplicationRateLimiter {
  private readonly tiers: Record<RateLimitTier, RateLimitTierConfig>;
  private readonly maxTrackedEntries: number;
  private readonly windows = new Map<string, WindowBucket>();
  private cleanupTimer?: NodeJS.Timeout;

  public static readonly DEFAULT_TIERS: Record<RateLimitTier, RateLimitTierConfig> = {
    UNAUTHENTICATED: {
      maxRequests: 100,
      windowMs: 60_000, // 100 req/min
      burstAllowance: 20,
    },
    AUTHENTICATED: {
      maxRequests: 600,
      windowMs: 60_000, // 600 req/min
      burstAllowance: 100,
    },
    SENSITIVE: {
      maxRequests: 30,
      windowMs: 60_000, // 30 req/min
      burstAllowance: 5,
    },
  };

  constructor(options: RateLimiterOptions = {}) {
    this.tiers = {
      UNAUTHENTICATED: options.tiers?.UNAUTHENTICATED || ApplicationRateLimiter.DEFAULT_TIERS.UNAUTHENTICATED,
      AUTHENTICATED: options.tiers?.AUTHENTICATED || ApplicationRateLimiter.DEFAULT_TIERS.AUTHENTICATED,
      SENSITIVE: options.tiers?.SENSITIVE || ApplicationRateLimiter.DEFAULT_TIERS.SENSITIVE,
    };
    this.maxTrackedEntries = options.maxTrackedEntries || 50_000;

    if (options.cleanupIntervalMs && options.cleanupIntervalMs > 0) {
      this.cleanupTimer = setInterval(() => {
        this.cleanExpired();
      }, options.cleanupIntervalMs);
      if (this.cleanupTimer.unref) {
        this.cleanupTimer.unref();
      }
    }
  }

  /**
   * Determine rate limit tier based on request URL and path
   */
  public resolveTier(pathname: string, isAuthenticated = false): RateLimitTier {
    if (
      pathname.includes('/containment') ||
      pathname.includes('/policy/rules') ||
      pathname.includes('/quarantine') ||
      pathname.includes('/threat/simulate')
    ) {
      return 'SENSITIVE';
    }

    if (pathname === '/health' || pathname === '/ready' || pathname === '/metrics' || pathname === '/' || pathname === '/dashboard') {
      return 'UNAUTHENTICATED';
    }

    return isAuthenticated ? 'AUTHENTICATED' : 'UNAUTHENTICATED';
  }

  /**
   * Evaluates if a request from an identifier (e.g. IP or serviceId) is allowed.
   */
  public checkLimit(
    identifier: string,
    tier: RateLimitTier,
    now: number = Date.now()
  ): RateLimitResult {
    const config = this.tiers[tier];
    const key = `${tier}:${identifier}`;
    const windowStart = now - config.windowMs;
    const effectiveLimit = config.maxRequests + config.burstAllowance;

    let bucket = this.windows.get(key);
    if (!bucket) {
      this.evictIfFull();
      bucket = { timestamps: [], lastAccess: now };
      this.windows.set(key, bucket);
    }

    bucket.lastAccess = now;
    // Slide window: remove timestamps older than windowMs
    bucket.timestamps = bucket.timestamps.filter((ts) => ts > windowStart);

    if (bucket.timestamps.length >= effectiveLimit) {
      const oldestInWindow = bucket.timestamps[0] || now;
      const resetTimeMs = oldestInWindow + config.windowMs;
      const retryAfterSeconds = Math.max(1, Math.ceil((resetTimeMs - now) / 1000));

      return {
        allowed: false,
        tier,
        currentRequests: bucket.timestamps.length,
        maxRequests: effectiveLimit,
        remainingRequests: 0,
        retryAfterSeconds,
        resetTimeMs,
      };
    }

    // Record request
    bucket.timestamps.push(now);

    return {
      allowed: true,
      tier,
      currentRequests: bucket.timestamps.length,
      maxRequests: effectiveLimit,
      remainingRequests: effectiveLimit - bucket.timestamps.length,
      retryAfterSeconds: 0,
      resetTimeMs: now + config.windowMs,
    };
  }

  /**
   * Periodic memory cleanup to purge expired client buckets
   */
  public cleanExpired(now: number = Date.now()): number {
    let evictedCount = 0;
    for (const [key, bucket] of this.windows.entries()) {
      const tier = key.split(':')[0] as RateLimitTier;
      const windowMs = this.tiers[tier]?.windowMs || 60_000;
      if (now - bucket.lastAccess > windowMs) {
        this.windows.delete(key);
        evictedCount++;
      }
    }
    return evictedCount;
  }

  /**
   * Bounded LRU eviction when memory capacity limit is breached
   */
  private evictIfFull(): void {
    if (this.windows.size < this.maxTrackedEntries) return;

    // Evict 10% oldest entries
    const evictTarget = Math.max(1, Math.floor(this.maxTrackedEntries * 0.1));
    let evicted = 0;
    for (const key of this.windows.keys()) {
      this.windows.delete(key);
      evicted++;
      if (evicted >= evictTarget) break;
    }
  }

  public getTrackedCount(): number {
    return this.windows.size;
  }

  public reset(): void {
    this.windows.clear();
  }

  public destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = undefined;
    }
    this.windows.clear();
  }
}
