/**
 * Pluggable rate limiter. Storage interface lets you back it with
 * Cosmos, Redis, in-memory, etc.
 */
export interface RateLimitStore {
  /**
   * Increment counter for `key` and return the new count + the timestamp
   * (ms) when the current window expires. The store should auto-create
   * the entry with TTL = windowMs and reset on expiry.
   */
  incr(key: string, windowMs: number): Promise<{ count: number; resetAt: number }>;
}

export interface RateLimiter {
  check(key: string): Promise<{ allowed: boolean; remaining: number; resetAt: number }>;
}

export interface RateLimiterConfig {
  store: RateLimitStore;
  windowMs: number;
  max: number;
}

export function createRateLimiter(cfg: RateLimiterConfig): RateLimiter {
  return {
    async check(key) {
      const { count, resetAt } = await cfg.store.incr(key, cfg.windowMs);
      const remaining = Math.max(0, cfg.max - count);
      return { allowed: count <= cfg.max, remaining, resetAt };
    }
  };
}

/** Simple in-memory store. Not safe across processes — use Cosmos/Redis for prod. */
export class MemoryRateLimitStore implements RateLimitStore {
  private buckets = new Map<string, { count: number; resetAt: number }>();
  async incr(key: string, windowMs: number) {
    const now = Date.now();
    let b = this.buckets.get(key);
    if (!b || b.resetAt <= now) {
      b = { count: 0, resetAt: now + windowMs };
      this.buckets.set(key, b);
    }
    b.count += 1;
    return { count: b.count, resetAt: b.resetAt };
  }
}
