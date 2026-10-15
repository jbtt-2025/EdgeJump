// Login Rate Limiting Durable Object for EdgeJump
// Tracks failed login attempts per IP and username in a sliding window

import type { Env } from '../types.ts';
import { logError } from '../logging.ts';

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  lockoutTtl: number; // in seconds
  totalFailedInWindow: number;
}

export interface RateLimitOptions {
  maxAttempts?: number; // default: 5 attempts
  windowMs?: number;    // default: 5 minutes (300,000 ms)
}

const DEFAULT_MAX_ATTEMPTS = 5;
const DEFAULT_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
type Attempt = number | { at: number; id: string };
const attemptTime = (attempt: Attempt): number => typeof attempt === 'number' ? attempt : attempt.at;

export class RateLimitDO {
  private readonly state?: DurableObjectState;
  private readonly env?: Env;
  private readonly inMemoryStore: Map<string, Attempt[]> = new Map();
  private attemptsQueue: Promise<unknown> = Promise.resolve();

  constructor(state?: DurableObjectState, env?: Env) {
    this.state = state;
    this.env = env;
  }

  private async getAttempts(key: string, windowMs: number): Promise<Attempt[]> {
    let attempts = this.inMemoryStore.get(key);

    if (!attempts && this.state?.storage) {
      const stored = await this.state.storage.get<Attempt[]>(`ratelimit:${key}`);
      if (stored && Array.isArray(stored)) {
        attempts = stored;
        this.inMemoryStore.set(key, attempts);
      }
    }

    if (!attempts) {
      attempts = [];
      this.inMemoryStore.set(key, attempts);
    }

    const cutoff = Date.now() - windowMs;
    const filtered = attempts.filter((t) => attemptTime(t) > cutoff);

    if (filtered.length !== attempts.length) {
      this.inMemoryStore.set(key, filtered);
      if (this.state?.storage) {
        if (filtered.length > 0) {
          await this.state.storage.put(`ratelimit:${key}`, filtered);
        } else {
          await this.state.storage.delete(`ratelimit:${key}`);
        }
      }
    }

    return filtered;
  }

  private async saveAttempts(key: string, attempts: Attempt[]): Promise<void> {
    this.inMemoryStore.set(key, attempts);
    if (this.state?.storage) {
      if (attempts.length > 0) {
        await this.state.storage.put(`ratelimit:${key}`, attempts);
      } else {
        await this.state.storage.delete(`ratelimit:${key}`);
      }
    }
  }

  /**
   * Checks whether attempts on this key are allowed without incrementing.
   */
  async check(key: string, options: RateLimitOptions = {}): Promise<RateLimitResult> {
    const maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    const windowMs = options.windowMs ?? DEFAULT_WINDOW_MS;

    const attempts = await this.getAttempts(key, windowMs);
    const count = attempts.length;

    if (count >= maxAttempts) {
      const oldest = attemptTime(attempts[0]);
      const now = Date.now();
      const lockoutTtl = Math.max(1, Math.ceil((oldest + windowMs - now) / 1000));
      return {
        allowed: false,
        remaining: 0,
        lockoutTtl,
        totalFailedInWindow: count,
      };
    }

    return {
      allowed: true,
      remaining: maxAttempts - count,
      lockoutTtl: 0,
      totalFailedInWindow: count,
    };
  }

  /**
   * Records a failed attempt for the given key and returns the updated rate limit status.
   */
  async recordFailure(key: string, options: RateLimitOptions = {}): Promise<RateLimitResult> {
    const maxAttempts = options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
    const windowMs = options.windowMs ?? DEFAULT_WINDOW_MS;

    const attempts = await this.getAttempts(key, windowMs);
    const now = Date.now();
    attempts.push(now);

    await this.saveAttempts(key, attempts);

    const count = attempts.length;
    if (count >= maxAttempts) {
      const oldest = attemptTime(attempts[0]);
      const lockoutTtl = Math.max(1, Math.ceil((oldest + windowMs - now) / 1000));
      return {
        allowed: false,
        remaining: 0,
        lockoutTtl,
        totalFailedInWindow: count,
      };
    }

    return {
      allowed: true,
      remaining: maxAttempts - count,
      lockoutTtl: 0,
      totalFailedInWindow: count,
    };
  }

  /**
   * Resets rate limit for a key (e.g. after successful login).
   */
  async reset(key: string): Promise<void> {
    this.inMemoryStore.delete(key);
    if (this.state?.storage) {
      await this.state.storage.delete(`ratelimit:${key}`);
    }
  }

  /**
   * Evaluates rate limit for IP and username combined.
   */
  async checkLogin(ip: string, username: string, options: RateLimitOptions = {}): Promise<RateLimitResult> {
    const ipKey = `ip:${ip.trim()}`;
    const userKey = `user:${username.trim().toLowerCase()}`;

    const [ipResult, userResult] = await Promise.all([
      this.check(ipKey, options),
      this.check(userKey, options),
    ]);

    const allowed = ipResult.allowed && userResult.allowed;
    const remaining = Math.min(ipResult.remaining, userResult.remaining);
    const lockoutTtl = Math.max(ipResult.lockoutTtl, userResult.lockoutTtl);
    const totalFailedInWindow = Math.max(ipResult.totalFailedInWindow, userResult.totalFailedInWindow);

    return {
      allowed,
      remaining,
      lockoutTtl,
      totalFailedInWindow,
    };
  }

  /**
   * Records a failed login attempt for both IP and username.
   */
  async recordLoginFailure(ip: string, username: string, options: RateLimitOptions = {}): Promise<RateLimitResult> {
    const ipKey = `ip:${ip.trim()}`;
    const userKey = `user:${username.trim().toLowerCase()}`;

    const [ipResult, userResult] = await Promise.all([
      this.recordFailure(ipKey, options),
      this.recordFailure(userKey, options),
    ]);

    const allowed = ipResult.allowed && userResult.allowed;
    const remaining = Math.min(ipResult.remaining, userResult.remaining);
    const lockoutTtl = Math.max(ipResult.lockoutTtl, userResult.lockoutTtl);
    const totalFailedInWindow = Math.max(ipResult.totalFailedInWindow, userResult.totalFailedInWindow);

    return {
      allowed,
      remaining,
      lockoutTtl,
      totalFailedInWindow,
    };
  }

  /**
   * Resets failed login records for both IP and username.
   */
  async resetLogin(ip: string, username: string): Promise<void> {
    const ipKey = `ip:${ip.trim()}`;
    const userKey = `user:${username.trim().toLowerCase()}`;
    await Promise.all([
      this.reset(ipKey),
      this.reset(userKey),
    ]);
  }

  /**
   * HTTP handler for DO requests.
   */
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === '/status' || path === '/health') {
        return Response.json({ ok: true, activeKeys: this.inMemoryStore.size });
      }

      if (request.method === 'GET' && path === '/check') {
        const ip = url.searchParams.get('ip');
        const username = url.searchParams.get('username');
        const key = url.searchParams.get('key');
        const maxAttempts = url.searchParams.get('maxAttempts') ? Number(url.searchParams.get('maxAttempts')) : undefined;
        const windowMs = url.searchParams.get('windowMs') ? Number(url.searchParams.get('windowMs')) : undefined;

        if (ip && username) {
          const res = await this.checkLogin(ip, username, { maxAttempts, windowMs });
          return Response.json(res);
        }
        if (key) {
          const res = await this.check(key, { maxAttempts, windowMs });
          return Response.json(res);
        }
        return Response.json({ error: 'Missing ip/username or key query parameter' }, { status: 400 });
      }

      if (request.method === 'POST') {
        const body = (await request.json().catch(() => ({}))) as {
          ip?: string;
          username?: string;
          key?: string;
          maxAttempts?: number;
          windowMs?: number;
          reservationId?: string;
        };

        const { ip, username, key, maxAttempts, windowMs } = body;
        const options: RateLimitOptions = { maxAttempts, windowMs };

        if (path === '/attempt' && key) {
          const task = this.attemptsQueue.then(async () => {
            const before = await this.check(key);
            if (!before.allowed) return before;
            const reservationId = crypto.randomUUID();
            const attempts = await this.getAttempts(key, DEFAULT_WINDOW_MS);
            attempts.push({ at: Date.now(), id: reservationId });
            await this.saveAttempts(key, attempts);
            const after = await this.check(key);
            return { ...after, allowed: true, reservationId };
          });
          this.attemptsQueue = task.catch(() => {});
          return Response.json(await task);
        }

        if (path === '/refund' && key && body.reservationId) {
          const task = this.attemptsQueue.then(async () => {
            const attempts = await this.getAttempts(key, DEFAULT_WINDOW_MS);
            await this.saveAttempts(key, attempts.filter((attempt) => typeof attempt === 'number' || attempt.id !== body.reservationId));
            return { success: true };
          });
          this.attemptsQueue = task.catch(() => {});
          return Response.json(await task);
        }

        if (path === '/check') {
          if (ip && username) {
            const res = await this.checkLogin(ip, username, options);
            return Response.json(res);
          }
          if (key) {
            const res = await this.check(key, options);
            return Response.json(res);
          }
          return Response.json({ error: 'Missing ip/username or key' }, { status: 400 });
        }

        if (path === '/fail' || path === '/record-failure') {
          if (ip && username) {
            const res = await this.recordLoginFailure(ip, username, options);
            return Response.json(res);
          }
          if (key) {
            const res = await this.recordFailure(key, options);
            return Response.json(res);
          }
          return Response.json({ error: 'Missing ip/username or key' }, { status: 400 });
        }

        if (path === '/reset' || path === '/success') {
          if (ip && username) {
            await this.resetLogin(ip, username);
            return Response.json({ success: true });
          }
          if (key) {
            const task = this.attemptsQueue.then(() => this.reset(key));
            this.attemptsQueue = task.catch(() => {});
            await task;
            return Response.json({ success: true });
          }
          return Response.json({ error: 'Missing ip/username or key' }, { status: 400 });
        }
      }

      return Response.json({ error: 'Not found' }, { status: 404 });
    } catch (err: unknown) {
      logError('rate_limit_failed', err);
      return Response.json({ error: 'Rate limiter unavailable' }, { status: 500 });
    }
  }
}
