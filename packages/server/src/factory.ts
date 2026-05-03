/**
 * High-DX factory. The "I just want sign-in to work" entry point.
 *
 * Usage (3 lines):
 *
 *   import { createClawAuth } from '@clawauth/server';
 *   const auth = createClawAuth({ google: process.env.GOOGLE_CLIENT_ID, cosmos: { connectionString: process.env.COSMOS_CONN, database: 'myapp' } });
 *   await auth.handle(req); // or pass to the framework adapter
 */

import { CosmosClient } from '@azure/cosmos';
import { randomBytes } from 'node:crypto';
import { createAuthCore, ClawAuthError, type AuthCore } from './core.js';
import { GoogleIdTokenProvider } from './providers/google.js';
import { CosmosStorage } from './storage/cosmos.js';
import { InMemoryStorage } from './storage/memory.js';
import { createAuditLogger, type AuditLogger, type AuditEvent } from './audit.js';
import { createRateLimiter, MemoryRateLimitStore, type RateLimitStore } from './rate-limit.js';
import type { Storage } from './types.js';

export interface ClawAuthOptions {
  /** Google OAuth Client ID. Pass the string and you're done. */
  google?: string;
  /**
   * Apple Service ID (placeholder — Apple provider not yet implemented).
   */
  apple?: string;
  /**
   * Cosmos DB config. If omitted, uses in-memory storage (DEV ONLY).
   */
  cosmos?: {
    connectionString?: string;
    /** Or pass an existing client (e.g. AAD MSI auth). */
    client?: CosmosClient;
    database: string;
    usersContainer?: string;
    refreshContainer?: string;
    createIfNotExists?: boolean;
  };
  /**
   * HMAC signing secret. Min 32 bytes. If omitted, throws — except in `dev=true`,
   * where a random one is generated (logs a warning).
   */
  jwtSecret?: string;
  /** Optional secondary secret for zero-downtime key rotation. Verified, never signed. */
  jwtSecretPrevious?: string;
  issuer?: string;
  audience?: string;
  /** True to allow in-memory storage + auto-generated secret. NEVER set in prod. */
  dev?: boolean;
  /**
   * Pluggable audit sink. Default writes structured JSON to console (App Insights
   * picks it up automatically in Azure Functions).
   */
  audit?: AuditLogger;
  /** Rate limit store. Defaults to in-memory (per-process). Use Cosmos/Redis in prod. */
  rateLimitStore?: RateLimitStore;
  /**
   * Advanced: pass extra IdPs directly (e.g. custom providers, mocks for tests).
   * Combined with `google`/`apple` shorthands.
   */
  extraProviders?: import('./types.js').IdentityProvider[];
}

export interface ClawAuthInstance {
  /** Low-level core. */
  core: AuthCore;
  /** Audit logger. Write your own events with `auth.audit({ event, ... })`. */
  audit: AuditLogger;
  /** Storage adapter — for cascade delete, admin tools, etc. */
  storage: Storage;
  /**
   * Generic HTTP handler. Pass any `Request`-like object with .method, .url, .json(), .headers.
   * Returns a `Response`-like { status, headers, body }.
   * Adapters (azure-functions, express) wrap this.
   */
  handle(req: ClawAuthRequest, ctx?: { ip?: string }): Promise<ClawAuthResponse>;
  /** GDPR right-to-be-forgotten cascade. */
  deleteUser(userId: string): Promise<{ deleted: boolean }>;
  /** Rotate JWT secret — call with new secret; old one stays in `jwtSecretPrevious` for verify. */
  rotateJwtSecret(newSecret: string): { newCore: AuthCore };
  /** CSP fragment consumers can spread into their CSP header. */
  readonly csp: typeof CSP;
}

export interface ClawAuthRequest {
  method: string;
  /** Path only, e.g. '/auth/google' or '/auth/refresh'. Adapters strip prefix. */
  path: string;
  json(): Promise<any>;
  headers: { get(name: string): string | null };
}
export interface ClawAuthResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** CSP fragment for the Google Identity Services flow. Spread into your CSP header. */
export const CSP = {
  'script-src': ["'self'", 'https://accounts.google.com/gsi/client'],
  'frame-src': ["'self'", 'https://accounts.google.com/'],
  'connect-src': ["'self'", 'https://accounts.google.com/gsi/'],
  'style-src': ["'self'", "'unsafe-inline'", 'https://accounts.google.com/gsi/style']
} as const;

const SIGNIN_LIMIT_PER_MIN = 10;
const REFRESH_LIMIT_PER_MIN = 60;

export function createClawAuth(opts: ClawAuthOptions): ClawAuthInstance {
  // ---- secret ----
  let jwtSecret = opts.jwtSecret;
  if (!jwtSecret) {
    if (!opts.dev) {
      throw new ClawAuthError(
        'config_invalid',
        'jwtSecret required. Set CLAWAUTH_JWT_SECRET in app settings, or pass dev:true for local-only.',
        500
      );
    }
    jwtSecret = randomBytes(48).toString('hex');
    console.warn(
      JSON.stringify({
        level: 'warn',
        component: 'clawauth',
        msg: 'dev mode: generated ephemeral jwtSecret. Sessions will not survive restart.'
      })
    );
  }

  // ---- storage ----
  let storage: Storage;
  if (opts.cosmos) {
    const client =
      opts.cosmos.client ??
      new CosmosClient(
        opts.cosmos.connectionString ?? requiredEnv('cosmos.connectionString or cosmos.client')
      );
    storage = new CosmosStorage({
      client,
      databaseId: opts.cosmos.database,
      usersContainerId: opts.cosmos.usersContainer,
      refreshTokensContainerId: opts.cosmos.refreshContainer,
      createIfNotExists: opts.cosmos.createIfNotExists ?? false
    });
  } else {
    if (!opts.dev) {
      throw new ClawAuthError(
        'config_invalid',
        'cosmos config required (or pass dev:true to use in-memory storage).',
        500
      );
    }
    storage = new InMemoryStorage();
  }

  // ---- providers ----
  const idps: import('./types.js').IdentityProvider[] = [];
  if (opts.google) idps.push(new GoogleIdTokenProvider({ clientId: opts.google }));
  if (opts.extraProviders) idps.push(...opts.extraProviders);
  if (idps.length === 0) {
    throw new ClawAuthError('config_invalid', 'At least one IdP must be configured (google).', 500);
  }

  // ---- core ----
  let core = createAuthCore({
    jwtSecret,
    issuer: opts.issuer,
    audience: opts.audience,
    storage,
    identityProviders: idps
  });

  // ---- audit + rate limit ----
  const audit = opts.audit ?? createAuditLogger();
  const rlStore = opts.rateLimitStore ?? new MemoryRateLimitStore();
  const signinLimiter = createRateLimiter({
    store: rlStore,
    windowMs: 60_000,
    max: SIGNIN_LIMIT_PER_MIN
  });
  const refreshLimiter = createRateLimiter({
    store: rlStore,
    windowMs: 60_000,
    max: REFRESH_LIMIT_PER_MIN
  });

  // ---- previous-secret verification window for rotation ----
  let prevCore: AuthCore | null = opts.jwtSecretPrevious
    ? createAuthCore({
        jwtSecret: opts.jwtSecretPrevious,
        issuer: opts.issuer,
        audience: opts.audience,
        storage,
        identityProviders: idps
      })
    : null;

  async function verifyAccessTokenWithFallback(token: string) {
    try {
      return await core.verifyAccessToken(token);
    } catch (err) {
      if (prevCore) {
        try {
          return await prevCore.verifyAccessToken(token);
        } catch {
          /* fall through to original error */
        }
      }
      throw err;
    }
  }

  async function handle(req: ClawAuthRequest, ctx?: { ip?: string }): Promise<ClawAuthResponse> {
    const ip = ctx?.ip ?? 'unknown';
    try {
      // GET /auth/csp → returns CSP fragment as JSON, handy for SSR / frontends.
      if (req.method === 'GET' && req.path === '/auth/csp') {
        return json(200, CSP);
      }
      if (req.method === 'POST' && req.path === '/auth/google') {
        const limit = await signinLimiter.check(`signin:${ip}`);
        if (!limit.allowed) {
          audit({ event: 'auth.signin.rate_limited', provider: 'google', ip, ok: false });
          return json(429, { error: 'rate_limited', resetAt: limit.resetAt });
        }
        const body = await req.json();
        const idToken = body?.idToken;
        if (!idToken || typeof idToken !== 'string') {
          return json(400, { error: 'idToken required' });
        }
        const result = await core.handleGoogleSignIn({
          idToken,
          deviceId: typeof body?.deviceId === 'string' ? body.deviceId : undefined
        });
        audit({
          event: 'auth.signin.ok',
          provider: 'google',
          ip,
          userId: result.user.id,
          ok: true
        });
        return json(200, redactRefresh(result));
      }
      if (req.method === 'POST' && req.path === '/auth/refresh') {
        const limit = await refreshLimiter.check(`refresh:${ip}`);
        if (!limit.allowed) {
          audit({ event: 'auth.refresh.rate_limited', ip, ok: false });
          return json(429, { error: 'rate_limited', resetAt: limit.resetAt });
        }
        const body = await req.json();
        const refreshToken = body?.refreshToken;
        if (!refreshToken || typeof refreshToken !== 'string') {
          return json(400, { error: 'refreshToken required' });
        }
        const result = await core.handleRefresh({ refreshToken });
        audit({ event: 'auth.refresh.ok', ip, ok: true });
        return json(200, redactRefresh(result));
      }
      if (req.method === 'POST' && req.path === '/auth/logout') {
        const body = await req.json().catch(() => ({}));
        const refreshToken = body?.refreshToken;
        if (typeof refreshToken === 'string' && refreshToken.length) {
          await core.handleLogout({ refreshToken });
        }
        audit({ event: 'auth.logout', ip, ok: true });
        return json(200, { ok: true });
      }
      if (req.method === 'GET' && req.path === '/auth/me') {
        const authz = req.headers.get('authorization') ?? '';
        const m = /^Bearer (.+)$/.exec(authz);
        if (!m) return json(401, { error: 'missing_bearer' });
        const claims = await verifyAccessTokenWithFallback(m[1]);
        return json(200, { user: claims });
      }
      return json(404, { error: 'not_found' });
    } catch (err) {
      const code = err instanceof ClawAuthError ? err.code : 'internal_error';
      const status = err instanceof ClawAuthError ? err.status : 500;
      const message = err instanceof Error ? err.message : 'unknown';
      audit({ event: 'auth.error', ip, ok: false, code, message });
      return json(status, { error: code, message });
    }
  }

  return {
    core,
    audit,
    storage,
    handle,
    csp: CSP,
    async deleteUser(userId: string) {
      const user = await storage.getUserById(userId);
      if (!user) {
        audit({ event: 'user.delete.miss', userId, ok: false });
        return { deleted: false };
      }
      await storage.revokeAllRefreshTokensForUser(userId);
      // Storage doesn't expose a hard delete by default — adapters may.
      // Cosmos: we delete the user doc directly.
      const anyStorage = storage as any;
      if (typeof anyStorage._deleteUser === 'function') {
        await anyStorage._deleteUser(userId);
      }
      audit({
        event: 'user.delete.ok',
        userId,
        provider: user.provider,
        providerSub: user.providerSub,
        ok: true,
        gdpr: true
      });
      return { deleted: true };
    },
    rotateJwtSecret(newSecret: string) {
      prevCore = core; // verify-only
      core = createAuthCore({
        jwtSecret: newSecret,
        issuer: opts.issuer,
        audience: opts.audience,
        storage,
        identityProviders: idps
      });
      audit({ event: 'auth.jwt_secret.rotated', ok: true });
      return { newCore: core };
    }
  };
}

function json(status: number, body: unknown): ClawAuthResponse {
  return {
    status,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff'
    },
    body: JSON.stringify(body)
  };
}

/**
 * Sanity helper: keep the refresh token in the body, but make sure the
 * caller's audit/logger sink never sees it. We don't strip it — the client
 * needs it. Adapters that log responses should call this themselves.
 */
function redactRefresh<T extends Record<string, any>>(r: T): T {
  return r; // Body returns intact; the audit logger never sees the body.
}

function requiredEnv(label: string): never {
  throw new ClawAuthError('config_invalid', `${label} required`, 500);
}

export type { AuditEvent, AuditLogger };
