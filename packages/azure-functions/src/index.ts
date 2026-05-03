/**
 * Azure Functions v4 adapter for clawauth.
 *
 * Consumer code (3 lines):
 *
 *   import { mountClawAuth } from '@clawauth/azure-functions';
 *   mountClawAuth({ google: process.env.GOOGLE_CLIENT_ID!, cosmos: { connectionString: process.env.COSMOS_CONN!, database: 'myapp' } });
 *
 * That's it. This registers HTTP triggers at:
 *   POST /api/auth/google
 *   POST /api/auth/refresh
 *   POST /api/auth/logout
 *   GET  /api/auth/me
 *   GET  /api/auth/csp
 *
 * The adapter reads the JWT secret from CLAWAUTH_JWT_SECRET unless you pass `jwtSecret` explicitly.
 */

import { app, type HttpRequest, type HttpResponseInit, type InvocationContext } from '@azure/functions';
import {
  createClawAuth,
  type ClawAuthInstance,
  type ClawAuthOptions,
  type ClawAuthRequest
} from '@clawauth/server';

export interface MountOptions extends Omit<ClawAuthOptions, 'jwtSecret'> {
  /** Override the JWT secret. Default: process.env.CLAWAUTH_JWT_SECRET. */
  jwtSecret?: string;
  /** Route prefix. Default 'auth'. The host.json routePrefix ('api') is added by Azure. */
  routePrefix?: string;
  /** Function name prefix for telemetry. Default 'clawauth'. */
  functionPrefix?: string;
}

export function mountClawAuth(opts: MountOptions): ClawAuthInstance {
  const jwtSecret = opts.jwtSecret ?? process.env.CLAWAUTH_JWT_SECRET;
  const auth = createClawAuth({ ...opts, jwtSecret });
  const prefix = (opts.routePrefix ?? 'auth').replace(/^\/+|\/+$/g, '');
  const fnPrefix = opts.functionPrefix ?? 'clawauth';

  const routes: Array<{ method: 'POST' | 'GET'; path: string; name: string }> = [
    { method: 'POST', path: 'google', name: 'signinGoogle' },
    { method: 'POST', path: 'refresh', name: 'refresh' },
    { method: 'POST', path: 'logout', name: 'logout' },
    { method: 'GET', path: 'me', name: 'me' },
    { method: 'GET', path: 'csp', name: 'csp' }
  ];

  for (const r of routes) {
    app.http(`${fnPrefix}_${r.name}`, {
      methods: [r.method],
      authLevel: 'anonymous',
      route: `${prefix}/${r.path}`,
      handler: makeHandler(auth, `/${prefix}/${r.path}`)
    });
  }

  return auth;
}

function makeHandler(auth: ClawAuthInstance, internalPath: string) {
  return async (req: HttpRequest, _ctx: InvocationContext): Promise<HttpResponseInit> => {
    const ip =
      req.headers.get('x-forwarded-for')?.split(',')[0].trim() ||
      req.headers.get('x-azure-clientip') ||
      'unknown';
    const adapted: ClawAuthRequest = {
      method: req.method,
      path: internalPath,
      json: async () => {
        try {
          return await req.json();
        } catch {
          return {};
        }
      },
      headers: { get: (n: string) => req.headers.get(n) }
    };
    const res = await auth.handle(adapted, { ip });
    return {
      status: res.status,
      headers: res.headers,
      body: res.body
    };
  };
}

/**
 * Convenience: build an Azure Functions handler that requires a valid clawauth bearer.
 * Returns 401 with structured body when missing/invalid.
 *
 *   import { requireUser } from '@clawauth/azure-functions';
 *   app.http('myProtectedRoute', {
 *     methods: ['GET'], route: 'me/profile',
 *     handler: requireUser(auth, async (req, ctx, user) => ({ status: 200, jsonBody: { user } }))
 *   });
 */
export function requireUser(
  auth: ClawAuthInstance,
  inner: (
    req: HttpRequest,
    ctx: InvocationContext,
    user: { sub: string; email: string | null; name: string | null; provider: string }
  ) => Promise<HttpResponseInit>
) {
  return async (req: HttpRequest, ctx: InvocationContext): Promise<HttpResponseInit> => {
    const authz = req.headers.get('authorization') ?? '';
    const m = /^Bearer (.+)$/.exec(authz);
    if (!m) {
      return { status: 401, jsonBody: { error: 'missing_bearer' } };
    }
    try {
      const claims = await auth.core.verifyAccessToken(m[1]);
      return inner(req, ctx, {
        sub: String(claims.sub),
        email: (claims.email as string | null) ?? null,
        name: (claims.name as string | null) ?? null,
        provider: (claims.provider as string) ?? 'unknown'
      });
    } catch (err: any) {
      return { status: 401, jsonBody: { error: 'token_invalid', message: err?.message } };
    }
  };
}

export type { ClawAuthInstance, MountOptions as ClawAuthFunctionsOptions };
