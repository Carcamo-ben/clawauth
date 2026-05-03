import { describe, expect, it } from 'vitest';
import { createClawAuth } from '../src/factory.js';
import { createAuditLogger } from '../src/audit.js';
import type { IdentityProvider } from '../src/types.js';

class MockGoogle implements IdentityProvider {
  readonly name = 'google';
  async verifyToken(token: string) {
    if (token === 'bad') throw new Error('invalid');
    return {
      sub: 'gsub-' + token,
      email: `${token}@example.com`,
      emailVerified: true,
      name: 'Mock ' + token,
      picture: null
    };
  }
}

function makeRequest(method: string, path: string, body?: any, headers: Record<string, string> = {}) {
  return {
    method,
    path,
    headers: {
      get(name: string) {
        return headers[name.toLowerCase()] ?? null;
      }
    },
    json: async () => body ?? {}
  };
}

function makeAuth(extra: Partial<Parameters<typeof createClawAuth>[0]> = {}) {
  const auth = createClawAuth({
    google: undefined,
    extraProviders: [new MockGoogle()],
    dev: true,
    jwtSecret: 'test-secret-please-make-this-very-long-32-chars-min',
    issuer: 'clawauth-test',
    audience: 'clawauth-test-aud',
    ...extra
  });
  return auth;
}

describe('createClawAuth (high-DX factory)', () => {
  it('rejects missing jwtSecret in non-dev mode', () => {
    expect(() =>
      createClawAuth({ google: 'x', cosmos: { connectionString: 'AccountEndpoint=x;', database: 'd' } })
    ).toThrow(/jwtSecret/);
  });

  it('rejects missing IdP', () => {
    expect(() => createClawAuth({ dev: true, jwtSecret: 'x'.repeat(40) })).toThrow(/IdP/);
  });

  it('serves /auth/csp', async () => {
    const auth = makeAuth();
    const res = await auth.handle(makeRequest('GET', '/auth/csp'));
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body)['script-src']).toContain('https://accounts.google.com/gsi/client');
  });

  it('full sign-in → me → refresh → logout cycle over the HTTP shape', async () => {
    const auth = makeAuth();
    const signin = await auth.handle(
      makeRequest('POST', '/auth/google', { idToken: 'alice' }),
      { ip: '1.1.1.1' }
    );
    expect(signin.status).toBe(200);
    const out = JSON.parse(signin.body);
    expect(out.accessToken).toMatch(/^eyJ/);

    const me = await auth.handle(
      makeRequest('GET', '/auth/me', undefined, { authorization: `Bearer ${out.accessToken}` })
    );
    expect(me.status).toBe(200);
    expect(JSON.parse(me.body).user.email).toBe('alice@example.com');

    const refreshed = await auth.handle(
      makeRequest('POST', '/auth/refresh', { refreshToken: out.refreshToken })
    );
    expect(refreshed.status).toBe(200);

    const logout = await auth.handle(
      makeRequest('POST', '/auth/logout', { refreshToken: JSON.parse(refreshed.body).refreshToken })
    );
    expect(logout.status).toBe(200);
  });

  it('rate-limits sign-in', async () => {
    const auth = makeAuth();
    let last = 0;
    for (let i = 0; i < 12; i++) {
      const r = await auth.handle(
        makeRequest('POST', '/auth/google', { idToken: 'spam' }),
        { ip: '9.9.9.9' }
      );
      last = r.status;
    }
    expect(last).toBe(429);
  });

  it('rotateJwtSecret keeps old tokens valid until expiry', async () => {
    const auth = makeAuth();
    const r = await auth.handle(makeRequest('POST', '/auth/google', { idToken: 'rot' }));
    const accessToken = JSON.parse(r.body).accessToken;
    auth.rotateJwtSecret('new-secret-also-very-long-32-chars-min-please-yes');
    const me = await auth.handle(
      makeRequest('GET', '/auth/me', undefined, { authorization: `Bearer ${accessToken}` })
    );
    expect(me.status).toBe(200);
  });

  it('deleteUser cascades and emits gdpr audit', async () => {
    const events: any[] = [];
    const auth = makeAuth({ audit: createAuditLogger({ sink: (l) => events.push(JSON.parse(l)) }) });
    const r = await auth.handle(makeRequest('POST', '/auth/google', { idToken: 'gdpr' }));
    const userId = JSON.parse(r.body).user.id;
    const result = await auth.deleteUser(userId);
    expect(result.deleted).toBe(true);
    expect(events.some((e) => e.event === 'user.delete.ok' && e.gdpr === true)).toBe(true);
    // Refresh token should now fail
    const refresh = await auth.handle(
      makeRequest('POST', '/auth/refresh', { refreshToken: JSON.parse(r.body).refreshToken })
    );
    expect(refresh.status).toBe(401);
  });
});

describe('audit logger never leaks secrets', () => {
  it('drops forbidden keys and high-entropy strings', () => {
    const lines: string[] = [];
    const log = createAuditLogger({ sink: (l) => lines.push(l) });
    log({
      event: 'test',
      ok: true,
      // @ts-expect-error intentional
      accessToken: 'eyJsupersecret.payload.signaturepart.thatislongenough',
      // @ts-expect-error intentional
      refreshToken: 'a'.repeat(64),
      // @ts-expect-error intentional
      jwtSecret: 'b'.repeat(64),
      // @ts-expect-error intentional
      authorization: 'Bearer ' + 'c'.repeat(64),
      userId: 'short-id-ok'
    });
    const out = lines[0];
    expect(out).toContain('"event":"test"');
    expect(out).toContain('"userId":"short-id-ok"');
    expect(out).not.toContain('eyJsupersecret');
    expect(out).not.toContain('aaaaaaaaaa');
    expect(out).not.toContain('bbbbbbbbbb');
    expect(out).not.toContain('Bearer');
  });

  it('full sign-in flow: scrub all log lines for any token material', async () => {
    const lines: string[] = [];
    const auth = makeAuth({ audit: createAuditLogger({ sink: (l) => lines.push(l) }) });
    const r = await auth.handle(makeRequest('POST', '/auth/google', { idToken: 'audit' }));
    const body = JSON.parse(r.body);
    const haystack = lines.join('\n');
    // Hard fail: no access token, refresh token, or JWT signature must appear.
    expect(haystack).not.toContain(body.accessToken);
    expect(haystack).not.toContain(body.refreshToken);
    // JWT signature segment is the last `.`-separated chunk; ensure it's not leaked.
    const sig = body.accessToken.split('.').pop();
    expect(haystack).not.toContain(sig);
  });
});
