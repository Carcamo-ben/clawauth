import { describe, expect, it } from 'vitest';
import { createAuthCore, sha256Hex } from '../src/core.js';
import { InMemoryStorage } from '../src/storage/memory.js';
import type { IdentityProvider } from '../src/types.js';

class MockProvider implements IdentityProvider {
  readonly name = 'mock';
  async verifyToken(token: string) {
    if (token === 'bad') throw new Error('nope');
    return {
      sub: 'mock-sub-' + token,
      email: `${token}@example.com`,
      emailVerified: true,
      name: 'Test ' + token,
      picture: null
    };
  }
}

function makeCore() {
  return createAuthCore({
    jwtSecret: 'this-is-a-very-long-test-secret-32+chars',
    issuer: 'clawauth-test',
    audience: 'clawauth-test-aud',
    accessTokenTtl: 60,
    refreshTokenTtl: 600,
    storage: new InMemoryStorage(),
    identityProviders: [new MockProvider()]
  });
}

describe('clawauth core', () => {
  it('signs in a new user and issues access+refresh tokens', async () => {
    const core = makeCore();
    const r = await core.handleSignIn({ provider: 'mock', token: 'alice' });
    expect(r.user.email).toBe('alice@example.com');
    expect(r.accessToken).toMatch(/^eyJ/);
    expect(r.refreshToken).toMatch(/^[0-9a-f]{64}$/);
    const claims = await core.verifyAccessToken(r.accessToken);
    expect(claims.sub).toBe(r.user.id);
    expect(claims.email).toBe('alice@example.com');
  });

  it('reuses existing user on subsequent sign-in', async () => {
    const core = makeCore();
    const a = await core.handleSignIn({ provider: 'mock', token: 'bob' });
    const b = await core.handleSignIn({ provider: 'mock', token: 'bob' });
    expect(a.user.id).toBe(b.user.id);
  });

  it('rejects unknown provider', async () => {
    const core = makeCore();
    await expect(core.handleSignIn({ provider: 'nope', token: 'x' })).rejects.toThrow(/Unknown/);
  });

  it('rejects bad IdP token', async () => {
    const core = makeCore();
    await expect(core.handleSignIn({ provider: 'mock', token: 'bad' })).rejects.toThrow(/IdP/);
  });

  it('rotates refresh token', async () => {
    const core = makeCore();
    const r1 = await core.handleSignIn({ provider: 'mock', token: 'carol' });
    const r2 = await core.handleRefresh({ refreshToken: r1.refreshToken });
    expect(r2.refreshToken).not.toBe(r1.refreshToken);
    expect(r2.accessToken).toMatch(/^eyJ/);
  });

  it('detects refresh token reuse and revokes chain', async () => {
    const core = makeCore();
    const r1 = await core.handleSignIn({ provider: 'mock', token: 'dan' });
    await core.handleRefresh({ refreshToken: r1.refreshToken });
    await expect(core.handleRefresh({ refreshToken: r1.refreshToken })).rejects.toThrow(/reuse/);
  });

  it('logout revokes refresh token', async () => {
    const core = makeCore();
    const r = await core.handleSignIn({ provider: 'mock', token: 'eve' });
    await core.handleLogout({ refreshToken: r.refreshToken });
    await expect(core.handleRefresh({ refreshToken: r.refreshToken })).rejects.toThrow(/revoked/);
  });

  it('verifyAccessToken rejects garbage', async () => {
    const core = makeCore();
    await expect(core.verifyAccessToken('not.a.token')).rejects.toThrow();
  });

  it('sha256Hex deterministic', () => {
    expect(sha256Hex('a')).toBe(sha256Hex('a'));
    expect(sha256Hex('a')).not.toBe(sha256Hex('b'));
  });
});
