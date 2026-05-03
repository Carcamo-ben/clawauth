import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import type {
  AccessTokenPayload,
  AuthCoreConfig,
  IdentityProvider,
  RefreshResult,
  SignInResult,
  Storage,
  User
} from './types.js';

const DEFAULT_ACCESS_TTL = 60 * 60; // 1h
const DEFAULT_REFRESH_TTL = 60 * 60 * 24 * 30; // 30d

export class ClawAuthError extends Error {
  status: number;
  code: string;
  constructor(code: string, message: string, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
    this.name = 'ClawAuthError';
  }
}

export interface AuthCore {
  /** Exchange an IdP token (e.g. Google ID token) for clawauth access+refresh tokens. */
  handleSignIn(input: { provider: string; token: string; deviceId?: string }): Promise<SignInResult>;
  /** Convenience wrapper: handleSignIn with provider='google'. */
  handleGoogleSignIn(input: { idToken: string; deviceId?: string }): Promise<SignInResult>;
  /** Rotate refresh token, return new pair. */
  handleRefresh(input: { refreshToken: string; deviceId?: string }): Promise<RefreshResult>;
  /** Revoke a refresh token. */
  handleLogout(input: { refreshToken: string }): Promise<void>;
  /** Verify an access token. Throws ClawAuthError on failure. */
  verifyAccessToken(token: string): Promise<AccessTokenPayload>;
  /** Generic middleware factory (framework-agnostic). */
  middleware(): (token: string | null) => Promise<AccessTokenPayload>;
  readonly config: Required<Omit<AuthCoreConfig, 'storage' | 'identityProviders' | 'issuer' | 'audience'>> & {
    issuer?: string;
    audience?: string;
    storage: Storage;
    identityProviders: IdentityProvider[];
  };
}

export function createAuthCore(cfg: AuthCoreConfig): AuthCore {
  if (!cfg.jwtSecret || cfg.jwtSecret.length < 16) {
    throw new ClawAuthError('config_invalid', 'jwtSecret missing or too short (min 16 chars; 32+ recommended)', 500);
  }
  const accessTokenTtl = cfg.accessTokenTtl ?? DEFAULT_ACCESS_TTL;
  const refreshTokenTtl = cfg.refreshTokenTtl ?? DEFAULT_REFRESH_TTL;
  const secretKey = new TextEncoder().encode(cfg.jwtSecret);
  const providers = new Map<string, IdentityProvider>();
  for (const p of cfg.identityProviders) providers.set(p.name, p);

  async function signAccessToken(user: User): Promise<{ token: string; expiresAt: string }> {
    const now = Math.floor(Date.now() / 1000);
    const exp = now + accessTokenTtl;
    const jwt = new SignJWT({
      email: user.email,
      name: user.name,
      picture: user.picture,
      provider: user.provider
    })
      .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
      .setSubject(user.id)
      .setIssuedAt(now)
      .setExpirationTime(exp)
      .setJti(randomUUID());
    if (cfg.issuer) jwt.setIssuer(cfg.issuer);
    if (cfg.audience) jwt.setAudience(cfg.audience);
    const token = await jwt.sign(secretKey);
    return { token, expiresAt: new Date(exp * 1000).toISOString() };
  }

  function mintRefreshToken(): { token: string; hash: string; expiresAt: string } {
    const token = randomBytes(32).toString('hex');
    const hash = sha256Hex(token);
    const expiresAt = new Date(Date.now() + refreshTokenTtl * 1000).toISOString();
    return { token, hash, expiresAt };
  }

  async function verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    try {
      const { payload } = await jwtVerify(token, secretKey, {
        issuer: cfg.issuer,
        audience: cfg.audience
      });
      return payload as AccessTokenPayload;
    } catch (err) {
      throw new ClawAuthError('token_invalid', `Access token invalid: ${(err as Error).message}`, 401);
    }
  }

  return {
    config: {
      jwtSecret: cfg.jwtSecret,
      accessTokenTtl,
      refreshTokenTtl,
      issuer: cfg.issuer,
      audience: cfg.audience,
      storage: cfg.storage,
      identityProviders: cfg.identityProviders
    },

    async handleSignIn({ provider, token, deviceId }) {
      const idp = providers.get(provider);
      if (!idp) throw new ClawAuthError('provider_unknown', `Unknown identity provider: ${provider}`, 400);
      const claims = await idp.verifyToken(token).catch((err) => {
        throw new ClawAuthError('idp_verify_failed', `IdP verify failed: ${err.message}`, 401);
      });
      if (!claims.sub) throw new ClawAuthError('idp_no_sub', 'IdP returned no subject', 401);

      const now = new Date().toISOString();
      let user = await cfg.storage.getUserBySub(provider, claims.sub);
      if (!user) {
        user = await cfg.storage.upsertUser({
          id: randomUUID(),
          provider,
          providerSub: claims.sub,
          email: claims.email ?? null,
          emailVerified: claims.emailVerified ?? false,
          name: claims.name ?? null,
          picture: claims.picture ?? null,
          createdAt: now,
          updatedAt: now
        });
      } else {
        // Refresh profile if changed.
        const next: User = {
          ...user,
          email: claims.email ?? user.email,
          emailVerified: claims.emailVerified ?? user.emailVerified,
          name: claims.name ?? user.name,
          picture: claims.picture ?? user.picture,
          updatedAt: now
        };
        user = await cfg.storage.upsertUser(next);
      }

      const access = await signAccessToken(user);
      const refresh = mintRefreshToken();
      await cfg.storage.addRefreshToken({
        userId: user.id,
        tokenHash: refresh.hash,
        expiresAt: refresh.expiresAt,
        deviceId: deviceId ?? null
      });

      return {
        user,
        accessToken: access.token,
        refreshToken: refresh.token,
        accessTokenExpiresAt: access.expiresAt,
        refreshTokenExpiresAt: refresh.expiresAt
      };
    },

    async handleGoogleSignIn({ idToken, deviceId }) {
      return this.handleSignIn({ provider: 'google', token: idToken, deviceId });
    },

    async handleRefresh({ refreshToken }) {
      const oldHash = sha256Hex(refreshToken);
      const refresh = mintRefreshToken();
      const { userId } = await cfg.storage
        .validateAndRotateRefreshToken({
          oldHash,
          newHash: refresh.hash,
          newExpiresAt: refresh.expiresAt
        })
        .catch((err) => {
          if (err instanceof ClawAuthError) throw err;
          throw new ClawAuthError('refresh_invalid', `Refresh token invalid: ${err.message}`, 401);
        });

      const user = await cfg.storage.getUserById(userId);
      if (!user) throw new ClawAuthError('user_missing', 'User no longer exists', 401);
      const access = await signAccessToken(user);
      return {
        accessToken: access.token,
        refreshToken: refresh.token,
        accessTokenExpiresAt: access.expiresAt,
        refreshTokenExpiresAt: refresh.expiresAt
      };
    },

    async handleLogout({ refreshToken }) {
      if (!refreshToken) return;
      const hash = sha256Hex(refreshToken);
      await cfg.storage.revokeRefreshToken(hash).catch(() => {
        /* swallow — logout should be idempotent */
      });
    },

    verifyAccessToken,

    middleware() {
      return async (token) => {
        if (!token) throw new ClawAuthError('token_missing', 'No bearer token provided', 401);
        return verifyAccessToken(token);
      };
    }
  };
}

export function sha256Hex(input: string): string {
  return createHash('sha256').update(input).digest('hex');
}
