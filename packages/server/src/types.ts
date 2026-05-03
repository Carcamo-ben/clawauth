/**
 * Public types for clawauth server.
 */

export interface User {
  /** Stable internal user id (uuid/string). */
  id: string;
  /** External provider name (e.g. 'google'). */
  provider: string;
  /** Subject id from the provider (Google `sub`). */
  providerSub: string;
  email: string | null;
  emailVerified: boolean;
  name: string | null;
  picture: string | null;
  createdAt: string; // ISO
  updatedAt: string; // ISO
  /** Free-form metadata that consumers can extend. */
  metadata?: Record<string, unknown>;
}

export interface IdentityClaims {
  sub: string;
  email?: string | null;
  emailVerified?: boolean;
  name?: string | null;
  picture?: string | null;
  /** Raw provider response, kept for debugging / app-specific use. */
  raw?: unknown;
}

export interface IdentityProvider {
  /** Stable name used as the discriminator alongside `sub` (e.g. 'google'). */
  readonly name: string;
  /** Verify a credential (e.g. Google ID token) and return identity claims. */
  verifyToken(token: string): Promise<IdentityClaims>;
}

export interface RefreshTokenRecord {
  /** sha256 hex of the opaque refresh token. */
  tokenHash: string;
  userId: string;
  deviceId?: string | null;
  createdAt: string;
  expiresAt: string;
  /** When rotated, points to its replacement so we can detect token reuse. */
  replacedByHash?: string | null;
  revokedAt?: string | null;
}

export interface IssueRefreshInput {
  userId: string;
  tokenHash: string;
  expiresAt: string;
  deviceId?: string | null;
}

export interface RotateInput {
  oldHash: string;
  newHash: string;
  newExpiresAt: string;
}

export interface Storage {
  getUserBySub(provider: string, sub: string): Promise<User | null>;
  getUserById(id: string): Promise<User | null>;
  upsertUser(user: User): Promise<User>;

  addRefreshToken(input: IssueRefreshInput): Promise<RefreshTokenRecord>;
  /**
   * Atomically validate the old refresh token hash, mark it as rotated,
   * and insert the new one. Throws on reuse / expiry / revocation.
   * Returns the userId associated with the old token.
   */
  validateAndRotateRefreshToken(input: RotateInput): Promise<{ userId: string }>;
  revokeRefreshToken(tokenHash: string): Promise<void>;
  revokeAllRefreshTokensForUser(userId: string): Promise<void>;
}

export interface AccessTokenPayload {
  sub: string; // user id
  email: string | null;
  name: string | null;
  picture: string | null;
  provider: string;
  /** Standard JWT fields are added at sign time. */
  [k: string]: unknown;
}

export interface AuthCoreConfig {
  /** HS256 signing secret. Min 32 bytes recommended. */
  jwtSecret: string;
  /** Issuer claim (`iss`). */
  issuer?: string;
  /** Audience claim (`aud`). */
  audience?: string;
  /** Access token TTL in seconds. Default: 3600 (1h). */
  accessTokenTtl?: number;
  /** Refresh token TTL in seconds. Default: 2592000 (30d). */
  refreshTokenTtl?: number;
  storage: Storage;
  identityProviders: IdentityProvider[];
}

export interface SignInResult {
  user: User;
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: string;
  refreshTokenExpiresAt: string;
}

export interface RefreshResult {
  accessToken: string;
  refreshToken: string;
  accessTokenExpiresAt: string;
  refreshTokenExpiresAt: string;
}
