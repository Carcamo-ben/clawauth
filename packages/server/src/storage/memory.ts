import { ClawAuthError } from '../core.js';
import type {
  IssueRefreshInput,
  RefreshTokenRecord,
  RotateInput,
  Storage,
  User
} from '../types.js';

/** In-memory storage for tests / local dev. Not for production. */
export class InMemoryStorage implements Storage {
  users = new Map<string, User>();
  bySub = new Map<string, string>(); // `${provider}:${sub}` → userId
  refresh = new Map<string, RefreshTokenRecord>();

  async getUserBySub(provider: string, sub: string) {
    const id = this.bySub.get(`${provider}:${sub}`);
    return id ? this.users.get(id) ?? null : null;
  }

  async getUserById(id: string) {
    return this.users.get(id) ?? null;
  }

  async upsertUser(user: User) {
    this.users.set(user.id, user);
    this.bySub.set(`${user.provider}:${user.providerSub}`, user.id);
    return user;
  }

  async addRefreshToken(input: IssueRefreshInput) {
    const rec: RefreshTokenRecord = {
      tokenHash: input.tokenHash,
      userId: input.userId,
      deviceId: input.deviceId ?? null,
      createdAt: new Date().toISOString(),
      expiresAt: input.expiresAt,
      replacedByHash: null,
      revokedAt: null
    };
    this.refresh.set(input.tokenHash, rec);
    return rec;
  }

  async validateAndRotateRefreshToken(input: RotateInput) {
    const old = this.refresh.get(input.oldHash);
    if (!old) throw new ClawAuthError('refresh_unknown', 'Refresh token not found', 401);
    if (old.revokedAt) throw new ClawAuthError('refresh_revoked', 'Refresh token revoked', 401);
    if (old.replacedByHash) {
      // Reuse detected — kill the whole chain for this user.
      await this.revokeAllRefreshTokensForUser(old.userId);
      throw new ClawAuthError('refresh_reused', 'Refresh token reuse detected', 401);
    }
    if (new Date(old.expiresAt).getTime() < Date.now()) {
      throw new ClawAuthError('refresh_expired', 'Refresh token expired', 401);
    }
    old.replacedByHash = input.newHash;
    this.refresh.set(input.oldHash, old);
    await this.addRefreshToken({
      userId: old.userId,
      tokenHash: input.newHash,
      expiresAt: input.newExpiresAt,
      deviceId: old.deviceId ?? null
    });
    return { userId: old.userId };
  }

  async revokeRefreshToken(tokenHash: string) {
    const r = this.refresh.get(tokenHash);
    if (r) {
      r.revokedAt = new Date().toISOString();
      this.refresh.set(tokenHash, r);
    }
  }

  async _deleteUser(userId: string) {
    const u = this.users.get(userId);
    if (u) {
      this.bySub.delete(`${u.provider}:${u.providerSub}`);
      this.users.delete(userId);
    }
  }

  async revokeAllRefreshTokensForUser(userId: string) {
    const now = new Date().toISOString();
    for (const r of this.refresh.values()) {
      if (r.userId === userId && !r.revokedAt) {
        r.revokedAt = now;
      }
    }
  }
}
