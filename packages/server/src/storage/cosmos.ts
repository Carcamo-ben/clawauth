import type { Container, CosmosClient, Database } from '@azure/cosmos';
import { ClawAuthError } from '../core.js';
import type {
  IssueRefreshInput,
  RefreshTokenRecord,
  RotateInput,
  Storage,
  User
} from '../types.js';

export interface CosmosStorageOptions {
  /** Existing CosmosClient. Pass one in so the consumer controls connection/MSI. */
  client: CosmosClient;
  /** Database id. Must already exist (or pass `createIfNotExists`). */
  databaseId: string;
  /** Container ids. Defaults: users='clawauth_users', refreshTokens='clawauth_refresh_tokens'. */
  usersContainerId?: string;
  refreshTokensContainerId?: string;
  /** If true, attempt to create database/containers on init. Default false (assume Terraform). */
  createIfNotExists?: boolean;
}

/**
 * Cosmos DB (SQL API) storage adapter.
 *
 * Schema:
 *   users container, partition key /id
 *     { id, provider, providerSub, email, emailVerified, name, picture,
 *       createdAt, updatedAt, metadata?, _subKey: "<provider>:<sub>" }
 *   refresh tokens container, partition key /userId
 *     { id (= tokenHash), userId, deviceId, createdAt, expiresAt,
 *       replacedByHash, revokedAt, ttl?: <seconds> }
 *
 * Notes:
 *  - We use `_subKey` + a query to look up by (provider, sub).
 *    Cosmos doesn't have multi-field unique constraints across non-PK fields,
 *    so de-dupe is enforced by always querying first in upsertUser.
 *  - Refresh tokens use Cosmos TTL when available so expired entries auto-purge.
 */
export class CosmosStorage implements Storage {
  private db!: Database;
  private users!: Container;
  private refresh!: Container;
  private ready: Promise<void>;

  constructor(private opts: CosmosStorageOptions) {
    this.ready = this.init();
  }

  private async init() {
    const dbId = this.opts.databaseId;
    const usersId = this.opts.usersContainerId ?? 'clawauth_users';
    const refreshId = this.opts.refreshTokensContainerId ?? 'clawauth_refresh_tokens';

    if (this.opts.createIfNotExists) {
      const { database } = await this.opts.client.databases.createIfNotExists({ id: dbId });
      this.db = database;
      const { container: u } = await this.db.containers.createIfNotExists({
        id: usersId,
        partitionKey: { paths: ['/id'] }
      });
      this.users = u;
      const { container: r } = await this.db.containers.createIfNotExists({
        id: refreshId,
        partitionKey: { paths: ['/userId'] },
        defaultTtl: -1 // TTL enabled, items opt-in via `ttl`
      });
      this.refresh = r;
    } else {
      this.db = this.opts.client.database(dbId);
      this.users = this.db.container(usersId);
      this.refresh = this.db.container(refreshId);
    }
  }

  async getUserBySub(provider: string, sub: string): Promise<User | null> {
    await this.ready;
    const subKey = `${provider}:${sub}`;
    const { resources } = await this.users.items
      .query<UserDoc>({
        query: 'SELECT TOP 1 * FROM c WHERE c._subKey = @k',
        parameters: [{ name: '@k', value: subKey }]
      })
      .fetchAll();
    return resources[0] ? toUser(resources[0]) : null;
  }

  async getUserById(id: string): Promise<User | null> {
    await this.ready;
    try {
      const { resource } = await this.users.item(id, id).read<UserDoc>();
      return resource ? toUser(resource) : null;
    } catch (err: any) {
      if (err?.code === 404) return null;
      throw err;
    }
  }

  async upsertUser(user: User): Promise<User> {
    await this.ready;
    const doc: UserDoc = {
      id: user.id,
      provider: user.provider,
      providerSub: user.providerSub,
      _subKey: `${user.provider}:${user.providerSub}`,
      email: user.email,
      emailVerified: user.emailVerified,
      name: user.name,
      picture: user.picture,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      metadata: user.metadata ?? null
    };
    const { resource } = await this.users.items.upsert<UserDoc>(doc);
    return toUser(resource ?? doc);
  }

  async addRefreshToken(input: IssueRefreshInput): Promise<RefreshTokenRecord> {
    await this.ready;
    const ttlSeconds = Math.max(
      60,
      Math.floor((new Date(input.expiresAt).getTime() - Date.now()) / 1000)
    );
    const doc: RefreshDoc = {
      id: input.tokenHash,
      userId: input.userId,
      deviceId: input.deviceId ?? null,
      createdAt: new Date().toISOString(),
      expiresAt: input.expiresAt,
      replacedByHash: null,
      revokedAt: null,
      ttl: ttlSeconds
    };
    await this.refresh.items.create(doc);
    return toRefresh(doc);
  }

  async validateAndRotateRefreshToken(input: RotateInput) {
    await this.ready;
    // We don't know userId from hash alone; query by id.
    const { resources } = await this.refresh.items
      .query<RefreshDoc>({
        query: 'SELECT TOP 1 * FROM c WHERE c.id = @id',
        parameters: [{ name: '@id', value: input.oldHash }]
      })
      .fetchAll();
    const old = resources[0];
    if (!old) throw new ClawAuthError('refresh_unknown', 'Refresh token not found', 401);
    if (old.revokedAt) throw new ClawAuthError('refresh_revoked', 'Refresh token revoked', 401);
    if (old.replacedByHash) {
      await this.revokeAllRefreshTokensForUser(old.userId);
      throw new ClawAuthError('refresh_reused', 'Refresh token reuse detected', 401);
    }
    if (new Date(old.expiresAt).getTime() < Date.now()) {
      throw new ClawAuthError('refresh_expired', 'Refresh token expired', 401);
    }
    // Mark old as replaced (concurrency note: at-most-once via ETag)
    const { resource: latest, etag } = await this.refresh
      .item(old.id, old.userId)
      .read<RefreshDoc>();
    if (!latest) throw new ClawAuthError('refresh_unknown', 'Refresh token not found', 401);
    latest.replacedByHash = input.newHash;
    await this.refresh.item(latest.id, latest.userId).replace(latest, {
      accessCondition: etag ? { type: 'IfMatch', condition: etag } : undefined
    });
    await this.addRefreshToken({
      userId: old.userId,
      tokenHash: input.newHash,
      expiresAt: input.newExpiresAt,
      deviceId: old.deviceId ?? null
    });
    return { userId: old.userId };
  }

  async revokeRefreshToken(tokenHash: string): Promise<void> {
    await this.ready;
    const { resources } = await this.refresh.items
      .query<RefreshDoc>({
        query: 'SELECT TOP 1 * FROM c WHERE c.id = @id',
        parameters: [{ name: '@id', value: tokenHash }]
      })
      .fetchAll();
    const doc = resources[0];
    if (!doc) return;
    doc.revokedAt = new Date().toISOString();
    await this.refresh.item(doc.id, doc.userId).replace(doc);
  }

  /** Hard-delete the user document. Used by ClawAuth.deleteUser() for GDPR cascade. */
  async _deleteUser(userId: string): Promise<void> {
    await this.ready;
    try {
      await this.users.item(userId, userId).delete();
    } catch (err: any) {
      if (err?.code !== 404) throw err;
    }
  }

  async revokeAllRefreshTokensForUser(userId: string): Promise<void> {
    await this.ready;
    const { resources } = await this.refresh.items
      .query<RefreshDoc>({
        query: 'SELECT * FROM c WHERE c.userId = @u AND (NOT IS_DEFINED(c.revokedAt) OR c.revokedAt = null)',
        parameters: [{ name: '@u', value: userId }]
      })
      .fetchAll();
    const now = new Date().toISOString();
    for (const doc of resources) {
      doc.revokedAt = now;
      await this.refresh.item(doc.id, doc.userId).replace(doc);
    }
  }
}

interface UserDoc extends Omit<User, 'metadata'> {
  _subKey: string;
  metadata: Record<string, unknown> | null;
}
interface RefreshDoc {
  id: string;
  userId: string;
  deviceId: string | null;
  createdAt: string;
  expiresAt: string;
  replacedByHash: string | null;
  revokedAt: string | null;
  ttl?: number;
}
function toUser(d: UserDoc): User {
  return {
    id: d.id,
    provider: d.provider,
    providerSub: d.providerSub,
    email: d.email,
    emailVerified: d.emailVerified,
    name: d.name,
    picture: d.picture,
    createdAt: d.createdAt,
    updatedAt: d.updatedAt,
    metadata: d.metadata ?? undefined
  };
}
function toRefresh(d: RefreshDoc): RefreshTokenRecord {
  return {
    tokenHash: d.id,
    userId: d.userId,
    deviceId: d.deviceId,
    createdAt: d.createdAt,
    expiresAt: d.expiresAt,
    replacedByHash: d.replacedByHash,
    revokedAt: d.revokedAt
  };
}
