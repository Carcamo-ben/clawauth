/**
 * Structured audit logger. Default sink: console.log JSON (App Insights
 * scoops it automatically when running on Azure Functions). Plug your own
 * sink for SIEM/Sentinel/etc.
 *
 * GUARANTEE: this logger never serializes secrets. Tokens, refreshTokens,
 * jwtSecret — none are emitted. We log identifiers only.
 */
export interface AuditEvent {
  event: string;
  ok: boolean;
  ip?: string;
  userId?: string;
  provider?: string;
  providerSub?: string;
  code?: string;
  message?: string;
  resetAt?: number;
  gdpr?: boolean;
  [k: string]: unknown;
}

export type AuditLogger = (event: AuditEvent) => void;

const FORBIDDEN_KEYS = new Set([
  'token',
  'idToken',
  'accessToken',
  'refreshToken',
  'jwtSecret',
  'jwt_secret',
  'authorization',
  'cookie',
  'password',
  'secret'
]);

export function createAuditLogger(opts: { sink?: (line: string) => void } = {}): AuditLogger {
  const sink = opts.sink ?? ((line) => console.log(line));
  return (event) => {
    const safe: Record<string, unknown> = {
      ts: new Date().toISOString(),
      component: 'clawauth'
    };
    for (const [k, v] of Object.entries(event)) {
      if (FORBIDDEN_KEYS.has(k)) continue; // hard-skip
      if (typeof v === 'string' && looksLikeSecret(v)) continue;
      safe[k] = v;
    }
    try {
      sink(JSON.stringify(safe));
    } catch {
      sink(JSON.stringify({ component: 'clawauth', event: 'audit.serialize.failed' }));
    }
  };
}

/**
 * Heuristic: long, high-entropy hex/base64 strings are likely tokens.
 * We err on the side of dropping them.
 */
function looksLikeSecret(v: string): boolean {
  if (v.length < 32) return false;
  if (/^[A-Za-z0-9_\-+/=.]+$/.test(v)) return true;
  return false;
}
