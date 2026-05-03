# SECURITY.md — clawauth threat model

clawauth is built so consumers don't have to be security experts to ship safely. This doc is the receipt: every claim has a mitigation and (where possible) a test that proves it.

## Scope

This covers `@clawauth/server`, `@clawauth/client`, `@clawauth/azure-functions`, and the example app's deploy script. Out of scope: your IdP's own security posture, your hosting provider, your DNS.

## Trust boundaries

```
[Browser] ─── HTTPS ───▶ [Azure Function: clawauth] ─── TLS ───▶ [Cosmos DB]
                                  │
                                  └─── verify (JWKS) ──▶ [Google IdP]
```

- Browser is **untrusted**. Anything sent from it is suspect.
- Function is **trusted**. Holds JWT signing key + Cosmos credentials.
- Cosmos is **trusted-but-blast-radius-bounded**. Keys come from `az` at deploy time, never live in tfstate.

## Threats and mitigations

| # | Threat | Mitigation | Proof |
|---|--------|------------|-------|
| T1 | **IdP token forgery** (someone fakes a Google ID token) | `GoogleIdTokenProvider` uses google-auth-library which fetches Google JWKS, verifies signature, audience, expiry. We never trust claims without verification. | Unit test rejects invalid tokens (`packages/server/test/core.test.ts: rejects bad IdP token`) |
| T2 | **Refresh-token theft** (attacker steals refresh token, races legit user) | Tokens are opaque 256-bit randoms; we store **sha256 hashes only**. On every use we mark the old token as `replacedByHash`. If a hash is presented twice → reuse detected → **whole chain revoked** for that user. | `core.test.ts: detects refresh token reuse and revokes chain`; `factory.test.ts: full sign-in cycle` |
| T3 | **JWT signing key compromise** | `rotateJwtSecret(newSecret)` swaps the active signer; the old key stays in a verify-only window so live sessions don't drop. Re-deploy with `--rotate-secret` rotates atomically. | `factory.test.ts: rotateJwtSecret keeps old tokens valid until expiry` |
| T4 | **Brute force / credential stuffing** on sign-in | Rate limit: **10/min/IP** sign-in, **60/min/IP** refresh. Limiter is pluggable (default in-memory; Cosmos/Redis stores supported). | `factory.test.ts: rate-limits sign-in` |
| T5 | **Replay** of access tokens beyond TTL | Access TTL **1h**, refresh TTL **30d**. JWTs include `iat`, `exp`, `jti`, optional `iss` + `aud`. `jose.jwtVerify` enforces all. | Built into core; covered by all signin/me tests. |
| T6 | **CSRF** on `/auth/*` endpoints | Endpoints accept ID tokens / opaque refresh tokens in the request **body**, not cookies. The browser SDK uses `localStorage` (not cookies) so there is nothing for a cross-origin form to abuse. CORS on Functions defaults to `*` for the auth API but no ambient credentials are used. | Architectural — no cookie auth surface exists. |
| T7 | **XSS exfiltrating tokens** | We can't stop XSS in your app, but we minimize blast radius: short access TTL (1h), refresh rotation on use, reuse detection (T2), one-call `signOut()` revokes server-side. Consumers get a `clawauth/csp` constant to lock down `script-src`/`frame-src`/`connect-src` to GIS only. | `CSP` exported from `@clawauth/server`; `auth.csp` on the instance. |
| T8 | **User enumeration** via sign-in error timing/messages | Sign-in errors return uniform `{ error: code }` responses. We do not differentiate "user does not exist" from "user exists but token bad" — Google handles both before us. | API design; `factory.test.ts` checks 401 shape. |
| T9 | **Secrets in logs** (operational leak) | `createAuditLogger()` drops a hardcoded set of forbidden keys (`token`, `accessToken`, `refreshToken`, `jwtSecret`, `authorization`, `cookie`, `password`, `secret`) AND any high-entropy string ≥32 chars matching base64/hex. Adapters never serialize the response body to logs. | `factory.test.ts: full sign-in flow: scrub all log lines for any token material` |
| T10 | **Secrets in tfstate** | Function app `app_settings` for `CLAWAUTH_JWT_SECRET`, `GOOGLE_CLIENT_ID`, `COSMOS_CONN` are set **after** `terraform apply` via `az functionapp config appsettings set`, with `lifecycle.ignore_changes` so TF won't re-read them. Cosmos primary keys are fetched at deploy-time via `az`. | `examples/azure-functions-cosmos/infra/main.tf`, `scripts/deploy.mjs` |
| T11 | **Right to be forgotten / GDPR Art. 17** | `auth.deleteUser(userId)` cascades: revokes all refresh tokens, hard-deletes the user document, emits a `user.delete.ok` audit event with `gdpr: true`. | `factory.test.ts: deleteUser cascades and emits gdpr audit` |
| T12 | **Dependency vulnerabilities** | CI runs `npm audit --audit-level=moderate` on every PR. Fails build on new vulns ≥ moderate. | `.github/workflows/ci.yml` |
| T13 | **Privilege escalation via host header / proxy spoof** | We accept `x-forwarded-for` for rate-limit binning only (best-effort). Auth decisions never depend on it. | `packages/azure-functions/src/index.ts` |
| T14 | **Stale tokens after server-side revoke** | Access tokens are stateless JWTs and **stay valid until exp** (max 1h). Refresh side is server-checked on every rotation, so revoke immediately stops new sessions. If you need instant access-token kill, set `accessTokenTtl` lower or add a denylist (planned). | Documented trade-off. |

## Reporting

Please report security issues privately. Open a GitHub Security Advisory on this repo, **do not file a public issue**.

## Audit log schema

Every event is a single line of JSON written to `console.log` (App Insights ingests it as a custom event when running on Azure Functions). Schema:

```json
{
  "ts": "2026-05-03T05:06:37.988Z",   // ISO timestamp
  "component": "clawauth",
  "event": "auth.signin.ok",          // see event catalog below
  "ok": true,                         // boolean outcome
  "ip": "1.2.3.4",                    // best-effort, may be 'unknown'
  "userId": "uuid-...",               // present when known
  "provider": "google",               // present on signin/me events
  "providerSub": "...",               // present on user.delete.* events
  "code": "refresh_reused",           // present on auth.error
  "message": "...",                   // present on auth.error
  "gdpr": true,                       // present on user.delete.ok
  "resetAt": 1714712797990            // present on rate-limited events
}
```

### Event catalog

| event                          | when |
|--------------------------------|------|
| `auth.signin.ok`               | Successful Google sign-in |
| `auth.signin.rate_limited`     | Sign-in IP exceeded 10/min |
| `auth.refresh.ok`              | Successful refresh-token rotation |
| `auth.refresh.rate_limited`    | Refresh IP exceeded 60/min |
| `auth.logout`                  | Logout endpoint hit |
| `auth.jwt_secret.rotated`      | `rotateJwtSecret()` called |
| `auth.error`                   | Any thrown ClawAuthError (with `code` + `message`) |
| `user.delete.ok`               | GDPR cascade succeeded (with `gdpr: true`) |
| `user.delete.miss`             | Delete called for unknown userId |

### What is NEVER logged

- Access tokens
- Refresh tokens (raw or hashed)
- JWT signing secret
- Authorization headers
- Cookies
- Anything matching the `looksLikeSecret` heuristic (≥32 chars, base64/hex pattern)

This is enforced in code (`packages/server/src/audit.ts`) and tested in `factory.test.ts: full sign-in flow: scrub all log lines for any token material`. If that test ever fails, ship is blocked.
