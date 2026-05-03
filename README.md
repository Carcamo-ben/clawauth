# 🦞 clawauth

**Self-hosted social auth for Azure Functions + Cosmos.** Escape Microsoft External ID. Paste a Google client ID, ship sign-in.

![CI](https://github.com/Carcamo-ben/clawauth/actions/workflows/ci.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Why

If you've fought Azure External ID's CIAM custom domains, IdP MFA dance, or the joy of `endpoints_resolution_error`, you know. clawauth gives you the bits you actually need — Google sign-in, JWTs, refresh rotation, Cosmos persistence — in three packages that mount in a few lines.

**Hardcoded secure defaults. Zero security knobs to think about.**

- Access token TTL: 1h
- Refresh token TTL: 30d, rotated on every use, reuse-detection revokes the chain
- Rate limit: 10/min/IP sign-in, 60/min/IP refresh
- Audit log: structured JSON to App Insights, secret-redacted (tested)
- Storage: Cosmos DB (SQL API), serverless free tier in the example

See **[SECURITY.md](SECURITY.md)** for the full threat model and proof.

## Quickstart (5 minutes)

1. **Get a Google OAuth Client ID** at [console.cloud.google.com → Credentials](https://console.cloud.google.com/apis/credentials). Type: **Web application**. Authorized JS origins: `http://localhost:8080` (and your prod URL once you have it). No client secret needed.
2. **Install:**
   ```bash
   gh repo clone Carcamo-ben/clawauth && cd clawauth/examples/azure-functions-cosmos
   npm install
   ```
3. **Paste** your client ID into `clawauth.config.json` (`googleClientId`).
4. **Function code (3 lines):**
   ```ts
   import { mountClawAuth } from '@clawauth/azure-functions';
   mountClawAuth({ google: process.env.GOOGLE_CLIENT_ID!, cosmos: { connectionString: process.env.COSMOS_CONN!, database: 'myapp' } });
   ```
5. **SPA code (3 lines):**
   ```ts
   import { createClawAuthClient } from '@clawauth/client';
   const auth = createClawAuthClient({ googleClientId: 'YOUR_ID.apps.googleusercontent.com' });
   document.getElementById('signin').onclick = () => auth.signInWithGoogle();
   ```
6. **Ship:**
   ```bash
   npm run dev      # local on http://localhost:8080
   az login
   npm run deploy   # one-shot Azure deploy → prints live URL
   ```

That's it.

## What `npm run deploy` does

`az login` is your only prerequisite. The script then:

1. `terraform apply` provisions a fresh RG + Cosmos (serverless free tier) + Linux Function App + storage + App Insights
2. Generates `CLAWAUTH_JWT_SECRET` (96 hex chars, `crypto.randomBytes`) — set as Function app setting, **never written to tfstate**
3. Sets `GOOGLE_CLIENT_ID` + `COSMOS_CONN` (Cosmos key fetched at deploy time via `az`, never logged)
4. `func azure functionapp publish`
5. Prints `https://func-xxxxxx.azurewebsites.net`

Re-run is idempotent. `npm run deploy -- --rotate-secret` rotates the JWT signing key.

## Packages

| Package | Purpose | Lines of code you write |
|---|---|---|
| [`@clawauth/server`](packages/server) | Core: JWT, refresh rotation, IdP + storage interfaces | (used via the others) |
| [`@clawauth/azure-functions`](packages/azure-functions) | Mount HTTP routes on Azure Functions v4 | **3** |
| [`@clawauth/client`](packages/client) | Browser SDK: lazy-loads GIS, popup, token storage, auto-refresh | **3** |

Express/Fastify/Bun adapters: contributions welcome — they're trivial wrappers around `auth.handle(req)`.

## Provider status

| Provider | Status |
|---|---|
| Google | ✅ shipped |
| Apple | 🚧 stub (PRs welcome — see `packages/server/src/providers/apple.ts`) |
| Meta  | 🚧 stub |
| TikTok | 🚧 stub |

## Compliance

- **GDPR Art. 17** — `auth.deleteUser(userId)` cascades user doc + all refresh tokens + audit emit (`gdpr: true`). Tested.
- **Audit log** — structured JSON, secret-redacted by allowlist + entropy heuristic. Tested.
- **Key rotation** — `auth.rotateJwtSecret(newSecret)` keeps live sessions valid via dual-key verify window. Tested.
- **Dependency hygiene** — CI fails on `npm audit --audit-level=moderate`.

## License

MIT — see [LICENSE](LICENSE).

Built with claws by [Santa Claws](https://github.com/Carcamo-ben). 🦞🎄
