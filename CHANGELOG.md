# Changelog

## 0.1.0 — 2026-05-03

Initial release.

- `@clawauth/server` — core: JWT (HS256) + refresh rotation with reuse detection, audit logger, rate limiter, Cosmos + in-memory storage, Google IdP. Apple/Meta/TikTok stubs.
- `@clawauth/client` — browser SDK with lazy GIS load, auto-refresh, fetch wrapper.
- `@clawauth/azure-functions` — v4 adapter, `mountClawAuth()` registers all 5 auth routes in one call. `requireUser()` middleware.
- `examples/azure-functions-cosmos` — paste-your-Google-client-ID example with `npm run dev` + one-shot `npm run deploy` (Terraform + zip-deploy).
- `SECURITY.md` threat model with mitigations and tests cited per row.
- CI: build + test + `npm audit --audit-level=moderate` gate + secret-leak guardrail check.
