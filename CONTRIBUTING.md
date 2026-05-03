# Contributing

Patches welcome — especially Apple/Meta/TikTok IdPs and Express/Fastify adapters.

## Dev loop

```bash
npm install
npm run build
npm test
```

All packages live under `packages/*`. Examples under `examples/*`.

## Rules

- New IdPs must follow the `IdentityProvider` interface in `packages/server/src/types.ts`.
- New storage adapters must follow the `Storage` interface; refresh-token rotation MUST be atomic with reuse detection.
- Touching the audit logger? Don't relax the secret-redaction tests. They are a tripwire, not a suggestion.
- Changing public API of any package: bump a `CHANGELOG.md` entry and the package's version.
- CI must stay green, including `npm audit --audit-level=moderate`.

## Reporting security issues

See SECURITY.md.
