# @clawauth/server

Server-side core for clawauth. JWT mint/verify (HS256), refresh token rotation with reuse detection, pluggable IdPs and storage.

```ts
import {
  createAuthCore,
  GoogleIdTokenProvider,
  CosmosStorage
} from '@clawauth/server';
import { CosmosClient } from '@azure/cosmos';

const core = createAuthCore({
  jwtSecret: process.env.CLAWAUTH_JWT_SECRET!,
  issuer: 'my-app',
  audience: 'my-app-api',
  accessTokenTtl: 60 * 60,           // 1h
  refreshTokenTtl: 60 * 60 * 24 * 30, // 30d
  storage: new CosmosStorage({
    client: new CosmosClient(process.env.COSMOS_CONN!),
    databaseId: 'myapp'
  }),
  identityProviders: [
    new GoogleIdTokenProvider({ clientId: process.env.GOOGLE_CLIENT_ID! })
  ]
});

const result = await core.handleGoogleSignIn({ idToken });
// → { user, accessToken, refreshToken, *ExpiresAt }
```

See the root README and `examples/azure-functions-cosmos` for an end-to-end deployable app.
