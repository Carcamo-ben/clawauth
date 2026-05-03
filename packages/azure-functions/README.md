# @clawauth/azure-functions

Azure Functions v4 adapter. Mount in 3 lines:

```ts
// src/functions/auth.ts
import { mountClawAuth } from '@clawauth/azure-functions';
mountClawAuth({
  google: process.env.GOOGLE_CLIENT_ID!,
  cosmos: { connectionString: process.env.COSMOS_CONN!, database: 'myapp' }
});
```

Routes registered automatically:

| Method | Path                | Purpose                               |
|--------|---------------------|---------------------------------------|
| POST   | /api/auth/google    | Exchange Google ID token for session  |
| POST   | /api/auth/refresh   | Rotate refresh token                  |
| POST   | /api/auth/logout    | Revoke refresh token                  |
| GET    | /api/auth/me        | Verify bearer, return user claims     |
| GET    | /api/auth/csp       | CSP fragment for the GIS popup        |

To protect your own routes:

```ts
import { app } from '@azure/functions';
import { requireUser } from '@clawauth/azure-functions';
app.http('profile', {
  methods: ['GET'], route: 'profile',
  handler: requireUser(auth, async (req, ctx, user) => ({ status: 200, jsonBody: { user } }))
});
```
