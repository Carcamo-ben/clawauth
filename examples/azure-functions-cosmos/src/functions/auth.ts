import { mountClawAuth, requireUser } from '@clawauth/azure-functions';
import { app } from '@azure/functions';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

// ──────────────────────────────────────────────────────────────────────────
// THE 3-LINE MOUNT. This is everything you need for sign-in.
// ──────────────────────────────────────────────────────────────────────────
const config = JSON.parse(
  readFileSync(resolve(dirname(fileURLToPath(import.meta.url)), '../../clawauth.config.json'), 'utf8')
);

const auth = mountClawAuth({
  google: process.env.GOOGLE_CLIENT_ID || config.googleClientId,
  cosmos: { connectionString: process.env.COSMOS_CONN!, database: 'clawauthdemo', createIfNotExists: true }
});

// Example protected route. Not part of clawauth — just shows how YOUR app uses it.
app.http('profile', {
  methods: ['GET'],
  authLevel: 'anonymous',
  route: 'profile',
  handler: requireUser(auth, async (_req, _ctx, user) => ({
    status: 200,
    jsonBody: { msg: `Hello ${user.name ?? user.email ?? user.sub}!`, user }
  }))
});
