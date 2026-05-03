#!/usr/bin/env node
/**
 * Local dev launcher.
 *
 *   node scripts/dev.mjs
 *
 * Builds TS, starts a static file server for /public on :8080 (also serves
 * the built @clawauth/client bundle), then `func start` for the API on :7071.
 * Sets up CLAWAUTH_JWT_SECRET in-memory and uses dev:false (real Cosmos)
 * if COSMOS_CONN is in local.settings.json — otherwise falls back to
 * dev mode with in-memory storage.
 */
import { spawn } from 'node:child_process';
import { copyFileSync, existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const cfgPath = resolve(root, 'clawauth.config.json');
if (!existsSync(cfgPath)) {
  console.error('❌ clawauth.config.json missing. Copy clawauth.config.json.example.');
  process.exit(1);
}
const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
if (!cfg.googleClientId || cfg.googleClientId.startsWith('PASTE_')) {
  console.error('❌ googleClientId is unset in clawauth.config.json.');
  console.error('   1. https://console.cloud.google.com/apis/credentials → Create OAuth Client ID');
  console.error('   2. Authorized JS origins: http://localhost:8080');
  console.error('   3. Paste the Client ID into clawauth.config.json');
  process.exit(1);
}

// Ensure local.settings.json exists.
const localSettings = resolve(root, 'local.settings.json');
if (!existsSync(localSettings)) {
  copyFileSync(resolve(root, 'local.settings.json.example'), localSettings);
}
// Patch in dev secrets without persisting to disk.
const devEnv = {
  ...process.env,
  CLAWAUTH_JWT_SECRET: process.env.CLAWAUTH_JWT_SECRET ?? randomBytes(48).toString('hex'),
  GOOGLE_CLIENT_ID: cfg.googleClientId,
  COSMOS_CONN: process.env.COSMOS_CONN ?? '__DEV__'
};

// Make the @clawauth/client bundle reachable from the static server.
const clientDist = resolve(root, '../../packages/client/dist/index.js');
if (!existsSync(clientDist)) {
  console.error('❌ @clawauth/client not built. Run `npm run build -w @clawauth/client` from repo root.');
  process.exit(1);
}
mkdirSync(resolve(root, 'public'), { recursive: true });
copyFileSync(clientDist, resolve(root, 'public/clawauth-client.mjs'));
copyFileSync(cfgPath, resolve(root, 'public/clawauth.config.json'));

// Static server on :8080 with /api → :7071 proxy.
const PUBLIC = resolve(root, 'public');
const server = createServer(async (req, res) => {
  if (req.url?.startsWith('/api/')) {
    // Proxy to Functions host.
    const target = `http://localhost:7071${req.url}`;
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks);
    try {
      const upstream = await fetch(target, {
        method: req.method,
        headers: Object.fromEntries(Object.entries(req.headers).filter(([, v]) => typeof v === 'string')),
        body: ['GET', 'HEAD'].includes(req.method ?? '') ? undefined : body
      });
      res.statusCode = upstream.status;
      upstream.headers.forEach((v, k) => res.setHeader(k, v));
      const buf = Buffer.from(await upstream.arrayBuffer());
      res.end(buf);
    } catch (err) {
      res.statusCode = 502;
      res.end('proxy error: ' + err.message);
    }
    return;
  }
  // Static.
  const url = req.url === '/' ? '/index.html' : req.url ?? '/';
  const filePath = resolve(PUBLIC, '.' + url);
  if (!filePath.startsWith(PUBLIC)) {
    res.statusCode = 403;
    return res.end('forbidden');
  }
  if (!existsSync(filePath)) {
    res.statusCode = 404;
    return res.end('not found');
  }
  const ext = filePath.split('.').pop();
  const ct =
    ext === 'html' ? 'text/html' :
    ext === 'mjs' || ext === 'js' ? 'application/javascript' :
    ext === 'json' ? 'application/json' : 'application/octet-stream';
  res.setHeader('content-type', ct);
  res.end(readFileSync(filePath));
});
server.listen(8080, () => console.log('🦞 static + proxy on http://localhost:8080'));

// Start Functions host.
console.log('Starting Azure Functions on http://localhost:7071 ...');
console.log('Make sure Azure Functions Core Tools v4 is installed: https://aka.ms/azfunc-install');
const buildFirst = spawn(process.platform === 'win32' ? 'npm.cmd' : 'npm', ['run', 'build'], {
  cwd: root,
  stdio: 'inherit'
});
buildFirst.on('exit', (code) => {
  if (code !== 0) {
    console.error('build failed');
    process.exit(code);
  }
  const fn = spawn(process.platform === 'win32' ? 'func.cmd' : 'func', ['start', '--javascript'], {
    cwd: root,
    env: devEnv,
    stdio: 'inherit'
  });
  fn.on('exit', (c) => process.exit(c ?? 0));
});
