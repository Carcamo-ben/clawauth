#!/usr/bin/env node
/**
 * One-shot Azure deploy.
 *
 *   az login   # only requirement
 *   node scripts/deploy.mjs
 *
 * Steps:
 *   1. Verify az login + gather subscription
 *   2. Read clawauth.config.json (require googleClientId)
 *   3. terraform init/apply in infra/ → provisions RG + Cosmos + Function app + storage + App Insights
 *   4. Generate CLAWAUTH_JWT_SECRET (48 random bytes) — set as Function app setting
 *   5. Set GOOGLE_CLIENT_ID + COSMOS_CONN app settings (Cosmos primary key from `az`, never tfstate)
 *   6. Build + zip-deploy Function app (func azure functionapp publish)
 *   7. Print URLs
 *
 * Idempotent: re-run rotates the JWT secret only if `--rotate-secret` is passed.
 */
import { execSync, spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const INFRA = resolve(ROOT, 'infra');
const cfgPath = resolve(ROOT, 'clawauth.config.json');
const ROTATE = process.argv.includes('--rotate-secret');

function step(n, msg) { console.log(`\n[${n}] ${msg}`); }
function run(cmd, opts = {}) {
  console.log('  $', cmd);
  return execSync(cmd, { stdio: 'inherit', ...opts });
}
function out(cmd, opts = {}) {
  return execSync(cmd, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts }).trim();
}

// ─── Step 1 ────────────────────────────────────────────────────────────
step(1, 'Verifying az login...');
let sub;
try {
  sub = JSON.parse(out('az account show -o json'));
  console.log(`  ✓ subscription: ${sub.name} (${sub.id})`);
} catch {
  console.error('❌ Not logged in. Run: az login');
  process.exit(1);
}

// ─── Step 2 ────────────────────────────────────────────────────────────
step(2, 'Reading clawauth.config.json...');
if (!existsSync(cfgPath)) {
  console.error('❌ clawauth.config.json missing.');
  process.exit(1);
}
const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
if (!cfg.googleClientId || cfg.googleClientId.startsWith('PASTE_')) {
  console.error('❌ Set googleClientId in clawauth.config.json (console.cloud.google.com → Credentials → Web app).');
  process.exit(1);
}
const az = cfg.azure ?? {};
const rg = az.resourceGroup ?? 'rg-clawauth-demo';
const location = az.location ?? 'canadacentral';
const namePrefix = az.namePrefix ?? 'clawauth';
console.log(`  ✓ rg=${rg} location=${location} prefix=${namePrefix}`);

// ─── Step 3 ────────────────────────────────────────────────────────────
step(3, 'Provisioning infra with Terraform...');
const tfvars = [
  `-var=resource_group=${rg}`,
  `-var=location=${location}`,
  `-var=name_prefix=${namePrefix}`
].join(' ');
run(`terraform -chdir=${quote(INFRA)} init -upgrade`);
run(`terraform -chdir=${quote(INFRA)} apply -auto-approve ${tfvars}`);

const tfOut = JSON.parse(out(`terraform -chdir=${quote(INFRA)} output -json`));
const fnName = tfOut.function_app_name.value;
const fnHost = tfOut.function_app_host.value;
const cosmosName = tfOut.cosmos_account_name.value;
const rgName = tfOut.resource_group_name.value;
console.log(`  ✓ function app: https://${fnHost}`);

// ─── Step 4 ────────────────────────────────────────────────────────────
step(4, 'Generating JWT secret...');
let jwtSecret;
const existing = out(`az functionapp config appsettings list -g ${rgName} -n ${fnName} -o json`);
const existingArr = JSON.parse(existing);
const existingSecret = existingArr.find((s) => s.name === 'CLAWAUTH_JWT_SECRET')?.value;
if (existingSecret && !ROTATE) {
  jwtSecret = existingSecret;
  console.log('  ✓ reusing existing CLAWAUTH_JWT_SECRET (use --rotate-secret to force rotation)');
} else {
  jwtSecret = randomBytes(48).toString('hex');
  console.log(`  ✓ ${ROTATE ? 'rotated' : 'generated'} CLAWAUTH_JWT_SECRET (96 hex chars)`);
}

// ─── Step 5 ────────────────────────────────────────────────────────────
step(5, 'Setting Function app settings...');
const cosmosConn = out(
  `az cosmosdb keys list --type connection-strings -g ${rgName} -n ${cosmosName} --query "connectionStrings[0].connectionString" -o tsv`
);
// Set settings without echoing secrets.
const settings = [
  `CLAWAUTH_JWT_SECRET=${jwtSecret}`,
  `GOOGLE_CLIENT_ID=${cfg.googleClientId}`,
  `COSMOS_CONN=${cosmosConn}`
];
const setRes = spawnSync(
  'az',
  [
    'functionapp', 'config', 'appsettings', 'set',
    '-g', rgName, '-n', fnName,
    '--settings', ...settings,
    '-o', 'none'
  ],
  { stdio: ['ignore', 'inherit', 'inherit'], shell: process.platform === 'win32' }
);
if (setRes.status !== 0) {
  console.error('❌ Failed to set app settings');
  process.exit(setRes.status ?? 1);
}
console.log('  ✓ app settings applied (CLAWAUTH_JWT_SECRET, GOOGLE_CLIENT_ID, COSMOS_CONN)');

// ─── Step 6 ────────────────────────────────────────────────────────────
step(6, 'Building + publishing Function app...');
run('npm run build', { cwd: ROOT });
run(`func azure functionapp publish ${fnName} --javascript`, { cwd: ROOT });

// ─── Step 7 ────────────────────────────────────────────────────────────
step(7, 'Done.');
console.log('');
console.log('  🦞  https://' + fnHost);
console.log('       try: curl https://' + fnHost + '/api/auth/csp');
console.log('');
console.log('  Sign-in endpoint: POST https://' + fnHost + '/api/auth/google');
console.log('  CSP fragment:     GET  https://' + fnHost + '/api/auth/csp');
console.log('');

function quote(p) {
  return process.platform === 'win32' ? `"${p}"` : `'${p}'`;
}
