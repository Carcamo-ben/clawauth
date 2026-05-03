#!/usr/bin/env node
/** Tear down everything `deploy.mjs` provisioned. */
import { execSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const INFRA = resolve(ROOT, 'infra');
const cfg = JSON.parse(readFileSync(resolve(ROOT, 'clawauth.config.json'), 'utf8'));
const az = cfg.azure ?? {};
const rg = az.resourceGroup ?? 'rg-clawauth-demo';
const location = az.location ?? 'canadacentral';
const namePrefix = az.namePrefix ?? 'clawauth';
const tfvars = `-var=resource_group=${rg} -var=location=${location} -var=name_prefix=${namePrefix}`;
const quote = (p) => process.platform === 'win32' ? `"${p}"` : `'${p}'`;
console.log('Destroying infra...');
execSync(`terraform -chdir=${quote(INFRA)} destroy -auto-approve ${tfvars}`, { stdio: 'inherit' });
console.log('Done.');
