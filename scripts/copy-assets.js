/**
 * Sovereign Security — Production Build Asset Copier
 * Copies HTML, SVG, and static assets from src/ to dist/
 */

import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');

const srcDashboard = resolve(root, 'src', 'dashboard');
const distDashboard = resolve(root, 'dist', 'dashboard');

if (!existsSync(distDashboard)) {
  mkdirSync(distDashboard, { recursive: true });
}

const assets = ['dashboard.html', 'favicon.svg'];

for (const asset of assets) {
  const src = resolve(srcDashboard, asset);
  const dest = resolve(distDashboard, asset);
  if (existsSync(src)) {
    copyFileSync(src, dest);
    console.log(`[build] Copied ${asset} -> dist/dashboard/${asset}`);
  }
}
