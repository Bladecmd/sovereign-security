/**
 * Sovereign Security — Cross-Platform Test Runner
 *
 * Reliably discovers and executes all test suites across Windows, Linux, and macOS.
 */

import { readdirSync } from 'node:fs';
import { join } from 'node:path';
import { run } from 'node:test';
import { spec } from 'node:test/reporters';

const testDir = 'tests';
const files = readdirSync(testDir)
  .filter((f) => f.endsWith('.test.ts'))
  .sort()
  .map((f) => join(testDir, f));

run({ files })
  .compose(spec)
  .pipe(process.stdout);
