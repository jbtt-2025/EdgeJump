import { readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

const files = readdirSync('tests', { recursive: true })
  .filter((file) => file.endsWith('.test.ts'))
  .sort()
  .map((file) => `tests/${file}`);
const result = spawnSync(process.execPath, ['--test', '--experimental-strip-types', ...files], { stdio: 'inherit' });
if (result.error) throw result.error;
process.exit(result.status ?? 1);
