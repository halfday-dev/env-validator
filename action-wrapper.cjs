const { execFileSync } = require('node:child_process');
const { join } = require('node:path');

const cli = join(__dirname, 'src', 'cli.js');

const path = process.env.INPUT_PATH || '.env';
const json = process.env.INPUT_JSON === 'true';
const quiet = process.env.INPUT_QUIET === 'true';

const args = [cli, path];
if (json) args.push('--json');
if (quiet) args.push('--quiet');

try {
  execFileSync('node', args, { stdio: 'inherit' });
} catch (err) {
  process.exitCode = err.status || 1;
}
