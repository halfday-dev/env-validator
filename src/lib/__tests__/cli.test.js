import { describe, it, expect } from 'vitest';
import { execFileSync, execSync } from 'node:child_process';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const cli = resolve(__dirname, '../../cli.js');
const fixtures = resolve(__dirname, 'fixtures');

function run(args = [], opts = {}) {
  try {
    const result = execFileSync('node', [cli, ...args], {
      encoding: 'utf8',
      timeout: 10000,
      ...opts,
    });
    return { stdout: result, exitCode: 0 };
  } catch (err) {
    return { stdout: err.stdout || '', stderr: err.stderr || '', exitCode: err.status };
  }
}

describe('halfday-env-scan CLI', () => {
  it('shows usage with --help', () => {
    const { stdout, exitCode } = run(['--help']);
    expect(stdout).toContain('halfday-env-scan');
    expect(stdout).toContain('Usage');
    expect(exitCode).toBe(0);
  });

  it('shows helpful error for missing file', () => {
    const { stderr, exitCode } = run(['nonexistent.env']);
    expect(stderr).toContain('File not found');
    expect(exitCode).toBe(1);
  });

  it('scans a clean file with exit code 0', () => {
    const { stdout, exitCode } = run([resolve(fixtures, 'clean.env')]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain('No issues found');
    expect(stdout).toContain('Grade');
    expect(stdout).toContain('A');
  });

  it('scans a dirty file with exit code 1', () => {
    const { stdout, exitCode } = run([resolve(fixtures, 'dirty.env')]);
    expect(exitCode).toBe(1);
    expect(stdout).toContain('critical');
  });

  it('--json outputs valid JSON for clean file', () => {
    const { stdout, exitCode } = run(['--json', resolve(fixtures, 'clean.env')]);
    expect(exitCode).toBe(0);
    const data = JSON.parse(stdout);
    expect(data.grade).toBe('A');
    expect(data.pass).toBe(true);
    expect(Array.isArray(data.findings)).toBe(true);
  });

  it('--json outputs valid JSON for dirty file', () => {
    const { stdout, exitCode } = run(['--json', resolve(fixtures, 'dirty.env')]);
    expect(exitCode).toBe(1);
    const data = JSON.parse(stdout);
    expect(data.pass).toBe(false);
    expect(data.findings.length).toBeGreaterThan(0);
    expect(data.summary.critical).toBeGreaterThan(0);
  });

  it('--quiet only shows grade', () => {
    const { stdout, exitCode } = run(['--quiet', resolve(fixtures, 'clean.env')]);
    expect(exitCode).toBe(0);
    expect(stdout.trim()).toMatch(/A/);
  });

  it('reads from stdin', () => {
    const { stdout, exitCode } = run(['--json'], {
      input: 'DB_PASSWORD=password123\nAWS_KEY=AKIAIOSFODNN7EXAMPLE\nSTRIPE=sk_live_abc123def456ghi789jkl012mno\nDB_URL=postgres://admin:pass@localhost/db\n',
    });
    expect(exitCode).toBe(1);
    const data = JSON.parse(stdout);
    expect(data.findings.length).toBeGreaterThan(0);
    expect(data.source).toBe('stdin');
  });

  it('--json with missing file returns JSON error', () => {
    const { stdout, exitCode } = run(['--json', 'nope.env']);
    expect(exitCode).toBe(1);
    const data = JSON.parse(stdout);
    expect(data.error).toContain('File not found');
  });
});
