const { describe, it } = require('node:test');
const assert = require('node:assert');
const { analyze, computeScore, patterns, weakPasswords } = require('../src/scanner');

describe('analyze', () => {
  it('returns empty array for empty input', () => {
    assert.deepStrictEqual(analyze(''), []);
    assert.deepStrictEqual(analyze('  \n  '), []);
  });

  it('detects AWS access key', () => {
    const findings = analyze('AWS_KEY=AKIAIOSFODNN7EXAMPLE');
    const aws = findings.find(f => f.name === 'AWS Access Key ID');
    assert.ok(aws, 'Should detect AWS key');
    assert.strictEqual(aws.severity, 'critical');
    assert.strictEqual(aws.line, 1);
  });

  it('detects GitHub PAT', () => {
    const findings = analyze('GH_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij');
    const gh = findings.find(f => f.name === 'GitHub Personal Access Token');
    assert.ok(gh);
    assert.strictEqual(gh.severity, 'critical');
  });

  it('detects weak passwords', () => {
    const findings = analyze('DB_PASSWORD=password123');
    const weak = findings.find(f => f.name === 'Weak/default password');
    assert.ok(weak);
    assert.strictEqual(weak.severity, 'critical');
  });

  it('detects empty values', () => {
    const findings = analyze('API_KEY=');
    const empty = findings.find(f => f.name === 'Empty value');
    assert.ok(empty);
    assert.strictEqual(empty.severity, 'info');
  });

  it('detects duplicate keys', () => {
    const findings = analyze('FOO=bar\nFOO=baz');
    const dup = findings.find(f => f.name === 'Duplicate key');
    assert.ok(dup);
  });

  it('detects commented-out secrets', () => {
    const findings = analyze('# AWS_KEY=AKIAIOSFODNN7EXAMPLE');
    const commented = findings.find(f => f.name.startsWith('Commented-out'));
    assert.ok(commented);
    assert.strictEqual(commented.severity, 'warning');
  });

  it('detects unquoted values with spaces', () => {
    const findings = analyze('MSG=hello world');
    const unquoted = findings.find(f => f.name === 'Unquoted value with spaces');
    assert.ok(unquoted);
  });

  it('detects database URLs with passwords', () => {
    const findings = analyze('DATABASE_URL=postgres://user:pass@localhost:5432/db');
    const db = findings.find(f => f.name === 'Database URL with Password');
    assert.ok(db);
    assert.strictEqual(db.severity, 'critical');
  });

  it('skips comments without secrets', () => {
    const findings = analyze('# This is a normal comment');
    assert.strictEqual(findings.length, 0);
  });

  it('handles clean env file', () => {
    const findings = analyze('NODE_ENV=production\nPORT=3000');
    assert.strictEqual(findings.length, 0);
  });
});

describe('computeScore', () => {
  it('returns A for no findings', () => {
    const result = computeScore([]);
    assert.strictEqual(result.grade, 'A');
    assert.strictEqual(result.score, 100);
  });

  it('returns F for many critical findings', () => {
    const findings = Array(10).fill({ severity: 'critical' });
    const result = computeScore(findings);
    assert.strictEqual(result.grade, 'F');
    assert.strictEqual(result.score, 0);
  });

  it('reduces score for warnings', () => {
    const findings = [{ severity: 'warning' }, { severity: 'warning' }];
    const result = computeScore(findings);
    assert.strictEqual(result.score, 90);
    assert.strictEqual(result.grade, 'A');
  });

  it('critical issues reduce score by 15', () => {
    const findings = [{ severity: 'critical' }];
    const result = computeScore(findings);
    assert.strictEqual(result.score, 85);
    assert.strictEqual(result.grade, 'B');
  });
});

describe('patterns', () => {
  it('has patterns array', () => {
    assert.ok(Array.isArray(patterns));
    assert.ok(patterns.length > 20);
  });

  it('all patterns have required fields', () => {
    for (const p of patterns) {
      assert.ok(p.name, 'pattern missing name');
      assert.ok(p.regex, 'pattern missing regex');
      assert.ok(p.severity, 'pattern missing severity');
      assert.ok(p.fix, 'pattern missing fix');
    }
  });
});

describe('weakPasswords', () => {
  it('includes common weak passwords', () => {
    assert.ok(weakPasswords.includes('password'));
    assert.ok(weakPasswords.includes('hunter2'));
    assert.ok(weakPasswords.includes('admin'));
  });
});
