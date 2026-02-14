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

describe('patterns count', () => {
  it('has at least 68 patterns matching web scanner', () => {
    assert.ok(patterns.length >= 68, `Expected >= 68 patterns, got ${patterns.length}`);
  });
});

describe('computeScore shape', () => {
  it('returns color and bg fields', () => {
    const result = computeScore([]);
    assert.ok(result.color, 'Should have color field');
    assert.ok(result.bg, 'Should have bg field');
    assert.strictEqual(result.color, 'text-emerald-400');
    assert.strictEqual(result.bg, 'border-emerald-500/30');
  });

  it('returns all 5 fields for every grade', () => {
    const grades = [
      { findings: [], expectedGrade: 'A' },
      { findings: [{ severity: 'critical' }], expectedGrade: 'B' },
      { findings: Array(2).fill({ severity: 'critical' }), expectedGrade: 'C' },
      { findings: Array(4).fill({ severity: 'critical' }), expectedGrade: 'D' },
      { findings: Array(10).fill({ severity: 'critical' }), expectedGrade: 'F' },
    ];
    for (const { findings, expectedGrade } of grades) {
      const result = computeScore(findings);
      assert.strictEqual(result.grade, expectedGrade);
      assert.ok('score' in result, `${expectedGrade} missing score`);
      assert.ok('label' in result, `${expectedGrade} missing label`);
      assert.ok('color' in result, `${expectedGrade} missing color`);
      assert.ok('bg' in result, `${expectedGrade} missing bg`);
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

// ─── Adversarial Tests (Whipper) ───

describe('adversarial: edge cases', () => {
  it('handles file with only comments', () => {
    const findings = analyze('# comment 1\n# comment 2\n# just notes');
    assert.strictEqual(findings.length, 0);
  });

  it('handles CRLF line endings', () => {
    const findings = analyze('DB_PASSWORD=password123\r\nFOO=bar\r\n');
    const weak = findings.find(f => f.name === 'Weak/default password');
    assert.ok(weak, 'Should detect weak password through CRLF');
  });

  it('handles keys with equals in value', () => {
    const findings = analyze('BASE64=abc=def=ghi=');
    // Should parse key as BASE64, value as abc=def=ghi=
    const invalid = findings.find(f => f.name === 'Invalid key name');
    assert.ok(!invalid, 'BASE64 is a valid key name');
  });

  it('handles unicode keys', () => {
    const findings = analyze('密码=mysecret');
    const invalid = findings.find(f => f.name === 'Invalid key name');
    assert.ok(invalid, 'Unicode keys should be flagged as invalid');
  });

  it('handles emoji in values', () => {
    // Should not crash
    const findings = analyze('EMOJI=🔑🔑🔑🔑🔑🔑🔑🔑');
    assert.ok(Array.isArray(findings));
  });

  it('handles null bytes in input', () => {
    // Should not crash
    const findings = analyze('KEY=val\x00ue');
    assert.ok(Array.isArray(findings));
  });

  it('handles lines without equals sign', () => {
    const findings = analyze('this is not a valid line\nFOO=bar');
    assert.strictEqual(findings.length, 0, 'Lines without = should be skipped silently');
  });

  it('handles extremely long values', () => {
    const longVal = 'A'.repeat(100000);
    const findings = analyze(`KEY=${longVal}`);
    assert.ok(Array.isArray(findings));
  });

  it('handles duplicate keys with different severity findings', () => {
    const findings = analyze('SECRET_KEY=password123\nSECRET_KEY=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij');
    const dup = findings.find(f => f.name === 'Duplicate key');
    assert.ok(dup, 'Should detect duplicate');
    const weak = findings.find(f => f.name === 'Weak/default password');
    assert.ok(weak, 'Should detect weak password on first occurrence');
    const ghp = findings.find(f => f.name === 'GitHub Personal Access Token');
    assert.ok(ghp, 'Should detect GH PAT on second occurrence');
  });

  it('handles commented secret mixed with real secret', () => {
    const findings = analyze('# AWS_KEY=AKIAIOSFODNN7EXAMPLE\nOTHER_KEY=AKIAIOSFODNN7EXAMPLE');
    const commented = findings.find(f => f.name.startsWith('Commented-out'));
    const real = findings.find(f => f.name === 'AWS Access Key ID' && !f.name.startsWith('Commented'));
    assert.ok(commented, 'Should flag commented secret');
    assert.ok(real, 'Should also flag the real secret');
  });

  it('handles values with regex special characters', () => {
    const findings = analyze('PATTERN=^(foo|bar).*$[0-9]+');
    assert.ok(Array.isArray(findings)); // should not crash
  });

  it('detects mismatched quotes', () => {
    const findings = analyze('FOO="hello');
    const mismatch = findings.find(f => f.name === 'Mismatched quotes');
    assert.ok(mismatch, 'Should detect mismatched quotes');
    assert.strictEqual(mismatch.severity, 'warning');
  });

  it('detects mismatched single quotes', () => {
    const findings = analyze("BAR='world");
    const mismatch = findings.find(f => f.name === 'Mismatched quotes');
    assert.ok(mismatch, 'Should detect mismatched single quotes');
  });

  it('does not flag properly quoted values', () => {
    const findings = analyze('FOO="hello world"');
    const mismatch = findings.find(f => f.name === 'Mismatched quotes');
    assert.ok(!mismatch, 'Properly quoted values should not be flagged');
  });

  it('handles 10K line file without crashing', () => {
    let bigEnv = '';
    for (let i = 0; i < 10000; i++) bigEnv += `VAR_${i}=value_${i}\n`;
    const start = Date.now();
    const findings = analyze(bigEnv);
    const elapsed = Date.now() - start;
    assert.ok(elapsed < 5000, `Should complete in <5s, took ${elapsed}ms`);
    assert.strictEqual(findings.length, 0);
  });
});
