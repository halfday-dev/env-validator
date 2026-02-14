import { describe, it, expect } from 'vitest';
import { patterns, weakPasswords, analyze, computeScore } from '../scanner.js';

// ─── Pattern Detection Tests ───

describe('patterns', () => {
  const testPattern = (name, positive, negative) => {
    const pattern = patterns.find(p => p.name === name);
    describe(name, () => {
      it('should detect a valid match', () => {
        expect(pattern.regex.test(positive)).toBe(true);
      });
      it('should not match invalid input', () => {
        expect(pattern.regex.test(negative)).toBe(false);
      });
    });
  };

  testPattern('AWS Access Key ID',
    'AKIAIOSFODNN7EXAMPLE',
    'NOTAKEY1234567890123');

  testPattern('AWS Secret Access Key',
    'aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'aws_secret_access_key=short');

  testPattern('Stripe Secret Key',
    'sk_live_abcdefghijklmnopqrstuvwx',
    'sk_test_abcdefghijklmnopqrstuv');

  testPattern('Stripe Publishable Key',
    'pk_live_abcdefghijklmnopqrstuvwx',
    'pk_test_abcdefghijklmnopqrstuv');

  testPattern('GitHub Personal Access Token',
    'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
    'ghp_short');

  testPattern('GitHub OAuth Token',
    'gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
    'gho_short');

  testPattern('GitHub App Token',
    'ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
    'ghu_short');

  testPattern('OpenAI API Key (new format)',
    'sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD',
    'sk-proj-short');

  testPattern('Google API Key',
    'AIzaSyA1234567890abcdefghijklmnopqrstuv',
    'AIzaShort');

  testPattern('Slack Bot Token',
    'xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx',
    'xoxb-123-456-abc');

  testPattern('SendGrid API Key',
    'SG.abcdefghijklmnopqrstuv.ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq',
    'SG.short.short');

  testPattern('npm Token',
    'npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
    'npm_short');

  testPattern('GitLab Token',
    'glpat-ABCDEFGHIJKLMNOPabcd',
    'glpat-short');

  testPattern('Private Key (PEM)',
    '-----BEGIN RSA PRIVATE KEY-----',
    '-----BEGIN PUBLIC KEY-----');

  testPattern('Database URL with Password',
    'postgres://user:pass123@localhost:5432/db',
    'postgres://localhost:5432/db');

  testPattern('Redis URL with Password',
    'redis://:secretpass@cache.example.com:6379',
    'redis://localhost:6379');

  testPattern('MongoDB URI with Password',
    'mongodb://admin:pass@cluster.mongodb.net/db',
    'mongodb://localhost/db');

  testPattern('DigitalOcean Token',
    'dop_v1_' + 'a'.repeat(64),
    'dop_v1_short');

  testPattern('Hugging Face Token',
    'hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh',
    'hf_short');

  testPattern('Shopify Access Token',
    'shpat_' + 'a'.repeat(32),
    'shpat_short');

  testPattern('Linear API Key',
    'lin_api_' + 'a'.repeat(40),
    'lin_api_short');
});

// ─── Weak Password Detection ───

describe('weakPasswords', () => {
  it('should include common weak passwords', () => {
    expect(weakPasswords).toContain('password');
    expect(weakPasswords).toContain('password123');
    expect(weakPasswords).toContain('changeme');
    expect(weakPasswords).toContain('hunter2');
    expect(weakPasswords).toContain('admin');
  });

  it('should not include strong passwords', () => {
    expect(weakPasswords).not.toContain('xK9$mP2!qR7@wL4');
  });
});

// ─── analyze() Tests ───

describe('analyze', () => {
  it('should return null for empty input', () => {
    expect(analyze('')).toBeNull();
    expect(analyze('   ')).toBeNull();
    expect(analyze('\n\n')).toBeNull();
  });

  it('should return empty array for comments-only input', () => {
    const result = analyze('# This is a comment\n# Another comment');
    expect(result).toEqual([]);
  });

  it('should return empty array for valid env with no secrets', () => {
    const result = analyze('APP_NAME=MyApp\nDEBUG=true\nPORT=3000');
    expect(result).toEqual([]);
  });

  it('should detect weak passwords', () => {
    const result = analyze('DB_PASSWORD=password123');
    const weak = result.find(f => f.name === 'Weak/default password');
    expect(weak).toBeDefined();
    expect(weak.severity).toBe('critical');
  });

  it('should detect duplicate keys', () => {
    const result = analyze('KEY=value1\nKEY=value2');
    const dup = result.find(f => f.name === 'Duplicate key');
    expect(dup).toBeDefined();
    expect(dup.severity).toBe('warning');
  });

  it('should detect empty values', () => {
    const result = analyze('EMPTY_VAR=');
    const empty = result.find(f => f.name === 'Empty value');
    expect(empty).toBeDefined();
    expect(empty.severity).toBe('info');
  });

  it('should detect unquoted values with spaces', () => {
    const result = analyze('APP_DESC=my cool app');
    const unquoted = result.find(f => f.name === 'Unquoted value with spaces');
    expect(unquoted).toBeDefined();
  });

  it('should detect commented-out secrets', () => {
    const result = analyze('# AWS_KEY=AKIAIOSFODNN7EXAMPLE');
    const commented = result.find(f => f.name.startsWith('Commented-out'));
    expect(commented).toBeDefined();
    expect(commented.severity).toBe('warning');
  });

  it('should detect API keys in values', () => {
    const result = analyze('GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij');
    const gh = result.find(f => f.name === 'GitHub Personal Access Token');
    expect(gh).toBeDefined();
    expect(gh.severity).toBe('critical');
  });

  it('should handle a mixed .env with multiple issues', () => {
    const env = [
      'DATABASE_URL=postgres://admin:password123@localhost:5432/myapp',
      'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
      'APP_NAME=MyApp',
      'DEBUG=true',
      'DEBUG=false',
      'EMPTY=',
      '# OLD_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh',
    ].join('\n');

    const result = analyze(env);
    const severities = result.map(f => f.severity);
    expect(severities).toContain('critical');
    expect(severities).toContain('warning');
    expect(severities).toContain('info');
    expect(result.length).toBeGreaterThan(3);
  });
});

// ─── computeScore() Tests ───

describe('computeScore', () => {
  it('should return A for no findings', () => {
    expect(computeScore([]).grade).toBe('A');
  });

  it('should return A for only info findings', () => {
    const findings = [{ severity: 'info' }, { severity: 'info' }];
    expect(computeScore(findings).grade).toBe('A');
  });

  it('should return B for a couple warnings', () => {
    const findings = Array(4).fill({ severity: 'warning' });
    // 100 - 20 = 80 → B
    expect(computeScore(findings).grade).toBe('B');
  });

  it('should return C for moderate issues', () => {
    // 2 critical = 100 - 30 = 70, plus 2 warnings = 60 → C
    const findings = [
      { severity: 'critical' }, { severity: 'critical' },
      { severity: 'warning' }, { severity: 'warning' },
    ];
    expect(computeScore(findings).grade).toBe('C');
  });

  it('should return D for many issues', () => {
    // 3 critical = 100 - 45 = 55, plus 1 warning = 50 → D
    const findings = [
      { severity: 'critical' }, { severity: 'critical' }, { severity: 'critical' },
      { severity: 'warning' },
    ];
    expect(computeScore(findings).grade).toBe('D');
  });

  it('should return F for critical overload', () => {
    const findings = Array(7).fill({ severity: 'critical' });
    // 100 - 105 = 0 → F
    expect(computeScore(findings).grade).toBe('F');
  });
});
