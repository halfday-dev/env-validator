import { describe, it, expect, vi } from 'vitest';
import {
  base64UrlDecode,
  decodeJWT,
  formatTimestamp,
  checkExpiry,
  inspectClaims,
  securityAudit,
  computeGrade,
  getAlgorithmInfo,
  analyzeJWT,
  STANDARD_CLAIMS,
} from '../src/lib/jwt-decoder.js';

// Helper: create a JWT from header/payload objects
function makeJWT(header, payload, sig = 'fakesig') {
  const enc = obj => btoa(JSON.stringify(obj)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${enc(header)}.${enc(payload)}.${sig}`;
}

// ─── base64UrlDecode ───
describe('base64UrlDecode', () => {
  it('decodes standard base64url', () => {
    const encoded = btoa('hello world').replace(/=/g, '');
    expect(base64UrlDecode(encoded)).toBe('hello world');
  });

  it('handles URL-safe characters (- and _)', () => {
    // A string that produces + and / in base64
    const encoded = btoa('subjects?_d').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    expect(base64UrlDecode(encoded)).toBe('subjects?_d');
  });

  it('throws on non-string input', () => {
    expect(() => base64UrlDecode(123)).toThrow('Invalid base64url input');
    expect(() => base64UrlDecode(null)).toThrow('Invalid base64url input');
  });

  it('throws on invalid base64url (pad=1)', () => {
    expect(() => base64UrlDecode('a')).toThrow('Invalid base64url string');
  });

  it('decodes JSON objects', () => {
    const json = JSON.stringify({ alg: 'HS256', typ: 'JWT' });
    const encoded = btoa(json).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    expect(base64UrlDecode(encoded)).toBe(json);
  });

  it('handles unicode characters', () => {
    const json = JSON.stringify({ name: 'José' });
    const encoded = btoa(unescape(encodeURIComponent(JSON.stringify({ name: 'José' })))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    expect(JSON.parse(base64UrlDecode(encoded)).name).toBe('José');
  });
});

// ─── decodeJWT ───
describe('decodeJWT', () => {
  it('decodes a valid JWT', () => {
    const token = makeJWT({ alg: 'HS256', typ: 'JWT' }, { sub: '123', name: 'Test' });
    const result = decodeJWT(token);
    expect(result.header.alg).toBe('HS256');
    expect(result.payload.sub).toBe('123');
    expect(result.signature).toBe('fakesig');
  });

  it('throws on empty string', () => {
    expect(() => decodeJWT('')).toThrow('non-empty string');
  });

  it('throws on non-string', () => {
    expect(() => decodeJWT(42)).toThrow('non-empty string');
    expect(() => decodeJWT(undefined)).toThrow('non-empty string');
  });

  it('throws on too few segments', () => {
    expect(() => decodeJWT('abc.def')).toThrow('expected 3 segments, got 2');
  });

  it('throws on too many segments', () => {
    expect(() => decodeJWT('a.b.c.d')).toThrow('expected 3 segments, got 4');
  });

  it('throws on empty header segment', () => {
    expect(() => decodeJWT('.eyJ0ZXN0IjoxfQ.sig')).toThrow('header and payload segments cannot be empty');
  });

  it('throws on empty payload segment', () => {
    const header = btoa(JSON.stringify({ alg: 'HS256' })).replace(/=/g, '');
    expect(() => decodeJWT(`${header}..sig`)).toThrow('header and payload segments cannot be empty');
  });

  it('throws on invalid header JSON', () => {
    const bad = btoa('not json').replace(/=/g, '');
    const payload = btoa(JSON.stringify({})).replace(/=/g, '');
    expect(() => decodeJWT(`${bad}.${payload}.sig`)).toThrow('Invalid JWT header');
  });

  it('throws on invalid payload JSON', () => {
    const header = btoa(JSON.stringify({ alg: 'HS256' })).replace(/=/g, '');
    const bad = btoa('not json').replace(/=/g, '');
    expect(() => decodeJWT(`${header}.${bad}.sig`)).toThrow('Invalid JWT payload');
  });

  it('trims whitespace from token', () => {
    const token = '  ' + makeJWT({ alg: 'RS256' }, { sub: '1' }) + '\n';
    expect(decodeJWT(token).header.alg).toBe('RS256');
  });

  it('preserves raw segments', () => {
    const token = makeJWT({ alg: 'ES256' }, { iss: 'test' }, 'mysignature');
    const result = decodeJWT(token);
    expect(result.raw.signature).toBe('mysignature');
    expect(token.startsWith(result.raw.header)).toBe(true);
  });

  it('handles empty signature segment (alg:none)', () => {
    const token = makeJWT({ alg: 'none' }, { sub: '1' }, '');
    const result = decodeJWT(token);
    expect(result.signature).toBe('');
  });
});

// ─── formatTimestamp ───
describe('formatTimestamp', () => {
  it('formats a Unix timestamp', () => {
    expect(formatTimestamp(0)).toBe('1970-01-01 00:00:00 UTC');
  });

  it('formats a real timestamp', () => {
    expect(formatTimestamp(1700000000)).toMatch(/2023-11-14/);
  });

  it('returns null for non-number', () => {
    expect(formatTimestamp('abc')).toBeNull();
    expect(formatTimestamp(undefined)).toBeNull();
  });

  it('returns null for non-finite', () => {
    expect(formatTimestamp(Infinity)).toBeNull();
    expect(formatTimestamp(NaN)).toBeNull();
  });
});

// ─── checkExpiry ───
describe('checkExpiry', () => {
  const now = 1700000000;

  it('detects expired token', () => {
    const result = checkExpiry({ exp: now - 100 }, now);
    expect(result.expired).toBe(true);
    expect(result.expiresIn).toBe(-100);
  });

  it('detects valid token', () => {
    const result = checkExpiry({ exp: now + 3600 }, now);
    expect(result.expired).toBe(false);
    expect(result.expiresIn).toBe(3600);
  });

  it('handles missing exp', () => {
    const result = checkExpiry({}, now);
    expect(result.expired).toBe(false);
    expect(result.expiresIn).toBeNull();
  });

  it('detects not-yet-valid token', () => {
    const result = checkExpiry({ nbf: now + 100 }, now);
    expect(result.notYetValid).toBe(true);
  });

  it('formats iat, exp, nbf', () => {
    const result = checkExpiry({ iat: now, exp: now + 3600, nbf: now }, now);
    expect(result.issuedAt).toContain('UTC');
    expect(result.expiresAt).toContain('UTC');
    expect(result.notBefore).toContain('UTC');
  });

  it('token expired exactly at exp', () => {
    const result = checkExpiry({ exp: now }, now);
    expect(result.expired).toBe(true);
  });
});

// ─── inspectClaims ───
describe('inspectClaims', () => {
  it('categorizes standard claims', () => {
    const { standard, custom } = inspectClaims({ iss: 'auth0', sub: '123', custom_field: 'val' });
    expect(standard).toHaveLength(2);
    expect(custom).toHaveLength(1);
    expect(standard[0].key).toBe('iss');
    expect(standard[0].name).toBe('Issuer');
  });

  it('formats timestamp claims', () => {
    const { standard } = inspectClaims({ exp: 1700000000 });
    expect(standard[0].formattedValue).toContain('UTC');
  });

  it('handles empty payload', () => {
    const { standard, custom } = inspectClaims({});
    expect(standard).toHaveLength(0);
    expect(custom).toHaveLength(0);
  });

  it('handles all standard claims', () => {
    const payload = { iss: 'a', sub: 'b', aud: 'c', exp: 1, iat: 2, nbf: 3, jti: 'd' };
    const { standard } = inspectClaims(payload);
    expect(standard).toHaveLength(7);
  });

  it('identifies custom claims correctly', () => {
    const { custom } = inspectClaims({ role: 'admin', permissions: ['read'] });
    expect(custom).toHaveLength(2);
    expect(custom[0].key).toBe('role');
  });
});

// ─── securityAudit ───
describe('securityAudit', () => {
  it('flags alg:none as critical', () => {
    const findings = securityAudit({ alg: 'none' }, {});
    const f = findings.find(f => f.id === 'alg-none');
    expect(f).toBeDefined();
    expect(f.severity).toBe('critical');
  });

  it('flags missing alg as critical', () => {
    const findings = securityAudit({}, {});
    expect(findings.find(f => f.id === 'alg-none')).toBeDefined();
  });

  it('flags HS256 as weak', () => {
    const findings = securityAudit({ alg: 'HS256' }, { exp: Date.now() / 1000 + 3600 });
    expect(findings.find(f => f.id === 'weak-alg')).toBeDefined();
  });

  it('flags HS384 as weak', () => {
    const findings = securityAudit({ alg: 'HS384' }, {});
    expect(findings.find(f => f.id === 'weak-alg')).toBeDefined();
  });

  it('does not flag RS256 as weak', () => {
    const findings = securityAudit({ alg: 'RS256' }, { exp: Date.now() / 1000 + 3600, aud: 'x', iss: 'y' });
    expect(findings.find(f => f.id === 'weak-alg')).toBeUndefined();
  });

  it('flags missing exp', () => {
    const findings = securityAudit({ alg: 'RS256' }, {});
    expect(findings.find(f => f.id === 'no-exp')).toBeDefined();
  });

  it('flags expired tokens', () => {
    const findings = securityAudit({ alg: 'RS256' }, { exp: 1000 });
    expect(findings.find(f => f.id === 'expired')).toBeDefined();
  });

  it('flags long-lived tokens (>24h)', () => {
    const now = Math.floor(Date.now() / 1000);
    const findings = securityAudit({ alg: 'RS256' }, { iat: now, exp: now + 200000 });
    expect(findings.find(f => f.id === 'long-lived')).toBeDefined();
  });

  it('does not flag short-lived tokens', () => {
    const now = Math.floor(Date.now() / 1000);
    const findings = securityAudit({ alg: 'RS256' }, { iat: now, exp: now + 3600 });
    expect(findings.find(f => f.id === 'long-lived')).toBeUndefined();
  });

  it('flags missing audience', () => {
    const findings = securityAudit({ alg: 'RS256' }, {});
    expect(findings.find(f => f.id === 'no-aud')).toBeDefined();
  });

  it('flags missing issuer', () => {
    const findings = securityAudit({ alg: 'RS256' }, {});
    expect(findings.find(f => f.id === 'no-iss')).toBeDefined();
  });

  it('flags not-yet-valid tokens', () => {
    const future = Math.floor(Date.now() / 1000) + 999999;
    const findings = securityAudit({ alg: 'RS256' }, { nbf: future });
    expect(findings.find(f => f.id === 'not-yet-valid')).toBeDefined();
  });

  it('flags unknown algorithms', () => {
    const findings = securityAudit({ alg: 'YOLO256' }, {});
    expect(findings.find(f => f.id === 'unknown-alg')).toBeDefined();
  });

  it('clean token produces minimal findings', () => {
    const now = Math.floor(Date.now() / 1000);
    const findings = securityAudit(
      { alg: 'RS256' },
      { iss: 'auth0', sub: '1', aud: 'api', exp: now + 3600, iat: now }
    );
    // Only info-level or none
    const serious = findings.filter(f => f.severity === 'critical' || f.severity === 'warning');
    expect(serious).toHaveLength(0);
  });
});

// ─── computeGrade ───
describe('computeGrade', () => {
  it('returns A for no findings', () => {
    expect(computeGrade([]).grade).toBe('A');
  });

  it('returns F for critical finding', () => {
    const findings = [
      { severity: 'critical' },
      { severity: 'critical' },
      { severity: 'critical' },
    ];
    expect(computeGrade(findings).grade).toBe('F');
  });

  it('returns B-C for warnings', () => {
    const findings = [{ severity: 'warning' }, { severity: 'warning' }];
    const grade = computeGrade(findings);
    expect(['B', 'C']).toContain(grade.grade);
  });

  it('includes label and color', () => {
    const grade = computeGrade([]);
    expect(grade.label).toBe('Excellent');
    expect(grade.color).toContain('emerald');
  });
});

// ─── getAlgorithmInfo ───
describe('getAlgorithmInfo', () => {
  it('returns info for known algorithms', () => {
    expect(getAlgorithmInfo('RS256').strength).toBe('strong');
    expect(getAlgorithmInfo('HS256').strength).toBe('weak');
  });

  it('returns critical for none', () => {
    expect(getAlgorithmInfo('none').strength).toBe('critical');
    expect(getAlgorithmInfo(null).strength).toBe('critical');
  });

  it('returns unknown for unrecognized', () => {
    expect(getAlgorithmInfo('CUSTOM').strength).toBe('unknown');
  });
});

// ─── analyzeJWT (integration) ───
describe('analyzeJWT', () => {
  it('full pipeline works', () => {
    const now = Math.floor(Date.now() / 1000);
    const token = makeJWT(
      { alg: 'RS256', typ: 'JWT' },
      { iss: 'halfday', sub: '42', aud: 'api', exp: now + 3600, iat: now }
    );
    const result = analyzeJWT(token);
    expect(result.header.alg).toBe('RS256');
    expect(result.payload.sub).toBe('42');
    expect(result.expiry.expired).toBe(false);
    expect(result.grade.grade).toBe('A');
    expect(result.claims.standard.length).toBeGreaterThan(0);
  });

  it('flags insecure token correctly', () => {
    const token = makeJWT({ alg: 'none' }, { sub: '1' }, '');
    const result = analyzeJWT(token);
    expect(result.grade.grade).toBe('F');
    expect(result.audit.some(f => f.id === 'alg-none')).toBe(true);
  });

  it('handles nested JWT in claim', () => {
    const innerToken = makeJWT({ alg: 'HS256' }, { role: 'admin' });
    const token = makeJWT({ alg: 'RS256' }, { token: innerToken });
    const result = analyzeJWT(token);
    expect(result.payload.token).toBe(innerToken);
  });

  it('handles JWT with many custom claims', () => {
    const payload = {};
    for (let i = 0; i < 50; i++) payload[`claim_${i}`] = i;
    const token = makeJWT({ alg: 'ES256' }, payload);
    const result = analyzeJWT(token);
    expect(result.claims.custom).toHaveLength(50);
  });
});
