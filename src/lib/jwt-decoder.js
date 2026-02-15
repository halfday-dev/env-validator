// ─── JWT Decoder & Inspector ───
// 100% client-side JWT decoding — no dependencies

/**
 * Standard JWT claims with human-readable descriptions
 */
export const STANDARD_CLAIMS = {
  iss: { name: 'Issuer', desc: 'Who issued this token' },
  sub: { name: 'Subject', desc: 'Who the token is about' },
  aud: { name: 'Audience', desc: 'Who the token is intended for' },
  exp: { name: 'Expiration', desc: 'When this token expires' },
  nbf: { name: 'Not Before', desc: 'Token is not valid before this time' },
  iat: { name: 'Issued At', desc: 'When this token was issued' },
  jti: { name: 'JWT ID', desc: 'Unique identifier for this token' },
};

/**
 * Algorithm security ratings
 */
const ALG_SECURITY = {
  none: { strength: 'critical', label: 'No signature — anyone can forge this token' },
  HS256: { strength: 'weak', label: 'HMAC-SHA256 — acceptable, but asymmetric algorithms preferred' },
  HS384: { strength: 'weak', label: 'HMAC-SHA384 — acceptable, but asymmetric algorithms preferred' },
  HS512: { strength: 'ok', label: 'HMAC-SHA512 — acceptable symmetric algorithm' },
  RS256: { strength: 'strong', label: 'RSA-SHA256 — strong asymmetric algorithm' },
  RS384: { strength: 'strong', label: 'RSA-SHA384 — strong asymmetric algorithm' },
  RS512: { strength: 'strong', label: 'RSA-SHA512 — strong asymmetric algorithm' },
  ES256: { strength: 'strong', label: 'ECDSA-SHA256 — strong, compact asymmetric algorithm' },
  ES384: { strength: 'strong', label: 'ECDSA-SHA384 — strong asymmetric algorithm' },
  ES512: { strength: 'strong', label: 'ECDSA-SHA512 — strong asymmetric algorithm' },
  PS256: { strength: 'strong', label: 'RSASSA-PSS SHA256 — strong asymmetric algorithm' },
  PS384: { strength: 'strong', label: 'RSASSA-PSS SHA384 — strong asymmetric algorithm' },
  PS512: { strength: 'strong', label: 'RSASSA-PSS SHA512 — strong asymmetric algorithm' },
  EdDSA: { strength: 'strong', label: 'EdDSA — modern, strong asymmetric algorithm' },
};

/**
 * Decode a base64url string to UTF-8 text
 */
export function base64UrlDecode(str) {
  if (typeof str !== 'string') throw new Error('Invalid base64url input');
  // Replace URL-safe chars and add padding
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  if (pad === 2) base64 += '==';
  else if (pad === 3) base64 += '=';
  else if (pad === 1) throw new Error('Invalid base64url string');

  try {
    return decodeURIComponent(
      atob(base64)
        .split('')
        .map(c => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
  } catch {
    throw new Error('Invalid base64url encoding');
  }
}

/**
 * Decode a JWT string into its parts
 * @param {string} token - The JWT string
 * @returns {{ header: object, payload: object, signature: string, raw: { header: string, payload: string, signature: string } }}
 */
export function decodeJWT(token) {
  if (typeof token !== 'string' || !token.trim()) {
    throw new Error('Token must be a non-empty string');
  }

  token = token.trim();
  const parts = token.split('.');

  if (parts.length !== 3) {
    throw new Error(`Invalid JWT: expected 3 segments, got ${parts.length}`);
  }

  if (!parts[0] || !parts[1]) {
    throw new Error('Invalid JWT: header and payload segments cannot be empty');
  }

  let header, payload;

  try {
    header = JSON.parse(base64UrlDecode(parts[0]));
  } catch (e) {
    throw new Error(`Invalid JWT header: ${e.message}`);
  }

  try {
    payload = JSON.parse(base64UrlDecode(parts[1]));
  } catch (e) {
    throw new Error(`Invalid JWT payload: ${e.message}`);
  }

  return {
    header,
    payload,
    signature: parts[2],
    raw: { header: parts[0], payload: parts[1], signature: parts[2] },
  };
}

/**
 * Format a Unix timestamp as a human-readable date string
 */
export function formatTimestamp(ts) {
  if (typeof ts !== 'number' || !Number.isFinite(ts)) return null;
  const d = new Date(ts * 1000);
  if (isNaN(d.getTime())) return null;
  return d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
}

/**
 * Check token expiry status
 * @returns {{ expired: boolean, expiresIn: number|null, notYetValid: boolean, issuedAt: string|null, expiresAt: string|null, notBefore: string|null }}
 */
export function checkExpiry(payload, nowSeconds = Math.floor(Date.now() / 1000)) {
  const result = {
    expired: false,
    expiresIn: null,
    notYetValid: false,
    issuedAt: formatTimestamp(payload.iat),
    expiresAt: formatTimestamp(payload.exp),
    notBefore: formatTimestamp(payload.nbf),
  };

  if (typeof payload.exp === 'number') {
    result.expired = nowSeconds >= payload.exp;
    result.expiresIn = payload.exp - nowSeconds;
  }

  if (typeof payload.nbf === 'number') {
    result.notYetValid = nowSeconds < payload.nbf;
  }

  return result;
}

/**
 * Inspect claims and categorize them
 */
export function inspectClaims(payload) {
  const standard = [];
  const custom = [];

  for (const [key, value] of Object.entries(payload)) {
    if (STANDARD_CLAIMS[key]) {
      standard.push({
        key,
        value,
        ...STANDARD_CLAIMS[key],
        formattedValue: ['exp', 'iat', 'nbf'].includes(key) && typeof value === 'number'
          ? formatTimestamp(value)
          : undefined,
      });
    } else {
      custom.push({ key, value });
    }
  }

  return { standard, custom };
}

/**
 * Run security audit on decoded JWT
 * @returns {Array<{ id: string, severity: 'critical'|'warning'|'info', title: string, detail: string }>}
 */
export function securityAudit(header, payload) {
  const findings = [];
  const alg = header.alg;
  const now = Math.floor(Date.now() / 1000);

  // alg: none
  if (!alg || alg.toLowerCase() === 'none') {
    findings.push({
      id: 'alg-none',
      severity: 'critical',
      title: 'Algorithm set to "none"',
      detail: 'This token has no signature. Anyone can forge it. Never accept unsigned JWTs.',
    });
  }

  // Weak symmetric algorithms
  if (alg === 'HS256' || alg === 'HS384') {
    findings.push({
      id: 'weak-alg',
      severity: 'warning',
      title: `Weak algorithm: ${alg}`,
      detail: 'Symmetric HMAC algorithms are vulnerable if the secret is short or leaked. Prefer RS256/ES256.',
    });
  }

  // Unknown algorithm
  if (alg && !ALG_SECURITY[alg] && alg.toLowerCase() !== 'none') {
    findings.push({
      id: 'unknown-alg',
      severity: 'warning',
      title: `Unknown algorithm: ${alg}`,
      detail: 'This algorithm is not in the standard JWT algorithm registry.',
    });
  }

  // Missing expiration
  if (payload.exp === undefined) {
    findings.push({
      id: 'no-exp',
      severity: 'warning',
      title: 'No expiration claim (exp)',
      detail: 'Tokens without expiration never expire. Always set an exp claim.',
    });
  }

  // Expired token
  if (typeof payload.exp === 'number' && now >= payload.exp) {
    findings.push({
      id: 'expired',
      severity: 'info',
      title: 'Token is expired',
      detail: `Expired ${formatTimestamp(payload.exp)}. This token should no longer be accepted.`,
    });
  }

  // Long-lived token (>24h)
  if (typeof payload.exp === 'number' && typeof payload.iat === 'number') {
    const lifetime = payload.exp - payload.iat;
    if (lifetime > 86400) {
      const hours = Math.round(lifetime / 3600);
      findings.push({
        id: 'long-lived',
        severity: 'warning',
        title: `Long-lived token (${hours}h)`,
        detail: 'Token lifetime exceeds 24 hours. Short-lived tokens with refresh are more secure.',
      });
    }
  }

  // Missing audience
  if (payload.aud === undefined) {
    findings.push({
      id: 'no-aud',
      severity: 'info',
      title: 'No audience claim (aud)',
      detail: 'Without an audience, this token could be replayed to unintended services.',
    });
  }

  // Missing issuer
  if (payload.iss === undefined) {
    findings.push({
      id: 'no-iss',
      severity: 'info',
      title: 'No issuer claim (iss)',
      detail: 'Without an issuer, the token origin cannot be verified.',
    });
  }

  // Not yet valid
  if (typeof payload.nbf === 'number' && now < payload.nbf) {
    findings.push({
      id: 'not-yet-valid',
      severity: 'info',
      title: 'Token is not yet valid',
      detail: `Valid from ${formatTimestamp(payload.nbf)}. This token cannot be used yet.`,
    });
  }

  return findings;
}

/**
 * Compute a security grade (A–F) from audit findings
 */
export function computeGrade(findings) {
  let score = 100;

  for (const f of findings) {
    if (f.severity === 'critical') score -= 40;
    else if (f.severity === 'warning') score -= 15;
    else if (f.severity === 'info') score -= 5;
  }

  score = Math.max(0, score);

  if (score >= 90) return { grade: 'A', score, color: 'text-emerald-400', bg: 'border-emerald-500/30', label: 'Excellent' };
  if (score >= 75) return { grade: 'B', score, color: 'text-blue-400', bg: 'border-blue-500/30', label: 'Good' };
  if (score >= 60) return { grade: 'C', score, color: 'text-yellow-400', bg: 'border-yellow-500/30', label: 'Fair' };
  if (score >= 40) return { grade: 'D', score, color: 'text-orange-400', bg: 'border-orange-500/30', label: 'Poor' };
  return { grade: 'F', score, color: 'text-red-400', bg: 'border-red-500/30', label: 'Critical' };
}

/**
 * Get algorithm info
 */
export function getAlgorithmInfo(alg) {
  if (!alg || alg.toLowerCase() === 'none') {
    return ALG_SECURITY.none;
  }
  return ALG_SECURITY[alg] || { strength: 'unknown', label: `Unknown algorithm: ${alg}` };
}

/**
 * Full decode + analysis pipeline
 */
export function analyzeJWT(token) {
  const decoded = decodeJWT(token);
  const expiry = checkExpiry(decoded.payload);
  const claims = inspectClaims(decoded.payload);
  const audit = securityAudit(decoded.header, decoded.payload);
  const grade = computeGrade(audit);
  const algInfo = getAlgorithmInfo(decoded.header.alg);

  return { ...decoded, expiry, claims, audit, grade, algInfo };
}
