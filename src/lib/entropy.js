// Shannon entropy calculator for secret detection
// Used by secret-scanner.js to flag high-entropy strings

/**
 * Calculate Shannon entropy of a string in bits per character.
 * @param {string} str
 * @returns {number}
 */
export function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Patterns to skip for entropy analysis (too many false positives)
const SKIP_PATTERNS = [
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i, // UUID
  /^[0-9a-f]{32}$/i,  // MD5
  /^[0-9a-f]{40}$/i,  // SHA-1
  /^[0-9a-f]{64}$/i,  // SHA-256
  /^(\/|\.\/|\.\.\/|[a-zA-Z]:\\)/, // File paths
  /^https?:\/\/[^:@]*$/,           // URLs without credentials
  /^[a-zA-Z][a-zA-Z0-9_.-]*\.[a-zA-Z]{2,}$/, // Domain names
];

/**
 * Check if a string should be skipped for entropy analysis.
 * @param {string} str
 * @returns {boolean}
 */
export function shouldSkipEntropy(str) {
  return SKIP_PATTERNS.some(p => p.test(str));
}
