// Secret Scanner — core detection engine
// Scans arbitrary text (code, logs, configs) for leaked secrets and credentials

import { shannonEntropy, shouldSkipEntropy } from './entropy.js';

/**
 * @typedef {Object} Finding
 * @property {number} line - 1-indexed line number
 * @property {number} startCol - 0-indexed start column
 * @property {number} endCol - 0-indexed end column (exclusive)
 * @property {string} matchedText - The actual matched string
 * @property {string} name - Pattern name
 * @property {'critical'|'warning'} severity
 * @property {string} fix - Remediation advice
 */

/**
 * @typedef {Object} ScanResult
 * @property {Finding[]} findings
 * @property {{ critical: number, warning: number }} counts
 * @property {string} redactedText
 * @property {number} scanTimeMs
 */

// Patterns adapted for free-text scanning (no KEY= prefix required)
const SECRET_PATTERNS = [
  // AWS
  { name: 'AWS Access Key ID', regex: /\b(AKIA[0-9A-Z]{16})\b/g, severity: 'critical', fix: 'Rotate immediately in AWS IAM console. Use IAM roles or environment variables.' },
  { name: 'AWS Secret Access Key', regex: /(?:aws_secret_access_key|aws_secret|secret_access_key)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi, severity: 'critical', fix: 'Rotate in AWS IAM. Use IAM roles or AWS Secrets Manager.' },

  // GitHub
  { name: 'GitHub Personal Access Token', regex: /\b(ghp_[0-9a-zA-Z]{36})\b/g, severity: 'critical', fix: 'Revoke at GitHub Settings → Developer Settings → Personal Access Tokens.' },
  { name: 'GitHub OAuth Token', regex: /\b(gho_[0-9a-zA-Z]{36})\b/g, severity: 'critical', fix: 'Revoke at GitHub Settings → Applications.' },
  { name: 'GitHub App Token', regex: /\b(gh[us]_[0-9a-zA-Z]{36})\b/g, severity: 'critical', fix: 'Rotate via your GitHub App settings.' },
  { name: 'GitHub Fine-grained PAT', regex: /\b(github_pat_[0-9a-zA-Z_]{82})\b/g, severity: 'critical', fix: 'Revoke at GitHub Settings → Developer Settings.' },

  // OpenAI
  { name: 'OpenAI API Key', regex: /\b(sk-[0-9a-zA-Z]{20}T3BlbkFJ[0-9a-zA-Z]{20})\b/g, severity: 'critical', fix: 'Rotate at platform.openai.com/api-keys. Set usage limits.' },
  { name: 'OpenAI API Key (new)', regex: /\b(sk-proj-[0-9a-zA-Z_-]{40,})\b/g, severity: 'critical', fix: 'Rotate at platform.openai.com/api-keys.' },

  // Stripe
  { name: 'Stripe Secret Key', regex: /\b(sk_live_[0-9a-zA-Z]{24,})\b/g, severity: 'critical', fix: 'Rotate in Stripe Dashboard → API Keys. Use restricted keys.' },
  { name: 'Stripe Publishable Key', regex: /\b(pk_live_[0-9a-zA-Z]{24,})\b/g, severity: 'warning', fix: 'Publishable keys are client-safe but should still be in env vars.' },
  { name: 'Stripe Restricted Key', regex: /\b(rk_live_[0-9a-zA-Z]{24,})\b/g, severity: 'critical', fix: 'Rotate in Stripe Dashboard → API Keys.' },

  // Slack
  { name: 'Slack Bot Token', regex: /\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24})\b/g, severity: 'critical', fix: 'Rotate at api.slack.com → Your Apps → OAuth & Permissions.' },
  { name: 'Slack User Token', regex: /\b(xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,})\b/g, severity: 'critical', fix: 'Rotate at api.slack.com → Your Apps → OAuth & Permissions.' },
  { name: 'Slack App Token', regex: /\b(xoxe\.xoxp-[0-9a-zA-Z-]+)\b/g, severity: 'critical', fix: 'Rotate at api.slack.com → Your Apps.' },
  { name: 'Slack Webhook URL', regex: /(hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9a-zA-Z]{24})/g, severity: 'warning', fix: 'Rotate the webhook in your Slack app settings.' },

  // Google
  { name: 'Google API Key', regex: /\b(AIzaSy[0-9A-Za-z_-]{33})\b/g, severity: 'critical', fix: 'Restrict key in Google Cloud Console → APIs & Services → Credentials.' },
  { name: 'Google OAuth Client Secret', regex: /\b(GOCSPX-[0-9A-Za-z_-]{28})\b/g, severity: 'critical', fix: 'Rotate in Google Cloud Console → OAuth 2.0 Client IDs.' },

  // SendGrid
  { name: 'SendGrid API Key', regex: /\b(SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43})\b/g, severity: 'critical', fix: 'Rotate at app.sendgrid.com → Settings → API Keys.' },

  // npm / PyPI / Docker
  { name: 'npm Token', regex: /\b(npm_[0-9a-zA-Z]{36})\b/g, severity: 'critical', fix: 'Revoke at npmjs.com → Access Tokens.' },
  { name: 'PyPI Token', regex: /\b(pypi-[0-9a-zA-Z_-]{50,})\b/g, severity: 'critical', fix: 'Revoke at pypi.org → Account Settings → API Tokens.' },
  { name: 'Docker Hub Token', regex: /\b(dckr_pat_[0-9a-zA-Z_-]{20,})\b/g, severity: 'critical', fix: 'Revoke at hub.docker.com → Account Settings → Security.' },

  // GitLab
  { name: 'GitLab Token', regex: /\b(glpat-[0-9a-zA-Z_-]{20})\b/g, severity: 'critical', fix: 'Revoke at GitLab → User Settings → Access Tokens.' },
  { name: 'GitLab Pipeline Token', regex: /\b(glptt-[0-9a-f]{40})\b/g, severity: 'critical', fix: 'Revoke in GitLab → CI/CD → Pipeline triggers.' },

  // Private keys
  { name: 'Private Key (PEM)', regex: /(-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)/g, severity: 'critical', fix: 'Never store private keys in code. Use a secrets manager or key vault.' },

  // Database URLs
  { name: 'Database URL with Password', regex: /((?:postgres(?:ql)?|mysql|mariadb|mssql):\/\/[^:\s]+:[^@\s]+@[^\s]+)/g, severity: 'critical', fix: 'Use separate DB_HOST/DB_PASSWORD vars or a secrets manager.' },
  { name: 'Redis URL with Password', regex: /(rediss?:\/\/[^:]*:[^@\s]+@[^\s]+)/g, severity: 'critical', fix: 'Use separate REDIS_HOST/REDIS_PASSWORD environment variables.' },
  { name: 'MongoDB URI with Password', regex: /(mongodb(?:\+srv)?:\/\/[^:\s]+:[^@\s]+@[^\s]+)/g, severity: 'critical', fix: 'Use MongoDB Atlas secrets or separate credential vars.' },

  // Basic auth in URLs
  { name: 'Basic Auth in URL', regex: /(https?:\/\/[^:\s]+:[^@\s]+@[^\s]+)/g, severity: 'critical', fix: 'Remove credentials from URLs. Use environment variables or a secrets manager.' },

  // Bearer tokens
  { name: 'Bearer Token', regex: /(?:Authorization|authorization)\s*[:=]\s*['"]?(Bearer\s+[A-Za-z0-9_.-]{20,})['"]?/g, severity: 'critical', fix: 'Remove hardcoded bearer tokens. Use runtime token injection.' },

  // HashiCorp Vault
  { name: 'HashiCorp Vault Token', regex: /\b(hvs\.[0-9a-zA-Z_-]{24,})\b/g, severity: 'critical', fix: 'Revoke in Vault and generate a new token.' },

  // Cloud providers
  { name: 'DigitalOcean Token', regex: /\b(dop_v1_[0-9a-f]{64})\b/g, severity: 'critical', fix: 'Revoke at cloud.digitalocean.com → API → Tokens.' },

  // Anthropic
  { name: 'Anthropic API Key', regex: /\b(sk-ant-api\d{2}-[0-9a-zA-Z_-]{90,})\b/g, severity: 'critical', fix: 'Rotate at console.anthropic.com → API Keys.' },

  // Hugging Face
  { name: 'Hugging Face Token', regex: /\b(hf_[0-9a-zA-Z]{34})\b/g, severity: 'critical', fix: 'Rotate at huggingface.co → Settings → Access Tokens.' },

  // Shopify
  { name: 'Shopify Access Token', regex: /\b(shpat_[0-9a-fA-F]{32})\b/g, severity: 'critical', fix: 'Rotate in Shopify Admin → Apps → Develop apps.' },
  { name: 'Shopify Shared Secret', regex: /\b(shpss_[0-9a-fA-F]{32})\b/g, severity: 'critical', fix: 'Rotate in Shopify Partner Dashboard.' },

  // Discord
  { name: 'Discord Bot Token', regex: /\b([MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,})\b/g, severity: 'critical', fix: 'Regenerate at discord.com/developers → Bot → Reset Token.' },

  // Telegram
  { name: 'Telegram Bot Token', regex: /\b(\d{8,10}:[0-9A-Za-z_-]{35})\b/g, severity: 'critical', fix: 'Revoke via @BotFather on Telegram.' },

  // Twilio
  { name: 'Twilio Account SID', regex: /\b(AC[0-9a-f]{32})\b/g, severity: 'warning', fix: 'SIDs are semi-public but should still be in env vars.' },

  // Sentry
  { name: 'Sentry DSN', regex: /(https:\/\/[0-9a-f]{32}@(?:o\d+\.)?(?:sentry\.io|[^/\s]+)\/\d+)/g, severity: 'warning', fix: 'DSNs are semi-public for client SDKs but should not be committed.' },

  // Mailgun
  { name: 'Mailgun API Key', regex: /\b(key-[0-9a-zA-Z]{32})\b/g, severity: 'critical', fix: 'Rotate in Mailgun Dashboard → API Security.' },

  // New Relic
  { name: 'New Relic API Key', regex: /\b(NRAK-[0-9A-Z]{27})\b/g, severity: 'critical', fix: 'Rotate at one.newrelic.com → API Keys.' },

  // Linear
  { name: 'Linear API Key', regex: /\b(lin_api_[0-9a-zA-Z]{40})\b/g, severity: 'critical', fix: 'Revoke at linear.app → Settings → API.' },

  // Resend
  { name: 'Resend API Key', regex: /\b(re_[0-9a-zA-Z]{20,})\b/g, severity: 'critical', fix: 'Rotate at resend.com → API Keys.' },

  // PlanetScale
  { name: 'PlanetScale Password', regex: /\b(pscale_pw_[0-9a-zA-Z_-]{40,})\b/g, severity: 'critical', fix: 'Rotate in PlanetScale Dashboard → Database → Passwords.' },

  // Mapbox
  { name: 'Mapbox Token', regex: /\b((?:pk|sk)\.eyJ[0-9a-zA-Z_-]+\.[0-9a-zA-Z_-]{20,})\b/g, severity: 'warning', fix: 'Rotate at mapbox.com → Account → Tokens.' },

  // Generic password/secret assignments
  { name: 'Generic Secret Assignment', regex: /(?:password|passwd|secret|token|apikey|api_key|auth_token|access_token|private_key)\s*[=:]\s*['"]?([^\s'"]{8,})['"]?/gi, severity: 'warning', fix: 'Review this value — ensure it is not a real credential committed to source control.' },
];

const MAX_FINDINGS = 500;

/**
 * Scan arbitrary text for secrets and credentials.
 * @param {string} text
 * @returns {ScanResult}
 */
export function scan(text) {
  const start = performance.now();
  const findings = [];
  const lines = text.split('\n');
  const seen = new Set(); // dedup: "line:startCol:name"

  // Pattern matching
  for (let i = 0; i < lines.length && findings.length < MAX_FINDINGS; i++) {
    const line = lines[i];
    for (const pattern of SECRET_PATTERNS) {
      // Reset regex lastIndex for global regexes
      pattern.regex.lastIndex = 0;
      let match;
      while ((match = pattern.regex.exec(line)) !== null) {
        const matched = match[1] || match[0];
        const startCol = match.index;
        const key = `${i + 1}:${startCol}:${pattern.name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          line: i + 1,
          startCol,
          endCol: startCol + matched.length,
          matchedText: matched,
          name: pattern.name,
          severity: pattern.severity,
          fix: pattern.fix,
        });
        if (findings.length >= MAX_FINDINGS) break;
      }
    }
  }

  // Entropy analysis for unrecognized high-entropy strings
  if (findings.length < MAX_FINDINGS) {
    const valueRegex = /(?:[=:]\s*['"]?|['"])([A-Za-z0-9+/=_-]{16,})(?:['"]|\s|$)/g;
    for (let i = 0; i < lines.length && findings.length < MAX_FINDINGS; i++) {
      const line = lines[i];
      valueRegex.lastIndex = 0;
      let match;
      while ((match = valueRegex.exec(line)) !== null) {
        const val = match[1];
        if (val.length < 16 || val.length > 500) continue;
        if (shouldSkipEntropy(val)) continue;

        // Skip if already caught by pattern matching
        const alreadyCaught = findings.some(
          f => f.line === i + 1 && val.includes(f.matchedText.substring(0, 16))
        );
        if (alreadyCaught) continue;

        const entropy = shannonEntropy(val);
        if (entropy > 4.5) {
          const startCol = match.index + match[0].indexOf(val);
          const key = `${i + 1}:${startCol}:entropy`;
          if (seen.has(key)) continue;
          seen.add(key);
          findings.push({
            line: i + 1,
            startCol,
            endCol: startCol + val.length,
            matchedText: val.length > 60 ? val.substring(0, 57) + '...' : val,
            name: entropy > 5.0 ? 'High Entropy String' : 'Suspicious Entropy String',
            severity: entropy > 5.0 ? 'critical' : 'warning',
            fix: 'Verify this isn\'t a secret. High-entropy strings may be API keys or tokens.',
          });
          if (findings.length >= MAX_FINDINGS) break;
        }
      }
    }
  }

  // Sort: critical first, then by line number
  findings.sort((a, b) => {
    if (a.severity !== b.severity) return a.severity === 'critical' ? -1 : 1;
    return a.line - b.line;
  });

  const counts = {
    critical: findings.filter(f => f.severity === 'critical').length,
    warning: findings.filter(f => f.severity === 'warning').length,
  };

  const scanTimeMs = Math.round(performance.now() - start);

  return {
    findings,
    counts,
    redactedText: redact(text, findings),
    scanTimeMs,
    capped: findings.length >= MAX_FINDINGS,
  };
}

/**
 * Generate redacted copy with secrets masked.
 * Preserves recognizable prefix (4-8 chars) for context.
 * @param {string} text
 * @param {Finding[]} findings
 * @returns {string}
 */
export function redact(text, findings) {
  if (!findings.length) return text;
  const lines = text.split('\n');

  // Group findings by line
  const byLine = {};
  for (const f of findings) {
    if (!byLine[f.line]) byLine[f.line] = [];
    byLine[f.line].push(f);
  }

  for (const [lineNum, lineFindings] of Object.entries(byLine)) {
    const idx = parseInt(lineNum) - 1;
    let line = lines[idx];
    // Process findings right-to-left so indices stay valid
    const sorted = [...lineFindings].sort((a, b) => b.startCol - a.startCol);
    for (const f of sorted) {
      const matched = f.matchedText;
      const pos = line.indexOf(matched);
      if (pos === -1) continue;
      // Determine prefix length to keep
      let prefixLen = 0;
      if (/^(AKIA|sk_live_|pk_live_|rk_live_|ghp_|gho_|ghu_|ghs_|sk-proj-|sk-ant-|xoxb-|xoxp-|SG\.|npm_|glpat-|shpat_|shpss_|hf_|hvs\.|dop_v1_|re_|lin_api_)/i.test(matched)) {
        prefixLen = Math.min(8, matched.indexOf('_', 3) + 1 || 4);
      } else if (matched.startsWith('-----BEGIN')) {
        prefixLen = 0;
      } else {
        prefixLen = Math.min(4, matched.length);
      }
      const prefix = matched.substring(0, prefixLen);
      const redacted = prefix + '****REDACTED****';
      line = line.substring(0, pos) + redacted + line.substring(pos + matched.length);
    }
    lines[idx] = line;
  }

  return lines.join('\n');
}
