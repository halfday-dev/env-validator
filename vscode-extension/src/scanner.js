// Adapted from halfday-dev/env-validator src/lib/scanner.js
// Self-contained copy for the VS Code extension

const patterns = [
  { name: 'AWS Access Key ID', regex: /(?:^|['"= ])?(AKIA[0-9A-Z]{16})(?:['"\s]|$)/, severity: 'critical', desc: 'AWS access key detected', fix: 'Rotate this key immediately in AWS IAM console and use environment-specific credentials.' },
  { name: 'AWS Secret Access Key', regex: /(?:aws_secret_access_key|aws_secret)\s*=\s*['"]?([A-Za-z0-9/+=]{40})['"]?/, severity: 'critical', desc: 'AWS secret key detected', fix: 'Rotate in AWS IAM. Use IAM roles or AWS Secrets Manager instead.' },
  { name: 'Stripe Secret Key', regex: /sk_live_[0-9a-zA-Z]{24,}/, severity: 'critical', desc: 'Stripe live secret key detected', fix: 'Rotate in Stripe Dashboard → API Keys. Use restricted keys with minimal permissions.' },
  { name: 'Stripe Publishable Key', regex: /pk_live_[0-9a-zA-Z]{24,}/, severity: 'info', desc: 'Stripe publishable key (safe for client-side, but keep out of repos)', fix: 'Publishable keys are designed for client use but should still be in env vars.' },
  { name: 'GitHub Personal Access Token', regex: /ghp_[0-9a-zA-Z]{36}/, severity: 'critical', desc: 'GitHub PAT detected', fix: 'Revoke at GitHub Settings → Developer Settings → Personal Access Tokens.' },
  { name: 'GitHub OAuth Token', regex: /gho_[0-9a-zA-Z]{36}/, severity: 'critical', desc: 'GitHub OAuth token detected', fix: 'Revoke at GitHub Settings → Applications.' },
  { name: 'GitHub App Token', regex: /(?:ghu|ghs)_[0-9a-zA-Z]{36}/, severity: 'critical', desc: 'GitHub App token detected', fix: 'Rotate via your GitHub App settings.' },
  { name: 'GitHub Fine-grained PAT', regex: /github_pat_[0-9a-zA-Z_]{82}/, severity: 'critical', desc: 'GitHub fine-grained PAT detected', fix: 'Revoke at GitHub Settings → Developer Settings.' },
  { name: 'OpenAI API Key', regex: /sk-[0-9a-zA-Z]{20}T3BlbkFJ[0-9a-zA-Z]{20}/, severity: 'critical', desc: 'OpenAI API key detected', fix: 'Rotate at platform.openai.com/api-keys. Set usage limits.' },
  { name: 'OpenAI API Key (new format)', regex: /sk-proj-[0-9a-zA-Z_-]{40,}/, severity: 'critical', desc: 'OpenAI project API key detected', fix: 'Rotate at platform.openai.com/api-keys.' },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/, severity: 'critical', desc: 'Google API key detected', fix: 'Restrict key in Google Cloud Console → APIs & Services → Credentials.' },
  { name: 'Google OAuth Client Secret', regex: /GOCSPX-[0-9A-Za-z_-]{28}/, severity: 'critical', desc: 'Google OAuth client secret detected', fix: 'Rotate in Google Cloud Console → OAuth 2.0 Client IDs.' },
  { name: 'Slack Bot Token', regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24}/, severity: 'critical', desc: 'Slack bot token detected', fix: 'Rotate at api.slack.com → Your Apps → OAuth & Permissions.' },
  { name: 'Slack User Token', regex: /xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}/, severity: 'critical', desc: 'Slack user token detected', fix: 'Rotate at api.slack.com → Your Apps → OAuth & Permissions.' },
  { name: 'Slack Webhook URL', regex: /hooks\.slack\.com\/services\/T[0-9A-Z]{8,}\/B[0-9A-Z]{8,}\/[0-9a-zA-Z]{24}/, severity: 'warning', desc: 'Slack webhook URL detected', fix: 'Rotate the webhook in your Slack app settings.' },
  { name: 'Twilio Account SID', regex: /AC[0-9a-f]{32}/, severity: 'warning', desc: 'Twilio Account SID detected', fix: 'SIDs are semi-public but should still be in env vars.' },
  { name: 'Twilio Auth Token', regex: /(?:twilio.*auth.*token|TWILIO_AUTH_TOKEN)\s*=\s*['"]?([0-9a-f]{32})['"]?/i, severity: 'critical', desc: 'Twilio auth token detected', fix: 'Rotate in Twilio Console → Account → API Keys.' },
  { name: 'SendGrid API Key', regex: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/, severity: 'critical', desc: 'SendGrid API key detected', fix: 'Rotate at app.sendgrid.com → Settings → API Keys.' },
  { name: 'Mailgun API Key', regex: /key-[0-9a-zA-Z]{32}/, severity: 'critical', desc: 'Mailgun API key detected', fix: 'Rotate in Mailgun Dashboard → API Security.' },
  { name: 'New Relic API Key', regex: /NRAK-[0-9A-Z]{27}/, severity: 'critical', desc: 'New Relic API key detected', fix: 'Rotate at one.newrelic.com → API Keys.' },
  { name: 'Sentry DSN', regex: /https:\/\/[0-9a-f]{32}@(?:o\d+\.)?(?:sentry\.io|[^/]+)\/\d+/, severity: 'warning', desc: 'Sentry DSN detected (contains project info)', fix: 'DSNs are semi-public for client SDKs but should not be committed.' },
  { name: 'Supabase Service Role Key', regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}/, severity: 'critical', desc: 'Supabase/JWT service key detected', fix: 'Rotate in Supabase Dashboard → Settings → API.' },
  { name: 'DigitalOcean Token', regex: /dop_v1_[0-9a-f]{64}/, severity: 'critical', desc: 'DigitalOcean personal access token detected', fix: 'Revoke at cloud.digitalocean.com → API → Tokens.' },
  { name: 'npm Token', regex: /npm_[0-9a-zA-Z]{36}/, severity: 'critical', desc: 'npm access token detected', fix: 'Revoke at npmjs.com → Access Tokens. Use granular tokens.' },
  { name: 'GitLab Token', regex: /glpat-[0-9a-zA-Z_-]{20}/, severity: 'critical', desc: 'GitLab personal access token detected', fix: 'Revoke at GitLab → User Settings → Access Tokens.' },
  { name: 'Private Key (PEM)', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, severity: 'critical', desc: 'Private key detected in env file', fix: 'Never store private keys in .env files. Use a secrets manager or key vault.' },
  { name: 'Database URL with Password', regex: /(?:postgres(?:ql)?|mysql|mariadb|mssql):\/\/[^:]+:[^@\s]+@[^\s]+/, severity: 'critical', desc: 'Database connection string with embedded password', fix: 'Use separate DB_HOST/DB_PASSWORD vars or a secrets manager.' },
  { name: 'Redis URL with Password', regex: /rediss?:\/\/[^:]*:[^@\s]+@[^\s]+/, severity: 'critical', desc: 'Redis URL with embedded password', fix: 'Use separate REDIS_HOST/REDIS_PASSWORD environment variables.' },
  { name: 'MongoDB URI with Password', regex: /mongodb(?:\+srv)?:\/\/[^:]+:[^@\s]+@[^\s]+/, severity: 'critical', desc: 'MongoDB connection string with embedded password', fix: 'Use MongoDB Atlas secrets or separate DB credential vars.' },
  { name: 'Discord Bot Token', regex: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/, severity: 'critical', desc: 'Discord bot token detected', fix: 'Regenerate at discord.com/developers → Bot → Reset Token.' },
  { name: 'Anthropic API Key', regex: /sk-ant-api\d{2}-[0-9a-zA-Z_-]{90,}/, severity: 'critical', desc: 'Anthropic API key detected', fix: 'Rotate at console.anthropic.com → API Keys.' },
  { name: 'Hugging Face Token', regex: /hf_[0-9a-zA-Z]{34}/, severity: 'critical', desc: 'Hugging Face access token detected', fix: 'Rotate at huggingface.co → Settings → Access Tokens.' },
  { name: 'Linear API Key', regex: /lin_api_[0-9a-zA-Z]{40}/, severity: 'critical', desc: 'Linear API key detected', fix: 'Revoke at linear.app → Settings → API.' },
  { name: 'Generic Secret in Value', regex: /(?:secret|password|passwd|token|apikey|api_key|auth_token|access_token)[\w]*\s*=\s*['"]?([^\s'"]{8,})['"]?/i, severity: 'warning', desc: 'Potential secret value detected', fix: 'Review this value and ensure it is not committed to version control.' },
];

const weakPasswords = ['password', 'password1', 'password123', '123456', '12345678', '123456789', '1234567890', 'admin', 'admin123', 'root', 'root123', 'test', 'test123', 'changeme', 'changeit', 'default', 'secret', 'letmein', 'welcome', 'qwerty', 'abc123', 'monkey', 'master', 'dragon', 'login', 'princess', 'football', 'shadow', 'sunshine', 'trustno1', 'iloveyou', 'batman', 'passw0rd', 'hello', 'charlie', 'donald', 'p@ssw0rd', 'P@ssw0rd', 'P@ssword1', 'supersecret', 'hunter2', 'letmein123'];

function analyze(text) {
  if (!text.trim()) return [];
  const lines = text.split('\n');
  const findings = [];
  const keys = {};
  let lineNum = 0;

  for (const line of lines) {
    lineNum++;
    const trimmed = line.trim();
    if (!trimmed) continue;

    if (trimmed.startsWith('#')) {
      const uncommented = trimmed.slice(1).trim();
      for (const p of patterns) {
        if (p.regex.test(uncommented)) {
          findings.push({ line: lineNum, severity: 'warning', name: `Commented-out ${p.name}`, desc: `Commented line still contains a ${p.name.toLowerCase()}. Remove it entirely.`, fix: 'Delete commented-out secrets completely rather than just commenting them.' });
          break;
        }
      }
      continue;
    }

    const match = trimmed.match(/^([^=]+?)=(.*)$/);
    if (!match) continue;
    const [, key, value] = match;
    const cleanKey = key.trim();
    const cleanVal = value.trim();

    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(cleanKey)) {
      findings.push({ line: lineNum, severity: 'warning', name: 'Invalid key name', desc: `"${cleanKey}" contains invalid characters.`, fix: 'Use only A-Z, 0-9, and underscore. Start with a letter or underscore.' });
    }

    if (keys[cleanKey]) {
      findings.push({ line: lineNum, severity: 'warning', name: 'Duplicate key', desc: `"${cleanKey}" is defined on lines ${keys[cleanKey]} and ${lineNum}.`, fix: 'Remove the duplicate definition to avoid confusion.' });
    }
    keys[cleanKey] = lineNum;

    if (cleanVal === '') {
      findings.push({ line: lineNum, severity: 'info', name: 'Empty value', desc: `"${cleanKey}" has an empty value.`, fix: 'Set a value or remove the variable if unused.' });
      continue;
    }

    if (cleanVal.includes(' ') && !cleanVal.startsWith('"') && !cleanVal.startsWith("'")) {
      findings.push({ line: lineNum, severity: 'warning', name: 'Unquoted value with spaces', desc: `"${cleanKey}" contains spaces but is not quoted.`, fix: 'Wrap the value in double quotes: KEY="value with spaces"' });
    }

    const lowerVal = cleanVal.replace(/^['"]|['"]$/g, '').toLowerCase();
    if (/(?:password|passwd|pass|secret|key|token)/i.test(cleanKey) && weakPasswords.includes(lowerVal)) {
      findings.push({ line: lineNum, severity: 'critical', name: 'Weak/default password', desc: `"${cleanKey}" uses a common weak password: "${lowerVal}".`, fix: 'Use a strong, randomly generated password (32+ characters, mixed case, numbers, symbols).' });
    }

    for (const p of patterns) {
      if (p.regex.test(trimmed)) {
        findings.push({ line: lineNum, severity: p.severity, name: p.name, desc: p.desc, fix: p.fix });
      }
    }
  }

  return findings;
}

function computeScore(findings) {
  const crits = findings.filter(f => f.severity === 'critical').length;
  const warns = findings.filter(f => f.severity === 'warning').length;
  const score = Math.max(0, 100 - crits * 15 - warns * 5);
  if (score >= 90) return { grade: 'A', label: 'Excellent', score };
  if (score >= 75) return { grade: 'B', label: 'Good', score };
  if (score >= 60) return { grade: 'C', label: 'Fair', score };
  if (score >= 40) return { grade: 'D', label: 'Poor', score };
  return { grade: 'F', label: 'Critical', score };
}

module.exports = { analyze, computeScore, patterns, weakPasswords };
