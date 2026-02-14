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
  { name: 'Datadog API Key', regex: /(?:datadog|dd)[\w_]*(?:api)?[\w_]*key\s*=\s*['"]?([0-9a-f]{32})['"]?/i, severity: 'critical', desc: 'Datadog API key detected', fix: 'Rotate in Datadog → Organization Settings → API Keys.' },
  { name: 'New Relic API Key', regex: /NRAK-[0-9A-Z]{27}/, severity: 'critical', desc: 'New Relic API key detected', fix: 'Rotate at one.newrelic.com → API Keys.' },
  { name: 'New Relic License Key', regex: /[0-9a-f]{36}NRAL/, severity: 'critical', desc: 'New Relic license key detected', fix: 'Rotate in New Relic account settings.' },
  { name: 'PagerDuty API Key', regex: /(?:pagerduty|pd)[\w_]*key\s*=\s*['"]?([0-9a-zA-Z+/=]{20,})['"]?/i, severity: 'critical', desc: 'PagerDuty key detected', fix: 'Rotate at PagerDuty → API Access Keys.' },
  { name: 'Sentry DSN', regex: /https:\/\/[0-9a-f]{32}@(?:o\d+\.)?(?:sentry\.io|[^/]+)\/\d+/, severity: 'warning', desc: 'Sentry DSN detected (contains project info)', fix: 'DSNs are semi-public for client SDKs but should not be committed.' },
  { name: 'Firebase API Key', regex: /(?:firebase|FIREBASE)[\w_]*(?:api)?[\w_]*key\s*=\s*['"]?(AIza[0-9A-Za-z_-]{35})['"]?/i, severity: 'warning', desc: 'Firebase API key detected', fix: 'Restrict via Firebase Console → Project Settings → API restrictions.' },
  { name: 'Supabase Service Role Key', regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}/, severity: 'critical', desc: 'Supabase/JWT service key detected', fix: 'Rotate in Supabase Dashboard → Settings → API.' },
  { name: 'Cloudflare API Token', regex: /(?:cloudflare|cf)[\w_]*(?:api)?[\w_]*token\s*=\s*['"]?([0-9a-zA-Z_-]{40})['"]?/i, severity: 'critical', desc: 'Cloudflare API token detected', fix: 'Rotate at Cloudflare Dashboard → My Profile → API Tokens.' },
  { name: 'Cloudflare Global API Key', regex: /(?:cloudflare|cf)[\w_]*(?:global)?[\w_]*key\s*=\s*['"]?([0-9a-f]{37})['"]?/i, severity: 'critical', desc: 'Cloudflare Global API key detected', fix: 'Use scoped API tokens instead. Rotate in Cloudflare profile.' },
  { name: 'DigitalOcean Token', regex: /dop_v1_[0-9a-f]{64}/, severity: 'critical', desc: 'DigitalOcean personal access token detected', fix: 'Revoke at cloud.digitalocean.com → API → Tokens.' },
  { name: 'DigitalOcean OAuth', regex: /doo_v1_[0-9a-f]{64}/, severity: 'critical', desc: 'DigitalOcean OAuth token detected', fix: 'Revoke at cloud.digitalocean.com → API.' },
  { name: 'Heroku API Key', regex: /(?:heroku[\w_]*(?:api)?[\w_]*key)\s*=\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?/i, severity: 'critical', desc: 'Heroku API key detected', fix: 'Regenerate at Heroku Dashboard → Account → API Key.' },
  { name: 'Vercel Token', regex: /(?:vercel[\w_]*token)\s*=\s*['"]?([0-9a-zA-Z]{24,})['"]?/i, severity: 'critical', desc: 'Vercel token detected', fix: 'Rotate at vercel.com → Settings → Tokens.' },
  { name: 'Netlify Token', regex: /(?:netlify[\w_]*token)\s*=\s*['"]?([0-9a-zA-Z_-]{40,})['"]?/i, severity: 'critical', desc: 'Netlify token detected', fix: 'Rotate at app.netlify.com → User Settings → Applications.' },
  { name: 'npm Token', regex: /npm_[0-9a-zA-Z]{36}/, severity: 'critical', desc: 'npm access token detected', fix: 'Revoke at npmjs.com → Access Tokens. Use granular tokens.' },
  { name: 'PyPI Token', regex: /pypi-[0-9a-zA-Z_-]{50,}/, severity: 'critical', desc: 'PyPI API token detected', fix: 'Revoke at pypi.org → Account Settings → API Tokens.' },
  { name: 'Docker Hub Token', regex: /dckr_pat_[0-9a-zA-Z_-]{20,}/, severity: 'critical', desc: 'Docker Hub personal access token detected', fix: 'Revoke at hub.docker.com → Account Settings → Security.' },
  { name: 'CircleCI Token', regex: /(?:circleci|circle)[\w_]*token\s*=\s*['"]?([0-9a-f]{40})['"]?/i, severity: 'critical', desc: 'CircleCI token detected', fix: 'Rotate at circleci.com → User Settings → Personal API Tokens.' },
  { name: 'Travis CI Token', regex: /(?:travis[\w_]*token)\s*=\s*['"]?([0-9a-zA-Z]{22,})['"]?/i, severity: 'critical', desc: 'Travis CI token detected', fix: 'Rotate in Travis CI account settings.' },
  { name: 'GitLab Token', regex: /glpat-[0-9a-zA-Z_-]{20}/, severity: 'critical', desc: 'GitLab personal access token detected', fix: 'Revoke at GitLab → User Settings → Access Tokens.' },
  { name: 'GitLab Pipeline Token', regex: /glptt-[0-9a-f]{40}/, severity: 'critical', desc: 'GitLab pipeline trigger token detected', fix: 'Revoke in GitLab → CI/CD → Pipeline triggers.' },
  { name: 'Bitbucket App Password', regex: /(?:bitbucket[\w_]*(?:app)?[\w_]*(?:pass|pw))\s*=\s*['"]?([0-9a-zA-Z]{18,})['"]?/i, severity: 'critical', desc: 'Bitbucket app password detected', fix: 'Revoke at Bitbucket → Personal Settings → App Passwords.' },
  { name: 'Azure Storage Key', regex: /(?:DefaultEndpointsProtocol=https;AccountName=)[^;]+;AccountKey=[A-Za-z0-9+/=]{86,88};/, severity: 'critical', desc: 'Azure Storage connection string detected', fix: 'Rotate in Azure Portal → Storage Account → Access Keys.' },
  { name: 'Azure Client Secret', regex: /(?:azure[\w_]*(?:client)?[\w_]*secret)\s*=\s*['"]?([0-9a-zA-Z~._-]{34,})['"]?/i, severity: 'critical', desc: 'Azure client secret detected', fix: 'Rotate in Azure AD → App Registrations → Certificates & Secrets.' },
  { name: 'GCP Service Account Key', regex: /"private_key":\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----/, severity: 'critical', desc: 'GCP service account private key detected', fix: 'Delete and recreate at GCP Console → IAM → Service Accounts → Keys.' },
  { name: 'GCP API Key', regex: /(?:gcp|google_cloud)[\w_]*(?:api)?[\w_]*key\s*=\s*['"]?(AIza[0-9A-Za-z_-]{35})['"]?/i, severity: 'critical', desc: 'GCP API key detected', fix: 'Restrict in GCP Console → APIs & Services → Credentials.' },
  { name: 'Private Key (PEM)', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, severity: 'critical', desc: 'Private key detected in env file', fix: 'Never store private keys in .env files. Use a secrets manager or key vault.' },
  { name: 'JWT Secret', regex: /(?:jwt[\w_]*secret|secret[\w_]*key)\s*=\s*['"]?([^\s'"]{8,})['"]?/i, severity: 'warning', desc: 'JWT secret or signing key detected', fix: 'Use a strong, random secret (256+ bits). Store in a secrets manager.' },
  { name: 'Database URL with Password', regex: /(?:postgres(?:ql)?|mysql|mariadb|mssql):\/\/[^:]+:[^@\s]+@[^\s]+/, severity: 'critical', desc: 'Database connection string with embedded password', fix: 'Use separate DB_HOST/DB_PASSWORD vars or a secrets manager.' },
  { name: 'Redis URL with Password', regex: /rediss?:\/\/[^:]*:[^@\s]+@[^\s]+/, severity: 'critical', desc: 'Redis URL with embedded password', fix: 'Use separate REDIS_HOST/REDIS_PASSWORD environment variables.' },
  { name: 'MongoDB URI with Password', regex: /mongodb(?:\+srv)?:\/\/[^:]+:[^@\s]+@[^\s]+/, severity: 'critical', desc: 'MongoDB connection string with embedded password', fix: 'Use MongoDB Atlas secrets or separate DB credential vars.' },
  { name: 'Shopify Access Token', regex: /shpat_[0-9a-fA-F]{32}/, severity: 'critical', desc: 'Shopify admin access token detected', fix: 'Rotate in Shopify Admin → Apps → Develop apps.' },
  { name: 'Shopify Shared Secret', regex: /shpss_[0-9a-fA-F]{32}/, severity: 'critical', desc: 'Shopify shared secret detected', fix: 'Rotate in Shopify Partner Dashboard.' },
  { name: 'Discord Bot Token', regex: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/, severity: 'critical', desc: 'Discord bot token detected', fix: 'Regenerate at discord.com/developers → Bot → Reset Token.' },
  { name: 'Telegram Bot Token', regex: /\d{8,10}:[0-9A-Za-z_-]{35}/, severity: 'critical', desc: 'Telegram bot token detected', fix: 'Revoke via @BotFather on Telegram.' },
  { name: 'Anthropic API Key', regex: /sk-ant-api\d{2}-[0-9a-zA-Z_-]{90,}/, severity: 'critical', desc: 'Anthropic API key detected', fix: 'Rotate at console.anthropic.com → API Keys.' },
  { name: 'Hugging Face Token', regex: /hf_[0-9a-zA-Z]{34}/, severity: 'critical', desc: 'Hugging Face access token detected', fix: 'Rotate at huggingface.co → Settings → Access Tokens.' },
  { name: 'Mapbox Token', regex: /(?:pk|sk)\.eyJ[0-9a-zA-Z_-]+\.[0-9a-zA-Z_-]{20,}/, severity: 'warning', desc: 'Mapbox access token detected', fix: 'Rotate at mapbox.com → Account → Tokens. Restrict token scopes.' },
  { name: 'Algolia API Key', regex: /(?:algolia[\w_]*(?:api)?[\w_]*key)\s*=\s*['"]?([0-9a-f]{32})['"]?/i, severity: 'warning', desc: 'Algolia API key detected', fix: 'Use search-only keys for client-side. Rotate admin keys in Algolia Dashboard.' },
  { name: 'Mixpanel Token', regex: /(?:mixpanel[\w_]*token)\s*=\s*['"]?([0-9a-f]{32})['"]?/i, severity: 'warning', desc: 'Mixpanel project token detected', fix: 'Tokens are semi-public but should not be committed.' },
  { name: 'Segment Write Key', regex: /(?:segment[\w_]*(?:write)?[\w_]*key)\s*=\s*['"]?([0-9a-zA-Z]{22,})['"]?/i, severity: 'warning', desc: 'Segment write key detected', fix: 'Rotate in Segment → Workspace → Sources → Settings.' },
  { name: 'Linear API Key', regex: /lin_api_[0-9a-zA-Z]{40}/, severity: 'critical', desc: 'Linear API key detected', fix: 'Revoke at linear.app → Settings → API.' },
  { name: 'Livekit API Key/Secret', regex: /(?:livekit[\w_]*(?:api)?[\w_]*(?:key|secret))\s*=\s*['"]?([0-9a-zA-Z]{20,})['"]?/i, severity: 'critical', desc: 'LiveKit credential detected', fix: 'Rotate in your LiveKit Cloud dashboard.' },
  { name: 'Postmark Server Token', regex: /(?:postmark[\w_]*(?:server)?[\w_]*token)\s*=\s*['"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['"]?/i, severity: 'critical', desc: 'Postmark server token detected', fix: 'Rotate in Postmark → Servers → API Tokens.' },
  { name: 'Resend API Key', regex: /re_[0-9a-zA-Z]{20,}/, severity: 'critical', desc: 'Resend API key detected', fix: 'Rotate at resend.com → API Keys.' },
  { name: 'Planetscale Password', regex: /pscale_pw_[0-9a-zA-Z_-]{40,}/, severity: 'critical', desc: 'PlanetScale database password detected', fix: 'Rotate in PlanetScale Dashboard → Database → Passwords.' },
  { name: 'Turso Database Token', regex: /(?:turso|libsql)[\w_]*(?:auth)?[\w_]*token\s*=\s*['"]?(eyJ[0-9a-zA-Z_-]+\.[0-9a-zA-Z_-]+\.[0-9a-zA-Z_-]+)['"]?/i, severity: 'critical', desc: 'Turso/LibSQL auth token detected', fix: 'Rotate via turso CLI: turso db tokens invalidate.' },
  { name: 'Clerk Secret Key', regex: /sk_live_[0-9a-zA-Z]{20,}/, severity: 'critical', desc: 'Clerk secret key detected', fix: 'Rotate in Clerk Dashboard → API Keys.' },
  { name: 'Generic Secret in Value', regex: /(?:secret|password|passwd|token|apikey|api_key|auth_token|access_token)[\w]*\s*=\s*['"]?([^\s'"]{8,})['"]?/i, severity: 'warning', desc: 'Potential secret value detected', fix: 'Review this value and ensure it is not committed to version control.' },
];

const weakPasswords = ['password', 'password1', 'password123', '123456', '12345678', '123456789', '1234567890', 'admin', 'admin123', 'root', 'root123', 'test', 'test123', 'changeme', 'changeit', 'default', 'secret', 'letmein', 'welcome', 'qwerty', 'abc123', 'monkey', 'master', 'dragon', 'login', 'princess', 'football', 'shadow', 'sunshine', 'trustno1', 'iloveyou', 'batman', 'passw0rd', 'hello', 'charlie', 'donald', 'p@ssw0rd', 'P@ssw0rd', 'P@ssword1', 'supersecret', 'hunter2', 'letmein123'];

// Cache for last scan results (used by hover provider to avoid re-scanning)
let lastScanCache = new Map();

function getLastFindings(uri) {
  return lastScanCache.get(uri) || [];
}

function analyze(text, uri) {
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

    // Mismatched quotes detection (#12)
    if ((cleanVal.startsWith('"') && cleanVal.includes('\\"') === false && (cleanVal.match(/"/g) || []).length % 2 !== 0) ||
        (cleanVal.startsWith("'") && (cleanVal.match(/'/g) || []).length % 2 !== 0)) {
      findings.push({ line: lineNum, severity: 'warning', name: 'Mismatched quotes', desc: `"${cleanKey}" has mismatched quotes.`, fix: 'Ensure opening and closing quotes match.' });
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

  if (uri) {
    lastScanCache.set(uri, findings);
  }

  return findings;
}

function computeScore(findings) {
  const crits = findings.filter(f => f.severity === 'critical').length;
  const warns = findings.filter(f => f.severity === 'warning').length;
  const score = Math.max(0, 100 - crits * 15 - warns * 5);
  if (score >= 90) return { grade: 'A', label: 'Excellent', score, color: 'text-emerald-400', bg: 'border-emerald-500/30' };
  if (score >= 75) return { grade: 'B', label: 'Good', score, color: 'text-green-400', bg: 'border-green-500/30' };
  if (score >= 60) return { grade: 'C', label: 'Fair', score, color: 'text-yellow-400', bg: 'border-yellow-500/30' };
  if (score >= 40) return { grade: 'D', label: 'Poor', score, color: 'text-orange-400', bg: 'border-orange-500/30' };
  return { grade: 'F', label: 'Critical', score, color: 'text-red-400', bg: 'border-red-500/30' };
}

module.exports = { analyze, computeScore, patterns, weakPasswords, getLastFindings };
