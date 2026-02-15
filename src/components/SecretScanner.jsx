import { useState, useCallback, useRef } from 'react';
import { scan } from '../lib/secret-scanner.js';

// Sample text is generated at runtime to avoid triggering GitHub secret scanning
function getSampleText() {
  // Build realistic-looking but obviously fake secrets
  const akia = 'AKIA' + 'IOSFODNN7EXAMPLE';
  const ghToken = 'ghp_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' + 'abcdefgh' + 'ij';
  const glToken = 'glpat-' + 'ABCDEFGHIJKLMNOPabcd';
  const npmToken = 'npm_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh' + 'ij';

  return `# Application Config
DATABASE_URL=postgres://admin:password123@db.example.com:5432/myapp
REDIS_URL=redis://:supersecret@cache.example.com:6379/0

# AWS Credentials
export AWS_ACCESS_KEY_ID="${akia}"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# GitHub Token in script
curl -H "Authorization: token ${ghToken}" https://api.github.com

# Private key leaked in log
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy5AoV5B2RYNdBx...

# npm token in .npmrc
//registry.npmjs.org/:_authToken=${npmToken}

# GitLab
GITLAB_DEPLOY_TOKEN=${glToken}

# MongoDB connection
mongo_uri = "mongodb+srv://appuser:S3cretP4ss@cluster0.example.net/prod?retryWrites=true"

# Basic auth
fetch("https://admin:hunter2@internal.example.com/api/data")

# Generic password
password = "SuperS3cretPassw0rd!"
secret_key = "j8K2mNpQ9xR4wY7zA1bC3dE5fG6hI0kL"
`;
}

const severityConfig = {
  critical: { bg: 'bg-red-500/10', border: 'border-red-500/20', badge: 'bg-red-500/20 text-red-400', icon: '🔴' },
  warning: { bg: 'bg-yellow-500/10', border: 'border-yellow-500/20', badge: 'bg-yellow-500/20 text-yellow-400', icon: '🟡' },
};

export default function SecretScanner() {
  const [input, setInput] = useState('');
  const [result, setResult] = useState(null);
  const [copied, setCopied] = useState(false);
  const debounceRef = useRef(null);

  const runScan = useCallback((text) => {
    if (!text.trim()) {
      setResult(null);
      return;
    }
    const r = scan(text);
    setResult(r);
  }, []);

  const handleInput = useCallback((e) => {
    const val = e.target.value;
    setInput(val);
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => runScan(val), 150);
  }, [runScan]);

  const loadExample = () => {
    const sample = getSampleText();
    setInput(sample);
    runScan(sample);
  };

  const clear = () => {
    setInput('');
    setResult(null);
  };

  const copyRedacted = async () => {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(result.redactedText);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {}
  };

  return (
    <div className="max-w-[900px] mx-auto w-full">
      {/* Trust Banner */}
      <div className="mb-6 flex items-center gap-2 bg-emerald-500/10 border border-emerald-500/20 rounded-lg px-4 py-3 text-emerald-400 text-sm">
        <svg className="w-5 h-5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
        <span><strong>100% client-side</strong> — your data never leaves this page. No server, no tracking, no logs.</span>
      </div>

      <h1 className="text-3xl font-bold mb-2">Secret & Credential Scanner</h1>
      <p className="text-gray-400 mb-6">Paste code, logs, config files, or any text to instantly detect leaked API keys, passwords, and tokens.</p>

      {/* Input */}
      <div className="mb-4 flex items-center gap-2">
        <button onClick={loadExample} className="text-sm px-3 py-1.5 rounded-md bg-gray-800 hover:bg-gray-700 text-gray-300 transition">Load Example</button>
        <button onClick={clear} className="text-sm px-3 py-1.5 rounded-md bg-gray-800 hover:bg-gray-700 text-gray-300 transition">Clear</button>
      </div>
      <textarea
        value={input}
        onChange={handleInput}
        className="w-full bg-gray-900 border border-gray-700 rounded-lg p-4 font-mono text-sm text-gray-200 focus:outline-none focus:ring-2 focus:ring-emerald-500 focus:border-transparent resize-y placeholder-gray-600"
        style={{ minHeight: '200px', maxHeight: '60vh' }}
        placeholder="Paste code, logs, config files, or any text to scan for secrets..."
      />

      {/* Results */}
      {result && (
        <div className="mt-8">
          {/* Summary */}
          <div className="flex flex-col sm:flex-row items-center gap-4 mb-6 rounded-lg border border-gray-800 bg-gray-900 p-4">
            <div className="flex items-center gap-4 flex-1">
              {result.counts.critical > 0 && (
                <span className="flex items-center gap-1.5 text-sm">
                  <span>🔴</span>
                  <span className="font-semibold text-red-400">{result.counts.critical}</span>
                  <span className="text-gray-400">Critical</span>
                </span>
              )}
              {result.counts.warning > 0 && (
                <span className="flex items-center gap-1.5 text-sm">
                  <span>🟡</span>
                  <span className="font-semibold text-yellow-400">{result.counts.warning}</span>
                  <span className="text-gray-400">Warning{result.counts.warning !== 1 ? 's' : ''}</span>
                </span>
              )}
              {result.findings.length === 0 && (
                <span className="text-emerald-400 text-sm font-medium">✅ No secrets detected!</span>
              )}
            </div>
            <span className="text-xs text-gray-500">{result.scanTimeMs}ms{result.capped ? ' · 500+ findings (showing first 500)' : ''}</span>
          </div>

          {/* Findings */}
          {result.findings.length > 0 && (
            <>
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-lg font-semibold">Findings</h2>
              </div>
              <div className="space-y-2 mb-6">
                {result.findings.map((f, i) => {
                  const c = severityConfig[f.severity];
                  return (
                    <div key={i} className={`rounded-lg ${c.bg} border ${c.border} p-4`}>
                      <div className="flex items-start gap-3">
                        <span className="text-sm mt-0.5">{c.icon}</span>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-sm font-medium text-gray-200">{f.name}</span>
                            <span className={`text-xs px-2 py-0.5 rounded-full ${c.badge}`}>{f.severity}</span>
                            <span className="text-xs text-gray-500 ml-auto">Line {f.line}</span>
                          </div>
                          <code className="block text-xs text-gray-400 mt-1.5 font-mono truncate">{f.matchedText.length > 80 ? f.matchedText.substring(0, 77) + '...' : f.matchedText}</code>
                          <p className="text-xs text-gray-500 mt-1.5">💡 {f.fix}</p>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Copy Redacted */}
              <div className="flex items-center gap-3">
                <button onClick={copyRedacted} className="text-sm px-4 py-2 rounded-md bg-gray-800 hover:bg-gray-700 text-gray-300 transition flex items-center gap-2">
                  {copied ? (
                    <>
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"/></svg>
                      Copied!
                    </>
                  ) : (
                    <>
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>
                      Copy Redacted
                    </>
                  )}
                </button>
                <span className="text-xs text-gray-500">Copies your text with all secrets masked</span>
              </div>
            </>
          )}

          {/* Cross-link */}
          <div className="mt-8 p-4 rounded-lg border border-white/[0.06] bg-white/[0.02] text-sm text-gray-400">
            Working with <code className="text-emerald-400/80">.env</code> files? Try our <a href="/tools/env-validator/" className="text-emerald-400 hover:underline">ENV Validator</a> for key-value validation, security scoring, and .gitignore suggestions.
          </div>
        </div>
      )}

      {/* Privacy footer */}
      <div className="mt-8 flex items-center gap-2 text-xs text-gray-500">
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
        <span>Your data never leaves this page. Everything runs in your browser.</span>
        <a href="https://github.com/halfday-dev/env-validator" className="text-gray-400 hover:text-gray-300 ml-1" target="_blank" rel="noopener noreferrer">Source ↗</a>
      </div>
    </div>
  );
}
