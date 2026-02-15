#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { analyze, computeScore } from '../lib/scanner.js';

// ANSI colors
const c = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
};

const severityColor = { critical: c.red, warning: c.yellow, info: c.blue };
const severityIcon = { critical: '●', warning: '▲', info: '○' };
const gradeColor = { A: c.green, B: c.green, C: c.yellow, D: c.red, E: c.red, F: c.red };

function usage() {
  console.log(`
${c.bold}halfday-env-scan${c.reset} — Scan .env files for security issues

${c.bold}Usage:${c.reset}
  halfday-env-scan <file>          Scan a .env file
  cat .env | halfday-env-scan      Scan from stdin

${c.bold}Options:${c.reset}
  --json       Output results as JSON
  --quiet      Only show grade and exit code
  --help       Show this help message
  --version    Show version

${c.bold}Exit codes:${c.reset}
  0  Grade A-C (pass)
  1  Grade D-F (fail)

${c.dim}halfday-env-scan • halfday.dev${c.reset}
`);
}

function readStdin() {
  return new Promise((resolve, reject) => {
    if (process.stdin.isTTY) { resolve(null); return; }
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', chunk => { data += chunk; });
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', reject);
  });
}

async function main() {
  const args = process.argv.slice(2);
  const flags = new Set(args.filter(a => a.startsWith('--')));
  const positional = args.filter(a => !a.startsWith('--'));

  if (flags.has('--help')) { usage(); process.exit(0); }
  if (flags.has('--version')) {
    const { createRequire } = await import('node:module');
    const require = createRequire(import.meta.url);
    const pkg = require('../package.json', { with: { type: 'json' } });
    console.log(pkg.version);
    process.exit(0);
  }

  const jsonMode = flags.has('--json');
  const quietMode = flags.has('--quiet');

  let text = null;
  let source = 'stdin';

  if (positional.length > 0) {
    const filePath = resolve(positional[0]);
    source = positional[0];
    try {
      text = readFileSync(filePath, 'utf8');
    } catch (err) {
      if (err.code === 'ENOENT') {
        if (jsonMode) console.log(JSON.stringify({ error: `File not found: ${source}` }));
        else console.error(`${c.red}Error:${c.reset} File not found: ${source}`);
        process.exit(1);
      }
      throw err;
    }
  } else {
    text = await readStdin();
    if (text === null) { usage(); process.exit(0); }
  }

  const findings = analyze(text);

  if (!findings) {
    if (jsonMode) console.log(JSON.stringify({ source, findings: [], grade: 'A', label: 'Excellent', pass: true }));
    else if (!quietMode) console.log(`${c.dim}Empty input — nothing to scan.${c.reset}`);
    process.exit(0);
  }

  const score = computeScore(findings);
  const pass = ['A', 'B', 'C'].includes(score.grade);

  if (jsonMode) {
    console.log(JSON.stringify({
      source,
      findings: findings.map(f => ({ line: f.line, severity: f.severity, name: f.name, desc: f.desc, fix: f.fix })),
      summary: {
        critical: findings.filter(f => f.severity === 'critical').length,
        warning: findings.filter(f => f.severity === 'warning').length,
        info: findings.filter(f => f.severity === 'info').length,
        total: findings.length,
      },
      grade: score.grade,
      label: score.label,
      pass,
    }, null, 2));
    process.exit(pass ? 0 : 1);
  }

  if (quietMode) {
    const gc = gradeColor[score.grade] || '';
    console.log(`${gc}${c.bold}${score.grade}${c.reset} ${score.label}`);
    process.exit(pass ? 0 : 1);
  }

  // Pretty output
  const crits = findings.filter(f => f.severity === 'critical').length;
  const warns = findings.filter(f => f.severity === 'warning').length;
  const infos = findings.filter(f => f.severity === 'info').length;

  console.log();
  console.log(`${c.bold}${c.cyan}halfday-env-scan${c.reset}`);
  console.log(`${c.dim}${'─'.repeat(50)}${c.reset}`);
  console.log(`${c.dim}Source:${c.reset} ${source}`);
  console.log();

  if (findings.length === 0) {
    console.log(`  ${c.green}✓ No issues found${c.reset}`);
  } else {
    const parts = [];
    if (crits > 0) parts.push(`${c.red}${crits} critical${c.reset}`);
    if (warns > 0) parts.push(`${c.yellow}${warns} warning${c.reset}`);
    if (infos > 0) parts.push(`${c.blue}${infos} info${c.reset}`);
    console.log(`  ${c.bold}Found ${findings.length} issue${findings.length !== 1 ? 's' : ''}:${c.reset} ${parts.join('  ')}`);
    console.log();

    for (const sev of ['critical', 'warning', 'info']) {
      const group = findings.filter(f => f.severity === sev);
      if (group.length === 0) continue;
      for (const f of group) {
        const sc = severityColor[sev];
        const icon = severityIcon[sev];
        console.log(`  ${sc}${icon} ${c.bold}${f.name}${c.reset}${c.dim} (line ${f.line})${c.reset}`);
        console.log(`    ${f.desc}`);
        console.log(`    ${c.dim}→ ${f.fix}${c.reset}`);
        console.log();
      }
    }
  }

  const gc = gradeColor[score.grade] || '';
  console.log(`${c.dim}${'─'.repeat(50)}${c.reset}`);
  console.log(`  ${c.bold}Grade: ${gc}${score.grade}${c.reset} ${c.dim}(${score.label})${c.reset}  ${pass ? `${c.green}PASS${c.reset}` : `${c.red}FAIL${c.reset}`}`);
  console.log();
  console.log(`  ${c.dim}halfday-env-scan • halfday.dev${c.reset}`);
  console.log();

  process.exit(pass ? 0 : 1);
}

main().catch(err => { console.error(err); process.exit(1); });
