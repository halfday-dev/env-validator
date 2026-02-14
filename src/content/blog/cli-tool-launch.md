---
title: "We Shipped a CLI Scanner in Under an Hour — Here's How"
description: "How we turned our browser-based .env security scanner into a zero-dependency CLI tool you can run with npx — and why CI pipelines were the obvious next step."
date: 2025-02-13
tags: [cli, security, npm, ci-cd, tools]
slug: cli-tool-launch
---

*We shipped a browser-based .env scanner this morning. By lunch, it had a CLI. Here's the story of `npx halfday-env-scan` and why zero-dependency tooling matters.*

---

## Same Day, Different Interface

Earlier today we shipped the [Halfday .env Validator](/blog/env-file-security-scanner) — a browser-based tool that scans your `.env` files for leaked API keys, syntax issues, and security misconfigurations. Client-side only, nothing leaves your browser, 50+ detection patterns. Cool.

But here's the thing about browser tools: developers don't live in browsers. We live in terminals.

The moment we shared the web tool, the first question was predictable: *"Can I run this in CI?"*

Yes. Yes you can. As of right now: `npx halfday-env-scan .env`. That's it. No install step, no config file, no setup wizard. Just scan.

## Why a CLI?

Three reasons, all obvious in hindsight:

**1. CI pipelines need exit codes, not web pages.** A browser tool is great for quick manual checks. But if you want to catch a leaked Stripe key *before* it hits your repo, you need something that runs in GitHub Actions, GitLab CI, or a pre-commit hook. That means a CLI with proper exit codes.

**2. npx is the perfect distribution channel.** No global install. No version management headaches. `npx halfday-env-scan` always pulls the latest version, runs it, and gets out of the way. It's how modern CLI tools should work.

**3. We already had the logic.** The browser scanner's core engine — the regex patterns, the severity ratings, the entropy analysis, the scoring algorithm — was already written as a pure JavaScript module. Moving it to Node was a matter of wiring up file I/O and terminal output. Not rebuilding.

## The Extraction Pattern

This is the part that made the whole thing fast.

When we built the web scanner, we made a decision that paid off immediately: **the scanning logic lives in its own module.** `scanner.js` exports two functions — `analyze()` and `computeScore()`. No DOM dependencies. No browser APIs. Just pure JavaScript that takes a string and returns structured results.

```javascript
import { analyze, computeScore } from './lib/scanner.js';

const results = analyze(envFileContents);
const { grade, score } = computeScore(results);
```

The browser version calls these functions with text from a `<textarea>`. The CLI calls them with text from `fs.readFileSync()` or `process.stdin`. Same engine, different I/O. That's it.

This is the kind of architectural decision that feels boring when you make it and brilliant when you need it. If we'd tangled the scanning logic with DOM manipulation, the CLI would have been a rewrite. Instead, it was a wrapper.

**Lesson for the build-in-public crowd:** Extract your core logic into pure functions early. You never know what interface you'll want to bolt on next.

## Zero Dependencies

Open our `package.json`. Look at the `dependencies` field. It's empty for the CLI — we use only Node.js built-ins.

No `chalk` for colors (we use ANSI escape codes directly). No `yargs` or `commander` for argument parsing (we parse `process.argv` ourselves). No `ora` for spinners. No nothing.

Why? Because `npx halfday-env-scan` should be *fast*. Every dependency is download time. Every dependency is potential supply chain risk — which is ironic for a security tool. Every dependency is a version to manage, a changelog to read, a breaking change to absorb.

For a focused CLI tool that does one thing, zero dependencies is the right call. The entire package is a handful of kilobytes. `npx` fetches it in under a second.

## How It Works

### Basic scan

```bash
npx halfday-env-scan .env
```

You get a colorized report: each finding with its severity (critical/warning/info), the variable name, what was detected, and a recommendation. At the bottom, a letter grade (A through F) and a summary.

### Pipe from stdin

```bash
cat .env.production | npx halfday-env-scan
```

Works with any tool that outputs to stdout. Decrypt your secrets manager export, pipe it through, catch issues before they deploy.

### JSON output

```bash
npx halfday-env-scan .env --json
```

Structured JSON output for programmatic consumption. Pipe it to `jq`, feed it to your dashboard, store it as a build artifact. The JSON includes every finding, the overall score, and the grade.

### Quiet mode

```bash
npx halfday-env-scan .env --quiet
```

Just the grade. Nothing else. Perfect for scripts that only care about pass/fail.

### Exit codes

- **Exit 0** — Grade A, B, or C. You're good.
- **Exit 1** — Grade D, E, or F. Something needs attention.

This is what makes CI integration work. A non-zero exit code fails your pipeline. Simple, Unix-standard, no surprises.

## CI Integration

### GitHub Actions

```yaml
name: Scan env files
on: [push, pull_request]
jobs:
  env-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npx halfday-env-scan .env.example --json > env-report.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: env-scan-report
          path: env-report.json
```

The `if: always()` ensures you get the report even when the scan fails (which is when you need it most).

### Pre-commit hook

```bash
#!/bin/sh
# .git/hooks/pre-commit
for f in $(git diff --cached --name-only | grep '\.env'); do
  npx halfday-env-scan "$f" --quiet || exit 1
done
```

Catches leaked keys before they even make it into a commit. This is the single highest-value integration — it's the last line of defense before `git push`.

### Generic CI

```bash
# Any CI system
npx halfday-env-scan .env.example
if [ $? -ne 0 ]; then
  echo "Environment file has security issues. Fix before deploying."
  exit 1
fi
```

## The Build-in-Public Angle

Let's be honest about the timeline here.

We shipped the web-based scanner this morning. We shipped the CLI this afternoon. Same day. Both functional, both tested, both deployed.

How? AI-assisted development. The same approach we described in the [first blog post](/blog/env-file-security-scanner). Claude helped with the ANSI color formatting, the argument parsing edge cases, the stdin detection logic. We focused on architecture and product decisions. The AI handled the boilerplate.

This is the Halfday model: build useful tools fast, ship them publicly, write about the process honestly. We're not pretending we hand-crafted every line in a candlelit artisan code cave. We used AI. It was faster. The tool works. That's what matters.

## What's Different from the Web Tool?

Nothing, in terms of detection. Same 50+ patterns, same severity levels, same scoring algorithm. Literally the same `scanner.js` module.

The difference is interface:
- **Web tool** → visual, interactive, good for one-off checks and demos
- **CLI tool** → scriptable, automatable, good for CI and workflows

Use both. The web tool at [halfday.dev/tools/env-validator](https://halfday.dev/tools/env-validator) is great for pasting in a file and exploring the results visually. The CLI is great for making sure nobody on your team ships a live API key to production.

## Try It

```bash
npx halfday-env-scan .env
```

That's it. One command. No install. No signup. No config.

If you get an F, don't panic — but do fix it.

---

## Links

- 🌐 **[Web scanner](https://halfday.dev/tools/env-validator)** — Browser-based, client-side
- 📦 **[npm package](https://www.npmjs.com/package/halfday-env-scan)** — `npx halfday-env-scan`
- ⭐ **[GitHub repo](https://github.com/halfday-dev/env-validator)** — Star it, fork it, open issues
- 📧 **[hello@halfday.dev](mailto:hello@halfday.dev)** — Feedback welcome

---

*Missing a detection pattern? Want a feature? [Open an issue](https://github.com/halfday-dev/env-validator/issues) — we ship fixes fast.*
