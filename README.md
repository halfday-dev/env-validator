# 🔒 ENV Validator & Security Scanner

> Detect leaked API keys, weak passwords, and misconfigurations in your `.env` files — entirely client-side.

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![CI](https://github.com/halfday-dev/env-validator/actions/workflows/ci.yml/badge.svg)](https://github.com/halfday-dev/env-validator/actions/workflows/ci.yml)

![Screenshot](docs/screenshot.png)

## What It Does

Paste a `.env` file and instantly get a security report. No data leaves your browser — all analysis runs 100% client-side.

## Features

- **50+ secret patterns** — AWS, Stripe, GitHub, OpenAI, Google, Slack, and many more
- **Weak password detection** — flags common/default passwords
- **Security scoring** — A through F grade with critical/warning/info breakdown
- **Structural checks** — duplicate keys, empty values, unquoted spaces, mismatched quotes
- **Commented-out secret detection** — catches secrets that were "removed" by commenting
- **Copy report** — one-click copy of findings for sharing
- **100% client-side** — your secrets never leave your browser

## CLI: `halfday-env-scan`

Scan `.env` files from your terminal or CI pipeline — zero config needed.

### Quick Start

```bash
npx halfday-env-scan .env
```

### Options

```bash
npx halfday-env-scan .env            # Pretty-print results
npx halfday-env-scan --json .env     # JSON output (for CI)
npx halfday-env-scan --quiet .env    # Grade only
cat .env | npx halfday-env-scan      # Read from stdin
```

### Exit Codes

| Code | Meaning |
|------|---------|
| `0`  | Grade A–C (pass) |
| `1`  | Grade D–F (fail) |

### GitHub Action

Use the reusable GitHub Action in your workflows:

```yaml
# .github/workflows/env-scan.yml
name: Env Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: halfday-dev/env-validator@main
        with:
          path: .env.example
          # json: true    # JSON output
          # quiet: true   # Grade only
```

Or as a one-liner in an existing workflow:

```yaml
- name: Scan .env for secrets
  run: npx halfday-env-scan@latest .env.example
```

### Pre-commit Hook

#### Manual Setup

```bash
cp hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

This hook automatically scans any staged `.env*` files and blocks commits with grade D–F.

#### pre-commit Framework

If you use [pre-commit](https://pre-commit.com), add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/halfday-dev/env-validator
    rev: main
    hooks:
      - id: halfday-env-scan
```

---

## Web App

### Getting Started

```bash
npm install
npm run dev
```

Open [http://localhost:4321](http://localhost:4321) in your browser.

## Running Tests

```bash
npm test
```

## Tech Stack

- [Astro](https://astro.build) — static site framework
- [Tailwind CSS](https://tailwindcss.com) — utility-first styling
- [Vitest](https://vitest.dev) — unit testing
- [GitHub Actions](https://github.com/features/actions) — CI/CD

## Contributing

Contributions are welcome! Please open an issue first to discuss what you'd like to change, then submit a PR.

1. Fork the repo
2. Create your branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes
4. Push and open a Pull Request

## License

[MIT](LICENSE) © 2025 [Halfday](https://halfday.dev)

---

Built by [Halfday](https://halfday.dev) — tools built in half a day.
