# @halfday/env-scan

Scan `.env` files for leaked API keys, weak passwords, and security issues.

50+ secret patterns · weak password detection · letter grade scoring · zero dependencies

## Install

```bash
npm install -g @halfday/env-scan
```

## Usage

```bash
# Scan a file
halfday-env-scan .env

# Pipe from stdin
cat .env | halfday-env-scan

# JSON output (great for CI)
halfday-env-scan .env --json

# Just the grade
halfday-env-scan .env --quiet
```

## What it detects

- **API keys**: AWS, Stripe, GitHub, OpenAI, Google, Slack, Twilio, SendGrid, Cloudflare, and 40+ more
- **Database credentials**: PostgreSQL, MySQL, MongoDB, Redis connection strings with embedded passwords
- **Weak passwords**: Common defaults like `password123`, `admin`, `changeme`, `hunter2`
- **Syntax issues**: Duplicate keys, mismatched quotes, unquoted values with spaces
- **Commented-out secrets**: Secrets that were "removed" by commenting instead of deleting

## Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Grade A–C (pass) |
| `1`  | Grade D–F (fail) |

Use in CI to fail builds that contain leaked secrets:

```yaml
# GitHub Actions
- run: npx @halfday/env-scan .env
```

## Grading

| Grade | Score | Label |
|-------|-------|-------|
| A | 90–100 | Excellent |
| B | 75–89 | Good |
| C | 60–74 | Fair |
| D | 40–59 | Poor |
| F | 0–39 | Critical |

Each critical finding deducts 15 points, each warning deducts 5.

## Options

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON |
| `--quiet` | Only show grade and exit code |
| `--help` | Show help |
| `--version` | Show version |

## Try it online

[halfday.dev/tools/env-scanner](https://halfday.dev/tools/env-scanner) — paste your `.env` and get an instant security grade.

## License

MIT © [Halfday](https://halfday.dev)
