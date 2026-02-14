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

## Getting Started

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
