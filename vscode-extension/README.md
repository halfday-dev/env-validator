# Halfday .env Validator

> Security scanner for `.env` files — detects exposed API keys, weak passwords, and misconfigurations right in your editor.

![Visual Studio Marketplace](https://img.shields.io/badge/vscode-extension-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

### 🔍 Real-time Security Scanning

Automatically scans `.env` files when you open or save them. Detects 50+ patterns of exposed secrets including:

- AWS, GCP, Azure credentials
- Stripe, OpenAI, GitHub tokens
- Database connection strings with embedded passwords
- Private keys, JWT secrets, and more

### 📊 Security Grade

Shows an A–F security grade in the status bar so you can see your `.env` health at a glance.

### ⚡ Quick Fixes

- Remove commented-out secrets
- Add `.env` to `.gitignore`

### 💡 Hover Information

Hover over any flagged line to see:
- What pattern was matched
- Why it's a risk
- How to fix it

## Screenshots

<!-- TODO: Add screenshots -->

## Installation

### From VSIX (local)

```bash
cd vscode-extension
npx @vscode/vsce package --no-dependencies
code --install-extension env-validator-0.1.0.vsix
```

### From Marketplace

*Coming soon*

## Supported File Types

- `.env`
- `.env.local`
- `.env.development`
- `.env.staging`
- `.env.production`
- `.env.test`
- `.env.example`
- Any `.env.*` file

## How It Works

The extension adapts the scanning engine from [halfday.dev/env-validator](https://halfday.dev) to run natively in VS Code. It parses your `.env` files and checks each line against a library of regex patterns for known secret formats.

Scoring:
- **A (90-100):** Excellent — no critical issues
- **B (75-89):** Good — minor issues
- **C (60-74):** Fair — some warnings
- **D (40-59):** Poor — multiple issues
- **F (0-39):** Critical — immediate action needed

## License

MIT — [halfday.dev](https://halfday.dev)
