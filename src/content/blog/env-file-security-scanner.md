---
title: "Your .env File Is a Ticking Time Bomb — So We Built a Scanner in Half a Day"
description: "How we used AI to build a client-side .env security scanner that detects 50+ API key patterns without your secrets ever leaving the browser."
date: 2026-02-13
tags: [security, dotenv, tools, ai]
---

*How we used AI to build a client-side .env security scanner that detects 50+ API key patterns without your secrets ever leaving the browser.*

---

We've all done it.

You're moving fast, shipping features, juggling three services and a database. You toss your Stripe key into `.env`, your AWS credentials right below it, maybe a database URL with the password inline. You `.gitignore` it (hopefully) and move on with your life.

Here's the thing: **your `.env` file is probably the most dangerous file in your entire project.** And almost nobody treats it that way.

So we built a tool to fix that. In about half a day. With a lot of help from AI. Let us tell you how.

## The Problem Nobody Talks About

Every developer knows you shouldn't commit secrets to git. That's table stakes. But `.env` file security goes way beyond "did I add it to `.gitignore`?"

Here's what actually goes wrong:

- **Leaked API keys** — GitHub's secret scanning catches some patterns, but only after you've already pushed. By then, bots have already scraped it. AWS keys get compromised in [under a minute](https://www.comparitech.com/blog/information-security/github-honeypot-experiment/).
- **Overly permissive keys** — That Stripe key in your `.env`? Is it the test key or the live one? Are you sure?
- **No validation** — Your `.env` file has no schema, no types, no validation. It's just raw text. A missing quote, a trailing space, a duplicated key — any of these can silently break your app or, worse, expose data.
- **Shared `.env` files** — Teams pass these around over Slack, email, sticky notes. Each copy is an untracked liability.
- **Docker and CI leaks** — Environment variables get baked into images, logged in CI output, cached in build artifacts. The `.env` file is just the beginning.

The dotenv security problem isn't a single vulnerability — it's a pattern of casual handling that compounds over time.

## What We Built

**[Halfday .env Validator & Security Scanner](https://halfday.dev/tools/env-validator)** — a free, browser-based tool that:

- 🔍 **Detects 50+ API key patterns** — AWS, Stripe, GitHub, Slack, Twilio, SendGrid, OpenAI, and dozens more
- ✅ **Validates .env syntax** — catches duplicates, malformed lines, missing values, and formatting issues
- 🔒 **Runs entirely client-side** — your secrets never leave your browser. Zero server calls. Zero logging. Zero trust required.
- 📊 **Gives you a security score** — a quick at-a-glance rating so you know how worried to be
- 💡 **Actionable recommendations** — not just "you have a problem" but "here's what to do about it"

Paste your `.env` file in, get instant feedback. That's it.

## How We Built It (The Half-Day Sprint)

This is a [Halfday](https://halfday.dev) project, which means two things: we build useful dev tools, and we build them fast — often with heavy AI assistance. This one came together in a single focused session.

### The Stack

Nothing fancy. Intentionally.

- **Frontend:** HTML, CSS, vanilla JavaScript (or your lightweight framework of choice)
- **Pattern matching:** Regular expressions — lots of them
- **Deployment:** Static site — no backend needed, no backend wanted
- **AI assist:** Claude for pattern generation, edge case discovery, and copy

We deliberately avoided a backend. The whole point is that your `.env` contents should never touch a server. A static site means we can make that promise and you can verify it — just open DevTools and watch the network tab. Nothing leaves.

### The Regex Engine

The core of the tool is a pattern-matching engine. Each "detector" is essentially:

```javascript
{
  name: "AWS Access Key ID",
  pattern: /AKIA[0-9A-Z]{16}/,
  severity: "critical",
  description: "AWS access keys grant programmatic access to AWS services",
  recommendation: "Rotate this key immediately via AWS IAM console"
}
```

Simple? Yes. Effective? Extremely. Most API keys follow predictable formats — specific prefixes, fixed lengths, known character sets. A well-crafted regex catches them reliably.

We also built detectors for structural issues:

- Duplicate variable names (last one wins, but did you mean that?)
- Lines missing `=` signs
- Unquoted values with spaces
- Empty values that might be placeholders
- Variables that look like they contain URLs with embedded credentials

## 50+ Patterns, and How AI Helped Generate Them

Here's where it got interesting.

We started with the obvious ones — AWS, Stripe, GitHub tokens. Patterns we'd seen a hundred times. But we wanted comprehensive coverage, and manually researching the key format for every SaaS API is... tedious.

So we asked Claude to help. And this is where AI-assisted development genuinely shines — not writing the core logic, but **accelerating the boring-but-important research**.

We prompted for:

- Known API key formats with their regex patterns
- Common prefixes (like `sk_live_`, `ghp_`, `xoxb-`)
- Key length constraints and character sets
- Which services use which patterns

Then we verified each one against real documentation. AI got us to 80% in minutes instead of hours. The remaining 20% was manual verification, edge case handling, and testing against actual key formats.

Here's a sample of what we detect:

| Service | Pattern | Severity |
|---------|---------|----------|
| AWS Access Key | `AKIA` + 16 chars | 🔴 Critical |
| Stripe Live Key | `sk_live_` prefix | 🔴 Critical |
| GitHub PAT | `ghp_` + 36 chars | 🟡 High |
| Slack Bot Token | `xoxb-` prefix | 🟡 High |
| OpenAI API Key | `sk-` + 48 chars | 🟡 High |
| SendGrid | `SG.` + base64 | 🟡 High |
| Twilio | 32-char hex | 🟠 Medium |
| Generic high-entropy | Shannon entropy check | 🟠 Medium |

The full list covers 50+ services and patterns, including Mailgun, Firebase, Heroku, DigitalOcean, Shopify, Discord, and more.

**The lesson:** AI is incredible at this kind of structured research task. It's not writing your app for you — it's compressing hours of documentation trawling into minutes of iterative prompting. That's the Halfday philosophy: use AI to build faster without sacrificing quality.

## The Privacy-First Architecture

Let's talk about the elephant in the room: **why would you paste your secrets into a web tool?**

You shouldn't. Not into most of them. And that's exactly why we built this differently.

The Halfday .env scanner is a **fully static, client-side application.** Here's what that means:

1. **No server-side processing** — The page loads, and everything runs in your browser's JavaScript engine
2. **No API calls** — Open your browser's Network tab. Paste your `.env`. Watch nothing happen. Zero requests.
3. **No analytics on content** — We don't track what you paste, what keys are found, or what your variables are named
4. **No storage** — Nothing goes to localStorage, sessionStorage, cookies, or IndexedDB
5. **Fully auditable** — The source is right there in your browser. View source. Read it. We dare you.

**Your secrets never leave your browser.** Period.

We could have built a fancier tool with server-side analysis, AI-powered recommendations, historical tracking. But every one of those features requires sending your secrets somewhere. And a security tool that asks for your secrets is an oxymoron.

## Things We Learned Building This

A few surprises from the half-day sprint:

**1. Key formats are wildly inconsistent.** Some services use clean prefixes (`sk_live_`). Others use generic hex strings. Some have moved through multiple formats over the years. Stripe alone has at least three key formats depending on when the key was generated.

**2. False positives are a real design challenge.** A 32-character hex string could be a Twilio Auth Token, a random hash, or your cat's name encoded in hex. We tuned severity levels and descriptions to account for ambiguity rather than pretending everything is definitive.

**3. Entropy detection is surprisingly useful.** Beyond specific patterns, we added Shannon entropy analysis. High-entropy strings (lots of randomness) in values are worth flagging even if they don't match a known pattern. If your `DATABASE_PASSWORD` has 4.5 bits of entropy per character, it's probably an actual secret, and you should know it's there.

**4. .env syntax is "standards-optional."** There's no formal spec for `.env` files. Different parsers handle quotes, spaces, comments, and multiline values differently. We had to make opinionated choices about what counts as "valid" — and document those choices.

## Try It — Seriously, Right Now

Here's our pitch: **you have a `.env` file open in another tab right now.** (Don't lie, we know you do.)

Go to **[halfday.dev/tools/env-validator](https://halfday.dev/tools/env-validator)**, paste it in, and see what comes back. It takes 10 seconds. Your secrets stay in your browser. And you might be surprised what's lurking in there.

We've already caught:

- Live Stripe keys in "development" `.env` files
- AWS keys that were copy-pasted from production
- Database URLs with plaintext passwords for services that support token auth
- Duplicate variables where the "wrong" one was silently winning

## What's Next

This is a Halfday project, which means we ship fast, iterate in public, and move on to the next thing. But we've got ideas for this one:

- **VS Code extension** — Scan on save, right in your editor
- **CLI tool** ✅ — shipped! `npx halfday-env-scan` — [read about it →](/blog/cli-tool-launch)
- **Team patterns** — Define custom patterns for your org's internal services
- **Pre-commit hook** — Catch issues before they hit version control

Want to see any of these happen? **Tell us.** We build what developers actually want.

---

## Follow the Build-in-Public Journey

Halfday is where we build useful dev tools with AI and write about the process — honestly, including the mistakes. Every tool, every sprint, every "how did we not think of that" moment.

- 🌐 **[halfday.dev](https://halfday.dev)** — Try the .env scanner
- ⭐ **Star us on GitHub** — Help other developers find these tools
- 📧 **[hello@halfday.dev](mailto:hello@halfday.dev)** — Get in touch

We build in half a day. You benefit for a lot longer.

---

*Have feedback on the .env scanner? Found a key pattern we're missing? [Let us know](mailto:hello@halfday.dev) — we ship fixes fast.*
