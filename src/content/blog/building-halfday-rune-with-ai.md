---
title: "Five Releases in Two Days: Building Halfday Rune With AI"
description: "A field report on the build loop behind a 0-to-shipped Obsidian encryption plugin. Parallel subagent review, the specific bugs the loop caught, and the ones we shipped anyway."
date: 2026-05-17
tags: [ai, development, obsidian, halfday, methodology]
draft: false
---

*A field report on the build loop behind a 0-to-shipped Obsidian encryption plugin. Parallel subagent review, the specific bugs the loop caught, and the ones we shipped anyway.*

---

## the bug that taught us how to test

Here's a CodeMirror 6 decoration call that looks fine and crashes every test that exercises a successful decoration:

```ts
pending.sort((a, b) => a.from - b.from || b.to - a.to);
```

That sort goes into a `RangeSetBuilder<Decoration>`, which CM6 uses to assemble live-preview overlays — the things that turn `**bold**` into **bold** without the asterisks. The builder requires ranges to be added in non-decreasing `(from, startSide)` order. `Decoration.replace` has `startSide = -1`. `Decoration.mark` has `startSide = 1`. At the same `from`, replace must come first.

Our sort doesn't enforce that. So the moment you decorate `**bold**` at offset zero — where the outer `mark` (0..8) and the inner `replace` for the leading `**` (0..2) share an offset — the builder throws:

```
Error: Ranges must be added sorted by `from` position and `startSide`
```

The fix is one line:

```ts
pending.sort(
  (a, b) =>
    a.from - b.from || a.startSide - b.startSide || b.to - a.to
);
```

The interesting part isn't the bug. It's where we caught it.

Our builder agent had run its own smoke harness — a Node script that imports `age-encryption@0.3.0`, generates a real X25519 keypair, round-trips a few documents through the actual crypto, and reports green. Everything passed. We were ready to ship.

Then the test suite ran on the real Mac with real `npm test`, against the *fake* crypto in `tests/`. Vitest, fake X25519, hard contract — and immediately, every test that touched `**bold**` blew up.

Why did the fake catch what the real didn't? Because the smoke runner was probing end-to-end behavior — does the file decrypt, does the editor open, does the cleartext appear? — and the live-preview decorations are silent on failure. CM6 swallows the throw, the editor renders without decoration, and "looks right enough" passes a visual eyeball. The unit tests against the fake encryption layer had no visual fallback. They asserted that the decoration set contained specific ranges. When the builder threw, the assertions died with it.

The fake catches the real. It's a tidy little methodology lesson that we filed in a memory note the same hour so the next person — or the next agent — doesn't pay for it again.

This post is about the loop that caught it, the loop that didn't, and the four other times we got bit shipping an encrypted-notes plugin for Obsidian in 48 hours.

---

## what we shipped

[Halfday Rune](/blog/halfday-rune-secure-obsidian-ai-era) is an Obsidian plugin that lets you keep `.md.age` files in your vault and edit them like normal notes — live preview, theme integration, the lock icon in the tab, the works — while the on-disk bytes stay encrypted with the [age format](https://github.com/FiloSottile/age). X25519 recipients. Multi-recipient by default. Vault key rotation as a command. The post-quantum story is a v0.7+ problem; the today story is "stop leaking plaintext to every background agent on your machine."

The 48-hour window covered five tagged releases:

- **v0.5.2** — rotate vault keys
- **v0.6.0** — editor chrome pass (theme integration, status bar, cursor, line numbers removed)
- **v0.6.1** — inline decorations (headings, emphasis, inline code, standard links)
- **v0.6.2** — block decorations (lists, fenced code, wikilinks)
- **v0.6.3** — sanitization (HTML, `javascript:`/`data:` URLs, remote images, embeds) + decrypt-back-to-markdown command

Plus roughly twenty fix-up commits across them. The numbers are real and the [git log](https://github.com/halfday-dev/halfday-rune/commits/main) is right there.

---

## the shop

Halfday is a one-human dev shop. The human in the loop is the one calling the shots. The shop is named, dispatched, and run through Claude Code with a multi-agent setup:

- **north** — the lead engineer agent. Reads direction from the human, breaks it into milestones, dispatches the builder, runs reviews, owns the ship/no-ship call.
- **lyra** — the builder. Writes the code and the tests. Picks a fresh codename per milestone, signs commits, and runs an in-sandbox smoke pass before handing back.
- **security reviewer + QA reviewer** — two parallel agents, each freshly dispatched per milestone, each named on the spot, each reading the same diff with a different lens. Security looks for cleartext leaks, DOM injection, regex ReDoS, URL-parsing edge cases. QA looks for spec compliance, regression risk, and the kind of carryover bugs that creep in when you refactor a module five times in two days.
- **the human** — the only one who runs `npm test` and `npm run build` on a real Mac with a real Obsidian against a real `.age` file.

The pattern is the documented [parallel-subagent dispatch model](https://www.anthropic.com/engineering/building-agents-with-the-claude-agent-sdk) — Anthropic's SDK ships it as a first-class primitive, and the broader Claude Code community has been refining it for months ([1](https://claudefa.st/blog/guide/agents/sub-agent-best-practices), [2](https://zachwills.net/how-to-use-claude-code-subagents-to-parallelize-development/)). We didn't invent it. What we did is wire it into a specific shape for a specific kind of work: shipping a security-sensitive open-source plugin with tests, reviews, and a real-environment smoke loop.

The loop, in order:

1. **Kickoff.** The human gives direction. north translates into a milestone scope — usually two or three modules, a test target, an acceptance criterion.
2. **Builder dispatch.** lyra writes the code, writes the tests, runs them in the sandbox, reports back with a tight summary.
3. **Parallel review.** north dispatches a security agent and a QA agent simultaneously. They each read the diff against their checklist. They each produce a list of findings tagged with severity. They don't see each other's output.
4. **Triage.** north merges the two finding lists, deduplicates the overlap (there's always some), and decides which findings ship in this milestone vs which fold into the next.
5. **Fix bundle.** lyra goes back with the merged list. One round, all findings, one commit.
6. **Mac smoke.** The human pulls the branch, runs `npm test`, runs `npm run build`, side-loads into Obsidian, paste-tests a smoke document.
7. **Ship or rework.** If the smoke is clean, push and tag. If it isn't, north triages the smoke findings into a fix-up commit and the human re-pulls.

Five times in two days. Roughly two hours per milestone end-to-end, including human review and Mac smoke. The bottleneck isn't generation — it's the human verification step, which is the only one that can't be parallelized.

---

## the catch rate, by reviewer

Here's the thing nobody publishes about parallel review: **the security agent and the QA agent caught different bugs every single time.** Not "mostly different." Different. The overlap was usually one or two findings out of fifteen.

A non-exhaustive sample from the v0.6 run:

| Milestone | Caught by security | Caught by QA |
|---|---|---|
| v0.6.0 chrome | `var()` fallbacks missing on load-bearing legibility props (light-mode breakage risk) | status bar item not removed on `onunload()` leak |
| v0.6.1 inline | wikilink-regex comment overstated correctness ("rejects nested brackets" — wrong) | `**bold `code` inside**` nesting case not tested |
| v0.6.2 block | strikethrough rule defined but never fires (caught: rule exists; missed: GFM not enabled) | `[[[[foo]]]]` decorates the inner wikilink and leaves outer brackets visible |
| v0.6.3 sanitization | HTML-entity-encoded `javascript:` URL bypass (`javascript&#58;`) in regex | `![[note]]` embed: sanitizer leaves the `!` visible, decorates the wikilink |

The security pass thinks like an attacker. The QA pass thinks like a user. Run them serially and you get the attacker's findings followed by a tired second pass. Run them in parallel and the QA agent comes in fresh, with no context for what's already been found, and re-discovers the gaps the security pass moved past.

This is the methodology gain that surprised us most. We expected parallel review to be faster. We didn't expect it to be *more thorough*.

---

## what the Mac smoke caught that the sandbox didn't

The sandbox is Linux/arm64. The real environment is macOS/arm64. Obsidian's plugin runtime is the real environment, and the sandbox can't reach it.

Concrete things that fell out of this:

**Rollup binary mismatch.** `npm test` in the sandbox can't pull the `darwin-arm64` rollup binary; it gets the linux variant and vitest dies on import. So the human runs vitest. The builder's "smoke pass" is a hand-rolled Node script with `--experimental-strip-types`, not vitest. This is the gap that masked the RangeSetBuilder bug.

**The CSS-not-in-`src/` trap.** [`obsidian-plugin-cli@0.4.5`](https://github.com/marcusolsson/obsidian-plugin-cli) builds `src/main.ts` into `main.js` but doesn't copy `src/styles.css` into the build output. Obsidian loads the stylesheet from `<plugin-root>/styles.css`. We learned this in v0.5.1 when an error-state CSS class rendered in default white instead of red. The builder had correctly edited `src/styles.css` and the test was still wrong, because the rule never reached the browser. Caught on Mac smoke, fixed by editing root-level `styles.css`, and filed as a memory.

**Inline `type` import modifier.** TypeScript 4.5 lets you write `import { x, type Y } from './mod'`. Vitest's TS pipeline is happy with it. `obsidian-plugin-cli@0.4.5` bundles a pre-4.5 esbuild and chokes:

```
Error: Expected '}' but found 'RotateResult'
```

`npm test` passed. `npm run build` failed. Caught on Mac smoke during v0.5.2 and filed as a memory.

**GFM not enabled.** `@codemirror/lang-markdown`'s default `markdown()` call parses CommonMark only. Strikethrough, tables, task lists, and bare-URL autolinks all live in GFM. The builder's `halfdayMarkdownHighlight` had a `tags.strikethrough` rule with the right text-decoration. It just never fired, because the parser never emitted a `strikethrough` tag. Mac smoke surfaced this from a paste-tested document; the fix was `markdown({ extensions: GFM })`, filed as a memory.

**The `block: true` edit-time hazard.** This one's the worst of the lot. v0.6.2 originally hid fenced-code-block fence lines when the cursor wasn't on them, using `Decoration.replace({block: true})`. Looked great in static smoke. The human's Mac smoke did something we hadn't: pressed backspace at a fence boundary. Ghost characters bled into adjacent lines. We bisected — bug reproduced two commits earlier — and the root cause turned out to be `Decoration.replace({block: true})` interacting badly with incremental Lezer reparses during edits. Stale block-replace ranges briefly target the wrong lines. The real fix wasn't a patch; it was deleting the feature. Fence lines now stay visible always. Small visual loss, no edit-time hazard. We left a comment to revisit with `atomicRanges` someday.

The pattern: **sandbox tests + builder smoke ≠ real-environment verification.** The Mac smoke step is the loop that closes. Skip it and you ship broken builds.

---

## where the AI got it wrong

This is the section that earns the right to write the rest of the post. The build agent (and the reviewers, and north herself) got plenty of things wrong in two days. A non-exhaustive list:

**Overstated comments.** A wikilink-regex helper in `v0.6.2` had a comment claiming it "correctly rejects nested wikilinks." It didn't. It would decorate the inner `[[foo]]` of `[[[[foo]]]]` and leave the outer brackets visible. The behavior was acceptable for v0.6.2 — we wrote it down as a known edge case — but the comment was a lie until a reviewer caught it. AI agents are eager to claim correctness and reluctant to write "this handles the common case but breaks on [X]." You have to push back.

**Subtle sort-order bugs.** The RangeSetBuilder ordering invariant isn't obvious unless you've used CM6 before. The builder wrote a sort that *looked* correct — "wider ranges first" makes intuitive sense — and was structurally wrong for one specific case (same `from`, replace vs mark). This is the kind of bug an AI is bad at unless it's seen the failure mode. After we filed the memory, the next decoration module included the three-tier sort in its first draft.

**Template literals in templates.** The first pass of `LICENSE` had the literal string `TBD-COPYRIGHT-HOLDER` where the copyright holder's name should go. Fine — we caught it in QA review — but illustrative of how AI agents fill templates rather than think about whether the content makes sense. The same pattern shows up with API stubs (`TODO: implement`) and tests that assert against placeholder return values.

**Defaulting to modern TS syntax in a legacy bundler.** The inline `type` modifier is TypeScript 4.5+ syntax. The builder defaulted to it because every modern project supports it. The project's pinned esbuild didn't. The fix was to split the import; the lesson is that "what's modern" isn't always "what builds here."

**Naming collisions.** Twice in two days, the security reviewer agent and the QA reviewer agent picked the same codename (north tries to keep an exclusion list to avoid this; fatigue erodes it). Cosmetic, but it tells you the dispatch layer is brittle in ways the build layer isn't.

What the AI did well, also non-exhaustively: it translated the spec into implementation cleanly across four milestones. It wrote tests that actually exercise the spec's contract, not just happy paths. It spotted carryover regressions in diff review (the v0.6.1 fix-up commit that re-added `tags.monospace` after we'd accidentally dropped it). It held a consistent voice across the codebase even as five different builder personas wrote pieces of it.

The split is the boring, honest one: ***AI is excellent at translation and tedium; humans are excellent at taste and context.*** Anybody telling you a different story is selling something.

---

## the memory layer

Every "we got bit" became a memory file. After two days we had five new ones, all narrowly scoped:

- **CM6 RangeSetBuilder ordering.** Decorations must be added in `(from asc, startSide asc, to desc)` order. Replace has `startSide = -1`, mark has `startSide = 1` — at the same `from`, replace comes first. Canonical failure case is `**bold**` at offset zero.
- **obsidian-plugin-cli doesn't copy styles.** The bundler builds `src/main.ts` but doesn't copy `src/styles.css` into the output. Obsidian loads the stylesheet from the plugin's root `styles.css`, so the root-level file is the only one that takes effect. Edit there or your CSS never ships.
- **Bundler chokes on inline `type` imports.** `obsidian-plugin-cli@0.4.5` bundles a pre-4.5 esbuild that rejects `import { x, type Y } from './mod'`. Use a separate `import type` line. Vitest is happy with the modern syntax; the build is not.
- **`@codemirror/lang-markdown` defaults to CommonMark.** Strikethrough, tables, task lists, and bare-URL autolinks all live in GFM. Pass `markdown({ extensions: GFM })` or your highlighter rules for those tags will never fire.
- **`chflags schg` on sealed files considered and rejected.** Immutability flags fight iCloud sync and don't match the adversary capability we're worried about. Documented the decision so we don't relitigate it; the value goes elsewhere.

Each one is a paragraph. Each one is something we know now and didn't before. Each one fires automatically the next time the relevant context comes up — so the next decoration module in this codebase (or the next plugin we build entirely) ships with the three-tier sort in its first commit, not in the first fix-up after a Mac smoke.

This is the compounding-value claim. AI-with-review isn't faster *once*. It's faster *over time*, because the scar tissue is reified into something the next agent inherits. The version of north that builds v0.7 doesn't need anyone to re-explain why `block: true` on a `Decoration.replace` is dangerous during edits. It's in the file.

There's a darker version of this where the memory layer fills up with low-quality notes and the signal-to-noise ratio collapses. We're not there yet; we've got fourteen entries total across two months of build work, all originated from a specific incident, all referenced when the relevant context comes back. The discipline is: a memory is earned by a real bite, not by speculation. "We might want to remember X" doesn't make it in. "X bit us on date Y, here's the fix, here's how to avoid it" does.

---

## methodology takeaways

If you're trying this loop yourself, the rules that emerged from two days of doing it:

1. **Parallel subagent review beats serial review.** Run security and QA at the same time, against the same diff, with different checklists. The overlap is small; the coverage gain is real.

2. **The fake catches the real.** Unit tests against a fake encryption layer (or any fake whose behavior is contract-defined, not empirically observed) will expose contract violations that an end-to-end smoke pass quietly swallows. Build the fake. Test against it.

3. **The real environment is non-negotiable.** Sandbox `npm test` and builder-self-smoke are not substitutes for "human runs `npm run build` on the target platform with the target runtime." Always close the loop on the real machine.

4. **Memories compound.** Every bite is a memory file. The cost of writing the memory is five minutes; the cost of not writing it is the next agent hitting the same bite.

5. **AI is great at translation, bad at taste.** Spec → implementation: fine. Architecture decisions, when-to-break-a-feature calls, "is this comment lying" judgments: still human work.

6. **Confidence is not competence.** This is the unmodified version of [Chalk's line from February](/blog/building-with-ai-agents). Every agent ships work that looks right. Some of it is right. The review loop is the difference between "looks right" and "is right."

7. **Name the dispatch pattern; don't claim it.** Parallel subagents are a well-documented Claude Code primitive. What's halfday-specific isn't the pattern — it's the specific shape we wired it into for security-OSS dev work. Borrow the pattern. Build your own shape.

---

## what's next

Halfday Rune v0.6 is shipped end-to-end and the [GitHub repo](https://github.com/halfday-dev/halfday-rune) is open. v0.7 is the community-plugin-center submission to Obsidian. v0.8 is the click-to-navigate work on wikilinks, which means another security pass on URL resolution. v1.0 is hardware-key support — Secure Enclave on macOS, eventually YubiKey via age-plugin-yubikey.

If you build dev tooling and you've been wondering whether the multi-agent-with-review loop actually pays off — it does, and the part that pays is the review, not the agents. Use them as accelerators. Keep the human in the verification seat. Build the memory layer. Don't trust confident output until something falsifiable has been run against it.

Halfday's bet: AI accelerates the work; review and memory make it durable. If the loop pays off for you, [the repo](https://github.com/halfday-dev/halfday-rune) is the source of truth. If you want the user-facing case, [start here](/blog/halfday-rune-secure-obsidian-ai-era). And [buying us a coffee](https://buymeacoffee.com/halfday) keeps the next thing shippable.

We build in half a day. You benefit for a lot longer.

---

*Halfday is an indie dev shop building security-flavored developer and knowledge-worker tools. The Rune source is at [`https://github.com/halfday-dev/halfday-rune`](https://github.com/halfday-dev/halfday-rune). The build loop described in this post runs out of Claude Code with Anthropic's Claude Agent SDK; the parallel subagent pattern is documented at [anthropic.com/engineering](https://www.anthropic.com/engineering/building-agents-with-the-claude-agent-sdk).*
