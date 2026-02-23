---
title: "Securing Your AI Agent on macOS with User Isolation"
description: "A practical guide to running OpenClaw as an isolated user on macOS — with every command you need."
date: 2026-02-20
author: "Halfday"
tags: ["security", "macos", "openclaw", "ai-agents"]
---

Our AI agent has shell access on the same Mac mini where our SSH keys live. That's a problem.

We run [OpenClaw](https://github.com/openclaw/openclaw) as an always-on assistant — it talks to us on Signal, commits code, manages deploys. It also runs arbitrary shell commands on our machine. So we created a dedicated macOS user called `hexagent`, locked it down, and gave it only what it needs. Took about 20 minutes.

Here's exactly how we did it, every command included.

## What you're defending against

An AI agent with tool access has a specific threat model:

- **Prompt injection.** Someone sends your agent a crafted message. Now it's running `curl` to an attacker's server with your env vars. Not hypothetical.
- **Compromised dependencies.** Your agent runs npm packages. Those packages have deps. One malicious dependency running as your main user has access to everything you do.
- **Lateral movement.** Agent gets compromised, reads your SSH keys, browser cookies, password manager vault. Game over.

The principle: **the agent should only be able to damage what it needs to touch.**

If OpenClaw runs as your daily-driver user, it inherits your home directory, your admin group, your keychain, your GitHub tokens — everything. One prompt injection from full compromise. Don't do that.

## What OpenClaw gives you out of the box

Before touching the OS, know what's already there:

- **Loopback binding** — Gateway binds to `127.0.0.1` by default. Not exposed to your network.
- **Token auth** — Every API call requires a bearer token.
- **Workspace-only filesystem** — Restricts file access to the workspace directory.
- **Exec allowlists** — Control which shell commands the agent can run.
- **`openclaw security audit`** — Checks your deployment for common misconfigs.

These are application-level controls. Good defaults. But if the process itself gets compromised — malicious dep, code execution via prompt injection — the attacker has whatever OS-level access the process user has. That's why you need user isolation on top.

## The setup

Tested on macOS Sequoia (15.x), Apple Silicon. You need admin access for setup, but the agent won't have it afterward.

### 1. Create the agent user

```bash
# Prefix with a space to keep the password out of shell history,
# or omit -password entirely for an interactive prompt.
 sudo sysadminctl -addUser hexagent \
  -fullName "Hex Agent" \
  -password "YourSecurePassword"
```

Do NOT pass `-admin`. The whole point is a non-admin user.

Verify:

```bash
dscl . -read /Groups/admin GroupMembership
# hexagent should NOT appear in this list
```

### 2. Create a shared group

Both your user and `hexagent` need workspace access. A shared group handles this cleanly.

```bash
sudo dscl . -create /Groups/shared_agents
sudo dscl . -create /Groups/shared_agents PrimaryGroupID 1050
sudo dscl . -create /Groups/shared_agents RealName "Shared Agent Group"

sudo dscl . -append /Groups/shared_agents GroupMembership hexagent
sudo dscl . -append /Groups/shared_agents GroupMembership $(whoami)
```

### 3. Set up directories

```bash
sudo mkdir -p /Users/hexagent/.openclaw/workspace
sudo chown -R hexagent:shared_agents /Users/hexagent/.openclaw/workspace
sudo chmod -R 770 /Users/hexagent/.openclaw/workspace

sudo mkdir -p /Users/hexagent/.openclaw/logs
sudo chown -R hexagent:staff /Users/hexagent/.openclaw/logs
```

### 4. Install OpenClaw

```bash
# Node.js (if not already installed)
brew install node@22

# OpenClaw globally so the LaunchDaemon can find it
# Note: this runs npm lifecycle scripts as root.
# Use --ignore-scripts if you want to audit first.
sudo npm install -g openclaw
```

### 5. Configure OpenClaw

```bash
sudo su - hexagent

openclaw onboard

# Or manually:
mkdir -p ~/.openclaw
cat > ~/.openclaw/openclaw.json << 'EOF'
{
  "gateway": {
    "mode": "local",
    "bind": "loopback",
    "auth": {
      "mode": "token"
    }
  },
  "tools": {
    "fs": { "workspaceOnly": true },
    "exec": { "security": "allowlist" }
  }
}
EOF

exit
```

### 6. Create the LaunchDaemon

This runs OpenClaw as `hexagent` at boot, no GUI login required.

```bash
sudo tee /Library/LaunchDaemons/ai.openclaw.gateway.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>ai.openclaw.gateway</string>

  <key>UserName</key>
  <string>hexagent</string>

  <!-- Run `which node` and `npm root -g` to get the right paths for your system.
       Homebrew on Apple Silicon uses /opt/homebrew/; Intel uses /usr/local/. -->
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/node</string>
    <string>/opt/homebrew/lib/node_modules/openclaw/dist/index.js</string>
    <string>gateway</string>
    <string>--port</string>
    <string>18789</string>
  </array>

  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key>
    <string>/Users/hexagent</string>
    <key>PATH</key>
    <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    <key>OPENCLAW_GATEWAY_PORT</key>
    <string>18789</string>
    <key>OPENCLAW_GATEWAY_TOKEN</key>
    <string>REPLACE_WITH_A_LONG_RANDOM_TOKEN</string>
  </dict>

  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>

  <key>StandardOutPath</key>
  <string>/Users/hexagent/.openclaw/logs/gateway.log</string>
  <key>StandardErrorPath</key>
  <string>/Users/hexagent/.openclaw/logs/gateway.err.log</string>
</dict>
</plist>
EOF
```

Generate your token and paste it in:

```bash
openssl rand -hex 24
```

Set permissions and load:

```bash
sudo chown root:wheel /Library/LaunchDaemons/ai.openclaw.gateway.plist
sudo chmod 644 /Library/LaunchDaemons/ai.openclaw.gateway.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/ai.openclaw.gateway.plist
```

**A note on that 644:** LaunchDaemon plists must be owned by root and world-readable, so the gateway token in the plist is visible to any local user. On a single-user machine, fine. On a shared machine, source the token from a separate file with restricted permissions instead.

### 7. Scope credentials

Give `hexagent` only what it needs.

```bash
sudo su - hexagent

mkdir -p ~/.ssh
chmod 700 ~/.ssh

# Generate a deploy key for a specific repo — not your personal key
ssh-keygen -t ed25519 -f ~/.ssh/deploy_halfday -C "hexagent-deploy-halfday" -N ""

cat > ~/.ssh/config << 'EOF'
Host github.com
  HostName github.com
  User git
  IdentityFile ~/.ssh/deploy_halfday
  IdentitiesOnly yes
EOF

chmod 600 ~/.ssh/config

exit
```

Add the public key (`~hexagent/.ssh/deploy_halfday.pub`) as a **deploy key** on the specific GitHub repo — not as an SSH key on your account.

For API access, use a fine-grained PAT scoped to only the repos the agent needs:

```bash
sudo su - hexagent
echo "github_pat_XXXXXXXXXXXX" > ~/.ssh/github_pat
chmod 600 ~/.ssh/github_pat
exit
```

### 8. Lock down your home directory

```bash
chmod 750 /Users/$(whoami)

# Verify
sudo su - hexagent -c "ls /Users/$(whoami)/"
# Should get: "Permission denied"
```

### 9. Test everything

```bash
# Daemon running?
sudo launchctl list | grep openclaw

# Running as hexagent?
ps aux | grep openclaw | grep -v grep

# Bound to localhost only?
lsof -i :18789
# Should show 127.0.0.1:18789, not *:18789

# API responding?
curl -s -H "Authorization: Bearer YOUR_TOKEN" http://127.0.0.1:18789/api/health

# Security audit
sudo su - hexagent -c "openclaw security audit"
```

### 10. Paranoia check

Run these as `hexagent`. They should all fail.

```bash
sudo su - hexagent

# No sudo access
sudo ls /
# "hexagent is not in the sudoers file"

# Can't read your home
ls /Users/yourusername/
# "Permission denied"

# Can't read your SSH keys
cat /Users/yourusername/.ssh/id_ed25519
# "Permission denied"

exit
```

## What this doesn't cover

**Egress filtering.** `hexagent` can still call out to any IP. A compromised agent could exfiltrate data over HTTP. Little Snitch and Lulu can monitor outbound connections but neither does per-user rules natively. No good solution yet.

**Mandatory access controls.** macOS doesn't have AppArmor or SELinux. `sandbox-exec` exists but is deprecated. User isolation is the best practical boundary without containers.

**Audit logging.** OpenClaw logs to `~/.openclaw/logs/`, and macOS Unified Logging captures some activity, but purpose-built agent audit logs would make incident response easier.

**Credential rotation.** Tokens and PATs should rotate on a schedule. We don't do this yet. You should.

## Honest grade: A-

If `hexagent` gets fully compromised, the blast radius is: our halfday-dev GitHub repo, Signal messages via the signal-cli API, and `/tmp`. Not ideal, but contained.

The missing points are egress filtering and audit logging. But user isolation + scoped credentials + loopback binding + token auth gets you 90% of the way. Oldest trick in the Unix playbook, and it works.

Run `openclaw security audit` and see where you stand.

---

*[Halfday](https://halfday.dev) builds tools for developers who run AI agents on their own hardware. [OpenClaw](https://github.com/openclaw/openclaw) is open source and MIT licensed.*
