#!/usr/bin/env bash
set -euo pipefail

# ─── Halfday Env Scanner ─────────────────────────────────────────────
# Runs halfday-env-scan, posts PR comment, and fails on bad grades.
# ─────────────────────────────────────────────────────────────────────

ENV_PATH="${INPUT_PATH:-.env.example}"
FAIL_GRADE="${INPUT_FAIL_GRADE:-D}"
COMMENT_ON_PR="${INPUT_COMMENT_ON_PR:-true}"

# Grade ordering (lower index = better)
GRADE_ORDER="A B C D F"

grade_index() {
  local i=0
  for g in $GRADE_ORDER; do
    if [[ "$g" == "$1" ]]; then
      echo "$i"
      return
    fi
    i=$((i + 1))
  done
  echo "99"
}

# ─── Install & Run ───────────────────────────────────────────────────

echo "🔒 Installing halfday-env-scan..."
npm install --no-save halfday-env-scan@^1 2>/dev/null

echo "🔍 Scanning ${ENV_PATH}..."

if [[ ! -f "$ENV_PATH" ]]; then
  echo "::error::File not found: ${ENV_PATH}"
  exit 1
fi

# Run scan and capture JSON output
SCAN_OUTPUT=$(npx halfday-env-scan --json "$ENV_PATH" 2>/dev/null || true)

# Parse results
GRADE=$(echo "$SCAN_OUTPUT" | jq -r '.grade // "F"')
TOTAL_FINDINGS=$(echo "$SCAN_OUTPUT" | jq -r '(.findings // []) | length')
CRITICAL=$(echo "$SCAN_OUTPUT" | jq -r '[(.findings // [])[] | select(.severity == "critical")] | length')
WARNING=$(echo "$SCAN_OUTPUT" | jq -r '[(.findings // [])[] | select(.severity == "warning")] | length')
INFO=$(echo "$SCAN_OUTPUT" | jq -r '[(.findings // [])[] | select(.severity == "info")] | length')

echo "📊 Grade: ${GRADE} | Findings: ${TOTAL_FINDINGS} (${CRITICAL} critical, ${WARNING} warning, ${INFO} info)"

# ─── PR Comment ──────────────────────────────────────────────────────

if [[ "$COMMENT_ON_PR" == "true" && -n "${GITHUB_EVENT_NAME:-}" && "$GITHUB_EVENT_NAME" == "pull_request" ]]; then
  PR_NUMBER=$(jq -r '.pull_request.number' "$GITHUB_EVENT_PATH")

  if [[ "$PR_NUMBER" != "null" && -n "$PR_NUMBER" ]]; then
    # Build grade emoji
    case "$GRADE" in
      A) EMOJI="🟢" ;;
      B) EMOJI="🟡" ;;
      C) EMOJI="🟠" ;;
      D) EMOJI="🔴" ;;
      F) EMOJI="💀" ;;
      *) EMOJI="❓" ;;
    esac

    # Build findings table
    FINDINGS_TABLE=""
    if [[ "$TOTAL_FINDINGS" -gt 0 ]]; then
      FINDINGS_TABLE=$(echo "$SCAN_OUTPUT" | jq -r '
        (.findings // [])[] |
        "| " +
        (if .severity == "critical" then "🔴 Critical"
         elif .severity == "warning" then "🟡 Warning"
         else "ℹ️ Info" end) +
        " | `" + .key + "` | " + .message + " |"
      ')
      FINDINGS_TABLE="
### Findings

| Severity | Key | Issue |
|----------|-----|-------|
${FINDINGS_TABLE}
"
    fi

    # Compose comment body
    COMMENT_BODY="## ${EMOJI} Halfday Env Scanner — Grade: ${GRADE}

**File:** \`${ENV_PATH}\`
**Findings:** ${TOTAL_FINDINGS} (${CRITICAL} critical, ${WARNING} warning, ${INFO} info)
${FINDINGS_TABLE}
---
<sub>🔒 Scanned by [Halfday](https://halfday.dev) — secure your .env files</sub>"

    # Post comment via GitHub API
    PAYLOAD=$(jq -n --arg body "$COMMENT_BODY" '{"body": $body}')
    REPO="${GITHUB_REPOSITORY}"
    API_URL="https://api.github.com/repos/${REPO}/issues/${PR_NUMBER}/comments"

    curl -s -X POST "$API_URL" \
      -H "Authorization: token ${GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github.v3+json" \
      -d "$PAYLOAD" > /dev/null

    echo "💬 PR comment posted."
  fi
fi

# ─── Grade Check ─────────────────────────────────────────────────────

FAIL_INDEX=$(grade_index "$FAIL_GRADE")
ACTUAL_INDEX=$(grade_index "$GRADE")

if [[ "$ACTUAL_INDEX" -gt "$FAIL_INDEX" ]]; then
  echo "::error::Grade ${GRADE} is below the minimum passing grade ${FAIL_GRADE}"
  exit 1
fi

echo "✅ Passed with grade ${GRADE}"
