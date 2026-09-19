#!/usr/bin/env bash
#
# Triggers the "Sample population" GitHub Actions workflow via workflow_dispatch.
#
# GitHub's scheduled cron is best-effort and often delayed or dropped under load.
# Running this from a reliable always-on host's crontab gives a dependable hourly
# sample. The workflow already enables workflow_dispatch, so no repo change is
# needed to use this.
#
# Setup:
#   1. Create a fine-grained PAT scoped to ONLY this repo with
#      "Actions: Read and write" permission (least privilege).
#      https://github.com/settings/tokens?type=beta
#   2. Export it as GH_DISPATCH_TOKEN where cron can see it (see crontab example
#      at the bottom of this file).
#
# Exit codes: 0 on a successful dispatch (HTTP 204), 1 if every retry failed.

set -euo pipefail

REPO="jmctune/unora-population-tracker"
WORKFLOW="population.yml"   # workflow file name (or its numeric id)
REF="main"                  # branch to run the workflow from
RETRIES=5

TOKEN="${GH_DISPATCH_TOKEN:?set GH_DISPATCH_TOKEN to a PAT with Actions:write on $REPO}"
API="https://api.github.com/repos/${REPO}/actions/workflows/${WORKFLOW}/dispatches"

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

for attempt in $(seq 1 "$RETRIES"); do
  code=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$API" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -d "{\"ref\":\"${REF}\"}" || echo "000")

  if [ "$code" = "204" ]; then
    echo "$(ts) dispatched $WORKFLOW on $REF (attempt $attempt)"
    exit 0
  fi

  echo "$(ts) dispatch failed: HTTP $code (attempt $attempt/$RETRIES)" >&2
  sleep $((attempt * 10))   # 10s, 20s, 30s, 40s backoff
done

echo "$(ts) gave up after $RETRIES attempts" >&2
exit 1

# ---------------------------------------------------------------------------
# crontab entry (run `crontab -e` on the always-on host). Fires at :05 each hour
# to dodge the top-of-hour API rush; the exact minute does not matter.
#
#   5 * * * * GH_DISPATCH_TOKEN=github_pat_xxx /path/to/trigger-population.sh >> /var/log/unora-trigger.log 2>&1
#
# Keep the token out of the script itself so it is not committed. Either inline it
# in the crontab line as above, or source it from a root-only file, e.g.:
#
#   5 * * * * . /etc/unora.env; /path/to/trigger-population.sh >> /var/log/unora-trigger.log 2>&1
# ---------------------------------------------------------------------------
