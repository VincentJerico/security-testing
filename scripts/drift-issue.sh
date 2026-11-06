#!/usr/bin/env bash
# Report the nightly drift watch on one GitHub issue labelled $LABEL (default security-drift).
#   Every check passed:  comment on the open issue (if any) and close it, then exit 0.
#   Anything else:       comment on the open issue, or open one, then exit 1.
# Inputs (env): TESTS, ZAP, TRIVY, DRIFT (each a step outcome such as success or failure) and
# RUN_URL. Reads drift.md if the comparison wrote one. Needs `gh` with GH_TOKEN.
set -euo pipefail
LABEL=${LABEL:-security-drift}

{
  echo "Nightly run: ${RUN_URL:-unknown}"
  echo
  echo "| Check | Outcome |"
  echo "| --- | --- |"
  echo "| Pinned security tests | $TESTS |"
  echo "| ZAP baseline (rules.conf gate) | $ZAP |"
  echo "| Trivy scan and scanner self-test | $TRIVY |"
  echo "| Compared with baseline/findings.json | $DRIFT |"
  echo
  if [ -f drift.md ]; then cat drift.md; else echo "The comparison didn't run, see the run log."; fi
} > issue.md

gh label create "$LABEL" --color B60205 \
  --description "Nightly scan found something the baseline doesn't know" >/dev/null 2>&1 || true
open_issue=$(gh issue list --label "$LABEL" --state open --json number --jq '.[0].number // empty')

if [ "$TESTS $ZAP $TRIVY $DRIFT" = "success success success success" ]; then
  if [ -n "$open_issue" ]; then
    gh issue comment "$open_issue" --body-file issue.md
    gh issue close "$open_issue" --comment "No drift in this run, closing."
  fi
  echo "No drift."
  exit 0
fi

if [ -n "$open_issue" ]; then
  gh issue comment "$open_issue" --body-file issue.md
else
  gh issue create --title "Security drift: the nightly scan found new results" \
    --label "$LABEL" --body-file issue.md
fi
echo "::error::Drift found, see the $LABEL issue."
exit 1
