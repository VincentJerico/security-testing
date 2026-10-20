#!/usr/bin/env bash
# Scan the Juice Shop image and the scanner self-test fixture with Trivy (pinned).
# The image scan only reports. The fixture scan fails unless Trivy finds the known lodash CVE.
set -euo pipefail
TRIVY=aquasec/trivy:0.76.0
mkdir -p reports .trivy-cache
run() { docker run --rm -v "$PWD/.trivy-cache:/root/.cache/trivy" -v "$PWD:/work" -w /work "$TRIVY" "$@"; }

run fs --quiet --scanners vuln --format json --output reports/selftest-trivy.json fixtures/vulnerable-lockfile
node scripts/trivy-summary.mjs reports/selftest-trivy.json --expect CVE-2020-8203

run image --quiet --scanners vuln --severity HIGH,CRITICAL --format json \
  --output reports/juice-shop-trivy.json bkimminich/juice-shop:v18.0.0
node scripts/trivy-summary.mjs reports/juice-shop-trivy.json
