#!/usr/bin/env bash
# Run ZAP's passive baseline scan against the local Juice Shop and gate on zap/rules.conf.
# zap-baseline.py exits 0 (all pass), 1 (a FAIL rule triggered), 2 (warnings only) or 3 (error).
set -u
config=${1:-rules.conf}
docker compose run --rm zap zap-baseline.py -t http://juice-shop:3000 \
  -c "$config" -r report.html -J report.json
code=$?
case $code in
  0 | 2) echo "ZAP baseline: no new issues (exit $code)"; exit 0 ;;
  1) echo "ZAP baseline: a FAIL rule triggered, see zap/report.html"; exit 1 ;;
  *) echo "ZAP baseline: scan error (exit $code)"; exit "$code" ;;
esac
