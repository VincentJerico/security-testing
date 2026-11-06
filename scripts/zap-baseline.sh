#!/usr/bin/env bash
# Run ZAP's passive baseline scan against the local Juice Shop and gate on zap/rules.conf.
# zap-baseline.py exits 0 (all pass), 1 (a FAIL rule triggered), 2 (warnings only) or 3 (error).
set -u
config=${1:-rules.conf}
# Remove reports from an earlier run, so a crash can't pass off an old report as this one.
rm -f zap/report.json zap/report.html
docker compose run --rm zap zap-baseline.py -t http://juice-shop:3000 \
  -c "$config" -r report.html -J report.json
code=$?
# zap-baseline.py also exits 1 when it crashes (for example on a missing config file), so a
# missing report means the scan itself failed, whatever the exit code says.
if [ ! -s zap/report.json ]; then
  echo "ZAP baseline: scan error, no zap/report.json was written (exit $code)"
  exit 3
fi
case $code in
  0 | 2) echo "ZAP baseline: no new issues (exit $code)"; exit 0 ;;
  1) echo "ZAP baseline: a FAIL rule triggered, see zap/report.html"; exit 1 ;;
  *) echo "ZAP baseline: scan error (exit $code)"; exit "$code" ;;
esac
