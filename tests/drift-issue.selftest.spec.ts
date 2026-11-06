import { test, expect } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

/**
 * Runs scripts/drift-issue.sh with a fake `gh` that records its calls, for each combination of
 * "checks passed or not" and "a drift issue is open or not". Proves the nightly job opens, updates
 * and closes the issue as described, and fails the run whenever something drifted.
 */
const SCRIPT = resolve('scripts/drift-issue.sh');

function run(outcomes: { tests?: string; drift?: string }, openIssue: string, driftMd?: string) {
  const dir = mkdtempSync(join(tmpdir(), 'drift-issue-'));
  const log = join(dir, 'gh.log');
  writeFileSync(
    join(dir, 'gh'),
    `#!/usr/bin/env bash\necho "$*" >> "${log}"\n` +
      `if [ "$1 $2" = "issue list" ]; then echo "${openIssue}"; fi\n`,
  );
  chmodSync(join(dir, 'gh'), 0o755);
  if (driftMd) writeFileSync(join(dir, 'drift.md'), driftMd);
  const result = spawnSync('bash', [SCRIPT], {
    cwd: dir,
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${dir}:${process.env.PATH}`,
      TESTS: outcomes.tests ?? 'success',
      ZAP: 'success',
      TRIVY: 'success',
      DRIFT: outcomes.drift ?? 'success',
      RUN_URL: 'https://example.test/run/1',
    },
  });
  const calls = readFileSync(log, 'utf8').trim().split('\n');
  return { status: result.status, calls, issue: readFileSync(join(dir, 'issue.md'), 'utf8') };
}

const ghCalls = (calls: string[]) => calls.filter((c) => !c.startsWith('label create'));

test.describe('drift issue self-test', () => {
  test('clean run with no open issue: nothing to do, exit 0', () => {
    const r = run({}, '');
    expect(r.status).toBe(0);
    expect(ghCalls(r.calls)).toEqual([
      'issue list --label security-drift --state open --json number --jq .[0].number // empty',
    ]);
  });

  test('clean run with an open issue: comment and close it, exit 0', () => {
    const r = run({}, '7', 'No drift: the scans match the baseline.');
    expect(r.status).toBe(0);
    expect(ghCalls(r.calls).slice(1)).toEqual([
      'issue comment 7 --body-file issue.md',
      'issue close 7 --comment No drift in this run, closing.',
    ]);
  });

  test('drift with no open issue: open one, exit 1', () => {
    const r = run({ drift: 'failure' }, '', '### 1 new CVE(s)\n\n- CVE-2026-9999');
    expect(r.status).toBe(1);
    expect(ghCalls(r.calls).slice(1)).toEqual([
      'issue create --title Security drift: the nightly scan found new results ' +
        '--label security-drift --body-file issue.md',
    ]);
    expect(r.issue).toContain('| Compared with baseline/findings.json | failure |');
    expect(r.issue).toContain('CVE-2026-9999');
  });

  test('a failing pinned test with an open issue: comment on it, exit 1', () => {
    const r = run({ tests: 'failure' }, '7');
    expect(r.status).toBe(1);
    expect(ghCalls(r.calls).slice(1)).toEqual(['issue comment 7 --body-file issue.md']);
    expect(r.issue).toContain('| Pinned security tests | failure |');
    expect(r.issue).toContain("The comparison didn't run, see the run log.");
  });
});
