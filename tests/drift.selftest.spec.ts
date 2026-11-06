import { test, expect } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  compare,
  currentFindings,
  driftReport,
  hasNewFindings,
  type Baseline,
} from '../scripts/drift.js';

/**
 * Proves the drift watch can fail: a planted new CVE and a planted new ZAP alert must be reported
 * and make the check exit 1, while findings that disappear are reported without failing.
 */
const trivy = (...ids: string[]) => ({
  ArtifactName: 'bkimminich/juice-shop:v18.0.0',
  CreatedAt: '2026-11-06T13:44:47Z',
  Results: [
    { Vulnerabilities: ids.slice(0, 1).map((VulnerabilityID) => ({ VulnerabilityID })) },
    { Vulnerabilities: ids.map((VulnerabilityID) => ({ VulnerabilityID })) },
  ],
});

const zap = (...alerts: [string, string][]) => ({
  '@version': '2.17.0',
  site: [{ alerts: alerts.map(([alertRef, riskcode]) => ({ alertRef, riskcode })) }],
});

const BASELINE: Baseline = {
  note: 'test',
  image: 'bkimminich/juice-shop:v18.0.0',
  zapVersion: '2.17.0',
  scannedAt: '2026-11-06T13:44:47Z',
  cves: ['CVE-2026-0001', 'CVE-2026-0002'],
  zapAlerts: ['10038-1', '90004-2'],
};

test.describe('drift watch self-test', () => {
  test('collects unique CVEs and ZAP alerts of Low risk or above', () => {
    const found = currentFindings(
      trivy('CVE-2026-0002', 'CVE-2026-0001'),
      zap(['10038-1', '2'], ['10109', '0'], ['90004-2', '1']),
    );
    expect(found).toEqual({
      cves: ['CVE-2026-0001', 'CVE-2026-0002'],
      zapAlerts: ['10038-1', '90004-2'],
    });
  });

  test('no drift when the scans match the baseline', () => {
    const drift = compare(BASELINE, { cves: BASELINE.cves, zapAlerts: BASELINE.zapAlerts });
    expect(hasNewFindings(drift)).toBe(false);
    expect(driftReport(drift, BASELINE)).toContain('No drift: the scans match the baseline.');
  });

  test('a planted new CVE and ZAP alert are drift', () => {
    const drift = compare(BASELINE, {
      cves: [...BASELINE.cves, 'CVE-2026-9999'],
      zapAlerts: [...BASELINE.zapAlerts, '10020-1'],
    });
    expect(drift).toMatchObject({ newCves: ['CVE-2026-9999'], newZapAlerts: ['10020-1'] });
    expect(hasNewFindings(drift)).toBe(true);
    const report = driftReport(drift, BASELINE);
    expect(report).toContain('[CVE-2026-9999](https://nvd.nist.gov/vuln/detail/CVE-2026-9999)');
    expect(report).toContain('[10020-1](https://www.zaproxy.org/docs/alerts/10020/)');
  });

  test('findings that disappear are listed but are not drift', () => {
    const drift = compare(BASELINE, { cves: ['CVE-2026-0001'], zapAlerts: BASELINE.zapAlerts });
    expect(drift.resolvedCves).toEqual(['CVE-2026-0002']);
    expect(hasNewFindings(drift)).toBe(false);
    expect(driftReport(drift, BASELINE)).toContain('No longer reported');
  });

  test('the check exits 1 on drift and 0 without it', () => {
    const dir = mkdtempSync(join(tmpdir(), 'drift-'));
    mkdirSync(join(dir, 'baseline'));
    writeFileSync(join(dir, 'baseline/findings.json'), JSON.stringify(BASELINE));
    writeFileSync(join(dir, 'zap.json'), JSON.stringify(zap(['10038-1', '2'], ['90004-2', '1'])));
    const run = (ids: string[]) => {
      writeFileSync(join(dir, 'trivy.json'), JSON.stringify(trivy(...ids)));
      try {
        execFileSync('node', [resolve('scripts/drift.ts'), 'check', 'trivy.json', 'zap.json'], {
          cwd: dir,
          env: { ...process.env, GITHUB_STEP_SUMMARY: '' },
          stdio: 'pipe',
        });
        return 0;
      } catch (err) {
        return (err as { status: number }).status;
      }
    };
    expect(run(BASELINE.cves)).toBe(0);
    expect(run([...BASELINE.cves, 'CVE-2026-9999'])).toBe(1);
  });
});
