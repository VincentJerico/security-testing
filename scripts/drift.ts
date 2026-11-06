// Compare tonight's scan results with the committed baseline (baseline/findings.json).
// The images are pinned, so the target itself doesn't change. What does change is the outside
// world: Trivy's database learns about new CVEs in packages Juice Shop already ships.
//
//   node scripts/drift.ts check  <trivy.json> <zap.json> [--report drift.md]   exit 1 on new findings
//   node scripts/drift.ts update <trivy.json> <zap.json>                       rewrite the baseline
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export const BASELINE_FILE = 'baseline/findings.json';

export interface Findings {
  /** Unique CVE (or GHSA) IDs Trivy reports for the image. */
  cves: string[];
  /** ZAP alertRefs with risk Low or above (informational alerts don't count). */
  zapAlerts: string[];
}

export interface Baseline extends Findings {
  image: string;
  zapVersion: string;
  /** When the Trivy scan behind the baseline ran (the report's CreatedAt). */
  scannedAt: string;
  note: string;
}

interface TrivyReport {
  ArtifactName: string;
  CreatedAt: string;
  Results?: { Vulnerabilities?: { VulnerabilityID: string }[] }[];
}

interface ZapReport {
  '@version': string;
  site: { alerts: { alertRef: string; riskcode: string }[] }[];
}

const sortedUnique = (ids: string[]) => [...new Set(ids)].sort();

export function currentFindings(trivy: TrivyReport, zap: ZapReport): Findings {
  return {
    cves: sortedUnique(
      (trivy.Results ?? []).flatMap((r) => (r.Vulnerabilities ?? []).map((v) => v.VulnerabilityID)),
    ),
    zapAlerts: sortedUnique(
      zap.site.flatMap((s) =>
        s.alerts.filter((a) => Number(a.riskcode) >= 1).map((a) => a.alertRef),
      ),
    ),
  };
}

export interface Drift {
  newCves: string[];
  resolvedCves: string[];
  newZapAlerts: string[];
  resolvedZapAlerts: string[];
}

export function compare(baseline: Findings, current: Findings): Drift {
  const added = (base: string[], now: string[]) => now.filter((id) => !base.includes(id));
  return {
    newCves: added(baseline.cves, current.cves),
    resolvedCves: added(current.cves, baseline.cves),
    newZapAlerts: added(baseline.zapAlerts, current.zapAlerts),
    resolvedZapAlerts: added(current.zapAlerts, baseline.zapAlerts),
  };
}

export const hasNewFindings = (d: Drift) => d.newCves.length + d.newZapAlerts.length > 0;

const list = (ids: string[], link: (id: string) => string) =>
  ids.map((id) => `- [${id}](${link(id)})`).join('\n');
const cveLink = (id: string) =>
  id.startsWith('GHSA-')
    ? `https://github.com/advisories/${id}`
    : `https://nvd.nist.gov/vuln/detail/${id}`;
const zapLink = (ref: string) => `https://www.zaproxy.org/docs/alerts/${ref.split('-')[0]}/`;

export function driftReport(d: Drift, baseline: Baseline): string {
  const parts = [`Compared with \`${BASELINE_FILE}\` (scanned ${baseline.scannedAt}).`, ''];
  if (!hasNewFindings(d) && d.resolvedCves.length + d.resolvedZapAlerts.length === 0) {
    parts.push('No drift: the scans match the baseline.');
  }
  if (d.newCves.length) {
    parts.push(
      `### ${d.newCves.length} new CVE(s) in ${baseline.image}`,
      '',
      list(d.newCves, cveLink),
      '',
    );
  }
  if (d.newZapAlerts.length) {
    parts.push(
      `### ${d.newZapAlerts.length} new ZAP alert(s)`,
      '',
      list(d.newZapAlerts, zapLink),
      '',
    );
  }
  if (d.resolvedCves.length || d.resolvedZapAlerts.length) {
    parts.push(
      '### No longer reported',
      '',
      'These are in the baseline but not in this run. That is not a failure. Update the baseline',
      'in a PR (`npm run baseline:update`) once the change is understood.',
      '',
      list(d.resolvedCves, cveLink),
      list(d.resolvedZapAlerts, zapLink),
      '',
    );
  }
  return parts.filter((p, i, all) => p !== '' || all[i - 1] !== '').join('\n');
}

function read<T>(file: string): T {
  return JSON.parse(readFileSync(file, 'utf8')) as T;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [mode, trivyFile, zapFile, flag, reportFile] = process.argv.slice(2);
  if (!['check', 'update'].includes(mode ?? '') || !trivyFile || !zapFile) {
    console.error(
      'usage: node scripts/drift.ts check|update <trivy.json> <zap.json> [--report file]',
    );
    process.exit(2);
  }
  const trivy = read<TrivyReport>(trivyFile);
  const zap = read<ZapReport>(zapFile);
  const current = currentFindings(trivy, zap);

  if (mode === 'update') {
    const baseline: Baseline = {
      note: 'Known findings for the nightly drift watch. Regenerate with npm run baseline:update.',
      image: trivy.ArtifactName,
      zapVersion: zap['@version'],
      scannedAt: trivy.CreatedAt,
      ...current,
    };
    writeFileSync(BASELINE_FILE, JSON.stringify(baseline, null, 2) + '\n');
    console.log(`Baseline: ${current.cves.length} CVEs, ${current.zapAlerts.length} ZAP alerts.`);
  } else {
    const baseline = read<Baseline>(BASELINE_FILE);
    const drift = compare(baseline, current);
    const report = driftReport(drift, baseline);
    console.log(report);
    if (flag === '--report' && reportFile) writeFileSync(reportFile, report + '\n');
    if (process.env.GITHUB_STEP_SUMMARY)
      appendFileSync(process.env.GITHUB_STEP_SUMMARY, report + '\n');
    process.exit(hasNewFindings(drift) ? 1 : 0);
  }
}
