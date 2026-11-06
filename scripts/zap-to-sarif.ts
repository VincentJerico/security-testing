// Convert a ZAP baseline report (report.json) to SARIF 2.1.0, so GitHub code scanning can show the
// findings in the repo's Security tab. ZAP findings are about URLs, not source files, so each
// result points at the line of zap/rules.conf that decides how CI treats that rule.
//
// usage: node scripts/zap-to-sarif.ts <report.json> <rules.conf> <out.sarif>
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export interface ZapInstance {
  uri: string;
  method: string;
}

export interface ZapAlert {
  pluginid: string;
  alertRef: string;
  alert: string;
  riskcode: string;
  riskdesc: string;
  cweid: string;
  desc: string;
  solution: string;
  count: string;
  instances: ZapInstance[];
}

export interface ZapReport {
  '@version': string;
  site: { '@name': string; alerts: ZapAlert[] }[];
}

// Code scanning reads 'security-severity' as a CVSS-like score: 7.0+ is high, 4.0+ medium.
const SEVERITY: Record<string, { level: string; score: string }> = {
  '3': { level: 'error', score: '7.5' },
  '2': { level: 'warning', score: '5.0' },
  '1': { level: 'note', score: '3.0' },
};

const MAX_URLS_IN_MESSAGE = 3;

export function stripHtml(html: string): string {
  return html
    .replace(/<\/p>\s*<p>/g, '\n')
    .replace(/<[^>]+>/g, '')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&amp;/g, '&')
    .trim();
}

/** Line number (1-based) of each rule id in rules.conf. */
export function ruleLines(rulesConf: string): Map<string, number> {
  const lines = new Map<string, number>();
  rulesConf.split('\n').forEach((line, i) => {
    const id = line.split('\t')[0]?.trim();
    if (id && !id.startsWith('#')) lines.set(id, i + 1);
  });
  return lines;
}

/**
 * Informational alerts (risk 0) are left out: they describe the app, not a weakness. A rule that
 * isn't listed in rules.conf (ZAP added it after the file was written) points at line 1.
 */
export function zapToSarif(report: ZapReport, rulesConf: string, rulesPath = 'zap/rules.conf') {
  const lines = ruleLines(rulesConf);
  const alerts = report.site.flatMap((site) => site.alerts).filter((a) => SEVERITY[a.riskcode]);

  const rules = alerts.map((a) => ({
    id: a.alertRef,
    name: a.alert,
    shortDescription: { text: a.alert },
    fullDescription: { text: stripHtml(a.desc) },
    help: { text: stripHtml(a.solution) },
    helpUri: `https://www.zaproxy.org/docs/alerts/${a.pluginid}/`,
    properties: {
      tags: ['security', ...(Number(a.cweid) > 0 ? [`external/cwe/cwe-${a.cweid}`] : [])],
      'security-severity': SEVERITY[a.riskcode]!.score,
    },
  }));

  const results = alerts.map((a) => {
    const examples = a.instances.slice(0, MAX_URLS_IN_MESSAGE).map((i) => `${i.method} ${i.uri}`);
    const more =
      Number(a.count) > examples.length ? `, and ${Number(a.count) - examples.length} more` : '';
    return {
      ruleId: a.alertRef,
      level: SEVERITY[a.riskcode]!.level,
      message: {
        text: `${a.alert} (${a.riskdesc}) on ${a.count} URL(s): ${examples.join('; ')}${more}.`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: rulesPath },
            region: { startLine: lines.get(a.pluginid) ?? 1 },
          },
        },
      ],
      partialFingerprints: { zapAlertRef: a.alertRef },
    };
  });

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'OWASP ZAP',
            version: report['@version'],
            informationUri: 'https://www.zaproxy.org/',
            rules,
          },
        },
        results,
      },
    ],
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [reportFile, rulesFile, outFile] = process.argv.slice(2);
  if (!reportFile || !rulesFile || !outFile) {
    console.error('usage: node scripts/zap-to-sarif.ts <report.json> <rules.conf> <out.sarif>');
    process.exit(2);
  }
  const report = JSON.parse(readFileSync(reportFile, 'utf8')) as ZapReport;
  const sarif = zapToSarif(report, readFileSync(rulesFile, 'utf8'));
  writeFileSync(outFile, JSON.stringify(sarif, null, 2));
  console.log(`Wrote ${sarif.runs[0]!.results.length} ZAP results to ${outFile}`);
}
