#!/usr/bin/env node
// Summarize a Trivy JSON report: unique CVEs by severity and the most affected packages.
// usage: trivy-summary.mjs <report.json> [--expect CVE-ID]   (exits 1 if the expected CVE is missing)
import { readFileSync, appendFileSync } from 'node:fs';

const [file, flag, expected] = process.argv.slice(2);
const report = JSON.parse(readFileSync(file, 'utf8'));
const unique = new Map();
for (const result of report.Results ?? []) {
  for (const v of result.Vulnerabilities ?? []) {
    const seen = unique.get(v.VulnerabilityID) ?? { severity: v.Severity, packages: new Set() };
    seen.packages.add(v.PkgName);
    unique.set(v.VulnerabilityID, seen);
  }
}
const bySeverity = {};
const byPackage = {};
for (const { severity, packages } of unique.values()) {
  bySeverity[severity] = (bySeverity[severity] ?? 0) + 1;
  for (const p of packages) byPackage[p] = (byPackage[p] ?? 0) + 1;
}
const top = Object.entries(byPackage)
  .sort((a, b) => b[1] - a[1])
  .slice(0, 5);
const lines = [
  `### Dependency scan: ${report.ArtifactName}`,
  '',
  `Unique CVEs: ${unique.size} (${
    Object.entries(bySeverity)
      .map(([s, n]) => `${s} ${n}`)
      .join(', ') || 'none'
  })`,
  '',
  ...(top.length
    ? ['| Package | CVEs |', '| --- | --- |', ...top.map(([p, n]) => `| ${p} | ${n} |`)]
    : []),
  '',
];
console.log(lines.join('\n'));
if (process.env.GITHUB_STEP_SUMMARY)
  appendFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join('\n') + '\n');

if (flag === '--expect') {
  if (!unique.has(expected)) {
    console.error(`Expected ${expected} in ${file}, but the scan did not report it.`);
    process.exit(1);
  }
  console.log(`Found the expected ${expected}.`);
}
