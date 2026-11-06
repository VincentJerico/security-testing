// Run the security gate against a local app: response headers on each policy route, and a probe
// for stack traces on an unknown route. Exits 1 when the verdict isn't clean.
//
//   TARGET_URL=http://localhost:3000 node gate/check.ts <policy.json> [report.json]
import { readFileSync, writeFileSync } from 'node:fs';
import { checkHeaders, leaksStackTrace } from '../src/headers.ts';
import { resolveTarget } from '../src/target.ts';
import { STACK_TRACE, judge, parsePolicy, verdictReport, type Finding } from './policy.ts';

const [policyFile, reportFile] = process.argv.slice(2);
if (!policyFile) {
  console.error(
    'usage: TARGET_URL=http://localhost:3000 node gate/check.ts <policy.json> [report.json]',
  );
  process.exit(2);
}

// Refuses anything that isn't localhost before a single request is sent.
const target = resolveTarget(process.env.TARGET_URL ?? 'http://localhost:3000');
const policy = parsePolicy(JSON.parse(readFileSync(policyFile, 'utf8')));

async function get(route: string): Promise<Response> {
  return fetch(new URL(route, target), { redirect: 'manual' });
}

const findings: Finding[] = [];
for (const route of policy.routes) {
  const res = await get(route);
  const headers = Object.fromEntries([...res.headers].map(([k, v]) => [k.toLowerCase(), v]));
  for (const problem of checkHeaders(headers)) findings.push({ route, problem });
  console.log(`${res.status} ${route}`);
}
if (policy.probe) {
  const res = await get(policy.probe);
  if (leaksStackTrace(await res.text()))
    findings.push({ route: policy.probe, problem: STACK_TRACE });
  console.log(`${res.status} ${policy.probe} (probe)`);
}

const verdict = judge(findings, policy);
console.log(verdictReport(findings, verdict));
if (reportFile)
  writeFileSync(reportFile, JSON.stringify({ target, findings, ...verdict }, null, 2));
process.exit(verdict.unexpected.length + verdict.stale.length > 0 ? 1 : 0);
