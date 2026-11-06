// The security gate's policy: which routes to check and which findings the caller has accepted.
// Like the pinned tests in this repo, the gate fails on a finding nobody accepted and also on an
// accepted finding that no longer happens, so the policy file can't silently go stale.

/** Problem text the gate reports when the probe route's response shows a stack trace. */
export const STACK_TRACE = 'error response shows a stack trace or internal file paths';

export interface Acceptance {
  /** A route from `routes`, or "*" for every route. */
  route: string;
  /** Exact problem text, as the gate prints it. */
  problem: string;
  /** Why it's accepted for now. Required. */
  reason: string;
}

export interface Policy {
  routes: string[];
  /** A route that doesn't exist, requested to see whether the error page leaks a stack trace. */
  probe?: string;
  accepted: Acceptance[];
}

export interface Finding {
  route: string;
  problem: string;
}

export interface Verdict {
  unexpected: Finding[];
  stale: Acceptance[];
}

export function parsePolicy(raw: unknown): Policy {
  const p = raw as Partial<Policy>;
  const errors: string[] = [];
  if (!Array.isArray(p.routes) || p.routes.length === 0)
    errors.push('"routes" must list at least one route');
  for (const r of p.routes ?? [])
    if (typeof r !== 'string' || !r.startsWith('/'))
      errors.push(`route ${JSON.stringify(r)} must start with "/"`);
  if (p.probe !== undefined && (typeof p.probe !== 'string' || !p.probe.startsWith('/')))
    errors.push('"probe" must start with "/"');
  if (!Array.isArray(p.accepted)) errors.push('"accepted" must be a list (it can be empty)');
  for (const a of p.accepted ?? []) {
    if (!a?.route || !a?.problem || !a?.reason?.trim())
      errors.push(`accepted entry ${JSON.stringify(a)} needs route, problem and reason`);
    else if (a.route !== '*' && a.route !== p.probe && !p.routes?.includes(a.route))
      errors.push(`accepted entry for ${a.route} names a route the gate doesn't check`);
  }
  if (errors.length) throw new Error(`Invalid security gate policy:\n- ${errors.join('\n- ')}`);
  return { routes: p.routes!, probe: p.probe, accepted: p.accepted! };
}

const covers = (a: Acceptance, f: Finding) =>
  a.problem === f.problem && (a.route === '*' || a.route === f.route);

export function judge(findings: Finding[], policy: Policy): Verdict {
  return {
    unexpected: findings.filter((f) => !policy.accepted.some((a) => covers(a, f))),
    stale: policy.accepted.filter((a) => !findings.some((f) => covers(a, f))),
  };
}

export function verdictReport(findings: Finding[], verdict: Verdict): string {
  const lines = [
    `Security gate: ${findings.length} finding(s), ${verdict.unexpected.length} not accepted, ${verdict.stale.length} stale acceptance(s).`,
  ];
  for (const f of verdict.unexpected) lines.push(`  NEW    ${f.route}: ${f.problem}`);
  for (const a of verdict.stale)
    lines.push(`  STALE  ${a.route}: ${a.problem} (no longer happens; remove it from the policy)`);
  const accepted = findings.length - verdict.unexpected.length;
  if (accepted) lines.push(`  ${accepted} finding(s) matched an accepted entry.`);
  return lines.join('\n');
}
