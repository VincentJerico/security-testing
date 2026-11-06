import { test, expect } from '@playwright/test';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { STACK_TRACE, judge, parsePolicy, type Policy } from '../gate/policy.js';
import { TARGET } from '../src/target.js';

/**
 * Proves the reusable security gate can fail: unaccepted findings and stale acceptances fail it,
 * a bad policy is refused, and against the local Juice Shop the real policy passes while an empty
 * policy fails.
 */
const POLICY: Policy = {
  routes: ['/', '/api/x'],
  probe: '/nope',
  accepted: [
    { route: '*', problem: 'Referrer-Policy is missing', reason: 'tracked as X-1' },
    { route: '/nope', problem: STACK_TRACE, reason: 'tracked as X-2' },
  ],
};

test.describe('security gate policy self-test', () => {
  test('accepted findings pass, on every route for "*"', () => {
    const verdict = judge(
      [
        { route: '/', problem: 'Referrer-Policy is missing' },
        { route: '/api/x', problem: 'Referrer-Policy is missing' },
        { route: '/nope', problem: STACK_TRACE },
      ],
      POLICY,
    );
    expect(verdict).toEqual({ unexpected: [], stale: [] });
  });

  test('a finding nobody accepted fails the gate', () => {
    const verdict = judge(
      [
        { route: '/', problem: 'Referrer-Policy is missing' },
        { route: '/', problem: 'Content-Security-Policy is missing' },
        { route: '/nope', problem: STACK_TRACE },
      ],
      POLICY,
    );
    expect(verdict.unexpected).toEqual([
      { route: '/', problem: 'Content-Security-Policy is missing' },
    ]);
  });

  test('an accepted finding that no longer happens is stale and fails the gate', () => {
    const verdict = judge([{ route: '/', problem: 'Referrer-Policy is missing' }], POLICY);
    expect(verdict.stale).toEqual([POLICY.accepted[1]]);
  });

  test('a policy with a missing reason or an unknown route is refused', () => {
    expect(() =>
      parsePolicy({ routes: ['/'], accepted: [{ route: '/', problem: 'x', reason: ' ' }] }),
    ).toThrow('needs route, problem and reason');
    expect(() =>
      parsePolicy({ routes: ['/'], accepted: [{ route: '/other', problem: 'x', reason: 'y' }] }),
    ).toThrow("names a route the gate doesn't check");
    expect(() => parsePolicy({ routes: [], accepted: [] })).toThrow('at least one route');
  });
});

test.describe('security gate against the local Juice Shop', () => {
  const runGate = (policy: unknown) => {
    const dir = mkdtempSync(join(tmpdir(), 'gate-'));
    const file = join(dir, 'policy.json');
    writeFileSync(file, JSON.stringify(policy));
    return spawnSync('node', [resolve('gate/check.ts'), file, join(dir, 'report.json')], {
      encoding: 'utf8',
      env: { ...process.env, TARGET_URL: TARGET },
    });
  };
  const juiceShop = JSON.parse(readFileSync('gate/examples/juice-shop.policy.json', 'utf8'));

  test('passes with the Juice Shop policy (S-1 to S-5 accepted)', () => {
    const r = runGate(juiceShop);
    expect(r.stdout).toContain('0 not accepted, 0 stale');
    expect(r.status).toBe(0);
  });

  test('fails when nothing is accepted', () => {
    const r = runGate({ ...juiceShop, accepted: [] });
    expect(r.stdout).toContain(`NEW    /: Content-Security-Policy is missing`);
    expect(r.stdout).toContain(`NEW    /api/DoesNotExist: ${STACK_TRACE}`);
    expect(r.status).toBe(1);
  });

  test('fails on an acceptance for a problem Juice Shop does not have', () => {
    const r = runGate({
      ...juiceShop,
      accepted: [
        ...juiceShop.accepted,
        { route: '*', problem: 'X-Content-Type-Options is not "nosniff"', reason: 'test' },
      ],
    });
    expect(r.stdout).toContain('STALE  *: X-Content-Type-Options is not "nosniff"');
    expect(r.status).toBe(1);
  });

  test('refuses a target that is not localhost', () => {
    const r = spawnSync(
      'node',
      [resolve('gate/check.ts'), 'gate/examples/juice-shop.policy.json'],
      {
        encoding: 'utf8',
        env: { ...process.env, TARGET_URL: 'https://example.com' },
      },
    );
    expect(r.stderr).toContain('only tests a local app');
    expect(r.status).not.toBe(0);
  });
});
