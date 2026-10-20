import { test, expect } from '@playwright/test';
import { checkHeaders, leaksStackTrace, type Headers } from '../src/headers.js';

/**
 * Proves the checks can fail. A compliant header set must pass, and each planted defect must be
 * reported, so a green run against the app can't come from a checker that finds nothing.
 */
const GOOD: Headers = {
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'content-security-policy': "default-src 'self'",
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=()',
  'access-control-allow-origin': 'http://localhost:3000',
};

const without = (name: string): Headers =>
  Object.fromEntries(Object.entries(GOOD).filter(([k]) => k !== name));

test.describe('header checker self-test', () => {
  test('a compliant header set has no problems', () => {
    expect(checkHeaders(GOOD)).toEqual([]);
  });

  const planted: [string, Headers, string][] = [
    [
      'missing nosniff',
      without('x-content-type-options'),
      'X-Content-Type-Options is not "nosniff"',
    ],
    ['missing CSP', without('content-security-policy'), 'Content-Security-Policy is missing'],
    ['missing Referrer-Policy', without('referrer-policy'), 'Referrer-Policy is missing'],
    ['missing Permissions-Policy', without('permissions-policy'), 'Permissions-Policy is missing'],
    [
      'wildcard CORS',
      { ...GOOD, 'access-control-allow-origin': '*' },
      'Access-Control-Allow-Origin is "*", so any site can read responses',
    ],
  ];
  for (const [name, headers, problem] of planted) {
    test(`reports ${name}`, () => {
      expect(checkHeaders(headers)).toEqual([problem]);
    });
  }

  test('clickjacking needs X-Frame-Options or CSP frame-ancestors', () => {
    const noXfo = without('x-frame-options');
    expect(checkHeaders(noXfo)).toEqual([
      'no clickjacking protection (X-Frame-Options or CSP frame-ancestors)',
    ]);
    expect(checkHeaders({ ...noXfo, 'content-security-policy': "frame-ancestors 'none'" })).toEqual(
      [],
    );
  });

  test('detects stack traces and internal paths, but not ordinary errors', () => {
    expect(leaksStackTrace('at Layer.handle (/app/node_modules/express/lib/layer.js:95:5)')).toBe(
      true,
    );
    expect(
      leaksStackTrace('<li> (/juice-shop/node_modules/express/lib/router/index.js:328</li>'),
    ).toBe(true);
    expect(leaksStackTrace('{"message":"Not Found","errors":[]}')).toBe(false);
    expect(
      leaksStackTrace('<title>Not Found</title><p>at the moment this page is missing</p>'),
    ).toBe(false);
  });
});
