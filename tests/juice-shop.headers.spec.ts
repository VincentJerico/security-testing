import { test, expect } from '@playwright/test';
import { checkHeaders, leaksStackTrace } from '../src/headers.js';

/**
 * Header and error-page checks against the local Juice Shop. Each finding is pinned as today's
 * behavior with an `issue` annotation, so the test turns red when a finding is fixed (time to
 * update docs/FINDINGS.md) and also when a new problem appears.
 */
const KNOWN_HEADER_PROBLEMS = [
  'Content-Security-Policy is missing',
  'Referrer-Policy is missing',
  'Permissions-Policy is missing',
  'Access-Control-Allow-Origin is "*", so any site can read responses',
];

const ROUTES = ['/', '/rest/products/search?q=apple', '/api/Products/1'];

test.describe('Juice Shop response headers', () => {
  for (const route of ROUTES) {
    test(`${route} has exactly the known header findings (S-1 to S-4)`, async ({ request }) => {
      test
        .info()
        .annotations.push(
          { type: 'issue', description: 'S-1: no Content-Security-Policy header' },
          { type: 'issue', description: 'S-2: no Referrer-Policy header' },
          { type: 'issue', description: 'S-3: Feature-Policy only, no Permissions-Policy' },
          { type: 'issue', description: 'S-4: Access-Control-Allow-Origin is "*"' },
        );
      const res = await request.get(route);
      expect(res.status()).toBe(200);
      expect(checkHeaders(res.headers())).toEqual(KNOWN_HEADER_PROBLEMS);
    });
  }

  test('MIME sniffing and clickjacking protections stay in place', async ({ request }) => {
    const headers = (await request.get('/')).headers();
    expect(headers['x-content-type-options']).toBe('nosniff');
    expect(headers['x-frame-options']).toBe('SAMEORIGIN');
  });
});

test.describe('Juice Shop error responses', () => {
  test('an unknown API route leaks a stack trace (S-5)', async ({ request }) => {
    test.info().annotations.push({
      type: 'issue',
      description: 'S-5: the 500 page for an unknown API route shows a stack trace with file paths',
    });
    const res = await request.get('/api/DoesNotExist');
    expect(res.status()).toBe(500);
    expect(leaksStackTrace(await res.text())).toBe(true);
  });

  test('a missing resource returns JSON without a stack trace', async ({ request }) => {
    const res = await request.get('/api/Products/abc');
    expect(res.status()).toBe(404);
    expect(await res.json()).toEqual({ message: 'Not Found', errors: [] });
  });

  test('a request without a token is refused without a stack trace', async ({ request }) => {
    const res = await request.get('/rest/basket/1');
    expect(res.status()).toBe(401);
    expect(leaksStackTrace(await res.text())).toBe(false);
  });
});
