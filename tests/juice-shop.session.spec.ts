import { test, expect } from '@playwright/test';
import { checkSessionCookie } from '../src/cookies.js';
import { leaksStackTrace } from '../src/headers.js';
import { logInThroughUi, registerTestUser } from '../src/juiceShop.js';

/**
 * Session cookie and "login required" checks against the local Juice Shop, using a throwaway
 * account. Findings are pinned as today's behavior with `issue` annotations.
 */
test('the session token cookie has exactly the known finding (S-6)', async ({ page, request }) => {
  test.info().annotations.push({
    type: 'issue',
    description: 'S-6: the token cookie is set without HttpOnly, so page scripts can read it',
  });
  await logInThroughUi(page, await registerTestUser(request));
  const token = (await page.context().cookies()).find((c) => c.name === 'token');
  expect(token, 'login sets a token cookie').toBeDefined();
  expect(checkSessionCookie(token!)).toEqual(['token is readable by scripts (HttpOnly not set)']);
});

test.describe('requests without a login', () => {
  for (const route of ['/rest/basket/1', '/api/Users', '/api/Cards', '/api/Addresss']) {
    test(`${route} is refused with 401`, async ({ request }) => {
      expect((await request.get(route)).status()).toBe(401);
    });
  }

  test('whoami returns no user', async ({ request }) => {
    expect(await (await request.get('/rest/user/whoami')).json()).toEqual({ user: {} });
  });

  test('order history fails with a stack trace instead of a 401 (S-7)', async ({ request }) => {
    test.info().annotations.push({
      type: 'issue',
      description: 'S-7: order history without a token returns a 500 page with a stack trace',
    });
    const res = await request.get('/rest/order-history');
    expect(res.status()).toBe(500);
    expect(leaksStackTrace(await res.text())).toBe(true);
  });
});
