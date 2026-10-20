import { expect, type APIRequestContext, type Page } from '@playwright/test';
import { TARGET } from './target.js';

export interface TestUser {
  email: string;
  password: string;
}

/** Register a throwaway account in the local Juice Shop. */
export async function registerTestUser(request: APIRequestContext): Promise<TestUser> {
  const user = {
    email: `qa-${Date.now()}-${Math.floor(Math.random() * 1e6)}@test.local`,
    password: 'Qa-test-pass-123',
  };
  const res = await request.post('/api/Users', {
    data: {
      ...user,
      passwordRepeat: user.password,
      securityQuestion: { id: 1 },
      securityAnswer: 'test',
    },
  });
  expect(res.status()).toBe(201);
  return user;
}

/** Log in through the real login page, the way a user would. */
export async function logInThroughUi(page: Page, user: TestUser): Promise<void> {
  // The welcome dialog can cover the login button. These are the cookies Juice Shop itself sets
  // when a visitor dismisses the welcome banner and the cookie notice.
  await page.context().addCookies(
    ['welcomebanner_status', 'cookieconsent_status'].map((name) => ({
      name,
      value: 'dismiss',
      url: TARGET,
    })),
  );
  await page.goto('/#/login');
  await page.locator('#email').fill(user.email);
  await page.locator('#password').fill(user.password);
  await page.locator('#loginButton').click();
  await expect(page).toHaveURL(/#\/search/);
}
