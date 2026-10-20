import { test, expect } from '@playwright/test';
import { checkSessionCookie, type CookieFlags } from '../src/cookies.js';

/** Proves the cookie checks can fail before they're trusted against the app. */
const GOOD: CookieFlags = { name: 'token', httpOnly: true, secure: true, sameSite: 'Lax' };

test.describe('cookie checker self-test', () => {
  test('a well-protected session cookie has no problems', () => {
    expect(checkSessionCookie(GOOD, { https: true })).toEqual([]);
  });

  test('reports a cookie that scripts can read', () => {
    expect(checkSessionCookie({ ...GOOD, httpOnly: false })).toEqual([
      'token is readable by scripts (HttpOnly not set)',
    ]);
  });

  test('reports SameSite=None', () => {
    expect(checkSessionCookie({ ...GOOD, sameSite: 'None' })).toEqual([
      'token is sent on cross-site requests (SameSite=None)',
    ]);
  });

  test('requires Secure only over HTTPS', () => {
    const plain = { ...GOOD, secure: false };
    expect(checkSessionCookie(plain)).toEqual([]);
    expect(checkSessionCookie(plain, { https: true })).toEqual([
      'token can be sent over plain HTTP (Secure not set)',
    ]);
  });
});
