import { test, expect } from '@playwright/test';
import { resolveTarget } from '../src/target.js';

test.describe('target guard', () => {
  test('accepts loopback addresses', () => {
    expect(resolveTarget('http://localhost:3000')).toBe('http://localhost:3000');
    expect(resolveTarget('http://127.0.0.1:3000')).toBe('http://127.0.0.1:3000');
  });

  test('refuses any other host', () => {
    expect(() => resolveTarget('https://example.com')).toThrow('only tests a local app');
    expect(() => resolveTarget('http://localhost.example.com')).toThrow('only tests a local app');
  });
});

test('the local app is up', async ({ request }) => {
  const res = await request.get('/');
  expect(res.status()).toBe(200);
  expect(await res.text()).toContain('OWASP Juice Shop');
});
