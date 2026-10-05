/**
 * The only app these checks may touch. Juice Shop is OWASP's deliberately vulnerable training app,
 * run locally in Docker. Anything that isn't a loopback address is refused.
 */
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

export function resolveTarget(raw = process.env.TARGET_URL ?? 'http://localhost:3000'): string {
  const url = new URL(raw);
  if (!LOOPBACK.has(url.hostname)) {
    throw new Error(`Refusing to test ${url.hostname}: this repo only tests a local app.`);
  }
  return url.origin;
}

export const TARGET = resolveTarget();
