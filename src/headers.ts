/**
 * A response-header policy for a web app served over HTTP on localhost. Each rule returns a
 * problem message, or nothing when the headers comply. HSTS is left out on purpose: it only
 * applies over HTTPS, and the local app is served over plain HTTP.
 */
export type Headers = Record<string, string>;

type Rule = (h: Headers) => string | undefined;

const RULES: Rule[] = [
  (h) =>
    h['x-content-type-options']?.toLowerCase() === 'nosniff'
      ? undefined
      : 'X-Content-Type-Options is not "nosniff"',
  (h) =>
    /^(deny|sameorigin)$/i.test(h['x-frame-options'] ?? '') ||
    /frame-ancestors/i.test(h['content-security-policy'] ?? '')
      ? undefined
      : 'no clickjacking protection (X-Frame-Options or CSP frame-ancestors)',
  (h) => (h['content-security-policy'] ? undefined : 'Content-Security-Policy is missing'),
  (h) => (h['referrer-policy'] ? undefined : 'Referrer-Policy is missing'),
  (h) => (h['permissions-policy'] ? undefined : 'Permissions-Policy is missing'),
  (h) =>
    h['access-control-allow-origin'] === '*'
      ? 'Access-Control-Allow-Origin is "*", so any site can read responses'
      : undefined,
];

/** Every policy problem in a response's headers. Header names must be lower-case. */
export function checkHeaders(headers: Headers): string[] {
  return RULES.map((rule) => rule(headers)).filter((p): p is string => p !== undefined);
}

/** Stack frames such as `at fn (/app/x.js:12:3)` or `/node_modules/express/lib/router.js:95`. */
const STACK_FRAME = /\bat\s+\S.*\(\/[^)]*:\d+(?::\d+)?\)|\/node_modules\/[^\s:"<>]+:\d+/;

/** True when a response body reveals a server stack trace or internal file paths. */
export function leaksStackTrace(body: string): boolean {
  return STACK_FRAME.test(body);
}
