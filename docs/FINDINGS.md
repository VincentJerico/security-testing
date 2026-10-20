# Security findings: OWASP Juice Shop (local)

| Item      | Detail                                                                                                |
| --------- | ----------------------------------------------------------------------------------------------------- |
| Target    | OWASP Juice Shop v18.0.0, run locally in Docker on `localhost:3000`                                   |
| Mapped to | [OWASP Top 10 (2021)](https://top10.owasp.org/2021/)                                                  |
| Date      | 2026-10-20                                                                                            |
| Tester    | Vincent Jerico                                                                                        |
| Tools     | Playwright 1.63 (API and browser tests), OWASP ZAP 2.17.0 (passive baseline), Trivy 0.76.0, npm audit |

## Summary

Juice Shop is OWASP's deliberately vulnerable training app, so finding problems is expected. The
point of this repo is the method: every finding below was observed by hand first, then pinned by a
test that turns red if the finding is fixed or a new one appears. Every check also has a self-test
that proves it can fail.

The checks found 7 configuration and session findings (S-1 to S-7), 8 passive ZAP warnings that
CI tracks, and 130 unique high or critical CVEs in the app's dependencies. Two protections already
work and are guarded: MIME-sniffing protection and clickjacking protection.

All testing was passive or used ordinary requests. Every check is limited to the local app, and
[`src/target.ts`](../src/target.ts) refuses any other host.

## Findings

| ID  | Finding                                                        | OWASP 2021                             | Severity | Tracked by                                 |
| --- | -------------------------------------------------------------- | -------------------------------------- | -------- | ------------------------------------------ |
| S-1 | No `Content-Security-Policy` header                            | A05 Security Misconfiguration          | Medium   | `tests/juice-shop.headers.spec.ts`         |
| S-2 | No `Referrer-Policy` header                                    | A05 Security Misconfiguration          | Low      | `tests/juice-shop.headers.spec.ts`         |
| S-3 | Deprecated `Feature-Policy` only, no `Permissions-Policy`      | A05 Security Misconfiguration          | Low      | `tests/juice-shop.headers.spec.ts`         |
| S-4 | `Access-Control-Allow-Origin: *` on every response             | A05 Security Misconfiguration          | Medium   | `tests/juice-shop.headers.spec.ts`         |
| S-5 | Unknown API route returns a 500 page with a stack trace        | A05 Security Misconfiguration          | Low      | `tests/juice-shop.headers.spec.ts`         |
| S-6 | The login `token` cookie is set without `HttpOnly`             | A07 Identification and Auth Failures   | Medium   | `tests/juice-shop.session.spec.ts`         |
| S-7 | Order history without a login returns a 500 with a stack trace | A05 Security Misconfiguration          | Low      | `tests/juice-shop.session.spec.ts`         |
| D-1 | 130 unique high or critical CVEs in the app's dependencies     | A06 Vulnerable and Outdated Components | High     | `scripts/dependency-scan.sh` (report only) |

Severity here is a rough rating for this app: High means a known, exploitable weakness class is
present; Medium means a missing defense that makes other bugs worse; Low means information
leakage or a hardening gap.

---

### S-1 · No Content-Security-Policy

- **Observed:** No response sets `Content-Security-Policy`, on the home page, the product search
  API or a product record. ZAP's rule 10038 reports the same thing.
- **Why it matters:** A CSP limits where scripts can load from. Without one, any XSS bug can run
  arbitrary script, and S-6 means that script can read the session token.
- **Recommendation:** Start with a report-only policy, such as
  `Content-Security-Policy-Report-Only: default-src 'self'`, review the reports, then enforce it.

### S-2 · No Referrer-Policy

- **Observed:** No `Referrer-Policy` header, so the browser falls back to its default.
- **Why it matters:** Full URLs, including query strings, can leak to third-party sites in the
  `Referer` header.
- **Recommendation:** `Referrer-Policy: strict-origin-when-cross-origin`.

### S-3 · Feature-Policy instead of Permissions-Policy

- **Observed:** The app sends `Feature-Policy: payment 'self'`. Browsers replaced that header
  with `Permissions-Policy`, and ZAP's rule 10063 flags its absence.
- **Recommendation:** Send the same intent as `Permissions-Policy: payment=(self)`.

### S-4 · Wildcard CORS

- **Observed:** Every response, API responses included, sends `Access-Control-Allow-Origin: *`.
  ZAP's rule 10098 flags the same thing.
- **Why it matters:** Any website a user visits can read these responses from their browser. The
  wildcard doesn't send cookies, so this mostly exposes data that doesn't need a login, but it
  removes a layer of protection the API doesn't need to give up.
- **Recommendation:** Allow only the app's own origin, or omit the header where cross-origin
  access isn't needed.

### S-5 · Stack trace on an unknown API route

- **Observed:** `GET /api/DoesNotExist` returns a 500 page that includes a stack trace with
  internal paths such as `/juice-shop/node_modules/express/lib/router/layer.js:95`.
- **Why it matters:** It tells an attacker the framework, its layout on disk and the libraries in
  use. An unknown route should be a 404, not a server error.
- **Recommendation:** Return 404 for unknown routes and use a production error handler that never
  renders stack traces.
- **What works:** `GET /api/Products/abc` returns a clean JSON 404, and a request without a token
  is refused with a 401 page that has no trace.

### S-6 · Session token cookie readable by scripts

- **Observed:** After logging in through the login page with a throwaway local account, the
  browser holds a `token` cookie with `HttpOnly` off. `SameSite=Lax` is fine. `Secure` doesn't
  apply, because the local app is served over plain HTTP.
- **Why it matters:** Any script running on the page can read the session token. Combined with an
  XSS bug, that means session theft.
- **Recommendation:** Set the session cookie from the server with `HttpOnly`, `SameSite=Lax` and,
  over HTTPS, `Secure`. The page shouldn't need to read the token itself.

### S-7 · Order history fails with a stack trace instead of a 401

- **Observed:** `GET /rest/order-history` without a token returns a 500 page with a stack trace.
  The page title also echoes the requester's IP address.
- **Why it matters:** Same information leak as S-5. A missing login should get a plain 401, like
  the basket, users, cards and addresses endpoints already return.
- **Recommendation:** Check authentication before the handler runs and return 401.

### D-1 · Vulnerable dependencies

- **Observed:** Trivy found 130 unique high or critical CVEs in the image (46 critical, 84 high).
  Most are in Node.js packages. The most affected are `vm2` (45), `multer` (10), `libssl3` (9),
  `tar` (9) and `handlebars` (7). `vm2` is a sandboxing library that is no longer maintained.
- **Why it's report-only:** The app is vulnerable on purpose, and Trivy's database changes daily,
  so pinned counts would break CI for reasons unrelated to this repo. CI posts the current summary
  on every run and keeps the full JSON.
- **Recommendation:** For a real app, replace `vm2` (it has no fixed versions), then upgrade the
  remaining packages and the base image.

## ZAP baseline warnings

ZAP's passive scan runs in CI. These rules are accepted as warnings, and every other rule fails
the build if it starts triggering ([`zap/rules.conf`](../zap/rules.conf)).

| ZAP rule | Warning                                       | Covered above |
| -------- | --------------------------------------------- | ------------- |
| 10038    | Content Security Policy header not set        | S-1           |
| 10063    | Permissions Policy header not set             | S-3           |
| 10098    | Cross-domain misconfiguration                 | S-4           |
| 10003    | Vulnerable JS library                         | D-1           |
| 10017    | Cross-domain JavaScript source file inclusion | No            |
| 10096    | Timestamp disclosure                          | No            |
| 10110    | Dangerous JS functions                        | No            |
| 90004    | Insufficient site isolation (COEP header)     | No            |

Three rules are ignored on purpose: 10116 is about the scanner itself, and 10049 and 10109 are
informational (caching and app type).

## What works (guarded by tests)

- `X-Content-Type-Options: nosniff` on every response.
- `X-Frame-Options: SAMEORIGIN`, which blocks clickjacking.
- Account-only endpoints (basket, users, cards and addresses) refuse requests without a token
  with 401, and `whoami` returns no user.
- Clean error responses for a missing resource (JSON 404) and a missing token (401 without a
  trace).
- This repo's own dependencies: `npm audit` reports 0 high or critical issues and gates CI.

## How the checks prove themselves

- The header checker, the cookie checker and the stack-trace detector each have a self-test: a
  compliant input passes, and each planted defect is reported by name.
- Each pinned finding was checked to fail when the expected list is wrong.
- The ZAP gate was checked both ways: the real rules pass, and flipping one accepted warning to
  FAIL makes the scan fail.
- The dependency scan first scans a fixture lockfile with a known lodash CVE and fails unless
  Trivy reports it.

## Not covered

- **Active scanning and exploitation.** ZAP runs in passive mode only. Nothing here tries to break
  in.
- **Authorization between users.** Checking whether one account can reach another account's data
  was deliberately left out of scope.
- **HTTPS-only settings** such as HSTS and `Secure` cookies, because the local app is served over
  plain HTTP.
- **Business logic and the app's built-in challenges.** Juice Shop has many intentional flaws that
  are outside this repo's scope.
