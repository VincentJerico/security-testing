# Security Testing

[![CI](https://github.com/VincentJerico/security-testing/actions/workflows/ci.yml/badge.svg)](https://github.com/VincentJerico/security-testing/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

Defensive security checks a QA team can run in CI. The results are written up in
[docs/FINDINGS.md](docs/FINDINGS.md). The target is
[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/), a deliberately vulnerable training
app from OWASP, running locally in Docker.

## Scope

Every check runs against `localhost` only. `src/target.ts` refuses any other host before a test
starts, and a test proves it does.

## Getting started

Needs Node 22 and Docker.

```bash
npm install
npm run app:start   # starts Juice Shop on http://localhost:3000
npm test
npm run scan:baseline   # ZAP passive scan, report in zap/report.html
npm run app:stop
```

## ZAP baseline scan

ZAP 2.17.0 runs a passive scan of the local app over Docker's private network and writes
`zap/report.html`. [`zap/rules.conf`](zap/rules.conf) decides what fails the build. Every rule
that passes today is set to FAIL, so a new issue breaks CI. The 8 issues Juice Shop already has
(for example, no Content-Security-Policy header) are set to WARN until the findings report covers
them. Three rules are ignored: one is about the scanner itself, and two are informational.

## Header and error-page checks

[`src/headers.ts`](src/headers.ts) checks response headers against a short policy and spots
stack traces in error pages. A self-test proves it can fail: a compliant header set passes, and
each planted defect is reported. Against Juice Shop, these findings are pinned as they are today:

| ID  | Finding                                                        |
| --- | -------------------------------------------------------------- |
| S-1 | No `Content-Security-Policy` header                            |
| S-2 | No `Referrer-Policy` header                                    |
| S-3 | Deprecated `Feature-Policy` only, no `Permissions-Policy`      |
| S-4 | `Access-Control-Allow-Origin: *`, so any site can read the API |
| S-5 | The 500 page for an unknown API route shows a stack trace      |
| S-6 | The login `token` cookie is set without `HttpOnly`             |
| S-7 | Order history without a login returns a 500 with a stack trace |

A pinned check turns red when a finding is fixed and when a new one appears. MIME sniffing and
clickjacking protection already work, and a test keeps them that way. S-6 is checked in a real
browser after logging in through the login page with a throwaway local account, and account-only
endpoints are checked to refuse requests that carry no token.

## Dependency scanning

- This repo's own dependencies are gated in CI with `npm audit --audit-level=high`.
- `npm run scan:deps` scans the Juice Shop image with Trivy 0.76.0 and prints the unique CVEs by
  severity. Juice Shop is deliberately vulnerable, and Trivy's database changes daily, so this
  scan reports and doesn't gate. At the time of writing it found 130 unique high or critical
  CVEs, most of them in `vm2`.
- The same script first scans [a fixture lockfile](fixtures/vulnerable-lockfile/) that pins a
  lodash version with a known CVE, and fails unless Trivy reports it. That proves the scan
  actually detects known issues.

## Roadmap

1. Scaffold, target guard and CI (done)
2. Baseline scan with OWASP ZAP (done)
3. Security header and error-page checks (done)
4. Session cookie and login-required checks (done)
5. Dependency scanning (done)
6. Findings report mapped to the OWASP Top 10 (done): [docs/FINDINGS.md](docs/FINDINGS.md)
