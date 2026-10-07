# Security Testing

[![CI](https://github.com/VincentJerico/security-testing/actions/workflows/ci.yml/badge.svg)](https://github.com/VincentJerico/security-testing/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

Defensive security checks a QA team can run in CI. The target is
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

## Roadmap

1. Scaffold, target guard and CI (done)
2. Baseline scan with OWASP ZAP (done)
3. Security header and cookie checks
4. Access-control regression tests
5. Dependency scanning
6. Findings report mapped to the OWASP Top 10
