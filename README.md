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
npm run app:stop
```

## Roadmap

1. Scaffold, target guard and CI (done)
2. Baseline scan with OWASP ZAP
3. Security header and cookie checks
4. Access-control regression tests
5. Dependency scanning
6. Findings report mapped to the OWASP Top 10
