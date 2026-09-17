# Security

D3 Auth signs people in to other apps. A flaw here is a flaw in all of them, so please tell me
before you tell the internet.

## Reporting

Email **matthew@demers.dev** with enough detail to reproduce it: the request, the response, and what
you expected instead. A proof of concept against your own instance is ideal; please do not test
against `auth.d3cloud.io` or any instance you do not run.

You can expect an acknowledgement within a few days — this is a personal project, not a staffed
product — and an honest answer about whether and when it will be fixed. If you would like credit in
the changelog, say so; if you would rather not be named, that is fine too.

There is no bug bounty. I cannot pay for reports.

## Scope

**In scope:** the provider and its interaction flows, the console and its APIs, the CLIs, the SDKs
in `packages/`, the mail relay Worker, and anything in `docs/` that would lead an operator into an
insecure configuration.

**Out of scope:** findings that depend on an attacker already holding the `KEK`, the `PEPPER`, the
database, or a shell on the host — those are game over by design, and the runbooks say so. Also out
of scope: the deliberate decisions in [the README](README.md#what-it-refuses-to-do) and the two
recorded exemptions — the conformance suite's own clients skipping PKCE on a `.test` issuer
(ADR-002), and the console's built-in client, which any signed-in account may use to reach its own
account page (ADR-005).

## What is already checked

Every push runs, and must pass: four OpenID conformance plans (Basic, Config, RP-Initiated Logout,
Back-Channel Logout); an adversarial suite of 74 attacks in five classes — authorization surface,
protocol, credentials, privilege escalation, borrowed sessions — plus SDK and login-CSRF cases;
Semgrep with custom rules at zero findings; unit, integration and browser suites. Nightly: an
authenticated ZAP scan that fails on any High. Recorded in the vault: an ASVS 5.0 Level 2
self-assessment of V6, V7, V9 and V10 with no open failure.

None of that means there is nothing left to find. It means the obvious things have been looked for.

## Supported versions

The latest commit on `main` is what is supported. This is a young project with one operator; there
are no backported fixes and no long-term support branches.

## Handling a report

1. I confirm it and write a failing test.
2. I fix it, with the test in the same commit, and deploy.
3. The changelog says what was wrong, in plain words, and credits you if you want that.

Nothing is quietly patched: the audit trail of this project is its git history, and a security fix
that hides what it fixed is worth less than the fix.
