# Conformance harness

OpenID Conformance Suite (`release-v5.2.4`) run against a throwaway D3 Auth stack (T-0.9, REQ-126).

```bash
./conformance/run.sh                   # Basic, Config, RP-Initiated Logout and Back-Channel Logout OP plans
KEEP_STACK=1 ./conformance/run.sh      # then open https://localhost.emobix.co.uk:8443
```

- `docker-compose.conformance.yml` — overlay: Caddy (`op.d3auth.test`, internal CA) in front of the server,
  MongoDB, the suite and its nginx, and a Python runner using the suite's own `run-test-plan.py`.
  Caddy also answers for `localhost.emobix.co.uk` on the server's side, so back-channel logout tokens reach the
  suite; `run.sh` copies Caddy's CA into the server (`NODE_EXTRA_CA_CERTS`) once it exists.
- `plans/d3auth.json` — Basic and Config: two static clients and browser automation for the sign-in.
- `plans/d3auth-logout.json` — RP-Initiated Logout (T-5.2): the same clients, plus clicking through the sign-out
  confirmation, and screenshots of the error and signed-out pages the modules ask a reviewer to see.
- `plans/d3auth-backchannel.json` — Back-Channel Logout: two clients of its own (`conformance-3/4`) with a
  back-channel endpoint registered, so the RP-Initiated plan never receives a logout token it did not ask for.
- `seed.json` — the matching user and clients, applied with `dev-seed` into the ephemeral database.
- `expected-failures.json` / `expected-skips.json` — every entry must have a reason recorded in the vault.
- `logs/` — `stack.log` and exported plan results (uploaded as a CI artifact).

Fresh secrets are generated per run; nothing here is used outside the ephemeral stack.
