# Conformance harness

OpenID Conformance Suite (`release-v5.2.4`) run against a throwaway D3 Auth stack (T-0.9, REQ-126).

```bash
./conformance/run.sh                   # Basic (static clients, discovery) + Config OP plans
KEEP_STACK=1 ./conformance/run.sh      # then open https://localhost.emobix.co.uk:8443
```

- `docker-compose.conformance.yml` — overlay: Caddy (`op.d3auth.test`, internal CA) in front of the server,
  MongoDB, the suite and its nginx, and a Python runner using the suite's own `run-test-plan.py`.
- `plans/d3auth.json` — suite configuration: two static clients and browser automation for the Phase 0 dev login.
- `seed.json` — the matching user and clients, applied with `dev-seed` into the ephemeral database.
- `expected-failures.json` / `expected-skips.json` — every entry must have a reason recorded in the vault.
- `logs/` — `stack.log` and exported plan results (uploaded as a CI artifact).

Fresh secrets are generated per run; nothing here is used outside the ephemeral stack.
