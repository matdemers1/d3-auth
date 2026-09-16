#!/usr/bin/env bash
# Runs the OpenID Conformance Suite OP plans — Basic, Config, RP-Initiated Logout and Back-Channel
# Logout — against a throwaway D3 Auth stack.
#
#   ./conformance/run.sh                          both plans
#   ./conformance/run.sh <plan-spec> [...]        specific plans (run-test-plan.py syntax)
#   KEEP_STACK=1 ./conformance/run.sh             leave the stack up to inspect https://localhost.emobix.co.uk:8443
#
# Exits non-zero when any module fails outside conformance/expected-failures.json.
set -euo pipefail

SUITE_TAG=release-v5.2.4
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

compose() { docker compose -f docker-compose.yml -f conformance/docker-compose.conformance.yml "$@"; }

scripts="$HERE/.suite-scripts"
if [ ! -f "$scripts/.tag-$SUITE_TAG" ]; then
  rm -rf "$scripts" && mkdir -p "$scripts"
  for f in run-test-plan.py conformance.py test_plan_parser.py requirements.txt; do
    curl -fsSL "https://gitlab.com/openid/conformance-suite/-/raw/$SUITE_TAG/scripts/$f" -o "$scripts/$f"
  done
  touch "$scripts/.tag-$SUITE_TAG"
fi
# The runner substitutes client certificates from this directory; D3 Auth's plans need none.
mkdir -p "$scripts/certs-keys"

export CONFORMANCE_KEK="$(openssl rand -base64 32)"
export CONFORMANCE_PEPPER="$(openssl rand -base64 32)"
export CONFORMANCE_COOKIE_KEYS="$(openssl rand -base64 32)"

cleanup() {
  status=$?
  mkdir -p "$HERE/logs"
  compose logs --no-color server op-tls > "$HERE/logs/stack.log" 2>&1 || true
  compose logs --no-color suite suite-nginx > "$HERE/logs/suite.log" 2>&1 || true
  if [ -z "${KEEP_STACK:-}" ]; then compose down -v --remove-orphans > /dev/null 2>&1 || true; fi
  exit $status
}
trap cleanup EXIT

# Always start from nothing: keys from an earlier run are sealed under a different random KEK.
compose down -v --remove-orphans > /dev/null 2>&1 || true
# A file must exist before it is bind-mounted, or Docker makes a directory. The real certificate is
# copied in once the TLS bridge has minted its CA.
: > "$HERE/.op-tls-root.crt"

echo "==> Building"
compose build server
echo "==> Starting the provider (it migrates on boot)"
compose up -d --wait postgres server
echo "==> Seeding conformance clients and user"
compose exec -T server node dist/cli/dev-seed.js /conformance/seed.json
# Clients are read at boot, so the freshly seeded ones need a restart to exist.
compose up -d --wait --no-deps --force-recreate server
echo "==> Starting the TLS proxy and the suite"
compose up -d --wait op-tls mongodb suite suite-nginx
echo "==> Teaching the provider to trust the bridge's CA (back-channel logout)"
for attempt in $(seq 1 30); do
  compose cp op-tls:/data/caddy/pki/authorities/local/root.crt "$HERE/.op-tls-root.crt" > /dev/null 2>&1 && [ -s "$HERE/.op-tls-root.crt" ] && break
  [ "$attempt" = "30" ] && { echo "The TLS bridge never minted its CA" >&2; exit 1; }
  sleep 1
done
compose up -d --wait --no-deps --force-recreate server

echo "==> Waiting for the suite to accept API calls"
for attempt in $(seq 1 120); do
  code="$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/api/plan?length=1 || true)"
  [ "$code" = "200" ] && break
  if [ -z "$(compose ps --status running -q suite)" ]; then
    echo "The conformance suite exited during startup:" >&2
    compose logs --no-color --tail 40 suite >&2
    exit 1
  fi
  [ "$attempt" = "120" ] && { echo "The conformance suite did not come up (last HTTP $code)" >&2; exit 1; }
  sleep 3
done

if [ "$#" -eq 0 ]; then
  set -- \
    "oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]" /conformance/plans/d3auth.json \
    "oidcc-config-certification-test-plan" /conformance/plans/d3auth.json \
    "oidcc-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]" /conformance/plans/d3auth-logout.json \
    "oidcc-backchannel-rp-initiated-logout-certification-test-plan[response_type=code][client_registration=static_client]" /conformance/plans/d3auth-backchannel.json
fi

echo "==> Running: $*"
rm -rf "$HERE/logs/results" && mkdir -p "$HERE/logs/results"
compose run --rm runner sh -c '
  pip install --quiet --root-user-action=ignore -r requirements.txt &&
  python run-test-plan.py --no-parallel --verbose \
    --export-dir /conformance/logs/results \
    --expected-failures-file /conformance/expected-failures.json \
    --expected-skips-file /conformance/expected-skips.json \
    "$@"' runner "$@"
