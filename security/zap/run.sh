#!/usr/bin/env bash
# The authenticated ZAP scan (T-5.4, REQ-131), against the dev stack.
#
#   pnpm dev:up && ./security/zap/run.sh
#
# Exits non-zero on any High finding. Reports land in security/zap/report/.
set -euo pipefail

# Pinned by digest, like the actions and the Semgrep image. ZAP 2.17.0.
ZAP_IMAGE="ghcr.io/zaproxy/zaproxy@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
cd "$ROOT"

# ZAP shares the server container's network namespace and scans it as http://localhost:3000 — the
# issuer. Reaching it by service name instead (http://server:3000) breaks on the first redirect:
# / → /signin → the issuer's /oidc/auth, which from inside a separate ZAP container is ZAP itself,
# and the spider fails the plan on "connection refused". Same on a laptop and on a CI runner.
SERVER="$(docker compose -f docker-compose.yml -f docker-compose.dev.yml ps -q server)"
[ -n "$SERVER" ] || { echo "==> The dev stack is not up (pnpm dev:up)" >&2; exit 1; }
export ZAP_TARGET="${ZAP_TARGET:-http://localhost:3000}"

echo "==> Signing the dev owner in"
ZAP_COOKIE="$(ZAP_TARGET=http://localhost:3000 node "$HERE/session.mjs")"

rm -rf "$HERE/report" && mkdir -p "$HERE/report"
chmod 777 "$HERE/report"

# The plan is rendered with the cookie in it. ZAP substitutes ${VARS} in URLs but not in a replacer
# rule's replacement string, which it sends verbatim: every scan before this one went out with the
# header `Cookie: ${ZAP_COOKIE}`, got 401 from everything behind the sign-in, and reported clean.
# The rendered copy lives outside the report directory, and is removed on exit.
PLAN="$(mktemp -d "$HERE/.plan.XXXXXX")"
trap 'rm -rf "$PLAN"' EXIT
chmod 755 "$PLAN"
ZAP_COOKIE="$ZAP_COOKIE" node -e '
  const fs = require("node:fs");
  const plan = fs.readFileSync(process.argv[1], "utf8");
  if (!plan.includes("${ZAP_COOKIE}")) throw new Error("automation.yaml no longer carries ${ZAP_COOKIE}");
  fs.writeFileSync(process.argv[2], plan.replaceAll("${ZAP_COOKIE}", () => process.env.ZAP_COOKIE));
' "$HERE/automation.yaml" "$PLAN/automation.yaml"
chmod 644 "$PLAN/automation.yaml"

echo "==> Scanning $ZAP_TARGET"
# An explicit heap and a matching container limit: left to itself ZAP sizes the heap from the host,
# and the active scan was killed mid-run on a runner that shares memory with the stack it scans.
set +e
docker run --rm \
  --memory 3g \
  --network "container:$SERVER" \
  -e ZAP_TARGET \
  -v "$HERE/report:/zap/wrk/report:rw" \
  -v "$PLAN/automation.yaml:/zap/wrk/automation.yaml:ro" \
  "$ZAP_IMAGE" \
  zap.sh -Xmx2g -cmd -autorun /zap/wrk/automation.yaml 2>&1 | tee "$PLAN/zap.log"
status="${PIPESTATUS[0]}"
set -e

# A response-code mismatch in the requestor is only a plan warning, and warnings do not fail the
# plan. The session guards are the exception: a scan that is not signed in is not a pass.
if grep -q 'Difference in response code values' "$PLAN/zap.log"; then
  echo "==> ZAP was not signed in: a session guard in automation.yaml did not get its 200" >&2
  exit 1
fi

# ZAP exits 1 for a High (or a broken plan) and 2 when the worst finding is a Medium. The gate is
# "no High" (REQ-131), so 2 is reported and passes; the report is where Mediums are triaged.
case "$status" in
  0) echo "==> No findings above Informational" ;;
  2) echo "==> Medium or lower findings only — read security/zap/report/zap-report.html" ;;
  *) echo "==> ZAP failed the gate (exit ${status})" >&2; exit "${status}" ;;
esac
