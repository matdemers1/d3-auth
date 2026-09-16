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

# ZAP runs in a container on the dev stack's own network and reaches the server by its service name,
# which works the same on a laptop and on a CI runner.
NETWORK="${ZAP_NETWORK:-d3-auth_default}"
export ZAP_TARGET="${ZAP_TARGET:-http://server:3000}"

echo "==> Signing the dev owner in"
ZAP_COOKIE="$(ZAP_TARGET=http://localhost:3000 node "$HERE/session.mjs")"
export ZAP_COOKIE

rm -rf "$HERE/report" && mkdir -p "$HERE/report"
chmod 777 "$HERE/report"

echo "==> Scanning $ZAP_TARGET"
# An explicit heap and a matching container limit: left to itself ZAP sizes the heap from the host,
# and the active scan was killed mid-run on a runner that shares memory with the stack it scans.
docker run --rm \
  --memory 3g \
  --network "$NETWORK" \
  -e ZAP_TARGET -e ZAP_COOKIE \
  -v "$HERE:/zap/wrk:rw" \
  "$ZAP_IMAGE" \
  zap.sh -Xmx2g -cmd -autorun /zap/wrk/automation.yaml || status=$?

# ZAP exits 1 for a High (or a broken plan) and 2 when the worst finding is a Medium. The gate is
# "no High" (REQ-131), so 2 is reported and passes; the report is where Mediums are triaged.
case "${status:-0}" in
  0) echo "==> No findings above Informational" ;;
  2) echo "==> Medium or lower findings only — read security/zap/report/zap-report.html" ;;
  *) echo "==> ZAP failed the gate (exit ${status})" >&2; exit "${status}" ;;
esac
