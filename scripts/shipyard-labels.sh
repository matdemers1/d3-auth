#!/usr/bin/env bash
# Computes the two Shipyard deploy-contract labels for the server image (AUTH-T-002, SHP-D-019,
# SHP-D-022):
#
#   dev.d3cloud.shipyard.migration   expand|contract|none, from the HEAD commit's
#                                     `Shipyard-Migration:` trailer (empty trailer -> none)
#   dev.d3cloud.shipyard.schema      the newest directory in apps/server/prisma/migrations —
#                                     the same value /health reports once that migration has run
#
# Usage: ./scripts/shipyard-labels.sh [commit-ish]   (defaults to HEAD)
# Prints two lines: `migration=<value>` and `schema=<value>`. Exits non-zero on a bogus trailer.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
REF="${1:-HEAD}"

trailer="$(git -C "$ROOT" log -1 "$REF" --format='%(trailers:key=Shipyard-Migration,valueonly)' | tr -d '[:space:]')"
migration="${trailer:-none}"

case "$migration" in
  expand|contract|none) ;;
  *)
    echo "shipyard-labels: bogus Shipyard-Migration trailer '$migration' (want expand, contract or none)" >&2
    exit 1
    ;;
esac

migrations_dir="$ROOT/apps/server/prisma/migrations"
schema="$(find "$migrations_dir" -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | sort | tail -n 1)"

if [ -z "$schema" ]; then
  echo "shipyard-labels: no migrations found under $migrations_dir" >&2
  exit 1
fi

echo "migration=$migration"
echo "schema=$schema"
