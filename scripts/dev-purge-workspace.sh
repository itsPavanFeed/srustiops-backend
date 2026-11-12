#!/usr/bin/env bash
# Frees the slugs of removed workspaces in the local dev stack, so they can
# be created again. Outside development a removed slug stays reserved for
# good: it keeps old links, sign-in callbacks and audit history from
# pointing at a new workspace. This touches only the dev database and only
# workspaces whose status is already "removed".
#
#   scripts/dev-purge-workspace.sh provisioner-test1 [more slugs...]
#   scripts/dev-purge-workspace.sh --all-removed
set -euo pipefail

PG="${DEV_PG_CONTAINER:-srustiops-dev-mt-pg}"
[[ $# -gt 0 ]] || { echo "usage: $0 <slug>... | --all-removed" >&2; exit 2; }

if [[ "$1" == --all-removed ]]; then
  WHERE="status = 'removed'"
else
  for s in "$@"; do [[ "$s" =~ ^[a-z][a-z0-9-]{1,62}$ ]] || { echo "not a slug: $s" >&2; exit 2; }; done
  LIST=$(printf "'%s'," "$@"); WHERE="status = 'removed' AND slug IN (${LIST%,})"
fi

docker exec -i "$PG" psql -U postgres -d central -v ON_ERROR_STOP=1 -q <<SQL
BEGIN;
CREATE TEMP TABLE purge ON COMMIT DROP AS SELECT id, slug FROM tenants WHERE $WHERE;
DELETE FROM memberships WHERE tenant_id IN (SELECT id FROM purge);
DELETE FROM business_units WHERE tenant_id IN (SELECT id FROM purge);
DELETE FROM entities WHERE tenant_id IN (SELECT id FROM purge);
DELETE FROM tenants WHERE id IN (SELECT id FROM purge);
SELECT 'freed: ' || coalesce(string_agg(slug, ', ' ORDER BY slug), 'nothing (only removed workspaces can be purged)') FROM purge;
COMMIT;
SQL
