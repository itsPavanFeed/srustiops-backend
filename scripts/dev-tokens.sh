#!/usr/bin/env bash
# Reissue the local dev sign-in tokens into .dev/multi-tenant/tokens.env
# (mode 0600) without printing any of them. The platform root's token is
# rotated (its old one stops working); every seeded person gets a fresh
# 30-day token (their older tokens keep working until they expire or are
# revoked under My tokens). The runner token is kept.
#
#   scripts/dev-tokens.sh            # everyone
#   scripts/dev-tokens.sh ROOT TINA  # only these
set -euo pipefail
cd "$(dirname "$0")/.."
DEV="$PWD/.dev/multi-tenant"
[[ -f "$DEV/secrets.env" ]] || { echo "no dev environment here; run scripts/dev-up.sh first" >&2; exit 1; }
set -a; . "$DEV/secrets.env"; set +a
PG_PORT="${DEV_PG_PORT:-55434}"
CENTRAL="http://127.0.0.1:${DEV_CENTRAL_PORT:-8090}"
[[ -x bin/srustiops ]] || go build -o bin/srustiops ./cmd/srustiops

email_of() { case "$1" in TINA|ALICE|MIKE|RITA|PAUL|EVE|FIONA|SAM|AVA|DORA) echo "$1" | tr A-Z a-z;; esac; }
if [[ $# -gt 0 ]]; then want=("$@"); else want=(ROOT TINA ALICE MIKE RITA PAUL EVE FIONA SAM AVA DORA); fi

touch "$DEV/tokens.env"; chmod 600 "$DEV/tokens.env"
put() { # name value: replace or append the line
  local tmp; tmp=$(mktemp); grep -v "^$1=" "$DEV/tokens.env" >"$tmp" || true
  echo "$1=$2" >>"$tmp"; (umask 077; mv "$tmp" "$DEV/tokens.env"); chmod 600 "$DEV/tokens.env"
}

ROOT_TOKEN=$(SRUSTIOPS_DATABASE_URL="postgres://postgres:$PG_PASS@127.0.0.1:$PG_PORT/central?sslmode=disable" \
  bin/srustiops central bootstrap -email root@platform.local -ttl-days 30 2>/dev/null)
[[ -n "$ROOT_TOKEN" ]] || { echo "could not rotate the platform root's token (is the dev database running?)" >&2; exit 1; }
put ROOT "$ROOT_TOKEN"
done_list=(ROOT)

for n in "${want[@]}"; do
  [[ "$n" == ROOT ]] && continue
  e=$(email_of "$n"); [[ -n "$e" ]] || { echo "unknown person $n" >&2; continue; }
  t=$(curl -fsS -H "Authorization: Bearer $ROOT_TOKEN" -H 'Content-Type: application/json' -X POST "$CENTRAL/api/v1/tenants/acme/tokens" \
      --data-binary "{\"email\":\"$e@acme.local\",\"name\":\"dev\",\"ttl_days\":30}" |
      python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("secret",""))
except Exception: print("")') || t=""
  if [[ -n "$t" ]]; then put "$n" "$t"; done_list+=("$n"); else echo "could not issue a token for $n ($e@acme.local)" >&2; fi
done
echo "reissued: ${done_list[*]} → $DEV/tokens.env"
