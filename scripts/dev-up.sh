#!/usr/bin/env bash
# Local multi-tenant development stack, all on loopback:
#   central plane   http://127.0.0.1:8090   web UI, identity, routing (plain HTTP allowed on loopback only)
#   tenant "acme"   https://localhost:8444  its own database, state and runner; reached by central over mTLS
#   tenant "srustiops-1" https://localhost:8445, reached only through its tenant link: the link agent
#                   dials out to central's gateway (https://localhost:8091); nothing dials in.
#                   DEV_TENANT2_LINK=0 keeps it on direct mTLS instead.
# Seeds entities and business units, cloud connections and one person per role. Tokens are
# written to .dev/tokens.env (mode 0600).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(cd .. && pwd)"
DEV="$PWD/.dev/multi-tenant"
mkdir -p "$DEV" && chmod 700 "$PWD/.dev" "$DEV"
# One stack at a time: a dev-up still running holds the ports, and a second
# one would fail to bind and stop everything it started. Stop the old one.
if [[ -f "$DEV/dev-up.pid" ]] && OLD=$(cat "$DEV/dev-up.pid") && kill -0 "$OLD" 2>/dev/null \
   && ps -o command= -p "$OLD" | grep -q dev-up; then
  echo "stopping the dev stack already running (pid $OLD)" >&2
  kill -INT "$OLD" 2>/dev/null
  for _ in $(seq 1 40); do kill -0 "$OLD" 2>/dev/null || break; sleep 0.25; done
fi
# Processes left by a dev-up that was killed outright (its trap never ran).
pkill -f "^bin/srustiops (central|tenant|runner|link|dev-idp)( |$)|fake-cloud.py 18985|fake-claude.py 18998" 2>/dev/null && sleep 1
echo $$ >"$DEV/dev-up.pid"
PG_NAME=srustiops-dev-mt-pg
PG_PORT="${DEV_PG_PORT:-55434}"
CP="${DEV_CENTRAL_PORT:-8090}"
TP="${DEV_TENANT_PORT:-8444}"
TP2="${DEV_TENANT2_PORT:-8445}" # second tenant, srustiops-1
LP="${DEV_LINK_PORT:-8091}"      # tenant link gateway
C="$DEV/certs"

[[ -f "$DEV/secrets.env" ]] || {
  umask 077
  cat >"$DEV/secrets.env" <<EOT
PG_PASS=$(openssl rand -hex 16)
CENTRAL_MASTER_KEY=$(openssl rand -base64 32)
ACME_MASTER_KEY=$(openssl rand -base64 32)
SRUSTIOPS_STATE_KEY=$(openssl rand -hex 32)
EOT
}
grep -q '^SRUSTIOPS1_MASTER_KEY=' "$DEV/secrets.env" || (umask 077; echo "SRUSTIOPS1_MASTER_KEY=$(openssl rand -base64 32)" >>"$DEV/secrets.env")
# srustiops-1 encrypts its state with its own key. Its runner starts once a
# runner registered in srustiops-1 (Tenant settings → Runners) has its token in
# this file as SRUSTIOPS1_RUNNER_TOKEN=sop_r_…
grep -q '^SRUSTIOPS1_STATE_KEY=' "$DEV/secrets.env" || (umask 077; echo "SRUSTIOPS1_STATE_KEY=$(openssl rand -hex 32)" >>"$DEV/secrets.env")
# shellcheck disable=SC1091
source "$DEV/secrets.env"

if ! docker ps --format '{{.Names}}' | grep -qx "$PG_NAME"; then
  docker rm -f "$PG_NAME" >/dev/null 2>&1 || true
  docker run -d --name "$PG_NAME" -e POSTGRES_PASSWORD="$PG_PASS" \
    -v srustiops-dev-mt-pg:/var/lib/postgresql/data -p "127.0.0.1:$PG_PORT:5432" postgres:16-alpine >/dev/null
fi
until docker exec "$PG_NAME" pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
sleep 1

# Temporal orchestrates each run's lifecycle (UI on http://localhost:8233).
# DEV_TEMPORAL=0 uses the built-in database scheduler instead.
# OpenBao for secret references (dev mode: in memory, root token dev-root). DEV_OPENBAO=0 skips it.
BAO_NAME=srustiops-dev-openbao
if [[ "${DEV_OPENBAO:-1}" != 0 ]]; then
  if ! docker ps --format '{{.Names}}' | grep -qx "$BAO_NAME"; then
    docker rm -f "$BAO_NAME" >/dev/null 2>&1 || true
    docker run -d --name "$BAO_NAME" --cap-add=IPC_LOCK -p 127.0.0.1:8200:8200 \
      -e BAO_DEV_ROOT_TOKEN_ID=dev-root -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 openbao/openbao:latest server -dev >/dev/null
  fi
  for _ in $(seq 1 30); do curl -fsS http://127.0.0.1:8200/v1/sys/health >/dev/null 2>&1 && break; sleep 1; done
fi
TEMPORAL_NAME=srustiops-dev-temporal
if [[ "${DEV_TEMPORAL:-1}" != 0 ]]; then
  if ! docker ps --format '{{.Names}}' | grep -qx "$TEMPORAL_NAME"; then
    docker rm -f "$TEMPORAL_NAME" >/dev/null 2>&1 || true
    # in-memory dev server: workflow history resets when the container restarts;
    # the database stays the source of truth for runs
    docker run -d --name "$TEMPORAL_NAME" -p 127.0.0.1:7233:7233 -p 127.0.0.1:8233:8233 \
      temporalio/temporal:latest server start-dev --ip 0.0.0.0 >/dev/null
  fi
  ready=""
  for _ in $(seq 1 60); do
    docker exec "$TEMPORAL_NAME" temporal operator namespace describe -n default >/dev/null 2>&1 && { ready=1; break; }
    docker ps --format '{{.Names}}' | grep -qx "$TEMPORAL_NAME" || break # exited
    sleep 1
  done
  if [[ -n "$ready" ]]; then
    export SRUSTIOPS_TEMPORAL_ADDRESS=127.0.0.1:7233
  else
    echo "Temporal did not start (docker logs $TEMPORAL_NAME); using the built-in scheduler" >&2
  fi
fi
FRESH=""
for db in central acme; do
  if ! docker exec "$PG_NAME" psql -U postgres -Atc "SELECT 1 FROM pg_database WHERE datname='$db'" | grep -q 1; then
    docker exec "$PG_NAME" psql -U postgres -qc "CREATE DATABASE $db"
    FRESH=1
  fi
done
# The second tenant's database (its own, like every tenant plane).
docker exec "$PG_NAME" psql -U postgres -Atc "SELECT 1 FROM pg_database WHERE datname='srustiops_1'" | grep -q 1 ||
  docker exec "$PG_NAME" psql -U postgres -qc "CREATE DATABASE srustiops_1"
dburl() { echo "postgres://postgres:$PG_PASS@127.0.0.1:$PG_PORT/$1?sslmode=disable"; }

go build -o bin/srustiops ./cmd/srustiops
WEB="$ROOT/srustiops-web"
if [[ -d "$WEB" ]]; then (cd "$WEB" && { [[ -d node_modules ]] || npm ci; } && npm run build >/dev/null); fi
bin/srustiops dev-cert -dir "$C" -name central-client -client >/dev/null
bin/srustiops dev-cert -dir "$C" -name acme -host localhost,127.0.0.1 >/dev/null
bin/srustiops dev-cert -dir "$C" -name srustiops-1 -host localhost,127.0.0.1 >/dev/null
# The gateway's certificate also names host.docker.internal and
# host.minikube.internal, so tenants run in Docker or minikube on this machine
# can reach it.
# DEV_LINK_PUBLIC_URL (e.g. https://0.tcp.ngrok.io:12345, a TCP tunnel to the
# gateway port) lets tenants outside this machine, like a provisioned VM in
# AWS, reach the gateway; its host is added to the certificate.
LINK_PUBLIC="${DEV_LINK_PUBLIC_URL:-https://localhost:$LP}"
LINK_HOST="$(python3 -c 'import sys,urllib.parse;print(urllib.parse.urlparse(sys.argv[1]).hostname)' "$LINK_PUBLIC")"
LINK_HOSTS="localhost,127.0.0.1,host.docker.internal,host.minikube.internal"
[[ "$LINK_HOST" == localhost ]] || LINK_HOSTS="$LINK_HOSTS,$LINK_HOST"
openssl x509 -in "$C/central-link.pem" -noout -ext subjectAltName 2>/dev/null | grep -q host.minikube.internal || LINK_FORCE=-force
openssl x509 -in "$C/central-link.pem" -noout -ext subjectAltName 2>/dev/null | grep -q "$LINK_HOST" || LINK_FORCE=-force
bin/srustiops dev-cert -dir "$C" -name central-link -host "$LINK_HOSTS" ${LINK_FORCE:-} >/dev/null
TOFU_VERSION="$(tofu version -json | python3 -c 'import sys,json;print(json.load(sys.stdin)["terraform_version"])')"
CENTRAL=http://127.0.0.1:$CP

PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null; wait 2>/dev/null' EXIT INT TERM

# The assistant: a real key in SRUSTIOPS_ASSISTANT_API_KEY is passed through;
# DEV_ASSISTANT=fake uses the scripted stand-in from the e2e test instead.
if [[ "${DEV_ASSISTANT:-}" == fake ]]; then
  python3 "$ROOT/srustiops-test-resources/e2e/fake-claude.py" 18998 dev-fake-key >"$DEV/fake-claude.log" 2>&1 &
  PIDS+=($!)
  export SRUSTIOPS_ASSISTANT_API_KEY=dev-fake-key SRUSTIOPS_ASSISTANT_BASE_URL=http://127.0.0.1:18998
fi

# DEV_ACME_PUBLIC_URL gives acme a public https address (e.g. a cloudflared
# tunnel to $TP). acme is the OIDC issuer its runs present to clouds, so real
# AWS can only trust acme's runs when it can fetch the issuer's keys there.
# acme's inventory and organisation reads go to a local fake cloud with a
# realistic spread of services (DEV_CLOUD=real sends them to the real clouds).
# srustiops-1 always uses the real clouds: its connections are real accounts.
if [[ "${DEV_CLOUD:-fake}" == fake ]]; then
  python3 "$ROOT/srustiops-test-resources/e2e/fake-cloud.py" 18985 --rich >"$DEV/fake-cloud.log" 2>&1 &
  PIDS+=($!)
  export SRUSTIOPS_CLOUD_API_URL=http://127.0.0.1:18985
fi

# Webhooks from GitHub need a public address: SRUSTIOPS_WEBHOOK_BASE_URL, or an
# ngrok tunnel to the central port if one is running (ngrok http $CP).
if [[ -z "${SRUSTIOPS_WEBHOOK_BASE_URL:-}" ]]; then
  SRUSTIOPS_WEBHOOK_BASE_URL=$(curl -fsS http://127.0.0.1:4040/api/tunnels 2>/dev/null | python3 -c '
import json,sys
for t in json.load(sys.stdin).get("tunnels",[]):
    if t.get("public_url","").startswith("https://") and t.get("config",{}).get("addr","").endswith(":'"$CP"'"):
        print(t["public_url"]); break' 2>/dev/null || true)
fi
export SRUSTIOPS_WEBHOOK_BASE_URL
# Integration settings (GitHub App, webhook URL) live in .env and are hot-reloaded.
export SRUSTIOPS_ENV_FILE="${SRUSTIOPS_ENV_FILE:-$PWD/.env}"
[[ -f "$SRUSTIOPS_ENV_FILE" ]] || (umask 077; : > "$SRUSTIOPS_ENV_FILE")
HOOK_FROM_ENV=$(sed -n 's/^SRUSTIOPS_WEBHOOK_BASE_URL=//p' "$SRUSTIOPS_ENV_FILE" | tail -1)
[[ -n "$HOOK_FROM_ENV" ]] && SRUSTIOPS_WEBHOOK_BASE_URL="$HOOK_FROM_ENV"

SRUSTIOPS_DATABASE_URL="$(dburl central)" SRUSTIOPS_MASTER_KEY="$CENTRAL_MASTER_KEY" SRUSTIOPS_LISTEN=127.0.0.1:$CP \
SRUSTIOPS_PUBLIC_URL="$CENTRAL" SRUSTIOPS_INSECURE_HTTP=1 SRUSTIOPS_WEB_DIR="$WEB/dist" \
SRUSTIOPS_CLIENT_CERT="$C/central-client.pem" SRUSTIOPS_CLIENT_KEY="$C/central-client-key.pem" \
SRUSTIOPS_LINK_LISTEN=127.0.0.1:$LP SRUSTIOPS_LINK_PUBLIC_URL="$LINK_PUBLIC" SRUSTIOPS_LINK_SERVER_CA="$C/ca.pem" \
SRUSTIOPS_LINK_TLS_CERT="$C/central-link.pem" SRUSTIOPS_LINK_TLS_KEY="$C/central-link-key.pem" SRUSTIOPS_DEV_TRUST_DOMAINS=1 SRUSTIOPS_CLIENT_CA="$C/ca.pem" SRUSTIOPS_IMAGE_REPO="${DEV_IMAGE_REPO:-docker.io/mukkarapavankumarreddy}" SRUSTIOPS_IMAGE_TAG="${DEV_IMAGE_TAG:-0.2.0}" SRUSTIOPS_PROVISIONER_TENANT="${DEV_PROVISIONER_TENANT:-}" SRUSTIOPS_PROVISIONER_POOL="${DEV_PROVISIONER_POOL:-default}" \
  bin/srustiops central >"$DEV/central.log" 2>&1 &
PIDS+=($!)
SRUSTIOPS_DATABASE_URL="$(dburl acme)" SRUSTIOPS_MASTER_KEY="$ACME_MASTER_KEY" SRUSTIOPS_TENANT=acme \
SRUSTIOPS_BREAKGLASS_LISTEN=127.0.0.1:9444 \
SRUSTIOPS_LISTEN=127.0.0.1:$TP SRUSTIOPS_PUBLIC_URL="${DEV_ACME_PUBLIC_URL:-https://localhost:$TP}" SRUSTIOPS_TLS_CERT="$C/acme.pem" SRUSTIOPS_TLS_KEY="$C/acme-key.pem" \
SRUSTIOPS_CENTRAL_URL="$CENTRAL" SRUSTIOPS_CENTRAL_CLIENT_CA="$C/ca.pem" \
SRUSTIOPS_CATALOG_DIR="$ROOT/srustiops-modules/catalog" SRUSTIOPS_TOFU_VERSION="$TOFU_VERSION" \
SRUSTIOPS_ALLOW_LOCAL_CONTRACTS=1 SRUSTIOPS_BUNDLE_CACHE_DIR="$DEV/bundles-acme" \
  bin/srustiops tenant >"$DEV/tenant-acme.log" 2>&1 &
PIDS+=($!)
SRUSTIOPS_CLOUD_API_URL="" SRUSTIOPS_DATABASE_URL="$(dburl srustiops_1)" SRUSTIOPS_MASTER_KEY="$SRUSTIOPS1_MASTER_KEY" SRUSTIOPS_TENANT=srustiops-1 \
SRUSTIOPS_BREAKGLASS_LISTEN=127.0.0.1:9445 \
SRUSTIOPS_LISTEN=127.0.0.1:$TP2 SRUSTIOPS_PUBLIC_URL=https://localhost:$TP2 SRUSTIOPS_TLS_CERT="$C/srustiops-1.pem" SRUSTIOPS_TLS_KEY="$C/srustiops-1-key.pem" \
SRUSTIOPS_CENTRAL_URL="$CENTRAL" SRUSTIOPS_CENTRAL_CLIENT_CA="$C/ca.pem" \
SRUSTIOPS_CATALOG_DIR="$ROOT/srustiops-modules/catalog" SRUSTIOPS_TOFU_VERSION="$TOFU_VERSION" \
SRUSTIOPS_ALLOW_LOCAL_CONTRACTS=1 SRUSTIOPS_BUNDLE_CACHE_DIR="$DEV/bundles-srustiops-1" \
  bin/srustiops tenant >"$DEV/tenant-srustiops-1.log" 2>&1 &
PIDS+=($!)
until curl -fsS "$CENTRAL/healthz" >/dev/null 2>&1 && curl -fsS --cacert "$C/ca.pem" https://localhost:$TP/healthz >/dev/null 2>&1 &&
  curl -fsS --cacert "$C/ca.pem" https://localhost:$TP2/healthz >/dev/null 2>&1; do sleep 0.5; done

call() { local tok=$1 m=$2 p=$3; shift 3; curl -fsS -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -X "$m" "$CENTRAL$p" ${1:+--data-binary "$1"}; }
J() { python3 -c 'import sys,json;print(json.load(sys.stdin)[sys.argv[1]])' "$1"; }
# Seed on a fresh database (tokens from an older database would not work).
if [[ -n "$FRESH" || ! -f "$DEV/tokens.env" ]]; then
  RES="$ROOT/srustiops-test-resources"
  ROOT_TOKEN=$(SRUSTIOPS_DATABASE_URL="$(dburl central)" bin/srustiops central bootstrap -email root@platform.local -ttl-days 30 2>/dev/null)
  CA_JSON=$(python3 -c 'import json,sys;print(json.dumps(open(sys.argv[1]).read()))' "$C/ca.pem")
  call "$ROOT_TOKEN" POST /api/v1/tenants "{\"slug\":\"acme\",\"name\":\"Acme Corp\",\"backend_url\":\"https://localhost:$TP\",\"server_ca_pem\":$CA_JSON,\"admin_email\":\"tina@acme.local\"}" >/dev/null
  tok() { call "$1" POST /api/v1/tenants/acme/tokens "{\"email\":\"$2\",\"name\":\"dev\",\"ttl_days\":30}" | J secret; }
  TINA=$(tok "$ROOT_TOKEN" tina@acme.local)
  call "$TINA" POST /api/v1/tenants/acme/entities '{"slug":"retail","name":"Acme Retail Ltd"}' >/dev/null
  call "$TINA" POST /api/v1/tenants/acme/entities '{"slug":"platform","name":"Acme Platform Ltd"}' >/dev/null
  call "$TINA" POST /api/v1/tenants/acme/bus '{"slug":"payments","name":"Payments","entity":"retail"}' >/dev/null
  call "$TINA" POST /api/v1/tenants/acme/bus '{"slug":"checkout","name":"Checkout","entity":"retail"}' >/dev/null
  call "$TINA" POST /api/v1/tenants/acme/bus '{"slug":"data","name":"Data platform","entity":"platform"}' >/dev/null
  # email:role:scope-kind:scope (scope-kind is bu, entity, or empty for tenant-wide)
  for m in alice@acme.local:developer:bu:payments mike@acme.local:manager:bu:payments rita@acme.local:manager:entity:retail \
           paul@acme.local:manager:entity:platform eve@acme.local:developer:bu:data fiona@acme.local:finops:: sam@acme.local:security:: ava@acme.local:auditor:: dora@acme.local:devops::; do
    IFS=: read -r email role kind scope <<<"$m"
    body="{\"email\":\"$email\",\"role\":\"$role\"${kind:+,\"$kind\":\"$scope\"}}"
    call "$TINA" POST /api/v1/tenants/acme/members "$body" >/dev/null
  done
  for f in "$RES"/connections/*.json; do call "$TINA" POST /api/v1/t/acme/connections "@$f" >/dev/null; done
  RUNNER_TOKEN=$(call "$TINA" POST /api/v1/t/acme/runners '{"name":"dev-runner","pool":"default"}' | J secret)
  for f in retail-dev retail-prod platform-dev; do call "$TINA" POST /api/v1/t/acme/environments "@$RES/environments/$f.json" >/dev/null; done
  ALICE=$(tok "$TINA" alice@acme.local)
  for f in local-naming prod-naming; do call "$ALICE" POST /api/v1/t/acme/stacks "@$RES/stacks/$f.json" >/dev/null; done
  umask 077
  {
    echo "ROOT=$ROOT_TOKEN       # platform admin (onboarding only)"
    echo "TINA=$TINA       # acme tenant_admin"
    echo "ALICE=$ALICE       # developer, payments"
    for u in mike rita paul eve fiona sam ava dora; do echo "$(echo $u | tr a-z A-Z)=$(tok "$TINA" $u@acme.local)"; done
    echo "RUNNER_TOKEN=$RUNNER_TOKEN"
  } >"$DEV/tokens.env"
fi
# The root's recovery token is revoked when someone signs out with it in the
# console: issue a fresh one (dev only) before anything else uses it, so
# repeated rejections do not lock this address out.
ROOT_NOW=$(sed -n 's/^ROOT=\([^ ]*\).*/\1/p' "$DEV/tokens.env")
if [[ "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $ROOT_NOW" "$CENTRAL/api/v1/me")" == 401 ]]; then
  NEW_ROOT=$(SRUSTIOPS_DATABASE_URL="$(dburl central)" bin/srustiops central bootstrap -email root@platform.local -ttl-days 30 2>/dev/null)
  if [[ -n "$NEW_ROOT" ]]; then
    (umask 077; sed -i.bak "s|^ROOT=[^ ]*|ROOT=$NEW_ROOT|" "$DEV/tokens.env" && rm -f "$DEV/tokens.env.bak")
    echo "the platform root's token had been revoked; issued a new one into $DEV/tokens.env" >&2
  fi
fi
# The second tenant, srustiops-1: onboarded once by the platform admin. Its
# first tenant admin is DEV_TENANT2_ADMIN (default: the platform admin).
PADMIN=$(sed -n 's/^ROOT=\([^ ]*\).*/\1/p' "$DEV/tokens.env")
if ! curl -fsS -H "Authorization: Bearer $PADMIN" "$CENTRAL/api/v1/tenants" | grep -q '"slug":"srustiops-1"'; then
  CA_JSON=$(python3 -c 'import json,sys;print(json.dumps(open(sys.argv[1]).read()))' "$C/ca.pem")
  call "$PADMIN" POST /api/v1/tenants "{\"slug\":\"srustiops-1\",\"name\":\"SrustiOps 1\",\"backend_url\":\"https://localhost:$TP2\",\"server_ca_pem\":$CA_JSON,\"admin_email\":\"${DEV_TENANT2_ADMIN:-root@platform.local}\"}" >/dev/null \
    && echo "onboarded tenant srustiops-1 (backend https://localhost:$TP2)" || echo "could not onboard srustiops-1 (see $DEV/tenant-srustiops-1.log)" >&2
fi
# srustiops-1 is reached through its tenant link (DEV_TENANT2_LINK=0: direct).
# The agent enrols once with a one-time token and keeps its key and 24-hour
# certificate in $DEV/link-srustiops-1, renewing it itself.
LINK_STATUS="off (direct mTLS)"
if [[ "${DEV_TENANT2_LINK:-1}" != 0 ]]; then
  T2=$(curl -fsS -H "Authorization: Bearer $PADMIN" "$CENTRAL/api/v1/tenants/srustiops-1" || true)
  if ! printf '%s' "$T2" | grep -q '"connectivity":"tunnel"'; then
    printf '%s' "$T2" | python3 -c 'import sys,json;t=json.load(sys.stdin);print(json.dumps({"name":t["name"],"backend_url":t["backend_url"],"server_ca_pem":t.get("server_ca_pem",""),"connectivity":"tunnel"}))' \
      | curl -fsS -o /dev/null -H "Authorization: Bearer $PADMIN" -H 'Content-Type: application/json' -X PUT "$CENTRAL/api/v1/tenants/srustiops-1" --data-binary @- \
      && echo "srustiops-1 now connects through its tenant link"
  fi
  LINK_DIR="$DEV/link-srustiops-1"
  ENROLL=""
  if ! openssl x509 -checkend 600 -noout -in "$LINK_DIR/link.pem" >/dev/null 2>&1; then
    ENROLL=$(call "$PADMIN" POST /api/v1/tenants/srustiops-1/link/enrollments | J token)
  fi
  SRUSTIOPS_TENANT=srustiops-1 SRUSTIOPS_LINK_URL=https://localhost:$LP SRUSTIOPS_LINK_TARGET=127.0.0.1:$TP2 \
  SRUSTIOPS_LINK_SERVER_CA="$C/ca.pem" SRUSTIOPS_LINK_STATE_DIR="$LINK_DIR" SRUSTIOPS_LINK_ENROLL_TOKEN="$ENROLL" \
    bin/srustiops link >"$DEV/link-srustiops-1.log" 2>&1 &
  PIDS+=($!)
  for _ in $(seq 1 40); do
    curl -fsS -H "Authorization: Bearer $PADMIN" "$CENTRAL/api/v1/tenants/srustiops-1/link" 2>/dev/null | grep -q '"online":true' && break
    sleep 0.25
  done
  if curl -fsS -H "Authorization: Bearer $PADMIN" "$CENTRAL/api/v1/tenants/srustiops-1/link" 2>/dev/null | grep -q '"online":true'; then
    LINK_STATUS="online via gateway https://localhost:$LP (agent log link-srustiops-1.log)"
  else
    LINK_STATUS="OFFLINE: see $DEV/link-srustiops-1.log"
    echo "srustiops-1's tenant link did not come up (see $DEV/link-srustiops-1.log)" >&2
  fi
fi
# A stand-in identity provider for trying a tenant's own sign-in (Tenant
# settings → Access & sign-in → issuer http://127.0.0.1:18994, client srustiops-dev).
bin/srustiops dev-idp -listen 127.0.0.1:18994 >"$DEV/dev-idp.log" 2>&1 &
PIDS+=($!)
# Older seeds had no manager for the Platform product (BU Data): add one.
if ! grep -q '^PAUL=' "$DEV/tokens.env"; then
  # the platform admin can always do this (a tenant admin's token may have been signed out)
  TINA=$(sed -n 's/^ROOT=\([^ ]*\).*/\1/p' "$DEV/tokens.env")
  curl -sS -o "$DEV/paul.log" -H "Authorization: Bearer $TINA" -H 'Content-Type: application/json' -X POST "$CENTRAL/api/v1/tenants/acme/members" \
    --data-binary '{"email":"paul@acme.local","role":"manager","entity":"platform"}' || true
  PAUL=$(curl -sS -H "Authorization: Bearer $TINA" -H 'Content-Type: application/json' -X POST "$CENTRAL/api/v1/tenants/acme/tokens" \
    --data-binary '{"email":"paul@acme.local","name":"dev","ttl_days":30}' | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("secret",""))
except Exception: print("")' || true)
  if [[ -n "$PAUL" ]]; then
    (umask 077; echo "PAUL=$PAUL       # manager, entity platform (BU data)" >>"$DEV/tokens.env")
  else
    echo "could not add PAUL (see $DEV/paul.log)" >&2
  fi
fi
# Older seeds had no DevOps engineer (approves activating releases): add one.
if ! grep -q '^DORA=' "$DEV/tokens.env"; then
  ADMIN=$(sed -n 's/^ROOT=\([^ ]*\).*/\1/p' "$DEV/tokens.env")
  curl -sS -o /dev/null -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -X POST "$CENTRAL/api/v1/tenants/acme/members" \
    --data-binary '{"email":"dora@acme.local","role":"devops"}' || true
  DORA=$(curl -sS -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -X POST "$CENTRAL/api/v1/tenants/acme/tokens" \
    --data-binary '{"email":"dora@acme.local","name":"dev","ttl_days":30}' | python3 -c 'import sys,json
try: print(json.load(sys.stdin).get("secret",""))
except Exception: print("")' || true)
  [[ -n "$DORA" ]] && (umask 077; echo "DORA=$DORA       # devops: approves activating releases" >>"$DEV/tokens.env")
fi
RUNNER_TOKEN=$(grep '^RUNNER_TOKEN=' "$DEV/tokens.env" | cut -d= -f2)
# Dev seed for the inventory: more accounts and projects, then one scan of
# each (as the platform admin). Existing connections are left as they are.
if [[ -n "${SRUSTIOPS_CLOUD_API_URL:-}" ]]; then
  ADMIN=$(sed -n 's/^ROOT=\([^ ]*\).*/\1/p' "$DEV/tokens.env")
  seed() { curl -sS -o /dev/null -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -X "$1" "$CENTRAL/api/v1/t/acme$2" ${3:+--data-binary "$3"} || true; }
  seed POST /connections '{"name":"aws-checkout-prod","entities":["retail"],"cloud":{"provider":"aws","auth":"oidc","aws":{"region":"eu-west-1","role_arn":"arn:aws:iam::345678901234:role/srustiops-deployer","plan_role_arn":"arn:aws:iam::345678901234:role/srustiops-reader"}}}'
  seed POST /connections '{"name":"gcp-analytics","entities":["platform"],"cloud":{"provider":"gcp","auth":"oidc","gcp":{"project_id":"acme-analytics-7781","region":"europe-west1","service_account_email":"srustiops-deployer@acme-analytics-7781.iam.gserviceaccount.com","plan_service_account_email":"srustiops-reader@acme-analytics-7781.iam.gserviceaccount.com","workload_identity_provider":"projects/123456789012/locations/global/workloadIdentityPools/srustiops/providers/srustiops"}}}'
  seed POST /connections '{"name":"gcp-sandbox-dev","entities":["retail"],"cloud":{"provider":"gcp","auth":"oidc","gcp":{"project_id":"acme-sandbox-dev","region":"europe-west1","service_account_email":"srustiops-deployer@acme-sandbox-dev.iam.gserviceaccount.com","workload_identity_provider":"projects/123456789012/locations/global/workloadIdentityPools/srustiops/providers/srustiops"}}}'
  for c in aws-prod-account aws-checkout-prod gcp-prod-project gcp-analytics gcp-sandbox-dev azure-subscription; do seed POST "/connections/$c/scan"; done
fi
# A private copy of the modules repository for releases, so edits made in the
# console never touch your working copy.
if [[ ! -d "$DEV/modules-repo" ]]; then cp -R "$ROOT/srustiops-modules" "$DEV/modules-repo"; fi
# Configure OpenBao as each tenant's secret store. Every tenant signs run
# tokens with its own key, so each gets its own JWT auth mount, and its own KV
# mount and read policy, so one tenant cannot read another's secrets.
BAO_STATUS="off"
if [[ "${DEV_OPENBAO:-1}" != 0 ]] && curl -fsS http://127.0.0.1:8200/v1/sys/health >/dev/null 2>&1; then
  ADMIN=$(sed -n 's/^ROOT=\([^ ]*\).*/\1/p' "$DEV/tokens.env")
  bx() { docker exec -i -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN=dev-root "$BAO_NAME" bao "$@"; }
  # bao_tenant SLUG PORT AUTH_MOUNT KV_MOUNT
  bao_tenant() {
    local slug=$1 port=$2 auth=$3 kv=$4 store pem set body
    store=$(curl -fsS -H "Authorization: Bearer $ADMIN" "$CENTRAL/api/v1/t/$slug/integrations/secret-store" || true)
    pem=$(printf '%s' "$store" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("public_key_pem",""))' 2>/dev/null || true)
    # Once configured, a change goes through approval; re-runs leave it as is.
    set=$(printf '%s' "$store" | python3 -c 'import sys,json;d=json.load(sys.stdin);print("yes" if (d.get("config") or {}).get("address")=="http://127.0.0.1:8200" else "")' 2>/dev/null || true)
    body="{\"address\":\"http://127.0.0.1:8200\",\"role\":\"srustiops\"${auth:+,\"auth_mount\":\"$auth\"}}"
    [[ -n "$pem" ]] && {
      bx secrets list | grep "^$kv/" >/dev/null || bx secrets enable -path="$kv" kv-v2 >/dev/null
    } && printf 'path "%s/data/*" { capabilities = ["read"] }\n' "$kv" | bx policy write "$slug-read" - >/dev/null && {
      bx auth list | grep "^${auth:-jwt}/" >/dev/null || bx auth enable -path="${auth:-jwt}" jwt >/dev/null
    } && printf '%s\n' "$pem" | docker exec -i "$BAO_NAME" sh -c "cat > /tmp/issuer-$slug.pem" \
      && bx write "auth/${auth:-jwt}/config" bound_issuer="https://localhost:$port" jwt_validation_pubkeys=@/tmp/issuer-$slug.pem >/dev/null \
      && printf '{"role_type":"jwt","user_claim":"sub","bound_audiences":["srustiops-vault"],"bound_claims_type":"glob","bound_claims":{"sub":["srustiops:entity:*","srustiops:discovery:*"]},"token_ttl":"15m","token_policies":["%s-read"]}' "$slug" \
           | bx write "auth/${auth:-jwt}/role/srustiops" - >/dev/null \
      && { [[ -n "$set" ]] || curl -fsS -o /dev/null -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -X PUT \
           "$CENTRAL/api/v1/t/$slug/integrations/secret-store" --data-binary "$body"; }
  }
  # acme keeps the original mounts (jwt, kv).
  if bao_tenant acme "$TP" "" kv && bx kv put kv/payments/demo password=dev-only-value >/dev/null \
     && bao_tenant srustiops-1 "$TP2" jwt-srustiops-1 kv-srustiops-1; then
    BAO_STATUS="http://127.0.0.1:8200 (root token dev-root; CLI: ./scripts/bao) · KV mounts: acme kv/, srustiops-1 kv-srustiops-1/ · sample secret vault://kv/payments/demo#password"
  else
    echo "configuring OpenBao failed; secret references are unavailable in this dev stack" >&2
  fi
fi
# Point module releases at the local modules checkout (once): Tenant settings → Releases → Build now.
ADMIN=$(sed -n 's/^ROOT=\([^ ]*\).*/\1/p' "$DEV/tokens.env")
if ! curl -fsS -H "Authorization: Bearer $ADMIN" "$CENTRAL/api/v1/t/acme/releases/modules/source" 2>/dev/null | grep -q '"repo"'; then
  curl -sS -o /dev/null -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' -X PUT "$CENTRAL/api/v1/t/acme/releases/modules/source" \
    --data-binary "{\"provider\":\"local\",\"repo\":\"$DEV/modules-repo\",\"branch\":\"main\",\"path\":\"\",\"poll_seconds\":300,\"enabled\":false,\"approvals\":1}" || true
fi

SRUSTIOPS_SERVER_URL=https://localhost:$TP SRUSTIOPS_RUNNER_TOKEN="$RUNNER_TOKEN" SRUSTIOPS_STATE_KEY="$SRUSTIOPS_STATE_KEY" \
SRUSTIOPS_CA_FILE="$C/ca.pem" SRUSTIOPS_WORK_DIR="$DEV/runs" SRUSTIOPS_PLUGIN_CACHE_DIR="$DEV/plugin-cache" \
SRUSTIOPS_CATALOG_DIR="$ROOT/srustiops-modules/catalog" SRUSTIOPS_BUNDLE_CACHE_DIR="$DEV/runner-bundles" \
  bin/srustiops runner >"$DEV/runner-acme.log" 2>&1 &
PIDS+=($!)
RUNNER2_STATUS="no runner: register one in srustiops-1, then add SRUSTIOPS1_RUNNER_TOKEN=… to $DEV/secrets.env and re-run dev-up"
if [[ -n "${SRUSTIOPS1_RUNNER_TOKEN:-}" ]]; then
  SRUSTIOPS_SERVER_URL=https://localhost:$TP2 SRUSTIOPS_RUNNER_TOKEN="$SRUSTIOPS1_RUNNER_TOKEN" SRUSTIOPS_STATE_KEY="$SRUSTIOPS1_STATE_KEY" \
  SRUSTIOPS_CA_FILE="$C/ca.pem" SRUSTIOPS_WORK_DIR="$DEV/runs-srustiops-1" SRUSTIOPS_PLUGIN_CACHE_DIR="$DEV/plugin-cache" \
  SRUSTIOPS_CATALOG_DIR="$ROOT/srustiops-modules/catalog" SRUSTIOPS_BUNDLE_CACHE_DIR="$DEV/runner-bundles-srustiops-1" \
    bin/srustiops runner >"$DEV/runner-srustiops-1.log" 2>&1 &
  PIDS+=($!)
  RUNNER2_STATUS="runner started (log runner-srustiops-1.log)"
fi
mkdir -p "$DEV/plugin-cache"

HOOKS="${SRUSTIOPS_WEBHOOK_BASE_URL:+$SRUSTIOPS_WEBHOOK_BASE_URL/webhooks/github/acme}"
HOOKS="${HOOKS:-no public URL (run ngrok http $CP before dev-up, or set SRUSTIOPS_WEBHOOK_BASE_URL)}"
cat <<EOT

  Tenant srustiops-1 at https://localhost:$TP2 (database srustiops_1) · $RUNNER2_STATUS.
  Tenant link (srustiops-1): $LINK_STATUS
  Dev identity provider: http://127.0.0.1:18994 (client_id srustiops-dev; domains verify without DNS in dev)
  SrustiOps is running at $CENTRAL  (central plane)  ->  tenant acme at https://localhost:$TP
  GitHub webhooks: $HOOKS
  Sign in with a token from $DEV/tokens.env:
    Tenant acme > entities Retail (BUs Payments, Checkout) and Platform (BU Data)
    ALICE  developer, BU Payments: plans stacks      MIKE   manager, BU Payments: signs the manager step
    RITA   manager, entity Retail (all its BUs)      PAUL   manager, entity Platform (BU Data)
    FIONA  finops (tenant): signs finops
    SAM    security (tenant): signs security         EVE    developer, BU Data: cannot see Retail
    AVA    auditor   TINA tenant admin   ROOT platform admin   DORA devops (approves releases)
  OpenBao: $BAO_STATUS
  Temporal: ${SRUSTIOPS_TEMPORAL_ADDRESS:-off (built-in scheduler)}${SRUSTIOPS_TEMPORAL_ADDRESS:+ · UI http://localhost:8233}
  Logs in $DEV/*.log.  Ctrl-C to stop (PostgreSQL and Temporal keep running: docker rm -f $PG_NAME $TEMPORAL_NAME).

EOT
wait "${PIDS[0]}"
