#!/usr/bin/env bash
# A copy of polaris-core's examples/walkthrough.sh (github.com/univeros/polaris-core), run from this demo
# directory, plus one step of this demo's own: GET /app/me, the application's route behind the framework's
# TokenAuthenticationMiddleware fed by the module's token bridge.
# The walkthrough every demo runs, executable: register -> verify -> login -> enrol TOTP -> confirm ->
# login again (MFA) -> verify the code -> create an organization -> list it -> switch to it -> list its
# members. Run from a demo directory (each examples/<host>/bin/walkthrough.sh does). Starts its own
# PHP server on POLARIS_DOCROOT (default public) unless POLARIS_URL points at a running one; reads the
# demo's mailbox from POLARIS_MAIL_LOG (default var/mail.log). Exits non-zero on the first failure.
set -euo pipefail

DOCROOT="${POLARIS_DOCROOT:-public}"
MAIL="${POLARIS_MAIL_LOG:-var/mail.log}"
SERVER_LOG="${POLARIS_SERVER_LOG:-var/server.log}"
URL="${POLARIS_URL:-}"
if [ -z "$URL" ]; then
    php -S 127.0.0.1:8080 -t "$DOCROOT" > "$SERVER_LOG" 2>&1 &
    SERVER=$!
    trap 'kill $SERVER 2>/dev/null || true' EXIT
    URL=http://127.0.0.1:8080
    for _ in $(seq 1 50); do curl -s -o /dev/null "$URL/auth/.well-known/jwks.json" && break; sleep 0.1; done
fi

EMAIL="ada+$(date +%s)@example.com"
PASSWORD='Sup3r-Secret-Passw0rd'

json() { php -r '$d = json_decode(stream_get_contents(STDIN), true); foreach (explode(".", $argv[1]) as $k) { $d = $d[$k] ?? null; } echo is_scalar($d) ? $d : json_encode($d);' -- "$1"; }
call() { # call METHOD PATH [TOKEN] [JSON]
    local method=$1 path=$2 token=${3:-} body=${4:-}
    local args=(-s -w '\n%{http_code}' -X "$method" "$URL$path" -H 'Content-Type: application/json')
    [ -n "$token" ] && args+=(-H "Authorization: Bearer $token")
    [ -n "$body" ] && args+=(-d "$body")
    local out; out=$(curl "${args[@]}")
    STATUS=${out##*$'\n'}; BODY=${out%$'\n'*}
}
step() { printf '%-52s %s\n' "$1" "$STATUS"; }
expect() { if [ "$STATUS" != "$1" ]; then echo "expected $1, got $STATUS: $BODY" >&2; exit 1; fi; }
totp() { php -r 'require "vendor/autoload.php"; echo OTPHP\TOTP::createFromSecret($argv[1])->at((int) $argv[2]);' -- "$1" "$2"; }

call POST /auth/register '' "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"; step "1. POST /auth/register"; expect 202
TOKEN=$(grep "\"$EMAIL\"" "$MAIL" | grep verify_email | tail -1 | json context.token)
call POST /auth/email/verify '' "{\"token\":\"$TOKEN\"}"; step "2. POST /auth/email/verify (token from $MAIL)"; expect 200
call POST /auth/login '' "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"; step "3. POST /auth/login"; expect 200
ACCESS=$(printf '%s' "$BODY" | json data.access_token)
call GET /auth/me "$ACCESS"; step "4. GET /auth/me"; expect 200
call POST /auth/mfa/totp/enroll "$ACCESS" '{}'; step "5. POST /auth/mfa/totp/enroll"; expect 200
FACTOR=$(printf '%s' "$BODY" | json data.factor_id); SECRET=$(printf '%s' "$BODY" | json data.secret)
call POST /auth/mfa/totp/confirm "$ACCESS" "{\"factor_id\":\"$FACTOR\",\"code\":\"$(totp "$SECRET" "$(date +%s)")\"}"; step "6. POST /auth/mfa/totp/confirm"; expect 200
call POST /auth/login '' "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}"; step "7. POST /auth/login (now answers mfa_required)"; expect 200
MFA_TOKEN=$(printf '%s' "$BODY" | json data.mfa_token)
[ -n "$MFA_TOKEN" ] || { echo "no mfa_token in $BODY" >&2; exit 1; }
call POST /auth/mfa/verify "$MFA_TOKEN" "{\"factor_id\":\"$FACTOR\",\"code\":\"$(totp "$SECRET" "$(( $(date +%s) + 30 ))")\"}"; step "8. POST /auth/mfa/verify (next TOTP step)"; expect 200
ACCESS=$(printf '%s' "$BODY" | json data.access_token)
call POST /orgs "$ACCESS" "{\"name\":\"Acme Rockets $(date +%s)\"}"; step "9. POST /orgs"; expect 201
ORG=$(printf '%s' "$BODY" | json data.id)
call GET /orgs "$ACCESS"; step "10. GET /orgs"; expect 200
call POST /auth/switch-org "$ACCESS" "{\"organization_id\":\"$ORG\"}"; step "11. POST /auth/switch-org (token scoped to the org)"; expect 200
ACCESS=$(printf '%s' "$BODY" | json data.access_token)
call GET "/orgs/$ORG/members" "$ACCESS"; step "12. GET /orgs/{id}/members"; expect 200
call GET /app/me; step "13. GET /app/me without a token (the framework middleware)"; expect 401
call GET /app/me "$ACCESS"; step "14. GET /app/me (the application's route, the org-scoped token)"; expect 200
[ "$(printf '%s' "$BODY" | json data.organization_id)" = "$ORG" ] || { echo "expected organization $ORG in $BODY" >&2; exit 1; }
echo "PASS: registered $EMAIL, verified, logged in with TOTP, created organization $ORG, read /app/me"
