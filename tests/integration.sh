#!/usr/bin/env bash
# Run Kerberus's CLI against a throwaway MIT KDC. Needs krb5-kdc and
# krb5-admin-server installed, but not root: the KDC runs on high ports with its
# config, database and caches in a temporary directory.
#
#   tests/integration.sh python3 kerberus.py
#   tests/integration.sh ./dist/Kerberus-1.2.3-x86_64.AppImage --appimage-extract-and-run
#   KERBERUS_TOOLS=bundled tests/integration.sh ./dist/Kerberus-...AppImage   # the AppImage's own kinit
#   KERBERUS_KCM=1 tests/integration.sh python3 kerberus.py   # tickets kept by Kerberus's KCM server
set -euo pipefail
[ $# -gt 0 ] || { echo "usage: $0 COMMAND..." >&2; exit 2; }
KERBERUS=("$@")

source "$(dirname "$0")/kdc.sh"

if [ -n "${KERBERUS_KCM:-}" ]; then
    # Kerberus serves the cache; the CLI and plain MIT tools both go through it.
    mkdir -p "$work/config/kerberus" "$work/run"
    echo '{"kcm": true}' > "$work/config/kerberus/settings.json"
    export XDG_RUNTIME_DIR=$work/run
    "$@" watch --kcm --interval 3600 > "$work/kcm.log" 2>&1 & pids+=($!)
    sleep 2
    export KRB5CCNAME=KCM: KRB5_CONFIG=$work/config/kerberus/krb5.conf:$KRB5_CONFIG
fi

k() { "${KERBERUS[@]}" "$@"; }
k_with_input() { local input=$1; shift; printf '%s\n' "$input" | "${KERBERUS[@]}" "$@"; }

check      "version"                 "^Kerberus "                      k --version
check      "tool source"             "Kerberos tools: ${KERBERUS_TOOLS:-host|bundled}" k --version
check      "no tickets yet"          "No Kerberos tickets"             k list
check      "get with password"       "Signed in as alice@$realm"       k_with_input alice-password get alice
fails_with "wrong password"          "Password incorrect"              k_with_input nope get bob
check      "plain klist sees it"     "Default principal: alice@$realm" klist
check      "service ticket (kvno)"   "kvno = 1"                        kvno host/svc.kerberus.test
check      "listed as a service"     "service:  host/svc.kerberus.test" k list
check      "second principal"        "Signed in as bob@$realm"         k_with_input bob-password get bob --lifetime 1h
check      "list both"               "alice@$realm"                    k list
check      "json"                    "\"principal\": \"bob@$realm\""   k list --json
check      "switch default"          "alice@$realm is now the default" k switch alice
if [ -n "${KERBERUS_KCM:-}" ]; then
    # The ntlm_auth helper Kerberus wrote reaches the server; without a window there's nobody to ask.
    helper=$work/config/kerberus/bin/ntlm_auth
    ntlm() { printf 'YR\nTT %s\n' "$(printf 'NTLMSSP\0\2\0\0\0' | base64 -w0)" | "$helper" --helper-protocol ntlmssp-client-1 --use-cached-creds --username alice; }
    check  "ntlm_auth helper negotiates" "^YR TlRMTVNTUAABAAAA"            ntlm
    check  "and has no credentials"      "^BH "                            ntlm
fi
check      "default moved"           "^alice@$realm  \(default\)"      k list
check      "renew"                   "Renewed the ticket for alice"    k renew
check      "renew all"               "Renewed the ticket for bob"      k renew --all
check      "change password"         "Password changed"                k_with_input $'alice-password\nnew-password\nnew-password' passwd alice
check      "sign in with new one"    "Signed in as alice@$realm"       k_with_input new-password get alice
check      "short ticket"            "Signed in as bob@$realm"         k_with_input bob-password get bob --lifetime 30s
check      "watch renews it"         "Renewed the ticket for bob"      k watch --once
check      "destroy one"             "Destroyed the tickets for bob"   k destroy bob
fails_with "destroyed is gone"       "No tickets for that principal"   k renew bob
check      "destroy all"             "Destroyed all tickets"           k destroy --all
check      "empty again"             "No Kerberos tickets"             k list

if [ "$fails" -gt 0 ]; then
    echo "$fails check(s) failed"
    exit 1
fi
echo "all checks passed"
