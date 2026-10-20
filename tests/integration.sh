#!/usr/bin/env bash
# Run Kerberus's CLI against a throwaway MIT KDC. Needs krb5-kdc and
# krb5-admin-server installed, but not root: the KDC runs on high ports with its
# config, database and caches in a temporary directory.
#
#   tests/integration.sh python3 kerberus.py
#   tests/integration.sh ./dist/Kerberus-1.2.3-x86_64.AppImage --appimage-extract-and-run
#   KERBERUS_TOOLS=bundled tests/integration.sh ./dist/Kerberus-...AppImage   # the AppImage's own kinit
set -euo pipefail
[ $# -gt 0 ] || { echo "usage: $0 COMMAND..." >&2; exit 2; }
KERBERUS=("$@")
PATH=$PATH:/usr/sbin:/sbin

work=$(mktemp -d)
pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
    rm -rf "$work"
}
trap cleanup EXIT

realm=KERBERUS.TEST
kdc_port=${KDC_PORT:-18888}
kadmin_port=$((kdc_port + 1))
kpasswd_port=$((kdc_port + 2))
cat > "$work/krb5.conf" <<EOF
[libdefaults]
    default_realm = $realm
    dns_lookup_realm = false
    dns_lookup_kdc = false
    ticket_lifetime = 10h
    renew_lifetime = 7d
[realms]
    $realm = {
        kdc = 127.0.0.1:$kdc_port
        admin_server = 127.0.0.1:$kadmin_port
        kpasswd_server = 127.0.0.1:$kpasswd_port
    }
EOF
cat > "$work/kdc.conf" <<EOF
[kdcdefaults]
    kdc_ports = $kdc_port
    kdc_tcp_ports = $kdc_port
[realms]
    $realm = {
        database_name = $work/principal
        key_stash_file = $work/stash
        acl_file = $work/kadm5.acl
        kadmind_port = $kadmin_port
        kpasswd_port = $kpasswd_port
        max_life = 10h
        max_renewable_life = 7d
    }
[logging]
    kdc = FILE:$work/kdc.log
    admin_server = FILE:$work/kadmind.log
EOF
touch "$work/kadm5.acl"
export KRB5_CONFIG=$work/krb5.conf KRB5_KDC_PROFILE=$work/kdc.conf
export KRB5CCNAME=DIR:$work/ccache XDG_CONFIG_HOME=$work/config
mkdir -p "$work/ccache"

kdb5_util create -s -r "$realm" -P master-password >/dev/null
kadmin.local -q "addprinc -pw alice-password alice" >/dev/null 2>&1
kadmin.local -q "addprinc -pw bob-password bob" >/dev/null 2>&1
kadmin.local -q "modprinc -maxrenewlife 7d krbtgt/$realm" >/dev/null 2>&1
krb5kdc -n -P "$work/kdc.pid" & pids+=($!)
kadmind -nofork -P "$work/kadmind.pid" & pids+=($!)
sleep 2

fails=0
check() {  # check DESCRIPTION EXPECTED-REGEX COMMAND...
    local name=$1 expect=$2 out
    shift 2
    if out=$("$@" 2>&1) && grep -Eq -- "$expect" <<<"$out"; then
        echo "ok   $name"
    else
        echo "FAIL $name"; sed 's/^/     /' <<<"$out"
        fails=$((fails + 1))
    fi
}
fails_with() {  # like check, for commands that must exit non-zero
    local name=$1 expect=$2 out
    shift 2
    if ! out=$("$@" 2>&1) && grep -Eq -- "$expect" <<<"$out"; then
        echo "ok   $name"
    else
        echo "FAIL $name"; sed 's/^/     /' <<<"$out"
        fails=$((fails + 1))
    fi
}
k() { "${KERBERUS[@]}" "$@"; }
k_with_input() { local input=$1; shift; printf '%s\n' "$input" | "${KERBERUS[@]}" "$@"; }

check      "version"                 "^Kerberus "                      k --version
check      "tool source"             "Kerberos tools: ${KERBERUS_TOOLS:-host|bundled}" k --version
check      "no tickets yet"          "No Kerberos tickets"             k list
check      "get with password"       "Signed in as alice@$realm"       k_with_input alice-password get alice
fails_with "wrong password"          "Password incorrect"              k_with_input nope get bob
check      "second principal"        "Signed in as bob@$realm"         k_with_input bob-password get bob --lifetime 1h
check      "list both"               "alice@$realm"                    k list
check      "json"                    "\"principal\": \"bob@$realm\""   k list --json
check      "switch default"          "alice@$realm is now the default" k switch alice
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
