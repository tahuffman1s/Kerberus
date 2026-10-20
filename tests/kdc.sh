#!/usr/bin/env bash
# Sourced by the tests: a throwaway MIT KDC for realm KERBERUS.TEST on high
# ports, with its config, database and caches in $work (removed on exit), and
# check/fails_with helpers. Needs krb5-kdc and krb5-admin-server, not root.
# Principals: alice (alice-password), bob (bob-password), host/svc.kerberus.test.
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
kadmin.local -q "addprinc -randkey host/svc.kerberus.test" >/dev/null 2>&1
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
