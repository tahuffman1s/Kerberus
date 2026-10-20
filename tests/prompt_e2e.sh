#!/usr/bin/env bash
# The sign-in prompt and the tray icon, end to end. Kerberus runs as the
# session's credential cache on a virtual display; "someapp" (a copy of kvno, so
# it isn't one of the Kerberos tools) asks for a service ticket with nobody
# signed in; the test answers the prompt from the keyboard and checks the app
# got its ticket. A stand-in tray host (fake_tray_host.py) reads the tray icon.
#
#   tests/prompt_e2e.sh python3 kerberus.py
#   tests/prompt_e2e.sh ./dist/Kerberus-1.2.3-x86_64.AppImage --appimage-extract-and-run
#
# Needs Xvfb, xdotool, dbus-x11 and python3-gi as well as the KDC packages.
set -euo pipefail
[ $# -gt 0 ] || { echo "usage: $0 COMMAND..." >&2; exit 2; }
KERBERUS=("$@")
here=$(cd "$(dirname "$0")" && pwd)
source "$here/kdc.sh"

mkdir -p "$work/config/kerberus" "$work/run"
chmod 700 "$work/run"
export XDG_RUNTIME_DIR=$work/run
echo "{\"kcm\": true, \"identities\": [\"alice@$realm\"]}" > "$work/config/kerberus/settings.json"
display=:$((RANDOM % 400 + 100))
Xvfb "$display" -screen 0 1000x800x24 >/dev/null 2>&1 & pids+=($!)
export DISPLAY=$display GSK_RENDERER=cairo GTK_A11Y=none
eval "$(dbus-launch --sh-syntax)"
pids+=("$DBUS_SESSION_BUS_PID")
"${PYTHON:-python3}" "$here/fake_tray_host.py" > "$work/tray.log" 2>&1 & pids+=($!)
sleep 1
"${KERBERUS[@]}" --background > "$work/app.log" 2>&1 & pids+=($!)
for _ in $(seq 40); do [ -S "$work/run/kerberus/kcm.sock" ] && break; sleep 0.5; done
export KRB5CCNAME=KCM: KRB5_CONFIG=$work/config/kerberus/krb5.conf:$KRB5_CONFIG
cp "$(readlink -f "$(command -v kvno)")" "$work/someapp"

someapp() {  # run the app in the background; its output and exit code go to someapp.log
    rm -f "$work/someapp.log"
    (status=0
     timeout 60 "$work/someapp" host/svc.kerberus.test > "$work/someapp.log.tmp" 2>&1 || status=$?
     echo "exit=$status" >> "$work/someapp.log.tmp"; mv "$work/someapp.log.tmp" "$work/someapp.log") &
}
waited() {  # waited SECONDS: wait for someapp to finish, then show its output
    for _ in $(seq $(($1 * 4))); do [ -e "$work/someapp.log" ] && break; sleep 0.25; done
    cat "$work/someapp.log" 2>/dev/null || echo "still waiting"
}
picker() {  # focus the sign-in window
    xdotool search --sync --onlyvisible --name "Kerberos Sign-In" windowfocus --sync >/dev/null
    sleep 0.5
}
tray() { tail -n 1 "$work/tray.log"; }

for _ in $(seq 20); do grep -q menu "$work/tray.log" && break; sleep 0.5; done
check      "tray icon registered"         '"icon": "[^"]*-inactive".*"Choose Identity'  tray
check      "tools don't wait for prompts" "^$"                        timeout 5 kdestroy -A
fails_with "neither does klist"           "not found"                 timeout 5 klist

someapp
sleep 3
check      "the app waits"                "still waiting"             waited 0
check      "tray asks for attention"      '"status": "NeedsAttention".*someapp is waiting' tray
picker
xdotool key Return                          # the first identity: alice
sleep 1
xdotool type --delay 30 alice-password
xdotool key Return
check      "the app got its ticket"       "kvno = 1.*exit=0"          eval 'waited 15 | tr "\n" " "'
check      "and it's in the cache"        "Default principal: alice@$realm" klist
sleep 1
check      "tray shows the ticket"        "alice@$realm: [0-9]+ h"    tray

kdestroy -A
someapp
sleep 3
picker
xdotool key Escape
check      "cancel answers the app"       "exit=1"                    eval 'waited 5 | tr "\n" " "'
someapp
check      "no second prompt for a while" "exit=1"                    eval 'waited 5 | tr "\n" " "'

if [ "$fails" -gt 0 ]; then
    echo "$fails check(s) failed; Kerberus said:"
    grep -av "DRI3\|accelerated rendering\|^kcm:" "$work/app.log" | sed 's/^/     /' | tail -20
    exit 1
fi
echo "all checks passed"
