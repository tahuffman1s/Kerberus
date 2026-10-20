#!/usr/bin/env python3
"""Kerberus: see, get, renew and destroy Kerberos tickets.

GUI by default (GTK 4 and libadwaita). Subcommands for the terminal:

    kerberus [--background]               open the window (or start hidden and keep renewing)
    kerberus list [--json]                show the credential caches and their tickets
    kerberus get PRINCIPAL [--keytab FILE] [--lifetime 10h] [--renewable 7d] [--remember]
    kerberus renew [PRINCIPAL | --all]    renew tickets
    kerberus destroy [PRINCIPAL | --all]  destroy tickets
    kerberus switch PRINCIPAL             make a principal's cache the default
    kerberus passwd [PRINCIPAL]           change a Kerberos password
    kerberus forget PRINCIPAL             remove a saved password from the keyring
    kerberus watch [--once] [--kcm]       renew in the terminal, without a window

It drives the MIT Kerberos tools (kinit, klist, kdestroy, kswitch, kpasswd), so it
uses the machine's krb5.conf and credential caches. The AppImage carries its own
copies of the tools for machines that don't have them installed.

With sign-in prompts turned on (Preferences), Kerberus is also the session's
credential cache: it serves the KCM protocol on a socket that every Kerberos
app is pointed at, so when an app (a browser doing Negotiate, smbclient, ssh)
needs a ticket and there isn't a valid one, Kerberus asks who to sign in as and
the app carries on once you have. It also stands in for Samba's ntlm_auth helper,
so Firefox's NTLM sign-ins (network.automatic-ntlm-auth.trusted-uris) are
answered the same way, with no winbind.
"""

import argparse
import base64
import binascii
import datetime as dt
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

APP_NAME = "Kerberus"
APP_ID = "io.github.tahuffman1s.Kerberus"
VERSION = "0.0.0-dev"  # the AppImage build stamps the release version here
WEBSITE = "https://github.com/tahuffman1s/kerberus"

CONFIG_HOME = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
SETTINGS_FILE = CONFIG_HOME / "kerberus" / "settings.json"
AUTOSTART_FILE = CONFIG_HOME / "autostart" / f"{APP_ID}.desktop"
DEFAULT_SETTINGS = {
    "auto_renew": True,       # renew TGTs before they expire
    "renew_before": 60,       # minutes
    "reacquire": True,        # sign in again with a saved password when renewing isn't possible
    "notify": True,           # warn before a ticket expires
    "notify_before": 15,      # minutes
    "background": True,       # keep running (and renewing) in the tray after the window is closed
    "kcm": False,             # be the session's credential cache and prompt when apps need a ticket
    "prompt_timeout": 120,    # seconds an app waits for you to sign in
    "ignored_apps": [],       # apps that never get a sign-in prompt
    "ntlm": True,             # answer NTLM sign-ins for apps that use Samba's ntlm_auth helper (Firefox)
    "ntlm_domain": "",        # the Windows domain sent with NTLM; "" is the first part of the realm
    "identities": [],         # principals signed in with before, most recent first
    "kcm_offer_dismissed": False,
    "last_principal": "",
    "lifetime": "",           # kinit -l; "" is the realm's default
    "renewable": "",          # kinit -r
    "forwardable": True,
}
LIFETIMES = [("Realm default", ""), ("1 hour", "1h"), ("4 hours", "4h"), ("8 hours", "8h"),
             ("10 hours", "10h"), ("1 day", "1d")]
RENEWABLE = [("Realm default", ""), ("1 day", "1d"), ("7 days", "7d"), ("30 days", "30d")]

TOOLS = ("kinit", "klist", "kdestroy", "kswitch", "kpasswd")
# What the AppImage's AppRun sets for the bundled Python and GTK. It saves the
# host's values as KERBERUS_HOST_<NAME>; the Kerberos tools get those back.
APPIMAGE_VARS = ("GI_TYPELIB_PATH", "GDK_PIXBUF_MODULE_FILE", "GSETTINGS_SCHEMA_DIR", "GSETTINGS_BACKEND",
                 "GIO_MODULE_DIR", "GTK_EXE_PREFIX", "XDG_DATA_DIRS")
# klist -f letters (MIT).
FLAG_NAMES = {
    "F": "forwardable", "f": "forwarded", "P": "proxiable", "p": "proxy", "D": "may be postdated",
    "d": "postdated", "R": "renewable", "I": "initial", "i": "invalid", "H": "hardware authenticated",
    "A": "pre-authenticated", "T": "transit policy checked", "O": "OK as delegate", "a": "anonymous",
}


# ---------------------------------------------------------------------------
# Settings


def load_settings():
    settings = dict(DEFAULT_SETTINGS)
    try:
        data = json.loads(SETTINGS_FILE.read_text())
        settings.update({k: v for k, v in data.items() if k in settings})
    except (OSError, ValueError, AttributeError):
        pass
    return settings


def save_settings(settings):
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(settings, indent=2, sort_keys=True) + "\n")


def launch_command():
    """How to start this app again: the AppImage, the installed command, or this script."""
    if os.environ.get("APPIMAGE"):
        return [os.environ["APPIMAGE"]]
    installed = shutil.which("kerberus")
    if installed:
        return [installed]
    return [sys.executable, str(Path(__file__).resolve())]


def desktop_quote(arg):
    if re.fullmatch(r"[\w@%+=:,./-]+", arg):
        return arg
    return '"' + re.sub(r'(["`$\\])', r"\\\1", arg) + '"'


def autostart_enabled():
    return AUTOSTART_FILE.exists()


def set_autostart(enabled):
    if not enabled:
        AUTOSTART_FILE.unlink(missing_ok=True)
        return
    command = " ".join(desktop_quote(a) for a in launch_command() + ["--background"])
    AUTOSTART_FILE.parent.mkdir(parents=True, exist_ok=True)
    AUTOSTART_FILE.write_text(
        "[Desktop Entry]\n"
        "Type=Application\n"
        f"Name={APP_NAME}\n"
        "Comment=Renew Kerberos tickets in the background\n"
        f"Exec={command}\n"
        f"Icon={APP_ID}\n"
        "Terminal=false\n"
        "NoDisplay=true\n"
        "X-GNOME-Autostart-enabled=true\n"
    )


# ---------------------------------------------------------------------------
# Running the Kerberos tools


def host_env():
    """The environment for the Kerberos tools: the host's, with dates and
    messages in the C locale so klist's output can be parsed, pointed at
    Kerberus's credential cache when that's turned on."""
    env = dict(os.environ)
    if env.pop("KERBERUS_APPDIR", None):
        for name in APPIMAGE_VARS:
            env.pop(name, None)
            saved = env.pop(f"KERBERUS_HOST_{name}", None)
            if saved is not None:
                env[name] = saved
    env.update(TOOLS_ENV)
    env["LC_ALL"] = "C"
    return env


TOOLS_ENV = {}  # set by use_kcm()


def find_tools():
    """Paths of the Kerberos tools: the host's, or the AppImage's copies when
    the host has none (or KERBERUS_TOOLS=bundled asks for them)."""
    choice = os.environ.get("KERBERUS_TOOLS", "")
    appdir = os.environ.get("KERBERUS_APPDIR")
    if choice != "bundled":
        host = {name: shutil.which(name) for name in TOOLS}
        if host["kinit"] and host["klist"]:
            return host, "host"
    if appdir and choice != "host":
        bundled = {name: str(Path(appdir) / "usr" / "bin" / name) for name in TOOLS}
        if all(os.access(p, os.X_OK) for p in bundled.values()):
            return bundled, "bundled"
    return {name: None for name in TOOLS}, None


TOOL_PATHS, TOOL_SOURCE = find_tools()
MISSING_TOOLS = ("The MIT Kerberos tools aren't installed. Install krb5-user (Debian, Ubuntu), "
                 "krb5-workstation (Fedora) or krb5 (Arch, NixOS).")


@dataclass
class Result:
    ok: bool
    message: str = ""
    password_expired: bool = False


def run_tool(name, *args, password_lines=None, timeout=60):
    """Run a Kerberos tool; returns a CompletedProcess (returncode 127 if it can't start).
    password_lines are written to its stdin, which kinit and kpasswd read prompts from."""
    path = TOOL_PATHS.get(name)
    argv = [path or name, *args]
    if not path:
        return subprocess.CompletedProcess(argv, 127, "", MISSING_TOOLS)
    stdin = "".join(line + "\n" for line in password_lines) if password_lines is not None else ""
    try:
        return subprocess.run(argv, input=stdin, capture_output=True, text=True, env=host_env(),
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", f"{name} timed out. Is the KDC reachable?")
    except OSError as e:
        return subprocess.CompletedProcess(argv, 127, "", f"{name}: {e.strerror}")


def tool_message(proc):
    """The useful part of a failed tool's output, without its prompts."""
    def meaningful(text):
        return [l.strip() for l in text.splitlines() if l.strip() and not l.rstrip().endswith(":")]
    lines = meaningful(proc.stderr) or meaningful(proc.stdout)
    message = " ".join(lines) or f"{Path(proc.args[0]).name} failed (exit code {proc.returncode})"
    message = re.sub(r"^k\w+: ", "", message)
    message = re.sub(r" while (getting|reading|finding|resolving|initializing|storing|retrieving)\b.*$", "", message)
    return message[:1].upper() + message[1:]


def result_of(proc, success=""):
    if proc.returncode == 0:
        return Result(True, success)
    expired = "Password expired" in proc.stdout + proc.stderr
    message = tool_message(proc)
    if expired:
        message = "The password has expired. Change it, then sign in with the new one."
    return Result(False, message, password_expired=expired)


# ---------------------------------------------------------------------------
# Tickets


@dataclass
class Ticket:
    service: str
    starts: dt.datetime
    expires: dt.datetime
    renew_until: dt.datetime | None = None
    flags: str = ""

    @property
    def is_tgt(self):
        return self.service.startswith("krbtgt/")

    def describe_flags(self):
        return ", ".join(FLAG_NAMES.get(f, f) for f in self.flags)


@dataclass
class Cache:
    name: str
    principal: str
    tickets: list = field(default_factory=list)
    default: bool = False

    @property
    def realm(self):
        return self.principal.rpartition("@")[2]

    @property
    def tgt(self):
        """The ticket-granting ticket for the principal's own realm (or the first ticket)."""
        own = f"krbtgt/{self.realm}@{self.realm}"
        for t in self.tickets:
            if t.service == own:
                return t
        return next((t for t in self.tickets if t.is_tgt), self.tickets[0] if self.tickets else None)

    @property
    def services(self):
        tgt = self.tgt
        return [t for t in self.tickets if t is not tgt]

    def can_renew(self, now):
        """True if `kinit -R` would push the TGT's expiry later."""
        t = self.tgt
        if not t or not t.renew_until or (t.flags and "R" not in t.flags):
            return False
        return t.renew_until > now and t.renew_until > t.expires

    def state(self, now, warn_minutes=15):
        t = self.tgt
        if t is None or t.expires <= now:
            return "expired"
        if (t.expires - now).total_seconds() < warn_minutes * 60:
            return "expiring"
        return "valid"

    def to_json(self, now):
        def iso(t):
            return t.isoformat() if t else None
        return {
            "principal": self.principal,
            "cache": self.name,
            "default": self.default,
            "state": self.state(now),
            "renewable": self.can_renew(now),
            "tickets": [{"service": t.service, "starts": iso(t.starts), "expires": iso(t.expires),
                         "renew_until": iso(t.renew_until), "flags": t.flags} for t in self.tickets],
        }


# klist prints local times with strftime("%x %X"); the C locale makes that this.
TIME_FORMATS = ("%m/%d/%y %H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%d %b %Y %H:%M:%S")
TICKET_RE = re.compile(r"^(\S+ \S+)\s+(\S+ \S+)\s+(\S+)$")
RENEW_RE = re.compile(r"renew until (\S+ \S+?)(?:,|$)")
FLAGS_RE = re.compile(r"Flags: (\S+)")


def parse_time(text):
    for fmt in TIME_FORMATS:
        try:
            return dt.datetime.strptime(text.strip(), fmt)
        except ValueError:
            pass
    return None


def parse_klist(text):
    """Caches from `klist -A -f` (MIT, C locale)."""
    caches = []
    cache = None
    for line in text.splitlines():
        if line.startswith("Ticket cache:"):
            cache = Cache(name=line.split(":", 1)[1].strip(), principal="")
            caches.append(cache)
        elif cache is None or not line.strip():
            continue
        elif line.startswith("Default principal:"):
            cache.principal = line.split(":", 1)[1].strip()
        elif line[0].isspace():
            # "renew until ..., Flags: FRI" belongs to the ticket above it.
            if cache.tickets:
                ticket = cache.tickets[-1]
                if m := RENEW_RE.search(line):
                    ticket.renew_until = parse_time(m.group(1))
                if m := FLAGS_RE.search(line):
                    ticket.flags = m.group(1)
        elif m := TICKET_RE.match(line):
            starts, expires = parse_time(m.group(1)), parse_time(m.group(2))
            if starts and expires:
                cache.tickets.append(Ticket(m.group(3), starts, expires))
    return [c for c in caches if c.principal]


class ToolsMissing(Exception):
    pass


def list_caches():
    """Every credential cache in the collection, the default one first."""
    if not TOOL_PATHS["klist"]:
        raise ToolsMissing(MISSING_TOOLS)
    m = re.search(r"^Ticket cache: (.+)$", run_tool("klist").stdout, re.M)
    default = m.group(1).strip() if m else None
    caches = parse_klist(run_tool("klist", "-A", "-f").stdout)
    for cache in caches:
        cache.default = cache.name == default
    caches.sort(key=lambda c: (not c.default, c.principal.lower()))
    return caches


def default_realm():
    for path in os.environ.get("KRB5_CONFIG", "/etc/krb5.conf").split(":"):
        try:
            m = re.search(r"^\s*default_realm\s*=\s*(\S+)", Path(path).read_text(), re.M)
        except OSError:
            continue
        if m:
            return m.group(1)
    return ""


def full_principal(name):
    """alice -> alice@DEFAULT.REALM"""
    name = name.strip()
    if "@" in name or not name:
        return name
    realm = default_realm()
    return f"{name}@{realm}" if realm else name


def find_cache(caches, principal):
    if not principal:
        return next((c for c in caches if c.default), caches[0] if caches else None)
    full = full_principal(principal)
    for cache in caches:
        if cache.principal in (principal, full) or cache.principal.lower() == full.lower():
            return cache
    return None


def get_ticket(principal, password=None, keytab=None, lifetime="", renewable="", forwardable=None, cache=None):
    args = []
    if lifetime:
        args += ["-l", lifetime]
    if renewable:
        args += ["-r", renewable]
    if forwardable is not None:
        args.append("-f" if forwardable else "-F")
    if cache:
        args += ["-c", cache]
    if keytab:
        args += ["-k", "-t", keytab]
    args.append(principal)
    proc = run_tool("kinit", *args, password_lines=None if keytab else [password or ""])
    return result_of(proc, f"Signed in as {principal}")


def ticket_options(settings):
    return {"lifetime": settings["lifetime"], "renewable": settings["renewable"],
            "forwardable": settings["forwardable"]}


def renew(cache):
    return result_of(run_tool("kinit", "-R", "-c", cache.name), f"Renewed the ticket for {cache.principal}")


def destroy(cache):
    return result_of(run_tool("kdestroy", "-c", cache.name), f"Destroyed the tickets for {cache.principal}")


def destroy_all():
    return result_of(run_tool("kdestroy", "-A"), "Destroyed all tickets")


def switch(cache):
    return result_of(run_tool("kswitch", "-c", cache.name), f"{cache.principal} is now the default")


def change_password(principal, old, new):
    return result_of(run_tool("kpasswd", principal, password_lines=[old, new, new]), "Password changed")


def tools_version():
    proc = run_tool("klist", "-V")
    return proc.stdout.strip() if proc.returncode == 0 else "unknown"


# ---------------------------------------------------------------------------
# Saved passwords


class Keyring:
    """Passwords saved in the Secret Service (GNOME Keyring, KWallet), one per principal."""

    def __init__(self):
        self.secret = None
        self.lock = threading.Lock()
        try:
            import gi
            gi.require_version("Secret", "1")
            from gi.repository import Secret
        except (ImportError, ValueError):
            return
        self.secret = Secret
        self.schema = Secret.Schema.new(APP_ID, Secret.SchemaFlags.NONE,
                                        {"principal": Secret.SchemaAttributeType.STRING})

    @property
    def available(self):
        return self.secret is not None

    def lookup(self, principal):
        if not self.secret:
            return None
        try:
            with self.lock:
                return self.secret.password_lookup_sync(self.schema, {"principal": principal}, None)
        except Exception:  # GLib.Error: no Secret Service, locked and dismissed, ...
            return None

    def store(self, principal, password):
        """Returns an error message, or "" when saved."""
        if not self.secret:
            return "No keyring library (libsecret) available"
        try:
            with self.lock:
                self.secret.password_store_sync(self.schema, {"principal": principal}, self.secret.COLLECTION_DEFAULT,
                                                f"Kerberos password for {principal}", password, None)
            return ""
        except Exception as e:
            return getattr(e, "message", str(e))

    def forget(self, principal):
        if not self.secret:
            return False
        try:
            with self.lock:
                return self.secret.password_clear_sync(self.schema, {"principal": principal}, None)
        except Exception:
            return False

    def principals(self):
        if not self.secret:
            return []
        try:
            with self.lock:
                items = self.secret.password_search_sync(self.schema, {}, self.secret.SearchFlags.ALL, None)
        except Exception:
            return []
        return sorted({i.get_attributes().get("principal") for i in items} - {None})


# ---------------------------------------------------------------------------
# Background renewal, shared by the window and `kerberus watch`


def renewal_action(cache, settings, now, has_password):
    """"renew", "sign-in" or None for a cache's TGT."""
    t = cache.tgt
    if t is None:
        return None
    left = (t.expires - now).total_seconds()
    lifetime = max((t.expires - t.starts).total_seconds(), 120)
    # Short-lived tickets are renewed half way through, not every check.
    ahead = min(settings["renew_before"] * 60, lifetime / 2)
    if left >= ahead:
        return None
    if settings["auto_renew"] and cache.can_renew(now):
        return "renew"
    if settings["reacquire"] and has_password:
        return "sign-in"
    return None


def fmt_duration(seconds):
    minutes = int(abs(seconds)) // 60
    if minutes < 1:
        return "less than a minute"
    if minutes < 60:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours} h {minutes} min" if minutes else f"{hours} h"
    days, hours = divmod(hours, 24)
    return f"{days} day{'s' if days != 1 else ''}" + (f" {hours} h" if hours else "")


def fmt_when(t, now):
    if t.date() == now.date():
        return t.strftime("%H:%M")
    if t.date() == (now + dt.timedelta(days=1)).date():
        return t.strftime("tomorrow %H:%M")
    if t.date() == (now - dt.timedelta(days=1)).date():
        return t.strftime("yesterday %H:%M")
    if abs((t - now).days) < 6:
        return t.strftime("%a %H:%M")
    return f"{t:%b} {t.day}, {t:%H:%M}" + (f" {t.year}" if t.year != now.year else "")


def expiry_text(cache, now):
    t = cache.tgt
    if t is None or t.expires <= now:
        return f"The Kerberos ticket for {cache.principal} has expired."
    return f"The Kerberos ticket for {cache.principal} expires in {fmt_duration((t.expires - now).total_seconds())}."


def maintain(caches, settings, keyring=None, now=None, log=print, failed=None):
    """Renew TGTs that are about to expire, sign in again with a saved password
    when they can't be renewed, and return (cache, text, key) for what the user
    should hear about. Principals whose saved password was rejected go into
    `failed` and aren't tried again, so the account doesn't get locked out."""
    now = now or dt.datetime.now()
    failed = failed if failed is not None else set()
    saved = set(keyring.principals()) - failed if keyring and settings["reacquire"] else set()
    notices = []
    for cache in caches:
        t = cache.tgt
        if t is None:
            continue
        has_password = cache.principal in saved
        action = renewal_action(cache, settings, now, has_password)
        if action == "renew":
            r = renew(cache)
            if r.ok:
                log(r.message)
                continue
            log(f"Could not renew the ticket for {cache.principal}: {r.message}")
            action = "sign-in" if has_password else None
        if action == "sign-in":
            password = keyring.lookup(cache.principal)
            r = (get_ticket(cache.principal, password, cache=cache.name, **ticket_options(settings))
                 if password is not None else Result(False, "the keyring didn't return it"))
            if r.ok:
                log(f"Signed in again as {cache.principal} with the saved password")
                continue
            failed.add(cache.principal)
            log(f"Could not sign in again as {cache.principal}: {r.message}")
            notices.append((cache, f"The saved password for {cache.principal} didn't work: {r.message}",
                            ("rejected", cache.principal)))
            continue
        if settings["notify"] and (t.expires - now).total_seconds() < settings["notify_before"] * 60:
            notices.append((cache, expiry_text(cache, now), (cache.principal, t.expires, t.expires <= now)))
    return notices


# ---------------------------------------------------------------------------
# Kerberus as the credential cache (KCM)
#
# MIT Kerberos's KCM: cache type keeps credentials in a daemon reached over a
# Unix socket. Pointing the session's apps at Kerberus's socket (KRB5CCNAME=KCM:
# plus a krb5.conf naming the socket, set through environment.d) means every
# app that needs a ticket asks Kerberus first, which is how it knows to ask you
# to sign in. The protocol is the subset MIT's client speaks (src/include/kcm.h
# and src/lib/krb5/ccache/cc_kcm.c in krb5): requests are a 4-byte length, the
# version (2, 0), a 16-bit opcode and parameters; replies are a length, a
# transport code and the payload, which starts with a krb5 error code.
# Principals and credentials use the v4 FILE ccache layout and are kept as the
# client sent them.

RUNTIME_DIR = Path(os.environ.get("XDG_RUNTIME_DIR") or f"/tmp/kerberus-{os.getuid()}") / "kerberus"
KCM_SOCKET = RUNTIME_DIR / "kcm.sock"
KCM_STATE = RUNTIME_DIR / "caches.json"  # tmpfs like /tmp/krb5cc_*; survives a restart, not a logout
KCM_KRB5_CONF = CONFIG_HOME / "kerberus" / "krb5.conf"
ENVIRONMENT_D = CONFIG_HOME / "environment.d" / "60-kerberus.conf"

(KCM_OP_NOOP, KCM_OP_GEN_NEW, KCM_OP_INITIALIZE, KCM_OP_DESTROY, KCM_OP_STORE, KCM_OP_GET_PRINCIPAL,
 KCM_OP_GET_CRED_UUID_LIST, KCM_OP_GET_CRED_BY_UUID, KCM_OP_GET_CACHE_UUID_LIST, KCM_OP_GET_CACHE_BY_UUID,
 KCM_OP_GET_DEFAULT_CACHE, KCM_OP_SET_DEFAULT_CACHE, KCM_OP_GET_KDC_OFFSET, KCM_OP_SET_KDC_OFFSET,
 KCM_OP_GET_CRED_LIST, KCM_OP_REPLACE) = (0, 3, 4, 5, 6, 8, 9, 10, 18, 19, 20, 21, 22, 23, 13001, 13002)
# What an app asks just before it needs a ticket; the moment to prompt.
KCM_TICKET_OPS = {KCM_OP_GET_PRINCIPAL, KCM_OP_GET_CRED_LIST, KCM_OP_GET_CRED_UUID_LIST, KCM_OP_GET_CACHE_UUID_LIST}
KRB5_CC_END = -1765328242
KRB5_CC_IO = -1765328191
KRB5_FCC_NOFILE = -1765328189
KRB5_CC_FORMAT = -1765328185
KRB5_CC_NOSUPP = -1765328137  # the client falls back (RETRIEVE) or reports it (REMOVE_CRED, only kdeltkt)
# Programs that look at caches without needing a ticket from you: the Kerberos
# tools themselves and desktop services that watch the collection.
DEBUG = bool(os.environ.get("KERBERUS_DEBUG"))  # log each KCM request
QUIET_PROGRAMS = {"klist", "kinit", "kdestroy", "kswitch", "kpasswd", "ktutil", "kadmin", "kerberus",
                  "goa-identity-service", "goa-daemon", "realmd", "sssd", "gssproxy"}


class KcmReader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError("truncated request")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u16(self):
        return struct.unpack(">H", self.take(2))[0]

    def u32(self):
        return struct.unpack(">I", self.take(4))[0]

    def i32(self):
        return struct.unpack(">i", self.take(4))[0]

    def counted(self):
        return self.take(self.u32())

    def name(self):
        end = self.data.find(b"\0", self.pos)
        if end < 0:
            raise ValueError("unterminated name")
        return self.take(end - self.pos + 1)[:-1].decode("utf-8", "replace")

    def principal(self):
        """(raw bytes, "a/b@REALM")"""
        start = self.pos
        self.u32()  # name type
        count = self.u32()
        realm = self.counted().decode("utf-8", "replace")
        parts = [self.counted().decode("utf-8", "replace") for _ in range(count)]
        return self.data[start:self.pos], "/".join(parts) + "@" + realm

    def rest(self):
        return self.take(len(self.data) - self.pos)


@dataclass
class KcmCred:
    raw: bytes
    uuid: bytes
    client: str
    server: str
    starttime: int
    endtime: int
    renew_till: int

    @classmethod
    def parse(cls, raw, uuid=None):
        r = KcmReader(raw)
        _, client = r.principal()
        _, server = r.principal()
        r.u16()  # session key type
        r.counted()
        authtime, starttime, endtime, renew_till = r.u32(), r.u32(), r.u32(), r.u32()
        r.take(1)  # is_skey
        r.u32()  # ticket flags
        for _ in range(r.u32()):  # addresses
            r.u16()
            r.counted()
        for _ in range(r.u32()):  # authorization data
            r.u16()
            r.counted()
        r.counted()  # ticket
        r.counted()  # second ticket
        if r.pos != len(raw):
            raise ValueError("trailing bytes after a credential")
        return cls(raw, uuid or secrets.token_bytes(16), client, server, starttime or authtime, endtime, renew_till)


@dataclass
class KcmCache:
    name: str
    uuid: bytes = field(default_factory=lambda: secrets.token_bytes(16))
    principal: bytes | None = None
    principal_name: str = ""
    creds: list = field(default_factory=list)
    kdc_offset: int = 0

    def tgt_end(self):
        """When the TGT for the principal's realm expires (0 if there isn't one)."""
        realm = self.principal_name.rpartition("@")[2]
        own = f"krbtgt/{realm}@{realm}"
        return max((c.endtime for c in self.creds if c.server == own), default=0)

    def valid(self, now=None):
        return self.tgt_end() > (now or time.time()) + 30


class KcmStore:
    """The credential caches Kerberus serves, saved to the runtime directory."""

    def __init__(self, path=None, uid=None):
        self.lock = threading.RLock()
        self.path = path
        self.primary = str(os.getuid() if uid is None else uid)
        self.caches = {}
        self.default = self.primary
        self.changed = None  # called (outside the lock) after any change
        if path:
            self.load()

    def load(self):
        try:
            data = json.loads(self.path.read_text())
            for c in data["caches"]:
                cache = KcmCache(c["name"], bytes.fromhex(c["uuid"]), kdc_offset=c.get("kdc_offset", 0))
                if c.get("principal"):
                    cache.principal = base64.b64decode(c["principal"])
                    cache.principal_name = KcmReader(cache.principal).principal()[1]
                cache.creds = [KcmCred.parse(base64.b64decode(raw)) for raw in c["creds"]]
                self.caches[cache.name] = cache
            self.default = data.get("default") or self.primary
        except (OSError, ValueError, KeyError, TypeError):
            pass

    def save(self):
        if not self.path:
            return
        data = {"default": self.default, "caches": [
            {"name": c.name, "uuid": c.uuid.hex(), "kdc_offset": c.kdc_offset,
             "principal": base64.b64encode(c.principal).decode() if c.principal else None,
             "creds": [base64.b64encode(cred.raw).decode() for cred in c.creds]}
            for c in self.caches.values()]}
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp, self.path)

    def needs_sign_in(self, name=None):
        """True if the named cache (or, with no name, the whole collection) has no valid TGT."""
        with self.lock:
            if name is None:
                return not any(c.valid() for c in self.caches.values())
            cache = self.caches.get(name)
            return cache is None or not cache.valid()

    def describe(self, name):
        """(principal, default cache name) for prompting about a cache."""
        with self.lock:
            name = name or self.default
            cache = self.caches.get(name)
            return (cache.principal_name if cache else ""), name

    def handle(self, opcode, r):
        """Run one request; returns (krb5 error code, reply bytes)."""
        with self.lock:
            status, reply, changed = self._handle(opcode, r)
            if changed:
                self.save()
        if changed and self.changed:
            self.changed()
        return status, reply

    def _cache(self, r):
        name = r.name()
        return name, self.caches.get(name)

    def _handle(self, op, r):
        if op == KCM_OP_NOOP:
            return 0, b"", False
        if op == KCM_OP_GET_DEFAULT_CACHE:
            return 0, self.default.encode() + b"\0", False
        if op == KCM_OP_SET_DEFAULT_CACHE:
            self.default = r.name()
            return 0, b"", True
        if op == KCM_OP_GEN_NEW:
            name = f"{self.primary}:{secrets.token_hex(4)}"
            self.caches[name] = KcmCache(name)
            return 0, name.encode() + b"\0", True
        if op == KCM_OP_GET_CACHE_UUID_LIST:
            uuids = [c.uuid for c in self.caches.values() if c.principal]
            return (0, b"".join(uuids), False) if uuids else (KRB5_FCC_NOFILE, b"", False)
        if op == KCM_OP_GET_CACHE_BY_UUID:
            uuid = r.take(16)
            cache = next((c for c in self.caches.values() if c.uuid == uuid), None)
            return (0, cache.name.encode() + b"\0", False) if cache else (KRB5_CC_END, b"", False)
        if op in (KCM_OP_INITIALIZE, KCM_OP_REPLACE):
            name, cache = self._cache(r)
            cache = cache or KcmCache(name)
            offset = r.i32() if op == KCM_OP_REPLACE else cache.kdc_offset
            principal, principal_name = r.principal()
            creds = [KcmCred.parse(r.counted()) for _ in range(r.u32())] if op == KCM_OP_REPLACE else []
            cache.principal, cache.principal_name, cache.creds, cache.kdc_offset = (
                principal, principal_name, creds, offset)
            self.caches[name] = cache
            return 0, b"", True

        name, cache = self._cache(r)
        if cache is None:
            return KRB5_FCC_NOFILE, b"", False
        if op == KCM_OP_DESTROY:
            del self.caches[name]
            return 0, b"", True
        if op == KCM_OP_GET_PRINCIPAL:
            return (0, cache.principal, False) if cache.principal else (KRB5_FCC_NOFILE, b"", False)
        if op == KCM_OP_STORE:
            cred = KcmCred.parse(r.rest())
            # A newer ticket for the same service replaces the old one.
            cache.creds = [c for c in cache.creds if (c.client, c.server) != (cred.client, cred.server)]
            cache.creds.append(cred)
            return 0, b"", True
        if op == KCM_OP_GET_CRED_LIST:
            body = b"".join(struct.pack(">I", len(c.raw)) + c.raw for c in cache.creds)
            return 0, struct.pack(">I", len(cache.creds)) + body, False
        if op == KCM_OP_GET_CRED_UUID_LIST:
            return 0, b"".join(c.uuid for c in cache.creds), False
        if op == KCM_OP_GET_CRED_BY_UUID:
            uuid = r.take(16)
            cred = next((c for c in cache.creds if c.uuid == uuid), None)
            return (0, cred.raw, False) if cred else (KRB5_CC_END, b"", False)
        if op == KCM_OP_GET_KDC_OFFSET:
            return 0, struct.pack(">i", cache.kdc_offset), False
        if op == KCM_OP_SET_KDC_OFFSET:
            cache.kdc_offset = r.i32()
            return 0, b"", True
        return KRB5_CC_NOSUPP, b"", False


@dataclass
class KcmClient:
    """The process on the other end of a KCM connection."""
    pid: int
    program: str = ""
    quiet: bool = True

    @classmethod
    def from_pid(cls, pid):
        try:
            exe = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            exe = ""
        program = program_name(exe) or "unknown"
        return cls(pid, program, program in QUIET_PROGRAMS or descends_from(pid, os.getpid()))


def program_name(path):
    """What to call an executable: NixOS wraps programs as .name-wrapped, and
    Debian installs the Kerberos tools as klist.mit behind alternatives."""
    return re.sub(r"^\.|-wrapped$|-bin$|\.(mit|heimdal)$", "", os.path.basename(path))


def others_can_replace(parent, uid=None):
    """True if someone else could rename entries in a directory with this stat:
    it isn't ours, isn't sticky (like /tmp), and others can write to it."""
    uid = os.getuid() if uid is None else uid
    return parent.st_uid != uid and not parent.st_mode & 0o1000 and bool(parent.st_mode & 0o022)


def parent_pid(pid):
    """The parent of a process, or 0."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            return int(f.read().rpartition(")")[2].split()[1])
    except (OSError, ValueError, IndexError):
        return 0


def descends_from(pid, ancestor):
    for _ in range(64):
        if pid == ancestor:
            return True
        if pid <= 1:
            return False
        pid = parent_pid(pid)
    return False


def peer_of(conn):
    """(pid, uid) of the process on the other end of a Unix socket."""
    pid, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
    return pid, uid


class UnixServer:
    """A Unix socket in the runtime directory, served one thread per connection."""

    name = "socket"

    def __init__(self, path, log=print):
        self.path, self.log = Path(path), log
        self.sock = None

    def start(self):
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Apps trust whatever answers on this socket with their tickets, so its
        # directory must be ours, and nobody else may be able to swap that
        # directory out: its parent must be ours, sticky like /tmp, or not
        # writable by others. (The /tmp fallback could be someone else's.)
        directory = self.path.parent
        if directory.stat().st_uid != os.getuid() or others_can_replace(directory.parent.stat()):
            raise RuntimeError(f"{directory} could be replaced by another user")
        os.chmod(directory, 0o700)
        if self.path.exists():
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.connect(str(self.path))
                raise RuntimeError(f"another Kerberus is already serving {self.path}")
            except (ConnectionRefusedError, FileNotFoundError):
                self.path.unlink(missing_ok=True)
            finally:
                probe.close()
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(str(self.path))
        os.chmod(self.path, 0o600)
        self.sock.listen(32)
        threading.Thread(target=self.accept_loop, daemon=True, name=f"{self.name}-accept").start()

    def stop(self):
        if self.sock:
            self.sock.close()
            self.sock = None
            self.path.unlink(missing_ok=True)

    def accept_loop(self):
        while self.sock:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(conn,), daemon=True, name=f"{self.name}-client").start()

    def serve(self, conn):
        raise NotImplementedError


class KcmServer(UnixServer):
    """Serves a KcmStore on a Unix socket.

    need_ticket(client, cache_name) is called, on that connection's thread,
    when an app asks for a cache without a valid TGT; the request waits until it
    returns, so a ticket you sign in for answers the request that asked."""

    name = "kcm"

    def __init__(self, store, path=KCM_SOCKET, need_ticket=None, log=print):
        super().__init__(path, log)
        self.store, self.need_ticket = store, need_ticket

    @staticmethod
    def recv_exact(conn, n):
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise EOFError
            data += chunk
        return data

    def serve(self, conn):
        with conn:
            pid, uid = peer_of(conn)
            if uid != os.getuid():
                return
            client = None
            try:
                while True:
                    length = struct.unpack(">I", self.recv_exact(conn, 4))[0]
                    if length < 4 or length > 10 * 1024 * 1024:
                        return
                    request = self.recv_exact(conn, length)
                    opcode = struct.unpack(">H", request[2:4])[0]
                    if DEBUG:
                        client = client or KcmClient.from_pid(pid)
                        self.log(f"kcm: {client.program}[{pid}] op {opcode} {request[4:60]!r}")
                    if self.need_ticket and opcode in KCM_TICKET_OPS:
                        name = None
                        if opcode != KCM_OP_GET_CACHE_UUID_LIST:
                            end = request.find(b"\0", 4)
                            name = request[4:end].decode("utf-8", "replace") if end > 0 else None
                        if self.store.needs_sign_in(name):
                            client = client or KcmClient.from_pid(pid)
                            if not client.quiet:
                                self.need_ticket(client, name)
                    try:
                        status, reply = self.store.handle(opcode, KcmReader(request[4:]))
                    except (ValueError, struct.error) as e:
                        self.log(f"Bad KCM request (opcode {opcode}) from pid {pid}: {e}")
                        status, reply = KRB5_CC_FORMAT, b""
                    payload = struct.pack(">i", status) + reply
                    conn.sendall(struct.pack(">II", len(payload), 0) + payload)
            except (EOFError, ConnectionError, OSError):
                return


def recover_quietly(principal, cache, settings, keyring=None, failed=None):
    """Give a KCM cache a valid ticket for its principal without asking: renew
    it, or sign in again with the saved password. True if that worked. A saved
    password the KDC rejects goes into `failed` and isn't tried again."""
    ccname = f"KCM:{cache}"
    if settings["auto_renew"] and result_of(run_tool("kinit", "-R", "-c", ccname)).ok:
        return True
    if keyring is None or not settings["reacquire"] or principal in (failed or ()):
        return False
    password = keyring.lookup(principal)
    if password is None:
        return False
    if get_ticket(principal, password, cache=ccname, **ticket_options(settings)).ok:
        return True
    if failed is not None:
        failed.add(principal)
    return False


def base_krb5_config():
    """The krb5.conf files apps would read without Kerberus."""
    ours = str(KCM_KRB5_CONF)
    paths = [p for p in os.environ.get("KRB5_CONFIG", "/etc/krb5.conf").split(":") if p and p != ours]
    return ":".join(paths) or "/etc/krb5.conf"


def kcm_env():
    return {"KRB5CCNAME": "KCM:", "KRB5_CONFIG": f"{KCM_KRB5_CONF}:{base_krb5_config()}"}


def use_kcm(enabled):
    """Point the Kerberos tools Kerberus runs at its own cache (or not)."""
    TOOLS_ENV.clear()
    if enabled:
        write_kcm_config()
        TOOLS_ENV.update(kcm_env())


def write_kcm_config():
    """The krb5.conf apps read first: it only names Kerberus's socket, and the
    files after it in KRB5_CONFIG supply the realms."""
    KCM_KRB5_CONF.parent.mkdir(parents=True, exist_ok=True)
    KCM_KRB5_CONF.write_text(
        "# Written by Kerberus. Apps read this before the system's krb5.conf (see KRB5_CONFIG)\n"
        "# so that their tickets live in Kerberus, which asks you to sign in when they need one.\n"
        "[libdefaults]\n"
        "    default_ccache_name = KCM:\n"
        f"    kcm_socket = {KCM_SOCKET}\n"
    )


def session_kcm_enabled():
    return ENVIRONMENT_D.exists()


def session_setup_current():
    """False if the environment.d file predates the ntlm_auth helper (or is gone)."""
    try:
        return "PATH=" in ENVIRONMENT_D.read_text()
    except OSError:
        return False


def session_path(with_helper):
    """The session's PATH as the systemd user manager has it (or ours), with
    Kerberus's helper directory first, or taken out (None if it isn't there)."""
    current = os.environ.get("PATH", "")
    if shutil.which("systemctl"):
        proc = subprocess.run(["systemctl", "--user", "show-environment"], env=host_env(),
                              capture_output=True, text=True, check=False)
        for line in proc.stdout.splitlines() if proc.returncode == 0 else []:
            if line.startswith("PATH="):
                try:
                    current = shlex.split(line)[0].partition("=")[2]
                except ValueError:
                    pass
    parts = [d for d in current.split(":") if d]
    if not with_helper and str(HELPER_DIR) not in parts:
        return None
    parts = [d for d in parts if d != str(HELPER_DIR)]
    return ":".join([str(HELPER_DIR)] * with_helper + parts)


def set_session_kcm(enabled):
    """Make the session's apps use Kerberus's cache (and its ntlm_auth) from the
    next login (environment.d), and tell the running systemd user manager and
    D-Bus activation environment now."""
    if enabled:
        write_kcm_config()
        write_ntlm_helper()
        env = kcm_env()
        ENVIRONMENT_D.parent.mkdir(parents=True, exist_ok=True)
        ENVIRONMENT_D.write_text(
            "# Written by Kerberus (Preferences → Sign-In Prompts): Kerberos apps keep their\n"
            "# tickets in Kerberus, which asks you to sign in when one needs a ticket, and apps\n"
            "# that do NTLM through Samba's ntlm_auth helper (Firefox) find Kerberus's instead.\n"
            + "".join(f"{k}={v}\n" for k, v in env.items())
            + f"PATH={HELPER_DIR}${{PATH:+:$PATH}}\n")
        assignments = [f"{k}={v}" for k, v in env.items()] + [f"PATH={session_path(True)}"]
        commands = [["systemctl", "--user", "set-environment", *assignments],
                    ["dbus-update-activation-environment", *assignments]]
    else:
        ENVIRONMENT_D.unlink(missing_ok=True)
        commands = [["systemctl", "--user", "unset-environment", "KRB5CCNAME", "KRB5_CONFIG"]]
        path = session_path(False)
        if path is not None:
            commands += [["systemctl", "--user", "set-environment", f"PATH={path}"],
                         ["dbus-update-activation-environment", f"PATH={path}"]]
    for argv in commands:
        if shutil.which(argv[0]):
            subprocess.run(argv, env=host_env(), capture_output=True, check=False)


# ---------------------------------------------------------------------------
# NTLM, for apps that use Samba's ntlm_auth helper
#
# Windows sign-in ("Negotiate") falls back to NTLM when Kerberos doesn't work
# out (no ticket to be had, a service without an SPN, a server that only
# speaks NTLM), and browsers do NTLM by themselves: nothing goes through a
# credential cache for Kerberus to see. Firefox is the exception: for sites in
# network.automatic-ntlm-auth.trusted-uris it runs Samba's
# `ntlm_auth --helper-protocol ntlmssp-client-1` from PATH and lets that do the
# handshake (so that winbind's credentials get used), and only asks for a
# password itself when that fails. Kerberus puts an ntlm_auth of its own first
# in the session's PATH (environment.d, next to KRB5CCNAME). It relays the
# helper protocol to the socket below, where Kerberus answers with NTLMv2
# messages (MS-NLMP) for the identity you choose, asking just as it does for a
# Kerberos ticket, and signing you in to Kerberos with the same password.
#
# The helper protocol is line based: "YR" asks for the NEGOTIATE message
# ("YR <base64>"), "TT <base64 CHALLENGE>" gets the AUTHENTICATE message
# ("AF <base64>"), and "BH <why>" says the helper can't.

NTLM_SOCKET = RUNTIME_DIR / "ntlm.sock"
HELPER_DIR = CONFIG_HOME / "kerberus" / "bin"
NTLM_HELPER = HELPER_DIR / "ntlm_auth"
NTLM_HELPER_SCRIPT = r'''#!/usr/bin/env python3
"""Written by Kerberus. Stands in for Samba's ntlm_auth, as far as Firefox uses
it: the ntlmssp-client-1 helper protocol is relayed to Kerberus, which does the
NTLM handshake for the identity you choose. When Kerberus isn't serving, the
real ntlm_auth (if there is one) gets the request instead."""
import os
import socket
import sys


def hand_over():
    me = os.path.realpath(__file__)
    for directory in os.environ.get("PATH", "").split(":"):
        path = os.path.join(directory, "ntlm_auth")
        if directory and os.path.realpath(path) != me and os.access(path, os.X_OK):
            os.execv(path, [path] + sys.argv[1:])
    sys.stdout.write("BH Kerberus isn't running\n")
    sys.stdout.flush()
    sys.exit(1)


protocol = ""
for i, arg in enumerate(sys.argv):
    if arg.startswith("--helper-protocol="):
        protocol = arg.partition("=")[2]
    elif arg == "--helper-protocol" and i + 1 < len(sys.argv):
        protocol = sys.argv[i + 1]
if protocol != "ntlmssp-client-1":
    hand_over()
runtime = os.environ.get("XDG_RUNTIME_DIR") or "/tmp/kerberus-%d" % os.getuid()
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    sock.connect(os.path.join(runtime, "kerberus", "ntlm.sock"))
except OSError:
    hand_over()
replies = sock.makefile("rb")
while True:
    line = sys.stdin.buffer.readline()
    if not line:
        break
    sock.sendall(line.rstrip(b"\r\n") + b"\n")
    reply = replies.readline() or b"BH Kerberus went away\n"
    sys.stdout.buffer.write(reply)
    sys.stdout.buffer.flush()
'''


def write_ntlm_helper(path=NTLM_HELPER):
    path = Path(path)
    try:
        if path.read_text() == NTLM_HELPER_SCRIPT and path.stat().st_mode & 0o111:
            return
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(NTLM_HELPER_SCRIPT)
    os.chmod(tmp, 0o755)
    os.replace(tmp, path)


def md4(data):
    """MD4 (RFC 1320); OpenSSL 3 no longer gives it to hashlib."""
    def rotl(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    data = bytes(data)
    msg = data + b"\x80" + b"\0" * ((55 - len(data)) % 64) + struct.pack("<Q", len(data) * 8)
    for off in range(0, len(msg), 64):
        x = struct.unpack("<16I", msg[off:off + 64])
        aa, bb, cc, dd = a, b, c, d
        for i in range(16):
            f = (b & c) | (~b & d)
            a, d, c, b = d, c, b, rotl((a + f + x[i]) & 0xFFFFFFFF, (3, 7, 11, 19)[i % 4])
        for i in range(16):
            g = (b & c) | (b & d) | (c & d)
            a, d, c, b = d, c, b, rotl((a + g + x[(i % 4) * 4 + i // 4] + 0x5A827999) & 0xFFFFFFFF, (3, 5, 9, 13)[i % 4])
        for i in range(16):
            k = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15)[i]
            a, d, c, b = d, c, b, rotl((a + (b ^ c ^ d) + x[k] + 0x6ED9EBA1) & 0xFFFFFFFF, (3, 9, 11, 15)[i % 4])
        a, b, c, d = (a + aa) & 0xFFFFFFFF, (b + bb) & 0xFFFFFFFF, (c + cc) & 0xFFFFFFFF, (d + dd) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d)


NTLMSSP = b"NTLMSSP\0"
NTLM_UNICODE, NTLM_OEM, NTLM_REQUEST_TARGET, NTLM_NTLM, NTLM_ALWAYS_SIGN = 0x1, 0x2, 0x4, 0x200, 0x8000
NTLM_EXTENDED_SESSION_SECURITY, NTLM_TARGET_INFO, NTLM_VERSION, NTLM_128, NTLM_56 = (
    0x80000, 0x800000, 0x2000000, 0x20000000, 0x80000000)
NTLM_NEGOTIATE_FLAGS = (NTLM_UNICODE | NTLM_OEM | NTLM_REQUEST_TARGET | NTLM_NTLM | NTLM_ALWAYS_SIGN
                        | NTLM_EXTENDED_SESSION_SECURITY | NTLM_VERSION | NTLM_128 | NTLM_56)
NTLM_VERSION_FIELD = struct.pack("<BBHxxxB", 10, 0, 19041, 15)  # Windows 10, NTLMSSP revision 15
AV_EOL, AV_FLAGS, AV_TIMESTAMP = 0, 6, 7
AV_MIC_PRESENT = 0x2


def hmac_md5(key, data):
    return hmac.new(key, data, hashlib.md5).digest()


def utf16(text):
    return text.encode("utf-16-le")


def filetime(t):
    """Windows FILETIME (100 ns since 1601) of a Unix time."""
    return struct.pack("<Q", int((t + 11644473600) * 10_000_000))


def ntowf_v2(user, domain, password):
    """The NTLMv2 response key: HMAC-MD5 of the NT hash over the upper-cased user and the domain."""
    return hmac_md5(md4(utf16(password)), utf16(user.upper() + domain))


def ntlm_fields(offset, *items):
    """(length, maximum length, offset) headers for payload items laid out from offset, and the payload."""
    heads, body = b"", b""
    for item in items:
        heads += struct.pack("<HHI", len(item), len(item), offset + len(body))
        body += item
    return heads, body


def ntlm_negotiate(flags=NTLM_NEGOTIATE_FLAGS):
    """The NEGOTIATE message (type 1): no domain or workstation, a version."""
    heads, body = ntlm_fields(40, b"", b"")
    return NTLMSSP + struct.pack("<II", 1, flags) + heads + NTLM_VERSION_FIELD + body


class NtlmChallenge:
    """A CHALLENGE message (type 2) from the server."""

    def __init__(self, raw):
        if len(raw) < 48 or raw[:8] != NTLMSSP or struct.unpack_from("<I", raw, 8)[0] != 2:
            raise ValueError("not an NTLM challenge")
        self.raw = raw
        name_len, _, name_off = struct.unpack_from("<HHI", raw, 12)
        self.flags, = struct.unpack_from("<I", raw, 20)
        self.server_challenge = raw[24:32]
        info_len, _, info_off = struct.unpack_from("<HHI", raw, 40)
        self.target_name = raw[name_off:name_off + name_len].decode("utf-16-le", "replace") \
            if self.flags & NTLM_UNICODE else raw[name_off:name_off + name_len].decode("ascii", "replace")
        info = raw[info_off:info_off + info_len] if self.flags & NTLM_TARGET_INFO else b""
        self.pairs = []  # (id, value) AV pairs, without the terminator
        pos = 0
        while pos + 4 <= len(info):
            av_id, av_len = struct.unpack_from("<HH", info, pos)
            if av_id == AV_EOL:
                break
            self.pairs.append((av_id, info[pos + 4:pos + 4 + av_len]))
            pos += 4 + av_len

    def timestamp(self):
        return next((v for i, v in self.pairs if i == AV_TIMESTAMP and len(v) == 8), None)


def ntlm_authenticate(negotiate, challenge, user, domain, password, workstation="", client_challenge=None, now=None):
    """The AUTHENTICATE message (type 3) with an NTLMv2 response and a MIC, and the session key.

    No key exchange is negotiated (the session key is the one NTLMv2 derives), so
    there's no encrypted random session key; signing and sealing aren't asked for,
    which HTTP doesn't use."""
    client_challenge = client_challenge or secrets.token_bytes(8)
    key = ntowf_v2(user, domain, password)
    pairs, has_flags = [], False
    for av_id, value in challenge.pairs:  # the server's target info, saying a MIC is present
        if av_id == AV_FLAGS and len(value) == 4:
            value, has_flags = struct.pack("<I", struct.unpack("<I", value)[0] | AV_MIC_PRESENT), True
        pairs.append((av_id, value))
    if not has_flags:
        pairs.append((AV_FLAGS, struct.pack("<I", AV_MIC_PRESENT)))
    target_info = b"".join(struct.pack("<HH", i, len(v)) + v for i, v in pairs) + struct.pack("<HH", AV_EOL, 0)
    stamp = challenge.timestamp() or filetime(time.time() if now is None else now)
    temp = b"\x01\x01" + b"\0" * 6 + stamp + client_challenge + b"\0" * 4 + target_info + b"\0" * 4
    proof = hmac_md5(key, challenge.server_challenge + temp)
    # With a server timestamp the LM response is left empty (MS-NLMP 3.1.5.1.2).
    lm_response = b"\0" * 24 if challenge.timestamp() else (
        hmac_md5(key, challenge.server_challenge + client_challenge) + client_challenge)
    session_key = hmac_md5(key, proof)
    flags = (NTLM_UNICODE | NTLM_REQUEST_TARGET | NTLM_NTLM | NTLM_ALWAYS_SIGN | NTLM_VERSION
             | challenge.flags & (NTLM_TARGET_INFO | NTLM_EXTENDED_SESSION_SECURITY | NTLM_128 | NTLM_56))
    heads, body = ntlm_fields(88, lm_response, proof + temp, utf16(domain), utf16(user), utf16(workstation), b"")
    head = NTLMSSP + struct.pack("<I", 3) + heads + struct.pack("<I", flags) + NTLM_VERSION_FIELD
    mic = hmac_md5(session_key, negotiate + challenge.raw + head + b"\0" * 16 + body)
    return head + mic + body, session_key


def ntlm_identity(principal, domain=""):
    """The (user, domain) to sign in to Windows as: alice@CORP.EXAMPLE.COM is
    CORP\\alice, unless the domain is given."""
    user, at, realm = principal.rpartition("@")
    if not at:
        user, realm = principal, ""
    return user, domain or realm.partition(".")[0]


def workstation_name():
    return socket.gethostname().partition(".")[0].upper()[:15]


class NtlmServer(UnixServer):
    """Answers the ntlm_auth helper protocol (relayed by Kerberus's ntlm_auth).

    credentials(client) returns (user, domain, password) for the app that ran
    the helper, or None. Like KcmServer.need_ticket, it runs on the connection's
    thread and may wait for you to sign in; the app waits meanwhile."""

    name = "ntlm"

    def __init__(self, credentials, path=NTLM_SOCKET, log=print):
        super().__init__(path, log)
        self.credentials = credentials

    def serve(self, conn):
        with conn:
            pid, uid = peer_of(conn)
            if uid != os.getuid():
                return
            client = KcmClient.from_pid(parent_pid(pid) or pid)  # the helper's parent is the app
            negotiate = None
            try:
                for line in conn.makefile("rb"):
                    command, _, argument = line.decode("ascii", "replace").strip().partition(" ")
                    if DEBUG:
                        self.log(f"ntlm: {client.program}[{client.pid}] {command}")
                    try:
                        reply = self.answer(client, command, argument.strip(), negotiate)
                        if command == "YR":
                            negotiate = base64.b64decode(reply[3:])
                    except (ValueError, binascii.Error, struct.error) as e:
                        reply = f"BH {e}"
                    conn.sendall(reply.encode() + b"\n")
            except (ConnectionError, OSError):
                return

    def answer(self, client, command, argument, negotiate):
        if command == "YR":
            return "YR " + base64.b64encode(ntlm_negotiate()).decode()
        if command == "TT":
            if negotiate is None:
                return "BH no NEGOTIATE yet"
            challenge = NtlmChallenge(base64.b64decode(argument))
            found = self.credentials(client)
            if not found:
                self.log(f"ntlm: no credentials for {client.program} (server {challenge.target_name or '?'})")
                return "BH no credentials"
            user, domain, password = found
            message, _ = ntlm_authenticate(negotiate, challenge, user, domain, password, workstation_name())
            self.log(f"ntlm: {client.program} signs in to {challenge.target_name or '?'} as {domain}\\{user}")
            return "AF " + base64.b64encode(message).decode()
        if command in ("PW", "SF"):  # a password or flags: Kerberus has its own
            return "OK"
        return "BH unknown command"


# ---------------------------------------------------------------------------
# CLI


def read_password(prompt):
    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    return sys.stdin.readline().rstrip("\n")


def print_caches(caches, now):
    if not caches:
        print("No Kerberos tickets.")
    for cache in caches:
        t = cache.tgt
        print(cache.principal + ("  (default)" if cache.default else ""))
        print(f"  cache:    {cache.name}")
        if t is None:
            print("  no tickets")
        elif t.expires <= now:
            print(f"  status:   expired {fmt_duration((now - t.expires).total_seconds())} ago ({t.expires:%Y-%m-%d %H:%M})")
        else:
            print(f"  status:   valid for {fmt_duration((t.expires - now).total_seconds())} (until {t.expires:%Y-%m-%d %H:%M})")
        if t and t.renew_until:
            print(f"  renew:    until {t.renew_until:%Y-%m-%d %H:%M}")
        if t and t.flags:
            print(f"  flags:    {t.describe_flags()}")
        for s in cache.services:
            print(f"  service:  {s.service} (until {s.expires:%Y-%m-%d %H:%M})")
        print()


def report(result):
    print(result.message, file=sys.stdout if result.ok else sys.stderr)
    return 0 if result.ok else 1


def cli(args):
    keyring = Keyring() if args.command in ("get", "forget", "watch", "passwd") else None
    if args.command == "forget":
        found = keyring.forget(full_principal(args.principal))
        print("Forgot the saved password." if found else "No saved password for that principal.")
        return 0 if found else 1
    if not TOOL_PATHS["klist"]:
        print(MISSING_TOOLS, file=sys.stderr)
        return 1
    serve = args.command == "watch" and args.kcm
    use_kcm(load_settings()["kcm"] or serve)
    now = dt.datetime.now()

    if args.command == "list":
        caches = list_caches()
        if args.json:
            print(json.dumps([c.to_json(now) for c in caches], indent=2))
        else:
            print_caches(caches, now)
        return 0

    if args.command == "get":
        principal = full_principal(args.principal)
        settings = load_settings()
        options = {"lifetime": args.lifetime or settings["lifetime"],
                   "renewable": args.renewable or settings["renewable"],
                   "forwardable": False if args.no_forwardable else settings["forwardable"]}
        if args.keytab:
            return report(get_ticket(principal, keytab=args.keytab, **options))
        password = read_password(f"Password for {principal}: ")
        result = get_ticket(principal, password, **options)
        if result.ok and args.remember:
            error = keyring.store(principal, password)
            print(f"Could not save the password: {error}" if error else "Saved the password in the keyring.",
                  file=sys.stderr if error else sys.stdout)
        return report(result)

    if args.command == "passwd":
        caches = list_caches()
        default = find_cache(caches, None)
        principal = full_principal(args.principal) if args.principal else (default.principal if default else "")
        if not principal:
            print("Which principal? kerberus passwd PRINCIPAL", file=sys.stderr)
            return 1
        old = read_password(f"Current password for {principal}: ")
        new = read_password("New password: ")
        if read_password("New password again: ") != new:
            print("The new passwords don't match.", file=sys.stderr)
            return 1
        result = change_password(principal, old, new)
        if result.ok and keyring.lookup(principal) is not None:
            keyring.store(principal, new)
        return report(result)

    if args.command == "watch":
        settings = load_settings()
        failed, told = set(), set()
        if serve:
            store, lock = KcmStore(KCM_STATE), threading.Lock()

            def need_ticket(client, name):
                principal, cache = store.describe(name)
                with lock:
                    if principal and store.needs_sign_in(name):
                        ok = recover_quietly(principal, cache, settings, keyring, failed)
                        print(f"{client.program} needs a ticket for {principal}: "
                              + ("got one" if ok else "sign in with the window or kerberus get"), flush=True)

            def ntlm_credentials(client):
                principal = store.describe(None)[0] or settings["last_principal"]
                password = keyring.lookup(principal) if principal and principal not in failed else None
                if password is None:
                    print(f"{client.program} wants to sign in with NTLM: no saved password"
                          + (f" for {principal}" if principal else ""), flush=True)
                    return None
                return (*ntlm_identity(principal, settings["ntlm_domain"]), password)

            server = KcmServer(store, need_ticket=need_ticket, log=lambda m: print(m, flush=True))
            try:
                server.start()
                if settings["ntlm"]:
                    write_ntlm_helper()
                    NtlmServer(ntlm_credentials, log=lambda m: print(m, flush=True)).start()
            except (RuntimeError, OSError) as e:
                print(f"Can't serve the credential cache: {e}", file=sys.stderr)
                return 1
            print(f"Serving the KCM credential cache on {KCM_SOCKET}"
                  + (f" and NTLM sign-ins on {NTLM_SOCKET}." if settings["ntlm"] else "."), flush=True)
        print(f"Watching tickets every {args.interval} s (renew {settings['renew_before']} min ahead).", flush=True)
        while True:
            notices = maintain(list_caches(), settings, keyring, log=lambda m: print(m, flush=True), failed=failed)
            for _, text, key in notices:
                if key not in told:
                    told.add(key)
                    print(text, flush=True)
            if args.once:
                return 0
            time.sleep(args.interval)

    if args.command == "destroy" and args.all:
        return report(destroy_all())

    caches = list_caches()
    if args.command == "renew" and args.all:
        results = [renew(c) for c in caches if c.can_renew(now)]
        if not results:
            print("Nothing to renew.")
        return max([report(r) for r in results], default=0)
    cache = find_cache(caches, getattr(args, "principal", None))
    if cache is None:
        print("No tickets for that principal." if getattr(args, "principal", None) else "No Kerberos tickets.",
              file=sys.stderr)
        return 1
    action = {"renew": renew, "destroy": destroy, "switch": switch}[args.command]
    return report(action(cache))


# ---------------------------------------------------------------------------
# GUI


def icon_dir():
    """The icon theme directory with the app and tray icons: data/icons in a
    checkout, usr/share/icons in the AppImage."""
    here = Path(__file__).resolve().parent
    for candidate in (here / "data" / "icons", here.parent / "icons"):
        if (candidate / "hicolor" / "scalable" / "apps" / f"{APP_ID}.svg").exists():
            return candidate
    return None




def gui(background=False, smoke_test=False):
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, Gdk, Gio, GLib, Gtk

    def in_thread(work, done):
        """Run work() off the main loop and done(result) back on it."""
        def target():
            try:
                result = work()
            except Exception as e:  # shown to the user instead of lost in a thread
                result = Result(False, f"{type(e).__name__}: {e}")
            GLib.idle_add(lambda: done(result) and False)
        threading.Thread(target=target, daemon=True).start()

    def target_action(name, callback):
        action = Gio.SimpleAction.new(name, GLib.VariantType.new("s"))
        action.connect("activate", lambda _a, param: callback(param.get_string()))
        return action

    def plain_action(name, callback):
        action = Gio.SimpleAction.new(name, None)
        action.connect("activate", lambda *_: callback())
        return action

    def menu_item(label, action, target):
        item = Gio.MenuItem.new(label, None)
        item.set_action_and_target_value(action, GLib.Variant("s", target))
        return item

    def esc(text):
        return GLib.markup_escape_text(text)

    @dataclass
    class PromptRequest:
        """An app waiting (on a KCM or NTLM connection thread) for you to sign in."""
        client: KcmClient
        principal: str
        cache: str
        kind: str = "ticket"      # or "ntlm": the app wants an NTLM sign-in, not a ticket
        done: threading.Event = field(default_factory=threading.Event)
        signed_in_as: str = ""    # filled in when you sign in: the identity and its password
        password: str | None = None

    def app_info_for(program):
        """The installed app (desktop file) whose executable is `program`."""
        for info in Gio.AppInfo.get_all():
            exe = info.get_executable() or ""
            if exe and program_name(exe) == program:
                return info
        return None

    class App(Adw.Application):
        def __init__(self):
            flags = getattr(Gio.ApplicationFlags, "DEFAULT_FLAGS", Gio.ApplicationFlags.FLAGS_NONE)
            super().__init__(application_id=APP_ID, flags=flags)
            self.settings = load_settings()
            self.keyring = Keyring()
            self.caches = []
            self.saved = set()        # principals with a saved password
            self.error = None         # why there's nothing to show (no tools)
            self.window = None
            self.start_hidden = background
            self.held = False
            self.refreshing = False
            self.refresh_again = False
            self.refresh_queued = False
            self.maintaining = False
            self.failed = set()       # principals whose saved password was rejected
            self.told = set()         # notifications already sent
            self.store = None         # the KCM caches, when Kerberus is the credential cache
            self.server = None
            self.ntlm = None          # the NTLM helper server, with it
            self.kcm_error = None
            self.prompt = None        # the PromptRequest being answered
            self.prompt_lock = threading.Lock()
            self.recover_lock = threading.Lock()
            self.snoozed = {}         # program -> time until which it isn't prompted for
            self.picker = None
            self.tray = None

        def do_startup(self):
            Adw.Application.do_startup(self)
            Gtk.Window.set_default_icon_name(APP_ID)
            icons = icon_dir()
            if icons:
                Gtk.IconTheme.get_for_display(Gdk.Display.get_default()).add_search_path(str(icons))
            for action in (plain_action("quit", self.request_quit), plain_action("refresh", self.refresh),
                           plain_action("preferences", self.show_preferences), plain_action("about", self.show_about),
                           plain_action("show", self.show_window), plain_action("pick-identity", self.open_picker),
                           target_action("sign-in", self.sign_in_from_notification)):
                self.add_action(action)
            self.set_accels_for_action("app.quit", ["<Control>q"])
            self.set_accels_for_action("app.refresh", ["<Control>r", "F5"])
            self.set_accels_for_action("app.preferences", ["<Control>comma"])
            self.set_accels_for_action("win.get-ticket", ["<Control>n"])
            self.set_accels_for_action("window.close", ["<Control>w"])
            if self.start_hidden or self.settings["background"]:
                self.set_held(True)
            if self.settings["kcm"]:
                self.start_kcm()
            self.tray = Tray(self)
            GLib.timeout_add_seconds(30, self.tick)

        def do_shutdown(self):
            self.stop_kcm()
            Adw.Application.do_shutdown(self)

        def do_activate(self):
            if self.start_hidden:
                self.start_hidden = False
                self.tick()
                return
            self.show_window()
            self.tick()

        def show_window(self):
            if self.window is None:
                self.window = Window(self)
                self.window.update()
            self.window.present()

        def toggle_window(self):
            if self.window and self.window.get_visible() and self.window.is_active() and self.held:
                self.window.set_visible(False)
            else:
                self.show_window()

        def set_held(self, held):
            """Keep running without a window (background renewal) or not."""
            if held and not self.held:
                self.hold()
            elif not held and self.held:
                self.release()
                if self.window and not self.window.get_visible():
                    self.window.destroy()
                    self.window = None
            self.held = held

        def request_quit(self):
            if not self.server:
                self.quit()
                return
            dialog = Adw.AlertDialog(heading="Quit Kerberus?",
                                     body="Apps can't get Kerberos tickets while Kerberus isn't running. "
                                          "It starts again when you log in.")
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("quit", "Quit")
            dialog.set_response_appearance("quit", Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.set_close_response("cancel")
            dialog.connect("response", lambda _d, response: response == "quit" and self.quit())
            dialog.present(self.window if self.window and self.window.get_visible() else None)

        # Kerberus as the credential cache

        def start_kcm(self):
            use_kcm(True)
            if session_kcm_enabled() and not session_setup_current():
                set_session_kcm(True)  # an older Kerberus set the session up: add the ntlm_auth helper
            self.store = KcmStore(KCM_STATE)
            self.store.changed = lambda: GLib.idle_add(self.queue_refresh)
            self.server = KcmServer(self.store, need_ticket=self.need_ticket,
                                    log=lambda m: print(m, file=sys.stderr))
            try:
                self.server.start()
                self.kcm_error = None
            except (RuntimeError, OSError) as e:
                self.server = None
                self.kcm_error = f"Kerberus can't keep the tickets for apps: {e}"
                return
            if self.settings["ntlm"]:
                self.start_ntlm()

        def start_ntlm(self):
            try:
                write_ntlm_helper()
                self.ntlm = NtlmServer(self.ntlm_credentials, log=lambda m: print(m, file=sys.stderr))
                self.ntlm.start()
            except (RuntimeError, OSError) as e:
                self.ntlm = None
                print(f"Kerberus can't answer NTLM sign-ins: {e}", file=sys.stderr)

        def stop_ntlm(self):
            if self.ntlm:
                self.ntlm.stop()
            self.ntlm = None

        def set_ntlm(self, enabled):
            self.set_setting("ntlm", enabled)
            if enabled and self.server and not self.ntlm:
                self.start_ntlm()
            elif not enabled:
                self.stop_ntlm()

        def stop_kcm(self):
            self.stop_ntlm()
            if self.server:
                self.server.stop()
            self.server = self.store = None
            self.kcm_error = None
            use_kcm(False)

        def set_kcm(self, enabled):
            self.set_setting("kcm", enabled)
            set_session_kcm(enabled)
            if enabled:
                self.start_kcm()
                set_autostart(True)
                self.set_setting("background", True)
            else:
                self.stop_kcm()
            self.refresh()

        def need_ticket(self, client, name):
            """An app asked for a cache with no valid ticket. Runs on the KCM
            connection's thread, which holds the app's request until this returns."""
            settings = self.settings
            if client.program in settings["ignored_apps"] or time.time() < self.snoozed.get(client.program, 0):
                return
            principal, cache = self.store.describe(name)
            with self.recover_lock:
                if not self.store.needs_sign_in(name):
                    return  # another request already got one
                if principal and recover_quietly(principal, cache, settings, self.keyring, self.failed):
                    return
            with self.prompt_lock:
                request = self.prompt
                if request is None:
                    request = self.prompt = PromptRequest(client, principal, cache)
                    GLib.idle_add(self.show_prompt, request)
            if DEBUG:
                print(f"prompt: {client.program}[{client.pid}] waits for {id(request):x}", file=sys.stderr)
            answered = request.done.wait(settings["prompt_timeout"])
            if DEBUG:
                print(f"prompt: {client.program}[{client.pid}] {'answered' if answered else 'timed out'}", file=sys.stderr)

        def ntlm_credentials(self, client):
            """An app's ntlm_auth helper has a challenge to answer. Runs on the
            NTLM connection's thread; the app waits until this returns."""
            settings = self.settings
            if client.program in settings["ignored_apps"] or time.time() < self.snoozed.get(client.program, 0):
                return None
            principal = (self.store.describe(None)[0] if self.store else "") or settings["last_principal"]
            password = self.keyring.lookup(principal) if principal and principal not in self.failed else None
            if password is None:
                with self.prompt_lock:
                    request = self.prompt
                    if request is None:
                        request = self.prompt = PromptRequest(client, principal, "", kind="ntlm")
                        GLib.idle_add(self.show_prompt, request)
                if DEBUG:
                    print(f"ntlm: {client.program}[{client.pid}] waits for {id(request):x}", file=sys.stderr)
                request.done.wait(settings["prompt_timeout"])
                principal, password = request.signed_in_as, request.password
            if not password:
                return None
            return (*ntlm_identity(principal, settings["ntlm_domain"]), password)

        def show_prompt(self, request):
            if self.picker:
                self.picker.attach(request)
            else:
                self.picker = IdentityPicker(self, request)
            self.picker.present()
            self.update_tray()
            return False

        def open_picker(self, principal=None):
            if not self.picker:
                self.picker = IdentityPicker(self, None)
            self.picker.present()

        def prompt_finished(self, request, outcome):
            """outcome: "signed-in", "cancelled" (ask again in 5 minutes) or "ignore" (never ask this app)."""
            self.picker = None
            if DEBUG:
                print(f"prompt: {id(request):x} finished: {outcome}", file=sys.stderr)
            if request:
                program = request.client.program
                if outcome == "cancelled":
                    self.snoozed[program] = time.time() + 300
                elif outcome == "ignore" and program not in self.settings["ignored_apps"]:
                    self.set_setting("ignored_apps", self.settings["ignored_apps"] + [program])
                with self.prompt_lock:
                    if self.prompt is request:
                        self.prompt = None
                request.done.set()
            self.refresh()

        # Tickets

        def tick(self):
            self.refresh(then=self.maintain)
            return True

        def queue_refresh(self):
            """Refresh soon; for bursts of changes (an app storing service tickets)."""
            if not self.refresh_queued:
                self.refresh_queued = True

                def run():
                    self.refresh_queued = False
                    self.refresh()
                    return False
                GLib.timeout_add(400, run)
            return False

        def refresh(self, then=None):
            if self.refreshing:
                self.refresh_again = True
                return
            self.refreshing = True

            def work():
                try:
                    return list_caches(), set(self.keyring.principals())
                except ToolsMissing as e:
                    return Result(False, str(e))

            def done(result):
                self.refreshing = False
                if isinstance(result, Result):
                    self.caches, self.saved, self.error = [], set(), result.message
                else:
                    (self.caches, self.saved), self.error = result, None
                if self.window:
                    self.window.update()
                if self.picker:
                    self.picker.refreshed()
                self.update_tray()
                if then:
                    then()
                if self.refresh_again:
                    self.refresh_again = False
                    self.refresh()
            in_thread(work, done)

        def update_tray(self):
            if self.tray:
                self.tray.update()

        def maintain(self):
            if self.maintaining or not self.caches:
                return
            self.maintaining = True
            caches, settings, changed = list(self.caches), dict(self.settings), []

            def done(notices):
                self.maintaining = False
                if isinstance(notices, Result):
                    print(notices.message, file=sys.stderr)
                    return
                for cache, text, key in notices:
                    if key not in self.told:
                        self.told.add(key)
                        self.send_ticket_notice(cache, text)
                if changed:
                    self.refresh()
            in_thread(lambda: maintain(caches, settings, self.keyring, log=changed.append, failed=self.failed), done)

        def renew_all(self):
            now = dt.datetime.now()
            caches = [c for c in self.caches if c.can_renew(now)]
            in_thread(lambda: [renew(c) for c in caches], lambda _results: self.refresh())

        def send_ticket_notice(self, cache, text):
            note = Gio.Notification.new("Kerberos ticket")
            note.set_body(text)
            note.set_default_action("app.show")
            note.add_button_with_target("Sign In…", "app.sign-in", GLib.Variant("s", cache.principal))
            self.send_notification(f"ticket-{cache.principal}", note)

        def identities(self):
            """Principals to offer when signing in: recent ones, saved passwords, current caches."""
            seen = []
            for principal in self.settings["identities"] + sorted(self.saved) + [c.principal for c in self.caches]:
                if principal and principal not in seen:
                    seen.append(principal)
            return seen

        def signed_in(self, principal):
            self.failed.discard(principal)
            self.withdraw_notification(f"ticket-{principal}")
            self.settings["last_principal"] = principal
            self.settings["identities"] = ([principal] + [p for p in self.settings["identities"] if p != principal])[:8]
            save_settings(self.settings)

        def forget_identity(self, principal):
            self.settings["identities"] = [p for p in self.settings["identities"] if p != principal]
            save_settings(self.settings)
            self.saved.discard(principal)
            in_thread(lambda: self.keyring.forget(principal), lambda _found: self.refresh())

        def sign_in_from_notification(self, principal):
            self.show_window()
            self.window.sign_in(principal)

        def set_setting(self, key, value):
            self.settings[key] = value
            save_settings(self.settings)
            if key == "background":
                self.set_held(value)

        def show_preferences(self):
            self.show_window()
            Preferences(self).present(self.window)

        def show_about(self):
            self.show_window()
            about = Adw.AboutDialog(
                application_name=APP_NAME, application_icon=APP_ID, version=VERSION,
                developer_name="tahuffman1s", license_type=Gtk.License.MIT_X11,
                website=WEBSITE, issue_url=f"{WEBSITE}/issues",
                comments="Get, renew and destroy Kerberos tickets.",
                debug_info=(f"Kerberus {VERSION}\nKerberos tools: {TOOL_SOURCE or 'not found'}"
                            f" ({TOOL_PATHS['kinit'] or '-'})\n{tools_version()}\n"
                            f"libadwaita {Adw.get_major_version()}.{Adw.get_minor_version()}."
                            f"{Adw.get_micro_version()}, GTK {Gtk.get_major_version()}.{Gtk.get_minor_version()}."
                            f"{Gtk.get_micro_version()}\nKRB5CCNAME={os.environ.get('KRB5CCNAME', '')}\n"
                            f"Credential cache server: {KCM_SOCKET if self.server else 'off'}\n"
                           f"NTLM helper: {NTLM_SOCKET if self.ntlm else 'off'}\n"
                            f"Tray: {'registered' if self.tray and self.tray.registered else 'no StatusNotifierWatcher'}\n"
                            f"Keyring: {'yes' if self.keyring.available else 'no'}"))
            about.present(self.window)

    class Window(Adw.ApplicationWindow):
        def __init__(self, app):
            super().__init__(application=app, title=APP_NAME, default_width=560, default_height=680)
            self.app = app
            self.groups = {}
            self.order = []
            for action in (plain_action("get-ticket", self.sign_in), plain_action("destroy-all", self.confirm_destroy_all),
                           target_action("renew", lambda name: self.cache_action(name, renew)),
                           target_action("make-default", lambda name: self.cache_action(name, switch)),
                           target_action("destroy", self.confirm_destroy),
                           target_action("sign-in", self.sign_in),
                           target_action("change-password", self.change_password),
                           target_action("forget-password", self.forget_password)):
                self.add_action(action)
            self.add_action(plain_action("change-password-default", lambda: self.change_password(None)))

            header = Adw.HeaderBar()
            self.title_widget = Adw.WindowTitle(title=APP_NAME)
            header.set_title_widget(self.title_widget)
            header.pack_start(Gtk.Button(icon_name="list-add-symbolic", tooltip_text="Get Ticket",
                                         action_name="win.get-ticket"))
            menu = Gio.Menu()
            tickets = Gio.Menu()
            tickets.append("Choose Identity…", "app.pick-identity")
            tickets.append("Change Password…", "win.change-password-default")
            tickets.append("Destroy All Tickets…", "win.destroy-all")
            menu.append_section(None, tickets)
            general = Gio.Menu()
            general.append("Preferences", "app.preferences")
            general.append("About Kerberus", "app.about")
            general.append("Quit", "app.quit")
            menu.append_section(None, general)
            header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu, primary=True,
                                           tooltip_text="Main Menu"))
            header.pack_end(Gtk.Button(icon_name="view-refresh-symbolic", tooltip_text="Refresh",
                                       action_name="app.refresh"))

            self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)
            empty = Adw.StatusPage(icon_name=APP_ID, title="No Tickets",
                                   description="Sign in to a Kerberos realm to get a ticket.")
            button = Gtk.Button(label="Get Ticket", halign=Gtk.Align.CENTER, action_name="win.get-ticket")
            button.add_css_class("pill")
            button.add_css_class("suggested-action")
            empty.set_child(button)
            self.stack.add_named(empty, "empty")
            self.missing = Adw.StatusPage(icon_name="dialog-warning-symbolic", title="Kerberos Tools Not Found")
            self.stack.add_named(self.missing, "missing")
            self.list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=24, margin_top=24,
                                    margin_bottom=24, margin_start=12, margin_end=12)
            scroller = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, vexpand=True,
                                          child=Adw.Clamp(maximum_size=640, child=self.list_box))
            self.stack.add_named(scroller, "list")

            self.toasts = Adw.ToastOverlay(child=self.stack)
            view = Adw.ToolbarView(content=self.toasts)
            view.add_top_bar(header)
            self.banner = Adw.Banner()
            self.banner.connect("button-clicked", self.banner_clicked)
            view.add_top_bar(self.banner)
            self.set_content(view)
            self.connect("close-request", self.on_close)

        def on_close(self, _window):
            if self.app.held:
                self.set_visible(False)
                return True
            self.app.window = None
            return False

        def toast(self, text):
            self.toasts.add_toast(Adw.Toast.new(text))

        def update(self):
            now = dt.datetime.now()
            caches = self.app.caches
            if self.app.error:
                self.missing.set_description(self.app.error)
                self.stack.set_visible_child_name("missing")
            elif not caches:
                self.stack.set_visible_child_name("empty")
            else:
                # A FILE cache keeps its name when someone else signs in to it.
                order = [(c.name, c.principal) for c in caches]
                if order != self.order:
                    for group in self.groups.values():
                        self.list_box.remove(group)
                    self.groups = {(c.name, c.principal): CacheGroup(c) for c in caches}
                    for key in order:
                        self.list_box.append(self.groups[key])
                    self.order = order
                for cache in caches:
                    self.groups[(cache.name, cache.principal)].update(cache, now, self.app)
                self.stack.set_visible_child_name("list")
            default = find_cache(caches, None)
            self.title_widget.set_subtitle(default.principal if default else "")
            self.update_banner()

        def update_banner(self):
            settings, title, button = self.app.settings, None, None
            if self.app.kcm_error:
                title = self.app.kcm_error
            elif not settings["kcm"] and not settings["kcm_offer_dismissed"]:
                title, button = "Kerberus can ask you to sign in whenever an app needs a Kerberos ticket", "Turn On…"
            elif settings["kcm"] and os.environ.get("KRB5CCNAME") != "KCM:":
                title = "Log out and back in so that apps ask Kerberus for their tickets"
            if title:
                self.banner.set_title(esc(title))
                self.banner.set_button_label(button)
            self.banner.set_revealed(bool(title))

        def banner_clicked(self, _banner):
            dialog = Adw.AlertDialog(
                heading="Ask When Apps Need a Ticket?",
                body="Kerberus becomes your session's Kerberos credential cache. When a browser, file manager or "
                     "other app needs a ticket and you don't have one, Kerberus asks which identity to sign in as, "
                     "and the app carries on once you have.\n\nKerberus will start at login and keep running in "
                     "the background. Log out and back in afterwards. You can turn this off in Preferences.")
            dialog.add_response("later", "Not Now")
            dialog.add_response("on", "Turn On")
            dialog.set_response_appearance("on", Adw.ResponseAppearance.SUGGESTED)
            dialog.set_close_response("later")

            def response(_dialog, answer):
                if answer == "on":
                    self.app.set_kcm(True)
                else:
                    self.app.set_setting("kcm_offer_dismissed", True)
                self.update_banner()
            dialog.connect("response", response)
            dialog.present(self)

        def cache_named(self, name):
            return next((c for c in self.app.caches if c.name == name), None)

        def cache_action(self, name, action):
            cache = self.cache_named(name)
            if cache:
                in_thread(lambda: action(cache), self.finished)

        def finished(self, result):
            self.toast(result.message)
            self.app.refresh()

        def confirm_destroy(self, name):
            cache = self.cache_named(name)
            if cache:
                self.confirm(f"Destroy the tickets for {cache.principal}?",
                             "You'll need to sign in again to use Kerberos services as this principal.",
                             lambda: in_thread(lambda: destroy(cache), self.finished))

        def confirm_destroy_all(self):
            self.confirm("Destroy all tickets?", "Every credential cache in the collection is removed.",
                         lambda: in_thread(destroy_all, self.finished))

        def confirm(self, heading, body, then):
            dialog = Adw.AlertDialog(heading=heading, body=body)
            dialog.add_response("cancel", "Cancel")
            dialog.add_response("destroy", "Destroy")
            dialog.set_response_appearance("destroy", Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.set_default_response("cancel")
            dialog.set_close_response("cancel")
            dialog.connect("response", lambda _d, response: response == "destroy" and then())
            dialog.present(self)

        def sign_in(self, principal=None):
            cache = find_cache(self.app.caches, principal) if principal else None
            SignInDialog(self, principal, cache.name if cache else None).present(self)

        def change_password(self, principal, on_changed=None):
            if not principal:
                default = find_cache(self.app.caches, None)
                principal = default.principal if default else self.app.settings["last_principal"]
            ChangePasswordDialog(self, principal, on_changed).present(self)

        def forget_password(self, principal):
            def done(found):
                self.toast("Forgot the saved password" if found else "No saved password")
                self.app.refresh()
            in_thread(lambda: self.app.keyring.forget(principal), done)

    class CacheGroup(Adw.PreferencesGroup):
        """One credential cache: its principal, TGT and service tickets."""

        def __init__(self, cache):
            super().__init__()
            self.menu_state = None
            self.service_rows = []
            self.service_key = None
            self.renew_button = Gtk.Button(label="Renew", valign=Gtk.Align.CENTER, action_name="win.renew",
                                           action_target=GLib.Variant("s", cache.name))
            self.renew_button.add_css_class("flat")
            self.more = Gtk.MenuButton(icon_name="view-more-symbolic", valign=Gtk.Align.CENTER, tooltip_text="More")
            self.more.add_css_class("flat")
            self.saved_icon = Gtk.Image(icon_name="dialog-password-symbolic", tooltip_text="Password saved",
                                        valign=Gtk.Align.CENTER)
            self.saved_icon.add_css_class("dim-label")
            suffix = Gtk.Box(spacing=6)
            for widget in (self.saved_icon, self.renew_button, self.more):
                suffix.append(widget)
            self.set_header_suffix(suffix)

            self.status = Adw.ActionRow(use_markup=False)
            self.status_icon = Gtk.Image(valign=Gtk.Align.CENTER)
            self.status.add_prefix(self.status_icon)
            self.level = Gtk.LevelBar(min_value=0, max_value=1, valign=Gtk.Align.CENTER, width_request=96)
            self.status.add_suffix(self.level)
            self.sign_in_button = Gtk.Button(label="Sign In…", valign=Gtk.Align.CENTER, action_name="win.sign-in",
                                             action_target=GLib.Variant("s", cache.principal))
            self.sign_in_button.add_css_class("suggested-action")
            self.status.add_suffix(self.sign_in_button)
            self.renew_row = Adw.ActionRow(title="Renewable Until", use_markup=False)
            self.flags_row = Adw.ActionRow(title="Flags", use_markup=False, subtitle_selectable=True)
            self.services = Adw.ExpanderRow(title="Service Tickets", use_markup=False)
            for row in (self.status, self.renew_row, self.flags_row, self.services):
                self.add(row)

        def update(self, cache, now, app):
            self.set_title(esc(cache.principal))
            self.set_description(esc(("Default · " if cache.default else "") + cache.name))
            t = cache.tgt
            state = cache.state(now, app.settings["notify_before"])
            for css in ("success", "warning", "error"):
                self.status_icon.remove_css_class(css)
            if t is None or state == "expired":
                self.status.set_title("Expired")
                self.status.set_subtitle(f"{fmt_duration((now - t.expires).total_seconds())} ago, at "
                                         f"{fmt_when(t.expires, now)}" if t else "No tickets")
                self.status_icon.set_from_icon_name("dialog-error-symbolic")
                self.status_icon.add_css_class("error")
            else:
                left = (t.expires - now).total_seconds()
                self.status.set_title(f"Valid for {fmt_duration(left)}")
                self.status.set_subtitle(f"Until {fmt_when(t.expires, now)}")
                icon, css = (("dialog-warning-symbolic", "warning") if state == "expiring"
                             else ("emblem-ok-symbolic", "success"))
                self.status_icon.set_from_icon_name(icon)
                self.status_icon.add_css_class(css)
            lifetime = (t.expires - t.starts).total_seconds() if t else 0
            self.level.set_value(max(0.0, min(1.0, (t.expires - now).total_seconds() / lifetime)) if lifetime > 0 else 0)
            self.level.set_visible(state != "expired")
            renewable = cache.can_renew(now)
            self.sign_in_button.set_visible(state == "expired" and not renewable)
            self.renew_button.set_sensitive(renewable)
            self.renew_button.set_tooltip_text(None if renewable else "This ticket can't be renewed any more")
            self.renew_row.set_visible(bool(t and t.renew_until))
            if t and t.renew_until:
                self.renew_row.set_subtitle(fmt_when(t.renew_until, now)
                                            + ("" if t.renew_until > now else " (passed)"))
            self.flags_row.set_visible(bool(t and t.flags))
            self.flags_row.set_subtitle(t.describe_flags().capitalize() if t else "")
            self.saved_icon.set_visible(cache.principal in app.saved)
            self.update_menu(cache, cache.principal in app.saved, len(app.caches) > 1)
            self.update_services(cache.services, now)

        def update_menu(self, cache, saved, several):
            state = (cache.default, saved, several)
            if state == self.menu_state:
                return  # replacing the model would close an open menu
            self.menu_state = state
            menu = Gio.Menu()
            main = Gio.Menu()
            if several and not cache.default:
                main.append_item(menu_item("Make Default", "win.make-default", cache.name))
            main.append_item(menu_item("Sign In Again…", "win.sign-in", cache.principal))
            main.append_item(menu_item("Change Password…", "win.change-password", cache.principal))
            if saved:
                main.append_item(menu_item("Forget Saved Password", "win.forget-password", cache.principal))
            menu.append_section(None, main)
            danger = Gio.Menu()
            danger.append_item(menu_item("Destroy Tickets…", "win.destroy", cache.name))
            menu.append_section(None, danger)
            self.more.set_menu_model(menu)

        def update_services(self, services, now):
            self.services.set_visible(bool(services))
            self.services.set_subtitle(f"{len(services)} ticket{'s' if len(services) != 1 else ''}")
            key = [(s.service, s.expires) for s in services]
            if key == self.service_key:
                return
            self.service_key = key
            for row in self.service_rows:
                self.services.remove(row)
            self.service_rows = []
            for s in services:
                row = Adw.ActionRow(title=s.service, use_markup=False, title_selectable=True,
                                    subtitle=("Expired" if s.expires <= now else f"Until {fmt_when(s.expires, now)}"))
                self.services.add_row(row)
                self.service_rows.append(row)

    class FormDialog(Adw.Dialog):
        """A dialog with Cancel and an action button in the header and an error banner."""

        def __init__(self, title, action_label):
            super().__init__(title=title, content_width=440)
            header = Adw.HeaderBar(show_start_title_buttons=False, show_end_title_buttons=False)
            cancel = Gtk.Button(label="Cancel")
            cancel.connect("clicked", lambda *_: self.close())
            header.pack_start(cancel)
            self.action_button = Gtk.Button(label=action_label, sensitive=False)
            self.action_button.add_css_class("suggested-action")
            self.action_button.connect("clicked", lambda *_: self.submit())
            self.spinner = Gtk.Spinner()
            header.pack_end(self.action_button)
            header.pack_end(self.spinner)
            self.banner = Adw.Banner()
            self.page = Adw.PreferencesPage()
            view = Adw.ToolbarView(content=self.page)
            view.add_top_bar(header)
            view.add_top_bar(self.banner)
            self.set_child(view)
            self.busy = False

        def entries(self):
            return []

        def validate(self, *_):
            self.action_button.set_sensitive(not self.busy and all(e.get_text() for e in self.entries()))

        def watch(self, *entries):
            for entry in entries:
                entry.connect("changed", self.validate)
                entry.connect("entry-activated", lambda *_: self.action_button.get_sensitive() and self.submit())
            self.validate()

        def set_busy(self, busy):
            self.busy = busy
            self.spinner.set_spinning(busy)
            self.set_can_close(not busy)
            self.validate()

        def show_error(self, text, button=None, callback=None):
            self.banner.set_title(esc(text))
            self.banner.set_button_label(button)
            if getattr(self, "banner_handler", None):
                self.banner.disconnect(self.banner_handler)
                self.banner_handler = None
            if callback:
                self.banner_handler = self.banner.connect("button-clicked", lambda *_: callback())
            self.banner.set_revealed(True)

    class SignInDialog(FormDialog):
        def __init__(self, window, principal=None, cache=None):
            super().__init__("Get Ticket", "Sign In")
            self.window, self.app, self.cache = window, window.app, cache
            settings = self.app.settings
            principal = principal or settings["last_principal"] or full_principal(getpass.getuser())
            account = Adw.PreferencesGroup()
            self.principal = Adw.EntryRow(title="Principal", text=principal)
            self.password = Adw.PasswordEntryRow(title="Password")
            self.remember = Adw.SwitchRow(title="Remember Password",
                                          subtitle="Keep it in the keyring to sign in again when the ticket can't be renewed",
                                          active=principal in self.app.saved, visible=self.app.keyring.available)
            for row in (self.principal, self.password, self.remember):
                account.add(row)
            self.page.add(account)

            options = Adw.PreferencesGroup(title="Options")
            self.lifetime = self.combo("Lifetime", LIFETIMES, settings["lifetime"])
            self.renewable = self.combo("Renewable For", RENEWABLE, settings["renewable"])
            self.forwardable = Adw.SwitchRow(title="Forwardable", subtitle="Let services you sign in to act on your behalf",
                                             active=settings["forwardable"])
            for row in (self.lifetime, self.renewable, self.forwardable):
                options.add(row)
            self.page.add(options)
            self.watch(self.principal, self.password)
            self.set_focus(self.password if principal else self.principal)

        @staticmethod
        def combo(title, choices, current):
            values = [v for _, v in choices]
            return Adw.ComboRow(title=title, model=Gtk.StringList.new([label for label, _ in choices]),
                                selected=values.index(current) if current in values else 0)

        def entries(self):
            return [self.principal, self.password]

        def submit(self):
            principal = full_principal(self.principal.get_text())
            password = self.password.get_text()
            remember = self.remember.get_active() and self.app.keyring.available
            options = {"lifetime": LIFETIMES[self.lifetime.get_selected()][1],
                       "renewable": RENEWABLE[self.renewable.get_selected()][1],
                       "forwardable": self.forwardable.get_active()}
            cache = self.cache if self.cache and self.app.caches and any(
                c.name == self.cache and c.principal == principal for c in self.app.caches) else None
            self.set_busy(True)
            self.banner.set_revealed(False)
            keyring = self.app.keyring

            def work():
                result = get_ticket(principal, password, cache=cache, **options)
                if result.ok and remember:
                    error = keyring.store(principal, password)
                    if error:
                        result.message += f" (could not save the password: {error})"
                elif result.ok and keyring.available and principal in self.app.saved:
                    keyring.forget(principal)
                return result

            def done(result):
                self.set_busy(False)
                if not result.ok:
                    if result.password_expired:
                        self.show_error(result.message, "Change Password", lambda: self.window.change_password(
                            principal, on_changed=self.changed))
                    else:
                        self.show_error(result.message)
                    return
                for key, value in options.items():
                    self.app.settings[key] = value
                self.app.signed_in(principal)
                self.force_close()
                self.window.finished(result)
            in_thread(work, done)

        def changed(self, new_password):
            self.password.set_text(new_password)
            self.submit()

    class ChangePasswordDialog(FormDialog):
        def __init__(self, window, principal, on_changed=None):
            super().__init__("Change Password", "Change")
            self.window, self.app, self.on_changed = window, window.app, on_changed
            group = Adw.PreferencesGroup()
            self.principal = Adw.EntryRow(title="Principal", text=principal or "")
            self.old = Adw.PasswordEntryRow(title="Current Password")
            self.new = Adw.PasswordEntryRow(title="New Password")
            self.again = Adw.PasswordEntryRow(title="New Password Again")
            for row in (self.principal, self.old, self.new, self.again):
                group.add(row)
            self.page.add(group)
            self.watch(self.principal, self.old, self.new, self.again)
            self.set_focus(self.old if principal else self.principal)

        def entries(self):
            return [self.principal, self.old, self.new, self.again]

        def submit(self):
            if self.new.get_text() != self.again.get_text():
                self.show_error("The new passwords don't match.")
                return
            principal = full_principal(self.principal.get_text())
            old, new = self.old.get_text(), self.new.get_text()
            keyring, saved = self.app.keyring, principal in self.app.saved
            self.set_busy(True)
            self.banner.set_revealed(False)

            def work():
                result = change_password(principal, old, new)
                if result.ok and saved:
                    keyring.store(principal, new)
                return result

            def done(result):
                self.set_busy(False)
                if not result.ok:
                    self.show_error(result.message)
                    return
                self.app.failed.discard(principal)
                self.force_close()
                self.window.toast(result.message)
                if self.on_changed:
                    self.on_changed(new)
            in_thread(work, done)

    class IdentityPicker(Adw.Window):
        """Choose who to sign in as: for an app that's waiting on a ticket, or from the tray."""

        def __init__(self, app, request):
            super().__init__(application=app, title="Kerberos Sign-In", default_width=440, default_height=620)
            self.app, self.request = app, None
            self.principal = None     # whose password the password page asks for (None: typed in)
            self.busy = False
            self.outcome = "cancelled"
            self.banner_handler = None

            header = Adw.HeaderBar()
            self.back = Gtk.Button(icon_name="go-previous-symbolic", tooltip_text="Back", visible=False)
            self.back.connect("clicked", lambda *_: self.show_choices())
            header.pack_start(self.back)
            self.spinner = Gtk.Spinner()
            header.pack_end(self.spinner)
            self.banner = Adw.Banner()
            self.stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.SLIDE_LEFT_RIGHT)

            choose = Adw.PreferencesPage()
            intro = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            self.app_icon = Gtk.Image(pixel_size=64)
            self.heading = Gtk.Label(wrap=True, justify=Gtk.Justification.CENTER)
            self.heading.add_css_class("title-2")
            self.subheading = Gtk.Label(wrap=True, justify=Gtk.Justification.CENTER)
            self.subheading.add_css_class("dim-label")
            for widget in (self.app_icon, self.heading, self.subheading):
                intro.append(widget)
            group = Adw.PreferencesGroup()
            group.add(intro)
            choose.add(group)
            self.choices = Adw.PreferencesGroup(title="Identities")
            self.choice_rows = []
            choose.add(self.choices)
            more = Adw.PreferencesGroup()
            other = Adw.ActionRow(title="Use Another Identity…", activatable=True)
            other.add_prefix(Gtk.Image(icon_name="list-add-symbolic"))
            other.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
            other.connect("activated", lambda *_: self.show_password(None))
            more.add(other)
            self.dont_ask = Adw.SwitchRow(use_markup=False)
            more.add(self.dont_ask)
            choose.add(more)
            self.stack.add_named(choose, "choose")

            password_page = Adw.PreferencesPage()
            who = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            self.avatar = Adw.Avatar(size=80, show_initials=True, halign=Gtk.Align.CENTER)
            self.who = Gtk.Label(wrap=True, justify=Gtk.Justification.CENTER)
            self.who.add_css_class("title-3")
            who.append(self.avatar)
            who.append(self.who)
            group = Adw.PreferencesGroup()
            group.add(who)
            password_page.add(group)
            fields = Adw.PreferencesGroup()
            self.principal_row = Adw.EntryRow(title="Principal")
            self.password_row = Adw.PasswordEntryRow(title="Password")
            self.remember_row = Adw.SwitchRow(title="Remember Password",
                                              subtitle="Sign in again by itself when the ticket can't be renewed",
                                              visible=app.keyring.available)
            for row in (self.principal_row, self.password_row, self.remember_row):
                fields.add(row)
            for row in (self.principal_row, self.password_row):
                row.connect("changed", lambda *_: self.validate())
                row.connect("entry-activated", lambda *_: self.sign_in_button.get_sensitive() and self.submit())
            password_page.add(fields)
            self.sign_in_button = Gtk.Button(label="Sign In", halign=Gtk.Align.CENTER)
            self.sign_in_button.add_css_class("pill")
            self.sign_in_button.add_css_class("suggested-action")
            self.sign_in_button.connect("clicked", lambda *_: self.submit())
            group = Adw.PreferencesGroup()
            group.add(self.sign_in_button)
            password_page.add(group)
            self.stack.add_named(password_page, "password")

            self.toasts = Adw.ToastOverlay(child=self.stack)
            view = Adw.ToolbarView(content=self.toasts)
            view.add_top_bar(header)
            view.add_top_bar(self.banner)
            self.set_content(view)
            keys = Gtk.ShortcutController()
            keys.add_shortcut(Gtk.Shortcut.new(Gtk.ShortcutTrigger.parse_string("Escape"),
                                               Gtk.CallbackAction.new(lambda *_: self.close() or True)))
            self.add_controller(keys)
            self.connect("close-request", self.on_close)
            self.attach(request)

        def attach(self, request):
            """Show who's waiting (an app's request), or a plain sign-in when nobody is."""
            self.request = request or self.request
            if self.request:
                info = app_info_for(self.request.client.program)
                name = info.get_display_name() if info else self.request.client.program.capitalize()
                icon = info.get_icon() if info else None
                if icon:
                    self.app_icon.set_from_gicon(icon)
                else:
                    self.app_icon.set_from_icon_name(APP_ID)
                self.heading.set_text(f"{name} Wants to Sign In")
                self.subheading.set_text(
                    f"{name} is signing in to a Windows server with NTLM and is waiting for you to choose "
                    "who to sign in as." if self.request.kind == "ntlm" else
                    f"{name} needs a Kerberos ticket and is waiting for you to choose who to sign in as.")
                self.dont_ask.set_title(f"Don't Ask for {name} Again")
                self.dont_ask.set_visible(True)
            else:
                self.app_icon.set_from_icon_name(APP_ID)
                self.heading.set_text("Sign In")
                self.subheading.set_text("Choose an identity to get a Kerberos ticket.")
                self.dont_ask.set_visible(False)
            if not self.busy:
                self.fill()

        def fill(self, navigate=True):
            for row in self.choice_rows:
                self.choices.remove(row)
            self.choice_rows = []
            people = self.app.identities()
            wanted = self.request.principal if self.request else ""
            if wanted:
                people = [wanted] + [p for p in people if p != wanted]
            now = dt.datetime.now()
            for principal in people:
                user, _, realm = principal.rpartition("@")
                notes = [realm] if user else []
                cache = next((c for c in self.app.caches if c.principal == principal), None)
                if cache:
                    notes.append("ticket expired" if cache.state(now) == "expired" else "signed in")
                if principal in self.app.saved:
                    notes.append("password saved")
                row = Adw.ActionRow(title=user or principal, subtitle=" · ".join(notes), activatable=True,
                                    use_markup=False)
                row.add_prefix(Adw.Avatar(size=40, text=principal, show_initials=True))
                row.add_suffix(Gtk.Image(icon_name="go-next-symbolic"))
                row.connect("activated", lambda _row, p=principal: self.choose(p))
                self.choices.add(row)
                self.choice_rows.append(row)
            self.choices.set_visible(bool(people))
            if not navigate:
                return
            if people:
                self.show_choices()
            else:
                self.show_password(None)

        def refreshed(self):
            """The ticket list changed; update the rows if they're what's showing."""
            if not self.busy and self.stack.get_visible_child_name() == "choose":
                self.fill(navigate=False)

        def show_choices(self):
            self.banner.set_revealed(False)
            self.back.set_visible(False)
            self.stack.set_visible_child_name("choose")

        def choose(self, principal):
            self.show_password(principal)
            if principal in self.app.saved and principal not in self.app.failed:
                self.submit(use_saved=True)

        def show_password(self, principal):
            self.principal = principal
            self.banner.set_revealed(False)
            self.principal_row.set_visible(principal is None)
            if principal is None:
                self.principal_row.set_text(self.app.settings["last_principal"] or full_principal(getpass.getuser()))
            self.avatar.set_text(principal or "")
            self.who.set_text(principal or "Another Identity")
            self.password_row.set_text("")
            self.remember_row.set_active(principal in self.app.saved)
            self.back.set_visible(bool(self.choice_rows))
            self.stack.set_visible_child_name("password")
            self.validate()
            self.set_focus(self.principal_row if principal is None else self.password_row)

        def validate(self):
            principal = self.principal or self.principal_row.get_text().strip()
            self.sign_in_button.set_sensitive(not self.busy and bool(principal) and bool(self.password_row.get_text()))

        def set_busy(self, busy):
            self.busy = busy
            self.spinner.set_spinning(busy)
            self.back.set_sensitive(not busy)
            self.sign_in_button.set_label("Signing In…" if busy else "Sign In")
            self.validate()

        def toast(self, text):
            self.toasts.add_toast(Adw.Toast.new(text))

        def show_error(self, text, button=None, callback=None):
            self.banner.set_title(esc(text))
            self.banner.set_button_label(button)
            if self.banner_handler:
                self.banner.disconnect(self.banner_handler)
                self.banner_handler = None
            if callback:
                self.banner_handler = self.banner.connect("button-clicked", lambda *_: callback())
            self.banner.set_revealed(True)

        def submit(self, use_saved=False):
            principal = self.principal or full_principal(self.principal_row.get_text())
            password = None if use_saved else self.password_row.get_text()
            remember = self.remember_row.get_active() and self.app.keyring.available
            was_saved = principal in self.app.saved
            # Sign in to the cache the waiting app asked for, so its request finds the ticket.
            request = self.request
            cache = f"KCM:{request.cache}" if request and request.cache and self.app.server else None
            settings, keyring = dict(self.app.settings), self.app.keyring
            self.set_busy(True)
            self.banner.set_revealed(False)

            def work():
                secret = password if password is not None else keyring.lookup(principal)
                if secret is None:
                    return Result(False, "The keyring didn't give back the saved password. Type it instead.")
                result = get_ticket(principal, secret, cache=cache, **ticket_options(settings))
                if result.ok and cache:
                    run_tool("kswitch", "-c", cache)
                if result.ok and request:  # an NTLM sign-in uses the same password
                    request.signed_in_as, request.password = principal, secret
                if result.ok and password is not None:
                    if remember:
                        error = keyring.store(principal, password)
                        if error:
                            result.message += f" (could not save the password: {error})"
                    elif was_saved:
                        keyring.forget(principal)
                return result

            def done(result):
                self.set_busy(False)
                if result.ok:
                    self.outcome = "signed-in"
                    self.app.signed_in(principal)
                    self.close()
                    return
                if use_saved:
                    self.app.failed.add(principal)  # don't try that password again by itself
                if result.password_expired:
                    self.show_error(result.message, "Change Password", lambda: ChangePasswordDialog(
                        self, principal, on_changed=self.changed).present(self))
                else:
                    self.show_error(result.message)
                self.set_focus(self.password_row)
            in_thread(work, done)

        def changed(self, new_password):
            self.password_row.set_text(new_password)
            self.submit()

        def on_close(self, _window):
            if self.busy:
                return True
            outcome = self.outcome
            if outcome == "cancelled" and self.request and self.dont_ask.get_active():
                outcome = "ignore"
            self.app.prompt_finished(self.request, outcome)
            return False

    SNI_XML = """<node><interface name="org.kde.StatusNotifierItem">
      <property name="Category" type="s" access="read"/>
      <property name="Id" type="s" access="read"/>
      <property name="Title" type="s" access="read"/>
      <property name="Status" type="s" access="read"/>
      <property name="WindowId" type="i" access="read"/>
      <property name="IconName" type="s" access="read"/>
      <property name="IconPixmap" type="a(iiay)" access="read"/>
      <property name="OverlayIconName" type="s" access="read"/>
      <property name="AttentionIconName" type="s" access="read"/>
      <property name="IconThemePath" type="s" access="read"/>
      <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
      <property name="ItemIsMenu" type="b" access="read"/>
      <property name="Menu" type="o" access="read"/>
      <method name="ContextMenu"><arg name="x" type="i" direction="in"/><arg name="y" type="i" direction="in"/></method>
      <method name="Activate"><arg name="x" type="i" direction="in"/><arg name="y" type="i" direction="in"/></method>
      <method name="SecondaryActivate"><arg name="x" type="i" direction="in"/><arg name="y" type="i" direction="in"/></method>
      <method name="Scroll"><arg name="delta" type="i" direction="in"/><arg name="orientation" type="s" direction="in"/></method>
      <signal name="NewTitle"/><signal name="NewIcon"/><signal name="NewAttentionIcon"/><signal name="NewToolTip"/>
      <signal name="NewStatus"><arg name="status" type="s"/></signal>
    </interface></node>"""
    MENU_XML = """<node><interface name="com.canonical.dbusmenu">
      <property name="Version" type="u" access="read"/>
      <property name="TextDirection" type="s" access="read"/>
      <property name="Status" type="s" access="read"/>
      <property name="IconThemePath" type="as" access="read"/>
      <method name="GetLayout"><arg type="i" name="parentId" direction="in"/><arg type="i" name="recursionDepth" direction="in"/>
        <arg type="as" name="propertyNames" direction="in"/><arg type="u" name="revision" direction="out"/>
        <arg type="(ia{sv}av)" name="layout" direction="out"/></method>
      <method name="GetGroupProperties"><arg type="ai" name="ids" direction="in"/><arg type="as" name="propertyNames" direction="in"/>
        <arg type="a(ia{sv})" name="properties" direction="out"/></method>
      <method name="GetProperty"><arg type="i" name="id" direction="in"/><arg type="s" name="name" direction="in"/>
        <arg type="v" name="value" direction="out"/></method>
      <method name="Event"><arg type="i" name="id" direction="in"/><arg type="s" name="eventId" direction="in"/>
        <arg type="v" name="data" direction="in"/><arg type="u" name="timestamp" direction="in"/></method>
      <method name="EventGroup"><arg type="a(isvu)" name="events" direction="in"/><arg type="ai" name="idErrors" direction="out"/></method>
      <method name="AboutToShow"><arg type="i" name="id" direction="in"/><arg type="b" name="needUpdate" direction="out"/></method>
      <method name="AboutToShowGroup"><arg type="ai" name="ids" direction="in"/><arg type="ai" name="updatesNeeded" direction="out"/>
        <arg type="ai" name="idErrors" direction="out"/></method>
      <signal name="ItemsPropertiesUpdated"><arg type="a(ia{sv})" name="updatedProps"/><arg type="a(ias)" name="removedProps"/></signal>
      <signal name="LayoutUpdated"><arg type="u" name="revision"/><arg type="i" name="parent"/></signal>
    </interface></node>"""

    class Tray:
        """The tray icon: a StatusNotifierItem (shown by KDE, GNOME with the AppIndicator
        extension, waybar and others) with a com.canonical.dbusmenu menu."""

        def __init__(self, app):
            self.app = app
            self.registered = self.owned = False
            self.watcher = None
            self.status, self.icon, self.tooltip = "Active", APP_ID, ""
            self.entries = []         # (label, enabled, callback); None is a separator
            self.revision = 0
            self.pixmaps = {}
            self.conn = app.get_dbus_connection()
            if self.conn is None:
                return
            self.bus_name = f"org.kde.StatusNotifierItem-{os.getpid()}-1"
            self.conn.register_object("/StatusNotifierItem", Gio.DBusNodeInfo.new_for_xml(SNI_XML).interfaces[0],
                                      self.item_call, self.item_property, None)
            self.conn.register_object("/MenuBar", Gio.DBusNodeInfo.new_for_xml(MENU_XML).interfaces[0],
                                      self.menu_call, self.menu_property, None)
            Gio.bus_own_name_on_connection(self.conn, self.bus_name, Gio.BusNameOwnerFlags.NONE,
                                           self.name_acquired, None)
            Gio.bus_watch_name_on_connection(self.conn, "org.kde.StatusNotifierWatcher",
                                             Gio.BusNameWatcherFlags.NONE, self.watcher_appeared, self.watcher_vanished)
            self.update()

        def name_acquired(self, _conn, _name):
            self.owned = True
            self.register()

        def watcher_appeared(self, _conn, name, _owner):
            self.watcher = name
            self.register()

        def watcher_vanished(self, _conn, _name):
            self.watcher, self.registered = None, False

        def register(self):
            if not (self.owned and self.watcher):
                return

            def finished(conn, result):
                try:
                    conn.call_finish(result)
                    self.registered = True
                except GLib.Error as e:
                    print(f"Tray icon not registered: {e.message}", file=sys.stderr)
            self.conn.call(self.watcher, "/StatusNotifierWatcher", "org.kde.StatusNotifierWatcher",
                           "RegisterStatusNotifierItem", GLib.Variant("(s)", (self.bus_name,)), None,
                           Gio.DBusCallFlags.NONE, -1, None, finished)

        def pixmap(self, name):
            """The icon as ARGB32 images, for hosts that don't look icons up by name."""
            if name not in self.pixmaps:
                from gi.repository import GdkPixbuf
                images = []
                path = (icon_dir() or Path()) / "hicolor" / "scalable" / "apps" / f"{name}.svg"
                for size in (22, 32, 48):
                    try:
                        pixbuf = GdkPixbuf.Pixbuf.new_from_file_at_size(str(path), size, size)
                    except GLib.Error:
                        break
                    if not pixbuf.get_has_alpha():
                        pixbuf = pixbuf.add_alpha(False, 0, 0, 0)
                    w, h, stride, pixels = pixbuf.get_width(), pixbuf.get_height(), pixbuf.get_rowstride(), pixbuf.get_pixels()
                    rgba = b"".join(pixels[y * stride:y * stride + w * 4] for y in range(h))
                    argb = bytearray(len(rgba))
                    argb[0::4], argb[1::4], argb[2::4], argb[3::4] = rgba[3::4], rgba[0::4], rgba[1::4], rgba[2::4]
                    images.append((w, h, bytes(argb)))
                self.pixmaps[name] = images
            return self.pixmaps[name]

        def update(self):
            app, now = self.app, dt.datetime.now()
            warn = app.settings["notify_before"]
            entries, tips = [], []
            for cache in app.caches:
                t = cache.tgt
                state = cache.state(now, warn)
                text = ("expired" if state == "expired" or t is None
                        else f"{fmt_duration((t.expires - now).total_seconds())} left")
                entries.append((f"{cache.principal}: {text}", False, None))
                tips.append(f"{cache.principal}: {text}")
            if not app.caches:
                entries.append(("Not signed in", False, None))
            entries += [None,
                        ("Choose Identity…", True, app.open_picker),
                        ("Renew Tickets", any(c.can_renew(now) for c in app.caches), app.renew_all),
                        ("Open Kerberus", True, app.show_window),
                        None,
                        ("Quit", True, app.request_quit)]
            states = [c.state(now, warn) for c in app.caches]
            if app.prompt:
                status, icon = "NeedsAttention", f"{APP_ID}-attention"
                tips.insert(0, f"{app.prompt.client.program} is waiting for you to sign in")
            elif not states or all(s == "expired" for s in states):
                status, icon = "Active", f"{APP_ID}-inactive"
            elif "expiring" in states or "expired" in states:
                status, icon = "Active", f"{APP_ID}-attention"
            else:
                status, icon = "Active", APP_ID
            tooltip = "\n".join(tips) or "Not signed in"
            if self.conn is None:
                return
            if [e and e[:2] for e in entries] != [e and e[:2] for e in self.entries]:
                self.revision += 1
                self.entries = entries
                self.conn.emit_signal(None, "/MenuBar", "com.canonical.dbusmenu", "LayoutUpdated",
                                      GLib.Variant("(ui)", (self.revision, 0)))
            else:
                self.entries = entries  # same layout, fresh callbacks
            if icon != self.icon:
                self.icon = icon
                self.conn.emit_signal(None, "/StatusNotifierItem", "org.kde.StatusNotifierItem", "NewIcon", None)
            if status != self.status:
                self.status = status
                self.conn.emit_signal(None, "/StatusNotifierItem", "org.kde.StatusNotifierItem", "NewStatus",
                                      GLib.Variant("(s)", (status,)))
            if tooltip != self.tooltip:
                self.tooltip = tooltip
                self.conn.emit_signal(None, "/StatusNotifierItem", "org.kde.StatusNotifierItem", "NewToolTip", None)

        def item_property(self, _conn, _sender, _path, _iface, name):
            values = {
                "Category": ("s", "ApplicationStatus"), "Id": ("s", "kerberus"), "Title": ("s", APP_NAME),
                "Status": ("s", self.status), "WindowId": ("i", 0), "IconName": ("s", self.icon),
                "IconPixmap": ("a(iiay)", self.pixmap(self.icon)), "OverlayIconName": ("s", ""),
                "AttentionIconName": ("s", f"{APP_ID}-attention"), "IconThemePath": ("s", str(icon_dir() or "")),
                "ToolTip": ("(sa(iiay)ss)", (self.icon, [], APP_NAME, self.tooltip)),
                "ItemIsMenu": ("b", False), "Menu": ("o", "/MenuBar"),
            }
            return GLib.Variant(*values[name]) if name in values else None

        def item_call(self, _conn, _sender, _path, _iface, method, _params, invocation):
            if method == "Activate":
                self.app.toggle_window()
            elif method == "SecondaryActivate":
                self.app.open_picker()
            invocation.return_value(None)

        def menu_property(self, _conn, _sender, _path, _iface, name):
            values = {"Version": ("u", 3), "TextDirection": ("s", "ltr"), "Status": ("s", "normal"),
                      "IconThemePath": ("as", [])}
            return GLib.Variant(*values[name]) if name in values else None

        def item_properties(self, item_id):
            if item_id == 0:
                return {"children-display": GLib.Variant("s", "submenu")}
            entry = self.entries[item_id - 1]
            if entry is None:
                return {"type": GLib.Variant("s", "separator")}
            return {"label": GLib.Variant("s", entry[0].replace("_", "__")), "enabled": GLib.Variant("b", entry[1])}

        def layout(self, item_id):
            children = []
            if item_id == 0:
                children = [GLib.Variant("(ia{sv}av)", (i, self.item_properties(i), []))
                            for i in range(1, len(self.entries) + 1)]
            return (item_id, self.item_properties(item_id), children)

        def clicked(self, item_id):
            if 1 <= item_id <= len(self.entries) and self.entries[item_id - 1] and self.entries[item_id - 1][2]:
                GLib.idle_add(lambda: self.entries[item_id - 1][2]() and False)

        def menu_call(self, _conn, _sender, _path, _iface, method, params, invocation):
            args = params.unpack()
            valid = range(0, len(self.entries) + 1)
            if method == "GetLayout":
                item_id = args[0] if args[0] in valid else 0
                invocation.return_value(GLib.Variant("(u(ia{sv}av))", (self.revision, self.layout(item_id))))
            elif method == "GetGroupProperties":
                ids = [i for i in (args[0] or valid) if i in valid]
                invocation.return_value(GLib.Variant("(a(ia{sv}))", ([(i, self.item_properties(i)) for i in ids],)))
            elif method == "GetProperty":
                value = self.item_properties(args[0]).get(args[1]) if args[0] in valid else None
                invocation.return_value(GLib.Variant("(v)", (value or GLib.Variant("s", ""),)))
            elif method == "Event":
                if args[1] == "clicked":
                    self.clicked(args[0])
                invocation.return_value(None)
            elif method == "EventGroup":
                for item_id, event, _data, _time in args[0]:
                    if event == "clicked":
                        self.clicked(item_id)
                invocation.return_value(GLib.Variant("(ai)", ([],)))
            elif method == "AboutToShow":
                invocation.return_value(GLib.Variant("(b)", (False,)))
            elif method == "AboutToShowGroup":
                invocation.return_value(GLib.Variant("(aiai)", ([], [])))
            else:
                invocation.return_dbus_error("org.freedesktop.DBus.Error.UnknownMethod", method)

    class Preferences(Adw.PreferencesDialog):
        def __init__(self, app):
            super().__init__()
            self.app = app
            page = Adw.PreferencesPage(title="General", icon_name="preferences-system-symbolic")
            self.add(page)

            prompts = Adw.PreferencesGroup(
                title="Sign-In Prompts",
                description="Kerberus keeps your session's Kerberos tickets and, when an app needs one you don't "
                            "have, asks which identity to sign in as. Log out and back in after changing this.")
            self.kcm_row = Adw.SwitchRow(title="Ask When Apps Need a Ticket", active=app.settings["kcm"])
            self.kcm_row.connect("notify::active", self.kcm_changed)
            prompts.add(self.kcm_row)
            timeout = self.spin("prompt_timeout", "Apps Wait For", "Seconds before an app gives up waiting", 15, 600, 15)
            prompts.add(timeout)
            self.ntlm_row = Adw.SwitchRow(title="Answer NTLM Sign-Ins", active=app.settings["ntlm"],
                                          subtitle="For Firefox and other apps that use Samba's ntlm_auth helper")
            self.ntlm_row.connect("notify::active", lambda row, _p: self.app.set_ntlm(row.get_active()))
            prompts.add(self.ntlm_row)
            self.domain_row = Adw.EntryRow(title="Windows Domain for NTLM (blank: the first part of the realm)", text=app.settings["ntlm_domain"],
                                           show_apply_button=True)
            self.domain_row.connect("apply", lambda row: self.app.set_setting("ntlm_domain", row.get_text().strip()))
            prompts.add(self.domain_row)
            self.ignored = Adw.ExpanderRow(title="Apps That Never Ask", use_markup=False)
            prompts.add(self.ignored)
            self.ignored_rows = []
            self.fill_ignored()
            page.add(prompts)

            renewal = Adw.PreferencesGroup(title="Renewal")
            renewal.add(self.switch("auto_renew", "Renew Automatically", "Renew tickets before they expire"))
            renewal.add(self.spin("renew_before", "Renew Ahead", "Minutes before a ticket expires", 5, 720, 5))
            reacquire = self.switch("reacquire", "Sign In With Saved Passwords",
                                    "When a ticket can't be renewed any more")
            reacquire.set_sensitive(app.keyring.available)
            renewal.add(reacquire)
            page.add(renewal)

            notifications = Adw.PreferencesGroup(title="Notifications")
            notifications.add(self.switch("notify", "Warn Before Tickets Expire", ""))
            notifications.add(self.spin("notify_before", "Warn Ahead", "Minutes before a ticket expires", 1, 240, 1))
            page.add(notifications)

            running = Adw.PreferencesGroup(title="Background",
                                           description="Tickets are only renewed while Kerberus is running.")
            self.background_row = self.switch("background", "Run in Background",
                                              "Keep running in the tray after the window is closed")
            running.add(self.background_row)
            self.autostart_row = Adw.SwitchRow(title="Start at Login", subtitle="In the background",
                                               active=autostart_enabled())
            self.autostart_row.connect("notify::active", lambda row, _p: set_autostart(row.get_active()))
            running.add(self.autostart_row)
            page.add(running)

            self.people = Adw.PreferencesGroup(title="Identities")
            page.add(self.people)
            self.people_rows = []
            self.fill_identities()

        def switch(self, key, title, subtitle):
            row = Adw.SwitchRow(title=title, subtitle=subtitle, active=self.app.settings[key])
            row.connect("notify::active", lambda r, _p: self.app.set_setting(key, r.get_active()))
            return row

        def spin(self, key, title, subtitle, low, high, step):
            row = Adw.SpinRow.new_with_range(low, high, step)
            row.set_title(title)
            row.set_subtitle(subtitle)
            row.set_value(self.app.settings[key])
            row.connect("notify::value", lambda r, _p: self.app.set_setting(key, int(r.get_value())))
            return row

        def kcm_changed(self, row, _param):
            if row.get_active() == self.app.settings["kcm"]:
                return
            self.app.set_kcm(row.get_active())
            # Prompts need Kerberus running, so turning them on turns these on too.
            self.background_row.set_active(self.app.settings["background"])
            self.autostart_row.set_active(autostart_enabled())
            self.add_toast(Adw.Toast.new("Log out and back in for apps to pick this up"))

        def fill_ignored(self):
            for row in self.ignored_rows:
                self.ignored.remove(row)
            self.ignored_rows = []
            ignored = self.app.settings["ignored_apps"]
            self.ignored.set_visible(bool(ignored))
            self.ignored.set_subtitle(", ".join(ignored))
            for program in ignored:
                info = app_info_for(program)
                row = Adw.ActionRow(title=info.get_display_name() if info else program, use_markup=False)
                again = Gtk.Button(label="Ask Again", valign=Gtk.Align.CENTER)
                again.add_css_class("flat")
                again.connect("clicked", self.ask_again, program)
                row.add_suffix(again)
                self.ignored.add_row(row)
                self.ignored_rows.append(row)

        def ask_again(self, _button, program):
            self.app.set_setting("ignored_apps", [p for p in self.app.settings["ignored_apps"] if p != program])
            self.fill_ignored()

        def fill_identities(self):
            for row in self.people_rows:
                self.people.remove(row)
            self.people_rows = []
            people = self.app.identities()
            self.people.set_description("" if people else "Identities you sign in as are listed here.")
            for principal in people:
                saved = principal in self.app.saved
                row = Adw.ActionRow(title=principal, use_markup=False,
                                    subtitle="Password saved in the keyring" if saved else "")
                row.add_prefix(Adw.Avatar(size=32, text=principal, show_initials=True))
                forget = Gtk.Button(label="Forget", valign=Gtk.Align.CENTER,
                                    tooltip_text="Remove from the list" + (" and forget the password" if saved else ""))
                forget.add_css_class("flat")
                forget.connect("clicked", self.forget, principal)
                row.add_suffix(forget)
                self.people.add(row)
                self.people_rows.append(row)

        def forget(self, _button, principal):
            self.app.forget_identity(principal)
            self.fill_identities()

    app = App()
    if not smoke_test:
        return app.run([sys.argv[0]])

    # --smoke-test: open every window and dialog against sample tickets, then quit.
    # Any exception in a callback fails the run.
    errors = []
    sys.excepthook = lambda *exc: (errors.append(exc), sys.__excepthook__(*exc))
    globals()["save_settings"] = lambda _settings: None  # leave the real settings alone
    app.settings = dict(DEFAULT_SETTINGS, identities=["carol@EXAMPLE.TEST"])
    now = dt.datetime.now()

    def stamp(t):
        return t.strftime("%m/%d/%y %H:%M:%S")

    sample = parse_klist(
        f"Ticket cache: FILE:/tmp/smoke-a\nDefault principal: alice@EXAMPLE.TEST\n\n"
        f"Valid starting     Expires            Service principal\n"
        f"{stamp(now - dt.timedelta(hours=1))}  {stamp(now + dt.timedelta(hours=9))}  krbtgt/EXAMPLE.TEST@EXAMPLE.TEST\n"
        f"\trenew until {stamp(now + dt.timedelta(days=6))}, Flags: FRIA\n"
        f"{stamp(now)}  {stamp(now + dt.timedelta(hours=9))}  HTTP/web.example.test@EXAMPLE.TEST\n\tFlags: FRA\n\n"
        f"Ticket cache: FILE:/tmp/smoke-b\nDefault principal: bob@EXAMPLE.TEST\n\n"
        f"Valid starting     Expires            Service principal\n"
        f"{stamp(now - dt.timedelta(hours=10))}  {stamp(now - dt.timedelta(minutes=5))}  krbtgt/EXAMPLE.TEST@EXAMPLE.TEST\n")
    sample[0].default = True

    def run_steps(steps):
        if not steps:
            app.quit()
            return False
        steps[0]()
        GLib.timeout_add(150, run_steps, steps[1:])
        return False

    def close_dialog():
        dialog = app.window.get_visible_dialog()
        if dialog:
            dialog.force_close()

    def close_picker():
        if app.picker:
            app.picker.close()

    def check_tray():
        tray = app.tray
        tray.update()
        layout = tray.layout(0)
        labels = [child.unpack()[1].get("label") for child in layout[2]]
        assert "Choose Identity…" in labels and "Quit" in labels, labels
        assert tray.pixmap(tray.icon), f"no pixmap for {tray.icon}"
        for name in ("IconName", "ToolTip", "Menu", "Status"):
            assert tray.item_property(None, None, None, None, name) is not None, name

    waiting = PromptRequest(KcmClient(1, "firefox", False), "bob@EXAMPLE.TEST", "0")

    def start():
        app.caches, app.saved, app.error = sample, {"alice@EXAMPLE.TEST"}, None
        app.show_window()
        app.window.update()
        run_steps([
            lambda: app.window.sign_in("alice@EXAMPLE.TEST"), close_dialog,
            lambda: app.window.change_password(None), close_dialog,
            app.show_preferences, close_dialog,
            app.show_about, close_dialog,
            app.window.confirm_destroy_all, close_dialog,
            lambda: (setattr(app, "prompt", waiting), app.show_prompt(waiting)), check_tray,
            lambda: app.picker.show_password("bob@EXAMPLE.TEST"), lambda: app.picker.show_password(None),
            lambda: app.picker.show_choices(), close_picker,
            lambda: app.open_picker(), check_tray, close_picker,
            lambda: (setattr(app, "error", MISSING_TOOLS), app.window.update()),
            lambda: (setattr(app, "error", None), setattr(app, "caches", []), app.window.update()),
        ])
        return False

    app.refresh = lambda then=None: None  # don't let real tickets replace the sample
    app.connect("activate", lambda *_: GLib.timeout_add(200, start))
    app.set_flags(app.get_flags() | Gio.ApplicationFlags.NON_UNIQUE)
    status = app.run([sys.argv[0]])
    if errors:
        print(f"smoke test: {len(errors)} error(s)", file=sys.stderr)
        return 1
    print("smoke test passed")
    return status


# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(prog="kerberus", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}\nKerberos tools: "
                        + (f"{TOOL_SOURCE} ({Path(TOOL_PATHS['kinit']).parent})" if TOOL_SOURCE else "not found"))
    parser.add_argument("--background", action="store_true", help="start without a window and keep renewing")
    parser.add_argument("--smoke-test", action="store_true", help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("list", help="show the credential caches and their tickets").add_argument(
        "--json", action="store_true", help="machine-readable output")
    get = sub.add_parser("get", help="get a ticket (kinit)")
    get.add_argument("principal", help="user or user@REALM")
    get.add_argument("--keytab", help="use a keytab instead of a password")
    get.add_argument("--lifetime", help="ticket lifetime, e.g. 10h")
    get.add_argument("--renewable", help="renewable lifetime, e.g. 7d")
    get.add_argument("--no-forwardable", action="store_true", help="don't ask for a forwardable ticket")
    get.add_argument("--remember", action="store_true", help="save the password in the keyring for automatic sign-in")
    for name, help_text in (("renew", "renew tickets"), ("destroy", "destroy tickets (kdestroy)")):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("principal", nargs="?", help="default: the default cache")
        p.add_argument("--all", action="store_true", help="every cache in the collection")
    sub.add_parser("switch", help="make a principal's cache the default (kswitch)").add_argument("principal")
    sub.add_parser("passwd", help="change a Kerberos password (kpasswd)").add_argument("principal", nargs="?")
    sub.add_parser("forget", help="remove a saved password from the keyring").add_argument("principal")
    watch = sub.add_parser("watch", help="renew tickets in the terminal, without a window")
    watch.add_argument("--interval", type=int, default=60, help="seconds between checks (default 60)")
    watch.add_argument("--once", action="store_true", help="check once and exit")
    watch.add_argument("--kcm", action="store_true",
                       help="also be the KCM credential cache (no sign-in prompts without the window)")
    args = parser.parse_args()
    if args.command is None:
        return gui(background=args.background, smoke_test=args.smoke_test)
    return cli(args)


if __name__ == "__main__":
    sys.exit(main())
