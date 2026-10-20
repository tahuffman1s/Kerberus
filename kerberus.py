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
    kerberus watch [--once]               renew in the terminal, without a window

It drives the MIT Kerberos tools (kinit, klist, kdestroy, kswitch, kpasswd), so it
uses the machine's krb5.conf and credential caches. The AppImage carries its own
copies of the tools for machines that don't have them installed.
"""

import argparse
import datetime as dt
import getpass
import json
import os
import re
import shutil
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
    "background": False,      # keep running (and renewing) after the window is closed
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
    messages in the C locale so klist's output can be parsed."""
    env = dict(os.environ)
    if env.pop("KERBERUS_APPDIR", None):
        for name in APPIMAGE_VARS:
            env.pop(name, None)
            saved = env.pop(f"KERBERUS_HOST_{name}", None)
            if saved is not None:
                env[name] = saved
    env["LC_ALL"] = "C"
    return env


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
            self.maintaining = False
            self.failed = set()       # principals whose saved password was rejected
            self.told = set()         # notifications already sent

        def do_startup(self):
            Adw.Application.do_startup(self)
            Gtk.Window.set_default_icon_name(APP_ID)
            icons = Path(__file__).resolve().parent / "data" / "icons"
            if icons.is_dir():
                Gtk.IconTheme.get_for_display(Gdk.Display.get_default()).add_search_path(str(icons))
            for action in (plain_action("quit", self.quit), plain_action("refresh", self.refresh),
                           plain_action("preferences", self.show_preferences), plain_action("about", self.show_about),
                           plain_action("show", self.show_window), target_action("sign-in", self.sign_in_from_notification)):
                self.add_action(action)
            self.set_accels_for_action("app.quit", ["<Control>q"])
            self.set_accels_for_action("app.refresh", ["<Control>r", "F5"])
            self.set_accels_for_action("app.preferences", ["<Control>comma"])
            self.set_accels_for_action("win.get-ticket", ["<Control>n"])
            self.set_accels_for_action("window.close", ["<Control>w"])
            if self.start_hidden or self.settings["background"]:
                self.set_held(True)
            GLib.timeout_add_seconds(30, self.tick)

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

        def tick(self):
            self.refresh(then=self.maintain)
            return True

        def refresh(self, then=None):
            if self.refreshing:
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
                if then:
                    then()
            in_thread(work, done)

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

        def send_ticket_notice(self, cache, text):
            note = Gio.Notification.new("Kerberos ticket")
            note.set_body(text)
            note.set_default_action("app.show")
            note.add_button_with_target("Sign In…", "app.sign-in", GLib.Variant("s", cache.principal))
            self.send_notification(f"ticket-{cache.principal}", note)

        def signed_in(self, principal):
            self.failed.discard(principal)
            self.withdraw_notification(f"ticket-{principal}")
            self.settings["last_principal"] = principal
            save_settings(self.settings)

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

    class Preferences(Adw.PreferencesDialog):
        def __init__(self, app):
            super().__init__()
            self.app = app
            page = Adw.PreferencesPage(title="General", icon_name="preferences-system-symbolic")
            self.add(page)

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
            running.add(self.switch("background", "Run in Background", "Keep renewing after the window is closed"))
            autostart = Adw.SwitchRow(title="Start at Login", subtitle="In the background",
                                      active=autostart_enabled())
            autostart.connect("notify::active", lambda row, _p: set_autostart(row.get_active()))
            running.add(autostart)
            page.add(running)

            self.passwords = Adw.PreferencesGroup(title="Saved Passwords")
            page.add(self.passwords)
            self.password_rows = []
            self.fill_passwords()

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

        def fill_passwords(self):
            for row in self.password_rows:
                self.passwords.remove(row)
            self.password_rows = []
            if not self.app.keyring.available:
                self.passwords.set_description("No keyring is available (libsecret is missing).")
                return
            saved = sorted(self.app.saved)
            self.passwords.set_description("" if saved else "Turn on Remember Password when you sign in to save one.")
            for principal in saved:
                row = Adw.ActionRow(title=principal, use_markup=False)
                forget = Gtk.Button(label="Forget", valign=Gtk.Align.CENTER)
                forget.add_css_class("flat")
                forget.connect("clicked", self.forget, principal)
                row.add_suffix(forget)
                self.passwords.add(row)
                self.password_rows.append(row)

        def forget(self, _button, principal):
            self.app.keyring.forget(principal)
            self.app.saved.discard(principal)
            self.fill_passwords()
            self.app.refresh()

    app = App()
    if not smoke_test:
        return app.run([sys.argv[0]])

    # --smoke-test: open every window and dialog against sample tickets, then quit.
    # Any exception in a callback fails the run.
    errors = []
    sys.excepthook = lambda *exc: (errors.append(exc), sys.__excepthook__(*exc))
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
    args = parser.parse_args()
    if args.command is None:
        return gui(background=args.background, smoke_test=args.smoke_test)
    return cli(args)


if __name__ == "__main__":
    sys.exit(main())
