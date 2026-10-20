# Kerberus

A GTK 4 / libadwaita app for Kerberos tickets: see what's in your credential
caches, sign in, renew, switch principals, change your password and destroy
tickets, and keep tickets renewed in the background so they don't run out in the
middle of the day.

<p align="center">
  <img src="docs/screenshot.png" width="420" alt="The main window with two principals">
  <img src="docs/sign-in.png" width="420" alt="Getting a ticket">
</p>

Kerberus drives the MIT Kerberos tools (`kinit`, `klist`, `kdestroy`, `kswitch`,
`kpasswd`), so it uses the machine's own `krb5.conf` and credential caches
(`FILE:`, `DIR:`, `KEYRING:` or `KCM:`): tickets it gets are the ones every other
program sees. The AppImage also carries its own copies of the tools, used when the
host has none.

## Install

Download `Kerberus-<version>-x86_64.AppImage` from the
[latest release](https://github.com/tahuffman1s/kerberus/releases/latest), then

```sh
chmod +x Kerberus-*-x86_64.AppImage
./Kerberus-*-x86_64.AppImage
```

It needs glibc 2.39 or newer (Ubuntu 24.04, Debian 13, Fedora 40, current Arch or
openSUSE Tumbleweed) and the usual desktop libraries (Mesa/GL, Vulkan loader,
fontconfig, X11/Wayland client libraries). Each release also has a `.zsync` file,
so [Gear Lever](https://flathub.org/apps/it.mijorus.gearlever) or
AppImageUpdate can update it in place.

On NixOS, turn on `programs.appimage = { enable = true; binfmt = true; };` and
run it as above, and add `krb5` to `environment.systemPackages` if you want the
system's tools used rather than the bundled ones.

## Using it

- **Get Ticket** (`Ctrl+N`) signs in with a password. *Remember Password* saves it
  in the keyring (GNOME Keyring or KWallet, through the Secret Service) so Kerberus
  can sign in again by itself when a ticket can't be renewed any more.
- Each principal shows how long its ticket-granting ticket is valid, how long it can
  be renewed, its flags and its service tickets. The ⋮ menu makes a principal the
  default, changes its password, forgets its saved password or destroys its tickets.
- If the password has expired, signing in offers to change it, then signs in with
  the new one.

**Renewal.** While it runs, Kerberus checks every 30 seconds. A renewable ticket is
renewed when it has less than an hour left (*Preferences → Renew Ahead*), or half
way through its life if that is sooner. When it can't be renewed (not renewable,
or past its renew-until time) and a password is saved, Kerberus signs in again. A
saved password that the KDC rejects is not tried again until you sign in by hand,
so a changed password can't lock your account. Otherwise you get a notification
before the ticket expires (*Warn Ahead*).

**Background.** Tickets are only renewed while Kerberus is running. *Run in
Background* keeps it running after the window is closed (quit from the menu or
with `Ctrl+Q`), and *Start at Login* adds an autostart entry that starts it hidden.

### Command line

The same things work from a terminal, without a window:

```
kerberus list [--json]                  caches and tickets
kerberus get alice [--remember]         sign in (reads the password from the terminal or stdin)
kerberus get svc/host --keytab FILE     sign in with a keytab
kerberus renew [PRINCIPAL | --all]
kerberus switch PRINCIPAL               make it the default (kswitch)
kerberus passwd [PRINCIPAL]
kerberus destroy [PRINCIPAL | --all]
kerberus forget PRINCIPAL               remove a saved password
kerberus watch [--once]                 renew in the foreground (e.g. a systemd user service)
kerberus --background                   start hidden and keep renewing
```

With the AppImage, run it as `./Kerberus-*.AppImage list`, and so on.
`KERBERUS_TOOLS=host` or `KERBERUS_TOOLS=bundled` picks which Kerberos tools
the AppImage uses; `kerberus --version` says which it found.

Settings live in `~/.config/kerberus/settings.json`.

## Releases

[`.github/workflows/build.yml`](.github/workflows/build.yml) runs on every push and
pull request: unit tests, integration tests against a throwaway KDC, the AppImage
build, a smoke test of the window under Xvfb, and the integration tests again
against the AppImage (with the host's Kerberos tools and with its own). The
AppImage is uploaded as a workflow artifact.

A push to `main` that passes is released: the workflow tags the next version and
publishes a GitHub release with the AppImage and its `.zsync`. The version comes
from the commits since the last tag ([`packaging/next-version.sh`](packaging/next-version.sh)):

| Commits since the last tag contain                                    | Release        |
| --------------------------------------------------------------------- | -------------- |
| nothing special                                                       | 1.4.2 → 1.4.3  |
| a subject starting `feat:`, or `[minor]` anywhere                     | 1.4.2 → 1.5.0  |
| `type!:` in a subject, `BREAKING CHANGE` in a body, or `[major]`      | 1.4.2 → 2.0.0  |

`[skip release]` in the pushed commit builds without releasing. Changes to
Markdown files and `LICENSE` alone don't start a build. The first release is 0.1.0.

## Development

Everything is in [`kerberus.py`](kerberus.py): the Kerberos tool wrappers and
`klist` parsing, the renewal logic shared by the window and `kerberus watch`, the
CLI, and the GUI. Run it from a checkout with the distro's PyGObject, GTK 4,
libadwaita (1.5 or newer) and libsecret typelibs installed:

```sh
python3 kerberus.py
python3 -m unittest discover -s tests          # no KDC needed
tests/integration.sh python3 kerberus.py        # starts its own KDC; needs krb5-kdc and krb5-admin-server
```

The integration test runs `krb5kdc` and `kadmind` as your user on ports
18888–18890 (`KDC_PORT=` moves them) with everything in a temporary directory, so
it doesn't touch `/etc/krb5.conf` or your tickets.

### Building the AppImage

On Ubuntu 24.04 (what the workflow runs on):

```sh
sudo packaging/appimage/deps.sh
packaging/appimage/build.sh 1.2.3        # -> dist/Kerberus-1.2.3-x86_64.AppImage
```

[`build.sh`](packaging/appimage/build.sh) copies the distro's Python, PyGObject,
the GObject introspection typelibs the app uses (and the libraries they name),
the SVG pixbuf loader, the Adwaita symbolic icons and the Kerberos tools into an
AppDir. [`bundle_libs.py`](packaging/appimage/bundle_libs.py) follows each ELF's
`DT_NEEDED` entries to bundle what they link against and sets every RUNPATH to
`usr/lib`, leaving glibc, graphics drivers and the other libraries on the AppImage
project's excludelist to the host. [`AppRun`](packaging/appimage/AppRun) points
GTK and GObject introspection at the bundle and saves the host's values of what it
changes, which `kerberus.py` restores for the Kerberos tools it runs. Then
appimagetool packs it.

## License

MIT
