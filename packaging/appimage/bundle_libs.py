#!/usr/bin/env python3
"""Copy the shared libraries an AppDir's ELF files need into APPDIR/usr/lib and
point every ELF's RUNPATH there.

    bundle_libs.py APPDIR EXCLUDE-REGEX [SONAME...]

Walks DT_NEEDED entries (not ldd's flattened closure), so libraries only needed
by excluded ones (which come from the host) aren't bundled or required. Extra
SONAMEs are libraries loaded with dlopen, such as those GObject introspection
typelibs name. Exits non-zero if a needed library can't be found.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


def is_elf(path):
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def needed(path):
    out = subprocess.run(["readelf", "-d", str(path)], capture_output=True, text=True, check=False).stdout
    return re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", out)


def system_libraries():
    """soname -> path for this machine's architecture, from the ld.so cache."""
    machine = os.uname().machine
    tag = {"x86_64": "x86-64", "aarch64": "AArch64"}.get(machine, machine)
    libs = {}
    out = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        m = re.match(r"\s*(\S+) \(([^)]*)\) => (\S+)", line)
        if m and tag in m.group(2):
            libs.setdefault(m.group(1), m.group(3))
    return libs


def main():
    appdir, exclude, extra = Path(sys.argv[1]).resolve(), re.compile(sys.argv[2]), sys.argv[3:]
    libdir = appdir / "usr" / "lib"
    system = system_libraries()
    missing = []
    queue = [p for p in appdir.rglob("*") if p.is_file() and not p.is_symlink() and is_elf(p)]
    wanted = [(soname, "dlopen") for soname in extra]
    for elf in queue:
        wanted += [(soname, elf) for soname in needed(elf)]
    while wanted:
        soname, by = wanted.pop()
        if exclude.match(soname) or (libdir / soname).exists():
            continue
        source = system.get(soname)
        if not source:
            missing.append(f"{soname} (needed by {by})")
            continue
        shutil.copy2(os.path.realpath(source), libdir / soname)
        os.chmod(libdir / soname, 0o755)
        queue.append(libdir / soname)
        print(f"  {soname}  <- {Path(by).name if by != 'dlopen' else by}")
        wanted += [(dep, libdir / soname) for dep in needed(libdir / soname)]
    for elf in queue:
        rel = os.path.relpath(libdir, elf.parent)
        rpath = "$ORIGIN" if rel == "." else f"$ORIGIN/{rel}"
        subprocess.run(["patchelf", "--set-rpath", rpath, str(elf)], check=True)
    if missing:
        print("Libraries not found:\n  " + "\n  ".join(sorted(set(missing))), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
