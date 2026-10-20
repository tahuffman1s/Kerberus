#!/usr/bin/env bash
# Build dist/Kerberus-<version>-<arch>.AppImage.
#
#   packaging/appimage/build.sh [VERSION]
#
# Runs on Ubuntu 24.04 (the GitHub runner) with the packages from deps.sh. The
# AppImage carries the distro's Python, PyGObject, GTK 4, libadwaita, libsecret
# and MIT Kerberos tools, with every bundled ELF's RUNPATH pointing at usr/lib.
# glibc, graphics drivers and a few libraries every desktop has (the AppImage
# project's excludelist) come from the host, so it needs glibc 2.39 or newer.
set -euo pipefail

VERSION=${1:-0.0.0-dev}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
HERE=$ROOT/packaging/appimage
ARCH=$(uname -m)
BUILD=$ROOT/build
APPDIR=$BUILD/AppDir
DIST=$ROOT/dist
APP_ID=io.github.tahuffman1s.Kerberus
REPO=${GITHUB_REPOSITORY:-tahuffman1s/kerberus}
APPIMAGETOOL_VERSION=1.9.0
OUTPUT=$DIST/Kerberus-$VERSION-$ARCH.AppImage

# Libraries taken from the host instead of bundled: glibc, GL/Vulkan drivers and
# what they pull in, and libraries whose config or protocol must match the host's.
EXCLUDE='^(ld-linux.*|libc|libm|libdl|libpthread|librt|libresolv|libutil|libanl|libnsl|libmvec|libBrokenLocale|libthread_db|libnss_[a-z]+|libGL|libGLX|libGLdispatch|libOpenGL|libEGL|libGLESv[12]_CM|libGLESv2|libgbm|libdrm|libglapi|libvulkan|libxcb|libX11|libX11-xcb|libxshmfence|libwayland-(client|server|egl|cursor)|libfontconfig|libfreetype|libharfbuzz|libexpat|libz|libgcc_s|libstdc\+\+|libcom_err|libgpg-error|libuuid|libasound|libjack|libp11-kit|libusb-1\.0|libICE|libSM|libgmp|libthai|libdatrie)\.so'

# The system Python that PyGObject is built for (python3 may be another version).
PYTHON=
for candidate in ${PYTHON_FOR_BUILD:-} /usr/bin/python3 /usr/bin/python3.12; do
    if [ -x "$candidate" ] && "$candidate" -c 'import gi' 2>/dev/null; then
        PYTHON=$candidate
        break
    fi
done
[ -n "$PYTHON" ] || { echo "no system Python with PyGObject; run deps.sh" >&2; exit 1; }
PYVER=$("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
MULTIARCH=$("$PYTHON" -c 'import sysconfig; print(sysconfig.get_config_var("MULTIARCH"))')
SYSLIB=/usr/lib/$MULTIARCH

echo "== Kerberus $VERSION for $ARCH (Python $PYVER)"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/lib" "$APPDIR/usr/share" "$APPDIR/usr/lib/gio/modules" "$DIST"

echo "== App and desktop files"
install -Dm644 "$ROOT/kerberus.py" "$APPDIR/usr/share/kerberus/kerberus.py"
sed -i "s/^VERSION = .*/VERSION = \"$VERSION\"/" "$APPDIR/usr/share/kerberus/kerberus.py"
grep -q "^VERSION = \"$VERSION\"$" "$APPDIR/usr/share/kerberus/kerberus.py"
install -Dm644 "$ROOT/data/$APP_ID.desktop" "$APPDIR/usr/share/applications/$APP_ID.desktop"
install -Dm644 "$ROOT/data/icons/hicolor/scalable/apps/$APP_ID.svg" \
    "$APPDIR/usr/share/icons/hicolor/scalable/apps/$APP_ID.svg"
install -Dm644 "$ROOT/data/$APP_ID.metainfo.xml" "$APPDIR/usr/share/metainfo/$APP_ID.appdata.xml"
sed -i "s|<releases>|<releases>\n    <release version=\"$VERSION\" date=\"$(date -u +%Y-%m-%d)\"/>|" \
    "$APPDIR/usr/share/metainfo/$APP_ID.appdata.xml"
cp "$APPDIR/usr/share/applications/$APP_ID.desktop" "$APPDIR/usr/share/icons/hicolor/scalable/apps/$APP_ID.svg" "$APPDIR/"
install -m755 "$HERE/AppRun" "$APPDIR/AppRun"

echo "== Python"
install -m755 "$(readlink -f "$PYTHON")" "$APPDIR/usr/bin/python3"
cp -rL "/usr/lib/python$PYVER" "$APPDIR/usr/lib/"
( cd "$APPDIR/usr/lib/python$PYVER" &&
  rm -rf test idlelib tkinter turtledemo ensurepip lib2to3 pydoc_data venv config-* site-packages dist-packages \
         curses dbm sqlite3 lib-dynload/{_curses,_curses_panel,_dbm,_gdbm,readline,_sqlite3,_tkinter}.* )
mkdir -p "$APPDIR/usr/lib/python3/dist-packages"
cp -rL /usr/lib/python3/dist-packages/gi "$APPDIR/usr/lib/python3/dist-packages/"
find "$APPDIR/usr/lib" -name __pycache__ -type d -prune -exec rm -rf {} +

echo "== Kerberos tools"
for tool in kinit klist kdestroy kswitch kpasswd; do
    install -m755 "$(command -v "$tool")" "$APPDIR/usr/bin/$tool"
done

echo "== GObject introspection"
# Typelibs and the libraries they load by name (invisible to ldd).
mkdir -p "$APPDIR/usr/lib/girepository-1.0"
gi_libs=()
while read -r kind value; do
    case $kind in
        typelib) cp "$value" "$APPDIR/usr/lib/girepository-1.0/" ;;
        lib) gi_libs+=("$value") ;;
    esac
done < <("$PYTHON" - <<'EOF'
import gi
gi.require_version("GIRepository", "2.0")
from gi.repository import GIRepository
repo = GIRepository.Repository.get_default()
for namespace, version in (("Gtk", "4.0"), ("Adw", "1"), ("Secret", "1")):
    repo.require(namespace, version, 0)
for namespace in repo.get_loaded_namespaces():
    print("typelib", repo.get_typelib_path(namespace))
    for lib in filter(None, (repo.get_shared_library(namespace) or "").split(",")):
        print("lib", lib)
EOF
)

echo "== GDK pixbuf loaders, GSettings schemas, icons"
loaders=$APPDIR/usr/lib/gdk-pixbuf-2.0/loaders
mkdir -p "$loaders"
cp "$SYSLIB"/gdk-pixbuf-2.0/2.10.0/loaders/libpixbufloader-{svg,png,jpeg,gif,ico,bmp,xpm}.so "$loaders/" 2>/dev/null || true
[ -e "$loaders/libpixbufloader-svg.so" ] || { echo "the SVG pixbuf loader (librsvg2-common) is missing" >&2; exit 1; }
"$SYSLIB/gdk-pixbuf-2.0/gdk-pixbuf-query-loaders" "$loaders"/*.so | sed "s|$APPDIR|@APPDIR@|g" \
    > "$APPDIR/usr/lib/gdk-pixbuf-2.0/loaders.cache.in"
grep -q '@APPDIR@/usr/lib/gdk-pixbuf-2.0/loaders/libpixbufloader-svg.so' "$APPDIR/usr/lib/gdk-pixbuf-2.0/loaders.cache.in"

mkdir -p "$APPDIR/usr/share/glib-2.0/schemas"
cp /usr/share/glib-2.0/schemas/org.gtk.gtk4.*.gschema.xml "$APPDIR/usr/share/glib-2.0/schemas/"
glib-compile-schemas "$APPDIR/usr/share/glib-2.0/schemas"

mkdir -p "$APPDIR/usr/share/icons/Adwaita"
cp /usr/share/icons/Adwaita/index.theme "$APPDIR/usr/share/icons/Adwaita/"
cp -r /usr/share/icons/Adwaita/symbolic "$APPDIR/usr/share/icons/Adwaita/"
cp /usr/share/icons/hicolor/index.theme "$APPDIR/usr/share/icons/hicolor/"

echo "== Libraries"
gi_sonames=$(printf '%s\n' "${gi_libs[@]}" | sort -u)
# shellcheck disable=SC2086
"$PYTHON" "$HERE/bundle_libs.py" "$APPDIR" "$EXCLUDE" $gi_sonames

echo "== Checking the bundle loads with nothing but excluded libraries from the host"
problems=0
while read -r elf; do
    if env -i ldd "$elf" 2>&1 | grep -q "not found"; then
        echo "  $elf:"; env -i ldd "$elf" | grep "not found"
        problems=$((problems + 1))
    fi
done < <(find "$APPDIR" -type f \( -name '*.so*' -o -path '*/usr/bin/*' \))
[ "$problems" = 0 ] || exit 1

echo "== Precompiling Python"
"$APPDIR/usr/bin/python3" -I -c 'import sys; assert sys.prefix.startswith(sys.argv[1]), sys.prefix' "$APPDIR"
"$APPDIR/usr/bin/python3" -I -m compileall -q -j0 --invalidation-mode unchecked-hash \
    "$APPDIR/usr/lib/python$PYVER" "$APPDIR/usr/lib/python3/dist-packages" "$APPDIR/usr/share/kerberus" >/dev/null

echo "== Validating metadata"
desktop-file-validate "$APPDIR/usr/share/applications/$APP_ID.desktop"
appstreamcli validate --no-net --explain "$APPDIR/usr/share/metainfo/$APP_ID.appdata.xml"

echo "== appimagetool"
tool=$BUILD/tools/appimagetool-$APPIMAGETOOL_VERSION-$ARCH.AppImage
if [ ! -x "$tool" ]; then
    mkdir -p "$BUILD/tools"
    curl -fsSL -o "$tool.part" \
        "https://github.com/AppImage/appimagetool/releases/download/$APPIMAGETOOL_VERSION/appimagetool-$ARCH.AppImage"
    chmod +x "$tool.part"
    mv "$tool.part" "$tool"
fi
rm -f "$OUTPUT" "$OUTPUT.zsync"
(cd "$DIST" && ARCH=$ARCH APPIMAGE_EXTRACT_AND_RUN=1 "$tool" --no-appstream \
    -u "gh-releases-zsync|${REPO%%/*}|${REPO##*/}|latest|Kerberus-*-$ARCH.AppImage.zsync" \
    "$APPDIR" "$OUTPUT")
ls -lh "$DIST"
