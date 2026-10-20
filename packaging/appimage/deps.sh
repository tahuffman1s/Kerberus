#!/bin/sh
# Packages build.sh and the tests need on Ubuntu 24.04 (the GitHub runner).
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    python3 python3-gi gir1.2-glib-2.0 gir1.2-girepository-2.0 gir1.2-gtk-4.0 gir1.2-adw-1 gir1.2-secret-1 \
    libgdk-pixbuf2.0-bin librsvg2-common adwaita-icon-theme hicolor-icon-theme libglib2.0-bin \
    krb5-user krb5-kdc krb5-admin-server \
    patchelf file zsync desktop-file-utils appstream curl ca-certificates \
    xvfb xauth xdotool dbus-x11
