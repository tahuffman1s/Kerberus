#!/bin/sh
# Work out the next release from the commits since the last vX.Y.Z tag and
# print it for $GITHUB_OUTPUT:
#
#   version=1.4.0   tag=v1.4.0   release=true|false
#
# The bump is a patch release unless a commit since the last tag says otherwise:
#   minor: a subject starting "feat:" or "feat(scope):", or "[minor]" anywhere
#   major: "type!:" in a subject, "BREAKING CHANGE" in a body, or "[major]"
# "[skip release]" in the newest commit builds without releasing. The first release is 0.1.0.
#
# RELEASE=true (set by the workflow for pushes to main) is what allows a release;
# otherwise the version gets a -dev.<commit> suffix.
set -eu

last=$(git describe --tags --abbrev=0 --match 'v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null || true)
if [ -n "$last" ]; then
    range="$last..HEAD"
    base=${last#v}
else
    range=HEAD
    base=
fi
log=$(git log --format='%s%n%b' "$range")

if [ -z "$base" ]; then
    version=0.1.0
else
    major=${base%%.*}; rest=${base#*.}; minor=${rest%%.*}; patch=${rest#*.}
    if printf '%s\n' "$log" | grep -Eq '^[a-z]+(\([^)]*\))?!:|BREAKING CHANGE|\[major\]'; then
        version=$((major + 1)).0.0
    elif printf '%s\n' "$log" | grep -Eq '^feat(\([^)]*\))?:|\[minor\]'; then
        version=$major.$((minor + 1)).0
    else
        version=$major.$minor.$((patch + 1))
    fi
fi

release=false
if [ "${RELEASE:-false}" = true ] && [ -n "$(git rev-list "$range" 2>/dev/null)" ] &&
   ! git log -1 --format='%s%n%b' | grep -q '\[skip release\]'; then
    release=true
fi
if [ "$release" != true ]; then
    version="$version-dev.$(git rev-parse --short HEAD)"
fi

echo "version=$version"
echo "tag=v$version"
echo "release=$release"
