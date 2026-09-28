#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${RELEASE_OUT:-$ROOT/build/release-v1.1.0-pre2}

VERSION=v1.1.0-pre2 \
RELEASE_OUT="$OUT" \
RELEASE_SUMS="$OUT/SHA256SUMS-v1.1.0-pre2-V65x.txt" \
RELEASE_DOC="$ROOT/docs/RELEASE_PRE2.md" \
exec "$ROOT/tools/package-v65x-pre1.sh"
