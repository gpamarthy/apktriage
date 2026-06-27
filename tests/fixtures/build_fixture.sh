#!/usr/bin/env bash
# Rebuild the deterministic benign fixture APK from committed source.
# Requires apktool and a C compiler on PATH. See README.md for what it plants.
set -euo pipefail
cd "$(dirname "$0")"

if command -v aarch64-linux-gnu-gcc >/dev/null 2>&1; then
    CC=aarch64-linux-gnu-gcc
else
    CC=gcc
    echo "note: aarch64 cross-compiler absent, building host-arch .so"
fi

mkdir -p src/lib/arm64-v8a
"$CC" -shared -fPIC -o src/lib/arm64-v8a/libdemo.so src/libdemo.c

rm -f benign_sample.apk
apktool b src -o benign_sample.apk
echo "built: $(ls -la benign_sample.apk)"
