#!/usr/bin/env bash
set -euxo pipefail

V8_DIR=${1:-"/content/v8"}
URL=${2:-"https://www.googleapis.com/download/storage/v1/b/v8-asan/o/linux-debug%2Fd8-arm-asan-linux-debug-v8-component-105103.zip?generation=1770313642314492&alt=media"}

mkdir -p "$V8_DIR"
cd "$V8_DIR"
rm -rf "$V8_DIR"/*

wget -O d8-asan.zip "$URL"
unzip -o d8-asan.zip

D8_BIN_PATH=$(find . -type f -name d8 -print -quit)
if [ -z "$D8_BIN_PATH" ]; then
  echo "❌ d8 binary not found after unzipping!" >&2
  exit 1
fi

chmod +x "$D8_BIN_PATH"

echo "d8 path: $V8_DIR/$D8_BIN_PATH"
file "$D8_BIN_PATH" || true
