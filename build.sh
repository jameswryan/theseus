#!/bin/sh

set -eu

TARGET="$1"
TARGET_DIR="target"
OUT_DIR="target/bins"

cargo build \
	--release \
	--target "$TARGET" \
	--target-dir "$TARGET_DIR"

mkdir -p "$OUT_DIR"
for bin in theseus theseusg; do
  cp "$TARGET_DIR/$TARGET/release/$bin" "$OUT_DIR/$bin:$TARGET"
done
