#!/bin/sh

set -eu

TARGET="$1"
TARGET_DIR="target"
OUT_DIR="golem"

cargo build --bin theseusg \
	--release \
	--target "$TARGET" \
	--target-dir "$TARGET_DIR"

mkdir -p "$OUT_DIR"
cp "$TARGET_DIR/$TARGET/release/theseusg" "$OUT_DIR/theseusg:$TARGET"
