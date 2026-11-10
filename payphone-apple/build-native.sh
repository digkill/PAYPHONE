#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"
cargo_bin="${CARGO_BIN:-cargo}"
export MACOSX_DEPLOYMENT_TARGET=13.0
export IPHONEOS_DEPLOYMENT_TARGET=16.0
# Include device and simulator libraries by default; --macos is useful for local tests.
targets=(aarch64-apple-darwin x86_64-apple-darwin aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)
if [[ "${1:-}" == --macos ]]; then targets=(aarch64-apple-darwin); fi
for target in "${targets[@]}"; do
  "$cargo_bin" build --locked -p payphone-mobile --release --target "$target"
done
headers="$repo/payphone-mobile/include"
args=(-library "$repo/target/aarch64-apple-darwin/release/libpayphone_mobile.a" -headers "$headers")
if [[ "${1:-}" != --macos ]]; then
  universal="$repo/target/payphone-apple-universal"
  mkdir -p "$universal/macos" "$universal/simulator"
  lipo -create "$repo/target/aarch64-apple-darwin/release/libpayphone_mobile.a" \
    "$repo/target/x86_64-apple-darwin/release/libpayphone_mobile.a" -output "$universal/macos/libpayphone_mobile.a"
  lipo -create "$repo/target/aarch64-apple-ios-sim/release/libpayphone_mobile.a" \
    "$repo/target/x86_64-apple-ios/release/libpayphone_mobile.a" -output "$universal/simulator/libpayphone_mobile.a"
  args=(-library "$universal/macos/libpayphone_mobile.a" -headers "$headers"
    -library "$repo/target/aarch64-apple-ios/release/libpayphone_mobile.a" -headers "$headers"
    -library "$universal/simulator/libpayphone_mobile.a" -headers "$headers")
fi
out="$repo/payphone-apple/PayphoneKit/Native/CPayphoneNative.xcframework"
mkdir -p "$(dirname "$out")"
if [[ -d "$out" ]]; then rm -r "$out"; fi
xcodebuild -create-xcframework "${args[@]}" -output "$out"
