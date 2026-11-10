#!/usr/bin/env bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/../.." && pwd)"
sdk="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Library/Android/sdk}}"
ndk="${ANDROID_NDK_HOME:-$(find -L "$sdk/ndk" -mindepth 1 -maxdepth 1 -type d | sort | tail -1)}"
host=darwin-x86_64
if [[ "$(uname -s)" == Linux ]]; then host=linux-x86_64; fi
toolchain="$ndk/toolchains/llvm/prebuilt/$host/bin"
cargo_bin="${CARGO_BIN:-cargo}"
target="${1:-aarch64-linux-android}"
case "$target" in
  aarch64-linux-android) abi=arm64-v8a; triple=aarch64-linux-android ;;
  x86_64-linux-android) abi=x86_64; triple=x86_64-linux-android ;;
  *) echo "Supported targets: aarch64-linux-android, x86_64-linux-android" >&2; exit 1 ;;
esac
linker="$toolchain/${triple}26-clang"
if [[ ! -x "$linker" ]]; then echo "NDK compiler missing: $linker (set ANDROID_NDK_HOME)" >&2; exit 1; fi
upper="$(echo "$target" | tr 'a-z-' 'A-Z_')"
lower="${target//-/_}"
cd "$repo"
env "CARGO_TARGET_${upper}_LINKER=$linker" "CC_${lower}=$linker" \
  "AR_${lower}=$toolchain/llvm-ar" \
  "CARGO_TARGET_${upper}_RUSTFLAGS=-C link-arg=-Wl,-z,max-page-size=16384" \
  "$cargo_bin" build --locked -p payphone-mobile --release --target "$target"
out="$repo/payphone-android/app/src/main/jniLibs/$abi"
mkdir -p "$out"
cp "target/$target/release/libpayphone_mobile.so" "$out/"
"$linker" -shared -fPIC -Wl,-z,max-page-size=16384 \
  -I"$repo/payphone-mobile/include" "$repo/payphone-android/native/jni.c" \
  -L"$out" -lpayphone_mobile -o "$out/libpayphone_jni.so"
echo "Built QUIC libraries for $abi"
