#!/bin/bash

# Configuration
NDK_HOME="/home/xhc/android-ndk-r25c"
HOST_TAG="linux-x86_64" # Adjust if on macOS (darwin-x86_64) or Windows (windows-x86_64)
MIN_SDK="24"

# Toolchain paths
TOOLCHAIN="$NDK_HOME/toolchains/llvm/prebuilt/$HOST_TAG"
BIN="$TOOLCHAIN/bin"

# Export environment variables for cc-rs and cargo
export PATH="$BIN:$PATH"

# Set C compilers for cross-compilation (used by cc crate)
export CC_aarch64_linux_android="$BIN/aarch64-linux-android$MIN_SDK-clang"
export AR_aarch64_linux_android="$BIN/llvm-ar"
export CXX_aarch64_linux_android="$BIN/aarch64-linux-android$MIN_SDK-clang++"

export CC_armv7_linux_androideabi="$BIN/armv7a-linux-androideabi$MIN_SDK-clang"
export AR_armv7_linux_androideabi="$BIN/llvm-ar"
export CXX_armv7_linux_androideabi="$BIN/armv7a-linux-androideabi$MIN_SDK-clang++"

export CC_x86_64_linux_android="$BIN/x86_64-linux-android$MIN_SDK-clang"
export AR_x86_64_linux_android="$BIN/llvm-ar"
export CXX_x86_64_linux_android="$BIN/x86_64-linux-android$MIN_SDK-clang++"

export CC_i686_linux_android="$BIN/i686-linux-android$MIN_SDK-clang"
export AR_i686_linux_android="$BIN/llvm-ar"
export CXX_i686_linux_android="$BIN/i686-linux-android$MIN_SDK-clang++"

# Build for aarch64 (default)
echo "Building for aarch64-linux-android..."
cargo build --target aarch64-linux-android --release

# Note: Add target if missing: rustup target add aarch64-linux-android
