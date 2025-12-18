# Linker Project with xDL

This project demonstrates how to compile a Rust executable for Android that links against the `xDL` library (C code).

## Prerequisites

1.  **Rust Toolchain**: Ensure `rustup` and `cargo` are installed.
2.  **Android NDK**: Located at `/home/xhc/android-ndk-r25c` (as configured).
3.  **Android Targets**: Install the Rust target for Android:
    ```bash
    rustup target add aarch64-linux-android
    ```

## Build Instructions

### Using the Build Script (Recommended)

A helper script `build_android.sh` is provided to set up the environment variables required by the `cc` crate to find the C compiler.

1.  Make the script executable:
    ```bash
    chmod +x build_android.sh
    ```
2.  Run the build:
    ```bash
    ./build_android.sh
    ```
    The output binary will be located at `target/aarch64-linux-android/release/linker`.

### Manual Build

If you prefer to run manually, ensure you export the `CC` and `AR` environment variables for the target architecture so that `build.rs` can compile the C sources using the NDK Clang.

```bash
export NDK_HOME="/home/xhc/android-ndk-r25c"
export PATH="$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"
export CC_aarch64_linux_android="aarch64-linux-android30-clang"
export AR_aarch64_linux_android="llvm-ar"

cargo build --target aarch64-linux-android --release
```

## Project Structure

*   `src/main.rs`: Rust entry point. Calls `xdl_iterate_phdr`.
*   `src/xdl/`: Source code for xDL library.
*   `build.rs`: Cargo build script that compiles xDL using the `cc` crate.
*   `.cargo/config.toml`: Configures the linker for Rust code generation.
