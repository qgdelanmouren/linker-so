# Custom In-Memory Linker (Android)



This crate builds an Android `cdylib` that acts as a **custom in-memory ELF loader/linker**.

It embeds one or more target `.so` files into the Rust library, loads them from memory, recursively loads their `DT_NEEDED` dependencies (embedded or system), performs relocations, runs constructors (`.init` / `.init_array`), and optionally forwards JNI entrypoints.

## Prerequisites

- **Rust toolchain**
  - Install Rust + Cargo (via `rustup`).
- **Android NDK**
  - This repo uses `build_android.bat` (Windows) and expects a valid `NDK_HOME`.
- **Rust Android targets**

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
```

## Embedded libraries layout

Embedded `.so` files live under:

```
src/libs/<abi>/*.so
```

Supported ABI directory names:

- **arm64-v8a**
- **armeabi-v7a**
- **x86_64**
- **x86**

## Main library selection (`src/libs/config`)

The main embedded library is configured by:

```
src/libs/config
```

Format:

```ini
main=libmain.so
```

Notes:

- The name must match a file under `src/libs/<abi>/`.
- During Android builds, `build.rs` validates that the configured main library exists for the current ABI.

## Build (Windows)

Use the provided script:

```bat
./build_android.bat
```

What it does:

- Builds 4 ABIs.
- Copies the produced `liblinker.so` and **renames it to the configured main library name**.

Output path:

```
lib/<abi>/<main_so_name>
```

Example (when `main=libmain.so`):

```
lib/arm64-v8a/libmain.so
lib/armeabi-v7a/libmain.so
lib/x86_64/libmain.so
lib/x86/libmain.so
```

## Runtime behavior

- **Logging**
  - On Android, `println!` is redirected to logcat via `android_logger`.
- **Loading**
  - The custom linker loads the configured `MAIN_LIB_NAME` from embedded bytes at library init (`.init_array`).
  - It recursively loads non-system `DT_NEEDED` dependencies from embedded libs when available.
- **JNI**
  - The wrapper library exports `JNI_OnLoad` and forwards it to the embedded libraries.
  - Default behavior: call `JNI_OnLoad` for the main library only.
  - Optional behavior: call `JNI_OnLoad` for all embedded modules (dependency order).

Enable calling JNI_OnLoad for all modules:

- Build-time feature: `--features jni_onload_all`
- Or runtime env: `CUSTOM_LINKER_JNI_ONLOAD_ALL=1`

## Project structure

- `src/lib.rs`
  - `cdylib` entrypoint and initialization (`.init_array`), JNI forwarding, log setup.
- `src/context.rs`
  - `LinkerContext` dependency loading and global symbol resolution hooks.
- `src/loader.rs`
  - ELF parsing, mapping segments, relocation processing, constructors.
- `src/tls.rs`
  - TLS support (`__tls_get_addr`) and emulated TLS (`__emutls_get_address`).
- `src/xdl/`
  - Embedded C implementation used for system `dlopen`/symbol access on Android.
- `build.rs`
  - Compiles xdl and generates the embedded libs index (`embedded_libs.rs`) based on `src/libs/<abi>` and `src/libs/config`.
