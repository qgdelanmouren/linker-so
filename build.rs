use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    generate_embedded_lib_index();

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();

    if target_os == "android" {
        // [New] 获取外部设置的 API Level，如果没有设置默认 21
        // 这样可以确保 xdl 不会调用高版本才有的 android_get_device_api_level
        let api_level = env::var("ANDROID_PLATFORM")
            .unwrap_or_else(|_| "24".to_string()) // 默认 android-24
            .replace("android-", ""); 

        // 1. 编译 xdl
        cc::Build::new()
            .file("src/xdl/xdl.c")
            .file("src/xdl/xdl_iterate.c")
            .file("src/xdl/xdl_linker.c")
            .file("src/xdl/xdl_lzma.c")
            .file("src/xdl/xdl_util.c")
            .include("src/xdl/include")
            // .define("__ANDROID_API__", api_level.as_str()) // Commented out to avoid redefinition warning
            .compile("xdl");

        // 2. 自动查找 NDK 库路径
        if let Ok(ndk_home) = env::var("ANDROID_NDK_HOME") {
            let ndk_path = PathBuf::from(ndk_home);
            let host_tag = if cfg!(windows) {
                "windows-x86_64"
            } else {
                "linux-x86_64"
            }; 
            
            // Map Rust target arch to Android NDK target triple directory
            let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
            println!("cargo:warning=Detected target architecture: {}", target_arch);
            
            let android_triple = match target_arch.as_str() {
                "aarch64" => "aarch64-linux-android",
                "arm" => "arm-linux-androideabi",
                "x86_64" => "x86_64-linux-android",
                "x86" => "i686-linux-android",
                _ => {
                    println!("cargo:warning=Unknown arch: {}, defaulting to aarch64", target_arch);
                    "aarch64-linux-android"
                }, 
            };

            let lib_path = ndk_path
                .join("toolchains/llvm/prebuilt")
                .join(host_tag)
                .join("sysroot/usr/lib")
                .join(android_triple)
                // 注意：NDK 的库目录里通常有按 API Level 分的子目录
                // 我们需要指向对应的 API 版本，否则可能会链接到高版本的 symbol
                .join(api_level.clone()); 
            
            if lib_path.exists() {
                println!("cargo:rustc-link-search=native={}", lib_path.display());
            } else {
                // 如果找不到特定 API 的目录，尝试回退到通用目录 (通常不需要，NDK 结构很规范)
                let fallback = lib_path.parent().unwrap();
                if fallback.exists() {
                     println!("cargo:rustc-link-search=native={}", fallback.display());
                }
            }
        }

        // 3. 不再链接 c++_static，防止崩溃
        // 保持之前的改动：只编译 xdl
    }
}

fn generate_embedded_lib_index() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown".to_string());
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    let config_path = manifest_dir.join("src").join("libs").join("config");
    println!("cargo:rerun-if-changed={}", config_path.display());
    let main_lib_name = read_main_lib_name(&config_path).unwrap_or_else(|| "libmain.so".to_string());

    let abi_dir = match target_arch.as_str() {
        "aarch64" => "arm64-v8a",
        "arm" => "armeabi-v7a",
        "x86" => "x86",
        "x86_64" => "x86_64",
        _ => "arm64-v8a",
    };

    let libs_dir = manifest_dir.join("src").join("libs").join(abi_dir);
    println!("cargo:rerun-if-changed={}", libs_dir.display());

    if target_os == "android" {
        let main_lib = libs_dir.join(&main_lib_name);
        if !main_lib.exists() {
            panic!(
                "Missing main library '{}' for ABI '{abi_dir}'. Expected: {}",
                main_lib_name,
                main_lib.display()
            );
        }
    }

    let mut libs: Vec<(String, String)> = Vec::new();
    if let Ok(entries) = fs::read_dir(&libs_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("so") {
                continue;
            }
            let file_name = match path.file_name().and_then(|s| s.to_str()) {
                Some(v) => v.to_string(),
                None => continue,
            };

            // Make path stable across machines: use CARGO_MANIFEST_DIR + relative path.
            let rel = match path.strip_prefix(&manifest_dir) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let rel_str = rel.to_string_lossy().replace('\\', "/");

            println!("cargo:rerun-if-changed={}", path.display());
            libs.push((file_name, rel_str));
        }
    }
    libs.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = String::new();
    out.push_str(&format!("pub const MAIN_LIB_NAME: &str = {main:?};\n\n", main = main_lib_name));
    out.push_str("pub fn embedded_lib_bytes(name: &str) -> Option<&'static [u8]> {\n");
    out.push_str("    match name {\n");
    for (name, rel) in libs {
        out.push_str(&format!(
            "        {name:?} => Some(include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/{rel}\")) as &'static [u8]),\n",
        ));
    }
    out.push_str("        _ => None,\n");
    out.push_str("    }\n");
    out.push_str("}\n");

    let dest = out_dir.join("embedded_libs.rs");
    let mut f = fs::File::create(&dest).unwrap();
    f.write_all(out.as_bytes()).unwrap();
}

fn read_main_lib_name(config_path: &PathBuf) -> Option<String> {
    let s = fs::read_to_string(config_path).ok()?;
    for raw_line in s.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        if k.trim() == "main" {
            let val = v.trim();
            if val.is_empty() {
                return None;
            }
            return Some(val.to_string());
        }
    }
    None
}