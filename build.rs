use std::env;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit,
    aead::{Aead, generic_array::GenericArray},
};
use rand::RngCore;

/// 加密 SO 文件
/// 格式: [ 12 bytes nonce ][ ciphertext + 16 bytes tag ]
fn encrypt_so(plaintext: &[u8], key: &[u8; 32]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    
    // 生成随机 nonce
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = GenericArray::from_slice(&nonce_bytes);
    
    // 加密
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .expect("Encryption failed");
    
    // 组合: nonce + ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    
    result
}

/// 生成随机密钥并拆分为两部分 (XOR 混淆)
fn generate_obfuscated_key() -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut key = [0u8; 32];
    let mut part_a = [0u8; 32];
    
    rand::thread_rng().fill_bytes(&mut key);
    rand::thread_rng().fill_bytes(&mut part_a);
    
    // part_b = key ^ part_a
    let mut part_b = [0u8; 32];
    for i in 0..32 {
        part_b[i] = key[i] ^ part_a[i];
    }
    
    (key, part_a, part_b)
}

/// 将字节数组格式化为 Rust 数组字面量
fn format_bytes_array(bytes: &[u8]) -> String {
    let parts: Vec<String> = bytes.iter()
        .map(|b| format!("0x{:02x}", b))
        .collect();
    format!("[{}]", parts.join(", "))
}

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

    // 生成加密密钥 (XOR 混淆存储)
    let (key, part_a, part_b) = generate_obfuscated_key();
    
    // 创建加密输出目录
    let encrypted_dir = out_dir.join("encrypted");
    fs::create_dir_all(&encrypted_dir).unwrap();
    
    // 收集并加密所有 SO 文件
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

            println!("cargo:rerun-if-changed={}", path.display());
            
            // 读取原始 SO 文件
            let plaintext = fs::read(&path).expect(&format!("Failed to read {}", path.display()));
            
            // 验证是 ELF 文件
            if plaintext.len() < 4 || &plaintext[0..4] != b"\x7fELF" {
                panic!("{} is not a valid ELF file", file_name);
            }
            
            // 加密
            let encrypted = encrypt_so(&plaintext, &key);
            
            // 写入加密文件
            let enc_name = format!("{}.enc", file_name);
            let enc_path = encrypted_dir.join(&enc_name);
            fs::write(&enc_path, &encrypted).expect(&format!("Failed to write {}", enc_path.display()));
            
            println!("cargo:warning=Encrypted {} -> {} ({} -> {} bytes)", 
                file_name, enc_name, plaintext.len(), encrypted.len());
            
            libs.push((file_name, enc_name));
        }
    }
    libs.sort_by(|a, b| a.0.cmp(&b.0));

    // 生成 embedded_libs.rs (指向加密文件)
    let mut out = String::new();
    out.push_str(&format!("pub const MAIN_LIB_NAME: &str = {main:?};\n\n", main = main_lib_name));
    out.push_str("pub fn embedded_lib_bytes(name: &str) -> Option<&'static [u8]> {\n");
    out.push_str("    match name {\n");
    for (name, enc_name) in &libs {
        out.push_str(&format!(
            "        {name:?} => Some(include_bytes!(concat!(env!(\"OUT_DIR\"), \"/encrypted/{enc_name}\")) as &'static [u8]),\n",
        ));
    }
    out.push_str("        _ => None,\n");
    out.push_str("    }\n");
    out.push_str("}\n");

    let dest = out_dir.join("embedded_libs.rs");
    let mut f = fs::File::create(&dest).unwrap();
    f.write_all(out.as_bytes()).unwrap();
    
    // 生成 crypto_key.rs (混淆的密钥)
    let mut key_out = String::new();
    key_out.push_str("// Auto-generated encryption key (XOR obfuscated)\n");
    key_out.push_str("// DO NOT EDIT - Generated by build.rs\n\n");
    key_out.push_str(&format!("pub const KEY_PART_A: [u8; 32] = {};\n", format_bytes_array(&part_a)));
    key_out.push_str(&format!("pub const KEY_PART_B: [u8; 32] = {};\n", format_bytes_array(&part_b)));
    
    let key_dest = out_dir.join("crypto_key.rs");
    let mut kf = fs::File::create(&key_dest).unwrap();
    kf.write_all(key_out.as_bytes()).unwrap();
    
    println!("cargo:warning=Generated encrypted libs and crypto key");
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