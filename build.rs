use std::env;
use std::path::PathBuf;

fn main() {
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
            // [Critical] 强制定义 API Level 宏
            .define("__ANDROID_API__", api_level.as_str())
            .compile("xdl");

        // 2. 自动查找 NDK 库路径
        if let Ok(ndk_home) = env::var("ANDROID_NDK_HOME") {
            let ndk_path = PathBuf::from(ndk_home);
            let host_tag = "linux-x86_64"; 
            let lib_path = ndk_path
                .join("toolchains/llvm/prebuilt")
                .join(host_tag)
                .join("sysroot/usr/lib/aarch64-linux-android")
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