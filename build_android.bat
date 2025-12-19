@echo off
setlocal

REM Configuration
REM 注意：请修改为你 Windows 机器上 NDK 的实际路径
set NDK_HOME=D:\IDE\Android\SDK\ndk\29.0.13846066
set ANDROID_NDK_HOME=%NDK_HOME%
set HOST_TAG=windows-x86_64
set MIN_SDK=24
set ANDROID_PLATFORM=android-%MIN_SDK%

REM Main library name (from src\libs\config: main=libxxx.so)
set MAIN_SO=libmain.so
if exist src\libs\config (
    for /f "usebackq tokens=1,* delims==" %%A in ("src\libs\config") do (
        if /i "%%A"=="main" set MAIN_SO=%%B
    )
)
set MAIN_SO=%MAIN_SO: =%

REM Toolchain paths
set TOOLCHAIN=%NDK_HOME%\toolchains\llvm\prebuilt\%HOST_TAG%
set BIN=%TOOLCHAIN%\bin

REM Export environment variables for cc-rs and cargo
set PATH=%BIN%;%PATH%

REM Set C compilers for cross-compilation (used by cc crate)
REM 注意：在 Windows NDK 中，带版本号的 clang 通常是 .cmd 脚本，ar 是 .exe

REM --- AArch64 ---
set CC_aarch64_linux_android=%BIN%\aarch64-linux-android%MIN_SDK%-clang.cmd
set AR_aarch64_linux_android=%BIN%\llvm-ar.exe
set CXX_aarch64_linux_android=%BIN%\aarch64-linux-android%MIN_SDK%-clang++.cmd

REM --- ARMv7 ---
set CC_armv7_linux_androideabi=%BIN%\armv7a-linux-androideabi%MIN_SDK%-clang.cmd
set AR_armv7_linux_androideabi=%BIN%\llvm-ar.exe
set CXX_armv7_linux_androideabi=%BIN%\armv7a-linux-androideabi%MIN_SDK%-clang++.cmd

REM --- x86_64 ---
set CC_x86_64_linux_android=%BIN%\x86_64-linux-android%MIN_SDK%-clang.cmd
set AR_x86_64_linux_android=%BIN%\llvm-ar.exe
set CXX_x86_64_linux_android=%BIN%\x86_64-linux-android%MIN_SDK%-clang++.cmd

REM --- x86 (i686) ---
set CC_i686_linux_android=%BIN%\i686-linux-android%MIN_SDK%-clang.cmd
set AR_i686_linux_android=%BIN%\llvm-ar.exe
set CXX_i686_linux_android=%BIN%\i686-linux-android%MIN_SDK%-clang++.cmd

REM Build for aarch64 (default)
echo Building for aarch64-linux-android...
cargo build --target aarch64-linux-android --release
if %ERRORLEVEL% neq 0 goto :error

if not exist lib\arm64-v8a mkdir lib\arm64-v8a
copy /y target\aarch64-linux-android\release\liblinker.so lib\arm64-v8a\%MAIN_SO% >nul

REM Build for armv7
echo Building for armv7-linux-androideabi...
cargo build --target armv7-linux-androideabi --release
if %ERRORLEVEL% neq 0 goto :error

if not exist lib\armeabi-v7a mkdir lib\armeabi-v7a
copy /y target\armv7-linux-androideabi\release\liblinker.so lib\armeabi-v7a\%MAIN_SO% >nul

REM Build for x86_64
echo Building for x86_64-linux-android...
cargo build --target x86_64-linux-android --release
if %ERRORLEVEL% neq 0 goto :error

if not exist lib\x86_64 mkdir lib\x86_64
copy /y target\x86_64-linux-android\release\liblinker.so lib\x86_64\%MAIN_SO% >nul

REM Build for x86
echo Building for i686-linux-android...
cargo build --target i686-linux-android --release
if %ERRORLEVEL% neq 0 goto :error

if not exist lib\x86 mkdir lib\x86
copy /y target\i686-linux-android\release\liblinker.so lib\x86\%MAIN_SO% >nul

echo All builds completed successfully.
endlocal
goto :eof

:error
echo Build failed.
exit /b %ERRORLEVEL%