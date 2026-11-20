@echo off
setlocal
echo ==============================================================================
echo [PHANTOM-SCAN] Compiling Ultra-Optimized Release Binary for Windows
echo ==============================================================================

if "%CARGO_HOME%"=="" set "CARGO_HOME=%USERPROFILE%\.cargo"

set RUSTFLAGS=--remap-path-prefix=%USERPROFILE%=/build --remap-path-prefix=%CARGO_HOME%=/cargo -C link-arg=-s -C opt-level=3
cargo build --release

if %ERRORLEVEL% NEQ 0 (
    echo [!] Build failed!
    exit /b %ERRORLEVEL%
)

echo.
echo [+] Build successful: target\release\phantom-scan.exe
echo ==============================================================================
