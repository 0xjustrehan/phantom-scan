#!/usr/bin/env bash
# ==============================================================================
# build-linux.sh — Native High-Performance Linux Build for phantom-scan
# ==============================================================================
set -e
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
cd "$(dirname "$0")"

echo "=============================================================================="
echo "[PHANTOM-SCAN] Compiling Linux release binary"
echo "=============================================================================="

# Check if musl build is specifically requested via argument
if [ "$1" == "--musl" ] || [ "$MUSL" == "1" ]; then
    TARGET="x86_64-unknown-linux-musl"
    echo "[*] Static Musl target requested: $TARGET"

    # Ensure musl-gcc is available for C dependencies
    if ! command -v x86_64-linux-musl-gcc &> /dev/null && ! command -v musl-gcc &> /dev/null; then
        echo "[!] musl C compiler not found. Attempting to install musl-tools..."
        if command -v apt-get &> /dev/null; then
            if [ "$EUID" -eq 0 ]; then
                apt-get update && apt-get install -y musl-tools
            elif command -v sudo &> /dev/null; then
                sudo apt-get update && sudo apt-get install -y musl-tools
            fi
        fi
    fi

    if command -v musl-gcc &> /dev/null && ! command -v x86_64-linux-musl-gcc &> /dev/null; then
        export CC_x86_64_unknown_linux_musl="musl-gcc"
    fi

    if ! rustup target list | grep -q "$TARGET (installed)"; then
        echo "[*] Installing Rust musl target: $TARGET"
        rustup target add $TARGET
    fi

    export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C target-feature=+crt-static -C opt-level=3"
    cargo build --release --target $TARGET

    echo ""
    echo "[+] Static Musl binary built successfully:"
    echo "    target/$TARGET/release/phantom-scan"
else
    # Standard high-speed native Linux build (works on all Linux distros with standard gcc)
    echo "[*] Building native Linux wire-speed binary..."
    export RUSTFLAGS="--remap-path-prefix $HOME=/home/anon --remap-path-prefix $(pwd)=/build -C link-arg=-s"
    cargo build --release

    echo ""
    echo "[+] Native Linux binary built successfully:"
    echo "    target/release/phantom-scan"
fi

echo "=============================================================================="
echo "Run scanner with:"
echo "  ./target/release/phantom-scan -h           (Command-line help)"
echo "  ./target/release/phantom-scan -i           (Interactive TUI wizard)"
echo "  ./target/release/phantom-scan -C slavic    (Scan slavic BGP CIDRs)"
echo "=============================================================================="
