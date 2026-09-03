#!/usr/bin/env bash

# What it does:
#   1. Installs system dependencies (git, cmake, python, gcc/clang, openssl, curl, sqlite)
#   2. Provisions LLVM (>= LLVM_MIN_VERSION) - prebuilt package by default, or built
#      from source with --from-source
#   3. Exports/persists JOCKY_ROOT, LLVM_DIR, and related environment variables
#   4. Runs CMake to configure the project build directory
#
# Usage:
#   ./bootstrap.sh                  # prebuilt LLVM via apt.llvm.org, Debug configure
#   ./bootstrap.sh --from-source    # build LLVM from source instead (slow: 1-3+ hours)
#   ./bootstrap.sh --release        # configure CMake in Release mode
#   ./bootstrap.sh --llvm-version 17
#   ./bootstrap.sh --skip-system-deps   # skip apt install step (e.g. re-runs)
#   ./bootstrap.sh --skip-cmake         # provision only, don't configure the project
#   ./bootstrap.sh -h | --help
#
# The script is idempotent: safe to re-run. It will skip steps whose outputs
# already exist unless you pass --force.

set -euo pipefail

LLVM_MIN_VERSION=16
LLVM_VERSION=18
BUILD_FROM_SOURCE=0
SKIP_SYSTEM_DEPS=0
SKIP_CMAKE=0
FORCE=0
CMAKE_BUILD_TYPE="Debug"
JOBS="$(nproc 2>/dev/null || echo 4)"

usage() {
    grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed -n '2,20p'
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --from-source) BUILD_FROM_SOURCE=1; shift ;;
        --release) CMAKE_BUILD_TYPE="Release"; shift ;;
        --llvm-version) LLVM_VERSION="$2"; shift 2 ;;
        --skip-system-deps) SKIP_SYSTEM_DEPS=1; shift ;;
        --skip-cmake) SKIP_CMAKE=1; shift ;;
        --force) FORCE=1; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown argument: $1" >&2; usage ;;
    esac
done

if (( LLVM_VERSION < LLVM_MIN_VERSION )); then
    echo "error: --llvm-version $LLVM_VERSION is below the required minimum ($LLVM_MIN_VERSION)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JOCKY_ROOT="$(dirname "$SCRIPT_DIR")"
JOCKY_VENDOR_DIR="$JOCKY_ROOT/.vendor"
JOCKY_LLVM_SRC_DIR="$JOCKY_VENDOR_DIR/llvm-project"
JOCKY_LLVM_BUILD_DIR="$JOCKY_VENDOR_DIR/llvm-build"
JOCKY_LLVM_INSTALL_DIR="$JOCKY_VENDOR_DIR/llvm-install-$LLVM_VERSION"
JOCKY_BUILD_DIR="$JOCKY_ROOT/build"
ENV_FILE="$JOCKY_ROOT/.jocky-env.sh"

log()  { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[bootstrap][warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[bootstrap][error]\033[0m %s\n' "$*" >&2; exit 1; }

mkdir -p "$JOCKY_VENDOR_DIR"

# system deps
install_system_deps() {
    log "Installing system dependencies via apt..."
    sudo apt-get update -y
    sudo apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        lld \
        git \
        wget \
        curl \
        ca-certificates \
        gnupg \
        lsb-release \
        software-properties-common \
        cmake \
        python3 \
        python3-pip \
        python3-venv \
        libssl-dev \
        libcurl4-openssl-dev \
        sqlite3 \
        libsqlite3-dev

    local cmake_version
    cmake_version="$(cmake --version | head -n1 | awk '{print $3}')"
    if ! printf '%s\n%s\n' "3.20" "$cmake_version" | sort -C -V; then
        warn "System CMake ($cmake_version) is older than 3.20; adding Kitware APT repo..."
        wget -qO - https://apt.kitware.com/keys/kitware-archive-latest.asc \
            | sudo gpg --dearmor -o /usr/share/keyrings/kitware-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ $(lsb_release -cs) main" \
            | sudo tee /etc/apt/sources.list.d/kitware.list >/dev/null
        sudo apt-get update -y
        sudo apt-get install -y cmake
    fi

    log "System dependencies installed."
}

if (( SKIP_SYSTEM_DEPS == 0 )); then
    install_system_deps
else
    log "Skipping system dependency install (--skip-system-deps)."
fi


install_llvm_prebuilt() {
    log "Installing prebuilt LLVM $LLVM_VERSION from apt.llvm.org..."

    if command -v "clang-$LLVM_VERSION" >/dev/null 2>&1 && (( FORCE == 0 )); then
        log "clang-$LLVM_VERSION already installed, skipping (use --force to reinstall)."
    else
        local script_path="$JOCKY_VENDOR_DIR/llvm.sh"
        wget -qO "$script_path" https://apt.llvm.org/llvm.sh
        chmod +x "$script_path"
        sudo "$script_path" "$LLVM_VERSION" all
    fi

    sudo update-alternatives --install /usr/bin/clang        clang        "/usr/bin/clang-$LLVM_VERSION"        100
    sudo update-alternatives --install /usr/bin/clang++      clang++      "/usr/bin/clang++-$LLVM_VERSION"      100
    sudo update-alternatives --install /usr/bin/llvm-config  llvm-config  "/usr/bin/llvm-config-$LLVM_VERSION"  100

    LLVM_DIR_RESOLVED="/usr/lib/llvm-$LLVM_VERSION/lib/cmake/llvm"
    if [[ ! -d "$LLVM_DIR_RESOLVED" ]]; then
        die "Expected LLVM cmake dir not found at $LLVM_DIR_RESOLVED - check the apt.llvm.org install."
    fi

    LLVM_ROOT_RESOLVED="/usr/lib/llvm-$LLVM_VERSION"
    log "Prebuilt LLVM ready. LLVM_DIR=$LLVM_DIR_RESOLVED"
}

build_llvm_from_source() {
    log "Building LLVM $LLVM_VERSION from source. This will take a while (1-3+ hours, ~30GB disk, lots of RAM)."

    if [[ -d "$JOCKY_LLVM_INSTALL_DIR" && -f "$JOCKY_LLVM_INSTALL_DIR/lib/cmake/llvm/LLVMConfig.cmake" && $FORCE -eq 0 ]]; then
        log "LLVM already built at $JOCKY_LLVM_INSTALL_DIR, skipping (use --force to rebuild)."
        LLVM_DIR_RESOLVED="$JOCKY_LLVM_INSTALL_DIR/lib/cmake/llvm"
        LLVM_ROOT_RESOLVED="$JOCKY_LLVM_INSTALL_DIR"
        return
    fi

    if [[ ! -d "$JOCKY_LLVM_SRC_DIR" ]]; then
        log "Cloning llvm-project (branch release/${LLVM_VERSION}.x, shallow)..."
        git clone --depth 1 --branch "release/${LLVM_VERSION}.x" \
            https://github.com/llvm/llvm-project.git "$JOCKY_LLVM_SRC_DIR"
    else
        log "llvm-project source already present at $JOCKY_LLVM_SRC_DIR, reusing."
    fi

    mkdir -p "$JOCKY_LLVM_BUILD_DIR"
    log "Configuring LLVM build (this alone can take several minutes)..."
    cmake -S "$JOCKY_LLVM_SRC_DIR/llvm" -B "$JOCKY_LLVM_BUILD_DIR" -G Ninja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$JOCKY_LLVM_INSTALL_DIR" \
        -DLLVM_ENABLE_PROJECTS="clang;lld" \
        -DLLVM_TARGETS_TO_BUILD="X86;AArch64" \
        -DLLVM_ENABLE_ASSERTIONS=OFF \
        -DLLVM_INCLUDE_TESTS=OFF \
        -DLLVM_INCLUDE_EXAMPLES=OFF \
        -DLLVM_INCLUDE_BENCHMARKS=OFF

    if ! command -v ninja >/dev/null 2>&1; then
        log "Installing ninja-build (required for the LLVM source build)..."
        sudo apt-get install -y ninja-build
    fi

    log "Building LLVM with $JOBS parallel jobs..."
    cmake --build "$JOCKY_LLVM_BUILD_DIR" -j "$JOBS"

    log "Installing LLVM into $JOCKY_LLVM_INSTALL_DIR..."
    cmake --install "$JOCKY_LLVM_BUILD_DIR"

    LLVM_DIR_RESOLVED="$JOCKY_LLVM_INSTALL_DIR/lib/cmake/llvm"
    LLVM_ROOT_RESOLVED="$JOCKY_LLVM_INSTALL_DIR"
    log "LLVM built from source. LLVM_DIR=$LLVM_DIR_RESOLVED"
}

if (( BUILD_FROM_SOURCE == 1 )); then
    build_llvm_from_source
else
    install_llvm_prebuilt
fi

log "Writing environment file to $ENV_FILE"
cat > "$ENV_FILE" <<EOF
# Auto-generated by bootstrap.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# Source this file (e.g. from your shell rc) to pick up project env vars:
#   source "$ENV_FILE"
export JOCKY_ROOT="$JOCKY_ROOT"
export JOCKY_BUILD_DIR="$JOCKY_BUILD_DIR"
export LLVM_VERSION="$LLVM_VERSION"
export LLVM_DIR="$LLVM_DIR_RESOLVED"
export LLVM_ROOT="$LLVM_ROOT_RESOLVED"
export PATH="\$LLVM_ROOT/bin:\$PATH"
EOF

export JOCKY_ROOT LLVM_VERSION
export LLVM_DIR="$LLVM_DIR_RESOLVED"
export LLVM_ROOT="$LLVM_ROOT_RESOLVED"
export PATH="$LLVM_ROOT/bin:$PATH"

log "Environment configured:"
log "  JOCKY_ROOT = $JOCKY_ROOT"
log "  LLVM_DIR   = $LLVM_DIR"
log "  LLVM_ROOT  = $LLVM_ROOT"

# ---------------------------------------------------------------------------
# 4. CMake configure
# ---------------------------------------------------------------------------
if (( SKIP_CMAKE == 1 )); then
    log "Skipping CMake configure (--skip-cmake)."
    log "Bootstrap finished. Run: source \"$ENV_FILE\"  to load env vars into your shell."
    exit 0
fi

if [[ ! -f "$JOCKY_ROOT/CMakeLists.txt" ]]; then
    warn "No CMakeLists.txt found at $JOCKY_ROOT - skipping configure step."
    warn "Bootstrap finished (env only). Run: source \"$ENV_FILE\""
    exit 0
fi

log "Configuring project with CMake (build type: $CMAKE_BUILD_TYPE)..."
cmake -S "$JOCKY_ROOT" -B "$JOCKY_BUILD_DIR" \
    -DCMAKE_BUILD_TYPE="$CMAKE_BUILD_TYPE" \
    -DLLVM_DIR="$LLVM_DIR" \
    -DCMAKE_C_COMPILER="$LLVM_ROOT/bin/clang" \
    -DCMAKE_CXX_COMPILER="$LLVM_ROOT/bin/clang++"

log "CMake configure complete. Build directory: $JOCKY_BUILD_DIR"
log ""
log "Next steps:"
log "  source \"$ENV_FILE\""
log "  cmake --build \"$JOCKY_BUILD_DIR\" -j $JOBS"