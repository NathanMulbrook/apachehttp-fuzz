#!/usr/bin/env bash
set -euo pipefail

LLVM_VERSION="23.1.1"
LLVM_SOURCE_SHA256="ebe9be46fe8756d58c5b198ffad0fa2a766257add81a4dc52179bfacc7888ee6"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source_name="llvm-project-$LLVM_VERSION.src.tar.xz"
source_url="https://github.com/llvm/llvm-project/releases/download/llvmorg-$LLVM_VERSION/$source_name"
work_dir="${LLVM_TOOLCHAIN_WORK_DIR:-$script_dir/work}"
install_dir="${LLVM_ROOT:-$script_dir/llvm-$LLVM_VERSION}"
jobs="${LLVM_TOOLCHAIN_JOBS:-$(nproc)}"
minimum_free_gb="${LLVM_MIN_FREE_GB:-80}"

archive="$work_dir/$source_name"
source_dir="$work_dir/llvm-project-$LLVM_VERSION.src"
build_dir="$work_dir/build-$LLVM_VERSION"

toolchain_ready() {
    local clang="$install_dir/bin/clang"
    local resource_dir

    [ -x "$clang" ] || return 1
    [ -x "$install_dir/bin/llvm-cov" ] || return 1
    [ -x "$install_dir/bin/llvm-profdata" ] || return 1
    "$clang" --version | sed -n '1p' | grep -Fq "clang version $LLVM_VERSION" || return 1
    resource_dir="$("$clang" -print-resource-dir)"
    [ -n "$(find "$resource_dir/lib" -type f -name 'libclang_rt.asan*.a' -print -quit)" ] || return 1
    [ -n "$(find "$resource_dir/lib" -type f -name 'libclang_rt.ubsan_standalone*.a' -print -quit)" ] || return 1
    [ -n "$(find "$resource_dir/lib" -type f -name 'libclang_rt.fuzzer_no_main*.a' -print -quit)" ] || return 1
    [ -n "$(find "$resource_dir/lib" -type f -name 'libclang_rt.profile*.a' -print -quit)" ] || return 1
}

if toolchain_ready; then
    echo "LLVM $LLVM_VERSION is already installed at $install_dir"
    exit
fi

for command in clang clang++ cmake curl ninja sha256sum tar; do
    if ! command -v "$command" >/dev/null; then
        echo "Missing required command: $command"
        exit 1
    fi
done

bootstrap_clang="$(command -v clang)"
bootstrap_clangxx="$(command -v clang++)"
if [ -x /usr/bin/clang ] && [ -x /usr/bin/clang++ ]; then
    bootstrap_clang=/usr/bin/clang
    bootstrap_clangxx=/usr/bin/clang++
fi
target_triple="$("$bootstrap_clang" -dumpmachine)"

mkdir -p "$work_dir" "$install_dir"
available_kb="$(df -Pk "$work_dir" | awk 'NR == 2 {print $4}')"
required_kb="$((minimum_free_gb * 1024 * 1024))"
if [ "$available_kb" -lt "$required_kb" ]; then
    echo "LLVM needs at least $minimum_free_gb GB free in $work_dir."
    exit 1
fi

if [ ! -f "$archive" ]; then
    echo "Downloading LLVM $LLVM_VERSION sources"
    curl --fail --location --retry 3 --output "$archive.part" "$source_url"
    mv "$archive.part" "$archive"
fi
printf '%s  %s\n' "$LLVM_SOURCE_SHA256" "$archive" | sha256sum --check

if [ ! -d "$source_dir" ]; then
    tar -xf "$archive" -C "$work_dir"
fi

cmake -S "$source_dir/llvm" -B "$build_dir" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$bootstrap_clang" \
    -DCMAKE_CXX_COMPILER="$bootstrap_clangxx" \
    -DCMAKE_INSTALL_PREFIX="$install_dir" \
    -DCLANG_CONFIG_FILE_SYSTEM_DIR=/etc/clang \
    -DLLVM_APPEND_VC_REV=OFF \
    -DLLVM_DEFAULT_TARGET_TRIPLE="$target_triple" \
    -DLLVM_ENABLE_PROJECTS="clang;lld" \
    -DLLVM_ENABLE_RUNTIMES="compiler-rt" \
    -DLLVM_TARGETS_TO_BUILD=X86 \
    -DLLVM_INCLUDE_BENCHMARKS=OFF \
    -DLLVM_INCLUDE_DOCS=OFF \
    -DLLVM_INCLUDE_EXAMPLES=OFF \
    -DLLVM_INCLUDE_TESTS=OFF \
    -DCLANG_INCLUDE_TESTS=OFF \
    -DCOMPILER_RT_BUILD_LIBFUZZER=ON \
    -DCOMPILER_RT_BUILD_PROFILE=ON \
    -DCOMPILER_RT_BUILD_SANITIZERS=ON \
    -DCOMPILER_RT_INCLUDE_TESTS=OFF \
    -DLLVM_PARALLEL_LINK_JOBS=2

cmake --build "$build_dir" --target install -j "$jobs"
cmake --build "$build_dir" --target install-runtimes -j "$jobs"

toolchain_ready || {
    echo "LLVM built, but required runtimes or tools are missing."
    exit 1
}
echo "LLVM $LLVM_VERSION installed at $install_dir"
