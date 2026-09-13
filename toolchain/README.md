# LLVM toolchain

The fuzzer build uses a local LLVM 23.1.1 toolchain so Clang, compiler-rt,
libFuzzer, and the coverage tools come from one build. The source archive is
pinned by SHA-256 and downloaded from the official LLVM release.

Build it once:

~~~console
./build.sh --bootstrap-toolchain
~~~

The build needs at least 80 GB free. It installs under
`toolchain/llvm-23.1.1`; resumable source and build files remain under
`toolchain/work`.

The following environment variables are optional:

- `LLVM_TOOLCHAIN_WORK_DIR` moves source and intermediate build files.
- `LLVM_TOOLCHAIN_JOBS` controls parallel compilation.
- `LLVM_ROOT` selects another complete LLVM 23.1.1 installation.
- `LLVM_MIN_FREE_GB` changes the free-space check.
