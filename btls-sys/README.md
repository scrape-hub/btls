# Low-level bindings to BoringSSL

[BoringSSL](https://boringssl.googlesource.com/boringssl) is Google's fork of OpenSSL for Chrome/Chromium and Android.

This crate builds the BoringSSL library (or optionally links a pre-built version) and generates FFI bindings for it.
It supports [FIPS-compatible builds of BoringSSL](https://boringssl.googlesource.com/boringssl/+/master/crypto/fipsmodule/FIPS.md),
as well as [Post-Quantum crypto](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
and [Raw Public Key](https://docs.rs/btls/latest/btls/ssl/struct.SslRef.html#method.peer_pubkey) extensions.

To use BoringSSL from Rust, prefer the [higher-level safe API](https://docs.rs/btls).

## Building

Building the bundled BoringSSL needs Rust, CMake and a C/C++ compiler (on Windows x64 also NASM).
The build script applies the patches of `patches/` itself, without git. For the targets in
`bindings/` the bindings are generated beforehand; other targets, external BoringSSL builds
(`BORING_BSSL_PATH`, `BORING_BSSL_SOURCE_PATH`, `BORING_BSSL_INCLUDE_PATH`) and the features
`fips`, `underscore-wildcards` and `prefix-symbols` generate them with bindgen, which needs
libclang.

`BTLS_WRITE_BINDINGS=<dir>` generates them with bindgen and also writes them to
`<dir>/<target>.rs`; with `DOCS_RS=1` BoringSSL itself is not built. The workflow
`.github/workflows/bindings.yml` does this for every target and fails when a file of `bindings/`
is out of date. `x86_64-pc-windows-gnu` is generated with the headers of Rtools:

```bash
CLANG_INC=$(ls -d "/c/Program Files/LLVM/lib/clang/"*/include | sort -V | tail -1)
RT=/c/rtools45/x86_64-w64-mingw32.static.posix
GCC_INC=$(ls -d $RT/lib/gcc/x86_64-w64-mingw32.static.posix/*/include | sort -V | tail -1)
BINDGEN_EXTRA_CLANG_ARGS="--target=x86_64-pc-windows-gnu -isystem $(cygpath -m "$CLANG_INC") \
  -isystem $(cygpath -m $GCC_INC) -isystem $(cygpath -m $RT/include)" \
  DOCS_RS=1 BTLS_WRITE_BINDINGS="$PWD/btls-sys/bindings" cargo check -p btls-sys --target x86_64-pc-windows-gnu
```

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed under the terms of both the Apache License,
Version 2.0 and the MIT license without any additional terms or conditions.
