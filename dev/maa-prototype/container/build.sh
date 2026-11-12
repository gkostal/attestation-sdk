#!/bin/bash
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Configure + build libnvat inside the container (source already synced to /work/src).
#
#   build.sh test    default symbol visibility, BUILD_TESTING=ON  (build tree: build/)
#   build.sh bundle  hidden symbols (NVAT_HIDE_INTERNAL_SYMBOLS=ON), tests off
#                    (build tree: build-bundle/)
#   build.sh asan|tsan  like `test` with -DSANITIZER=address|thread (build-asan/, build-tsan/);
#                    run with BUILD_DIR=build-asan test.sh -R <filter>
#
# All are Release / shared / USE_SYSTEM_DEPS=OFF (OpenSSL, curl, libxml2, xmlsec are
# built from source and statically linked into libnvat.so).

set -euo pipefail

MODE="${1:?usage: build.sh test|bundle|asan|tsan}"
export PATH="/opt/cargo/bin:$PATH"
JOBS="${JOBS:-$(nproc)}"
export CMAKE_BUILD_PARALLEL_LEVEL="$JOBS"

cd /work/src/nv-attestation-sdk-cpp

case "$MODE" in
    test)
        BUILD_DIR=build
        EXTRA=(-DBUILD_TESTING=ON)
        ;;
    asan|tsan)
        BUILD_DIR="build-$MODE"
        SANITIZER_NAME=$([ "$MODE" = asan ] && echo address || echo thread)
        EXTRA=(-DBUILD_TESTING=ON "-DSANITIZER=$SANITIZER_NAME")
        ;;
    bundle)
        BUILD_DIR=build-bundle
        # Hidden symbols (only nvat_* exported), no tests, and zlib linked statically from the
        # image's PIC build (/opt/zlib-static) so libnvat.so needs nothing beyond libc/libstdc++.
        EXTRA=(-DBUILD_TESTING=OFF -DNVAT_HIDE_INTERNAL_SYMBOLS=ON
               -DZLIB_ROOT=/opt/zlib-static -DZLIB_USE_STATIC_LIBS=ON
               "-DCMAKE_SHARED_LINKER_FLAGS=-L/opt/zlib-static/lib")
        ;;
    *)
        echo "unknown mode: $MODE" >&2
        exit 2
        ;;
esac

# Unix Makefiles (the repo default) on purpose: the ExternalProject libraries (xmlsec,
# openssl, ...) are not declared as byproducts, which Ninja rejects at graph-load time.
cmake -S . -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DBUILD_SHARED_LIBS=ON \
    -DUSE_SYSTEM_DEPS=OFF \
    "${EXTRA[@]}"
cmake --build "$BUILD_DIR" -j"$JOBS" ${BUILD_TARGET:+--target "$BUILD_TARGET"}
echo "build ($MODE) complete"
