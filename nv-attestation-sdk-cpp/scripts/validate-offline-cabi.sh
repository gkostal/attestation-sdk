#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
build="$(realpath "${1:?usage: $0 <build-dir> [library-dir]}")"
lib="$(realpath "${2:-$build}")"
out="$build/offline-validation"
mkdir -p "$out"
export LD_LIBRARY_PATH="$lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cd "$build/unit-tests"

./nvat-cabi-header-check
./nvat-offline-cabi-tests --gtest_output="xml:$out/cabi-results.xml" \
    > "$out/cabi-results.log" 2>&1
cat "$out/cabi-results.log"

# A fresh process ensures that a previous test cannot hide lazy native I/O.
strace -f -e trace=%file,%network,write -o "$out/offline-io.trace" \
    ./nvat-offline-cabi-tests --gtest_filter=OfflineCAbi.ZeroNativeIo \
    > "$out/offline-io.log" 2>&1
awk '/NVAT_OFFLINE_IO_BEGIN/{record=1; next}
     /NVAT_OFFLINE_IO_END/{record=0} record' "$out/offline-io.trace" \
    > "$out/offline-io-window.txt"
grep -q NVAT_OFFLINE_IO_BEGIN "$out/offline-io.trace"
grep -q NVAT_OFFLINE_IO_END "$out/offline-io.trace"
if [ -s "$out/offline-io-window.txt" ]; then
    cat "$out/offline-io-window.txt" >&2
    echo "Unexpected native I/O inside offline verification" >&2
    exit 1
fi

nm -D --defined-only "$lib/libnvat.so.2" | awk '{print $NF}' > "$out/exports.txt"
test -s "$out/exports.txt"
if grep -v '^nvat_' "$out/exports.txt"; then
    echo "Unexpected non-C-ABI dynamic export" >&2
    exit 1
fi
readelf -d "$lib/libnvat.so.2" > "$out/dynamic.txt"
grep -q 'Library soname: \[libnvat.so.2\]' "$out/dynamic.txt"
ldd "$lib/libnvat.so.2" > "$out/runtime-dependencies.txt"

# Reproduce a host that has already loaded Ubuntu 22.04's OpenSSL 3.0.
if [ -f /lib/x86_64-linux-gnu/libcrypto.so.3 ]; then
    LD_PRELOAD=/lib/x86_64-linux-gnu/libcrypto.so.3 \
        ./nvat-offline-cabi-tests --gtest_output="xml:$out/system-openssl-results.xml" \
        > "$out/system-openssl-results.log" 2>&1
fi
sha256sum "$lib/libnvat.so.2" "$build/include/nvat.h" > "$out/SHA256SUMS"
printf 'PASS: C header; offline matrix; zero native I/O; %s C ABI exports; SONAME; system OpenSSL coexistence\n' \
    "$(wc -l < "$out/exports.txt")"
