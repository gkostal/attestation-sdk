#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
build="${1:?usage: $0 <build-dir> <output-dir>}"
out="${2:?output-dir}"
mkdir -p "$out"

collect() {
    local name="$1" source="$2"
    [ -d "$source" ] || { echo "Missing dependency source: $source" >&2; exit 1; }
    mkdir -p "$out/$name"
    find "$source" -maxdepth 1 -type f \
        \( -iname 'license*' -o -iname 'copying*' -o -iname 'copyright*' -o -iname 'notice*' \) \
        -exec cp '{}' "$out/$name/" \;
    if [ -f "$source/Cargo.toml" ]; then
        sed -n '/^name = /p; /^version = /p; /^license = /p; /^license-file = /p' \
            "$source/Cargo.toml" | head -8 > "$out/$name/package-license-metadata.txt"
    fi
}
for name in fmt spdlog json jwt-cpp zcbor regorus; do
    collect "$name" "$build/_deps/$name-src"
done
collect openssl "$build/openssl_external-prefix/src/openssl_external"
collect curl "$build/curl_external-prefix/src/curl_external"
collect libxml2 "$build/libxml2_external-prefix/src/libxml2_external"
collect xmlsec "$build/xmlsec_external-prefix/src/xmlsec_external"
if [ -f "$build/_deps/regorus-src/bindings/ffi/Cargo.lock" ]; then
    cp "$build/_deps/regorus-src/bindings/ffi/Cargo.lock" "$out/regorus/"
fi

cargo tree --manifest-path "$build/_deps/regorus-src/bindings/ffi/Cargo.toml" \
    --target x86_64-unknown-linux-gnu -e normal,build --prefix none \
    -p regorus-ffi --features regorus/semver > "$out/rust-dependency-tree.txt"
awk '$2 ~ /^v[0-9]/ {print $1 "-" substr($2, 2)}' "$out/rust-dependency-tree.txt" \
    | sort -u > "$out/rust-packages.txt"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
while IFS= read -r package; do
    for source in "$cargo_home"/registry/src/*/"$package"; do
        [ -d "$source" ] || continue
        collect "rust/$package" "$source"
    done
done < "$out/rust-packages.txt"
sysroot=$(rustc --print sysroot)
if [ -d "$sysroot/share/doc/rust" ]; then
    collect rust-standard-library "$sysroot/share/doc/rust"
    if [ -d "$sysroot/share/doc/rust/licenses" ]; then
        cp -a "$sysroot/share/doc/rust/licenses" "$out/rust-standard-library/"
    fi
fi
cat > "$out/THIRD_PARTY_NOTICES.txt" <<'NOTICE'
NVIDIA Attestation SDK 2.0.0, Apache-2.0.
Source: https://github.com/NVIDIA/attestation-sdk
Modified source: https://github.com/gkostal/attestation-sdk
Modifications: offline per-call C ABI collateral/OCSP verification and ELF symbol isolation.

The accompanying library contains statically linked third-party components:
OpenSSL 3.6.4 (Apache-2.0), curl 8.22.0 (curl license), libxml2 2.15.4 (MIT),
xmlsec 1.2.39 (MIT), fmt 10.2.1 (MIT), spdlog 1.14.1 (MIT),
nlohmann/json 3.12.0 (MIT), jwt-cpp 0.7.1 (MIT),
zcbor bd28ef9fc2abe154cb420c232910a1a9f8258114 (Apache-2.0),
regorus 0.4.0 (MIT), and Rust standard-library / transitive crates.
Their original license/copyright notices are retained in the named subdirectories.
rust-dependency-tree.txt records the enabled normal/build dependency versions.

System runtime libraries (including glibc, libstdc++, libgcc_s, and zlib) are not
redistributed in this bundle; the Ubuntu 22.04 runtime supplies those libraries.
NOTICE
