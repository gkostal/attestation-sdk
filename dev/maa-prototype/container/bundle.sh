#!/bin/bash
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Verify and stage the libnvat bundle from the hidden-symbols build tree
# (/work/src/nv-attestation-sdk-cpp/build-bundle, see build.sh bundle).
#
#   bundle.sh <out-dir>      <out-dir> is the (bind-mounted) bundle directory
#
# Gates (the script fails, and so does build-bundle.ps1): only nvat_* symbols exported; exactly the
# functions of nvat.h; only core system libraries in DT_NEEDED.
# Produces: include/nvat.h, lib/linux-x64/libnvat.so.2, ldd.txt, symbols/*, build-info.json,
# fixtures/corim/*.cbor, fixtures/cmw/rubin_evidence.cmw.json, selftest/{smoke,smoke.c}.

set -euo pipefail

OUT="${1:?usage: bundle.sh <out-dir>}"
export PATH="/opt/cargo/bin:$PATH"
SRC=/work/src/nv-attestation-sdk-cpp
BUILD="$SRC/build-bundle"
HERE="$(cd "$(dirname "$0")" && pwd)"
TESTDATA="$SRC/unit-tests/testdata"

LIB_BUILT="$BUILD/libnvat.so.2"
[ -e "$LIB_BUILT" ] || { echo "error: $LIB_BUILT missing; run build.sh bundle first" >&2; exit 2; }

mkdir -p "$OUT/include" "$OUT/lib/linux-x64" "$OUT/symbols" "$OUT/fixtures/corim" \
         "$OUT/fixtures/cmw" "$OUT/selftest"

echo "--- header + library"
cp "$BUILD/include/nvat.h" "$OUT/include/nvat.h"
cp -L "$LIB_BUILT" "$OUT/lib/linux-x64/libnvat.so.2"
LIB="$OUT/lib/linux-x64/libnvat.so.2"

echo "--- symbol / dependency gate"
python3 "$HERE/check_symbols.py" "$LIB" "$OUT/include/nvat.h" "$OUT/symbols"

echo "--- ldd"
ldd "$LIB" | sed -E 's/ \(0x[0-9a-f]+\)//' > "$OUT/ldd.txt"
cat "$OUT/ldd.txt"

echo "--- fixtures"
# The Rubin CoRIMs, named by the canonical RIM id of their rim-locator
# (https://rim.attestation.nvidia.com/v1/rim/<id>) == the CORIM collateral lookup key.
cbor-diag --from=diag --to=bytes < "$TESTDATA/sample_rims/corim/rubin_vbios_example.diag" \
    > "$OUT/fixtures/corim/GR100_081D_9900230000.cbor"
cbor-diag --from=diag --to=bytes < "$TESTDATA/sample_rims/corim/rubin_driver_example.diag" \
    > "$OUT/fixtures/corim/NV_GPU_DRIVER_GR100_620.54.cbor"
cp "$TESTDATA/sample_attestation_data/rubin_evidence.cmw.json" "$OUT/fixtures/cmw/rubin_evidence.cmw.json"

echo "--- self-test program"
SMOKE_SRC="${SMOKE_SRC:-/selftest/smoke.c}"   # mounted by build-bundle.ps1
cp "$SMOKE_SRC" "$OUT/selftest/smoke.c"
clang -std=c99 -O1 -Wall -Wextra -Werror -I"$OUT/include" -o "$OUT/selftest/smoke" "$OUT/selftest/smoke.c" \
    -L"$OUT/lib/linux-x64" -l:libnvat.so.2 -ldl -Wl,-rpath,'$ORIGIN/../lib/linux-x64'

echo "--- build info"
glibc_max=$(objdump -T "$LIB" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)
glibcxx_max=$(objdump -T "$LIB" | grep -o 'GLIBCXX_[0-9.]*' | sort -uV | tail -1)
python3 - "$OUT/build-info.json" "$BUILD" "$LIB" "$glibc_max" "$glibcxx_max" <<'PY'
import json, re, subprocess, sys
out, build, lib, glibc_max, glibcxx_max = sys.argv[1:6]
def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()
def grep_define(path, pattern):
    try:
        m = re.search(pattern, open(path).read())
        return m.group(1) if m else None
    except OSError:
        return None
info = {
    "soname": "libnvat.so.2",
    "base_image": "ubuntu:22.04",
    "compiler": sh("clang --version | head -1"),
    "rust": sh("rustc --version"),
    "cmake": sh("cmake --version | head -1"),
    "cmake_build_type": "Release",
    "static_dependencies": {
        "openssl": grep_define(build + "/openssl-install/include/openssl/opensslv.h",
                               r'OPENSSL_VERSION_STR\s+"([^"]+)"'),
        "curl": grep_define(build + "/curl-install/include/curl/curlver.h",
                            r'LIBCURL_VERSION\s+"([^"]+)"'),
        "libxml2": grep_define(build + "/libxml2-install/include/libxml2/libxml/xmlversion.h",
                               r'LIBXML_DOTTED_VERSION\s+"([^"]+)"'),
        "zlib": grep_define("/opt/zlib-static/include/zlib.h", r'ZLIB_VERSION\s+"([^"]+)"'),
    },
    "max_glibc_symbol_version": glibc_max,
    "max_glibcxx_symbol_version": glibcxx_max,
    "size_bytes": int(sh("stat -c %s " + lib)),
}
open(out, "w").write(json.dumps(info, indent=2) + "\n")
print(json.dumps(info, indent=2))
PY
echo "bundle staged in $OUT"
