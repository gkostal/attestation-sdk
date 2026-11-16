#!/bin/bash
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Mirror the read-only source mount (/src-ro, the Windows working tree) into the
# persistent work volume (/work/src) so builds never write into the host tree.
# Build trees and the python venv inside /work/src are preserved across syncs.

set -euo pipefail

SRC_RO="${SRC_RO:-/src-ro}"
WORK_SRC="${WORK_SRC:-/work/src}"

mkdir -p "$WORK_SRC"
rsync -a --delete \
    --exclude '/.git' \
    --exclude '/nv-attestation-sdk-cpp/build*/' \
    --exclude '/nv-attestation-sdk-cpp/venv/' \
    --exclude '/nv-attestation-sdk-cpp/unit-tests/build/' \
    --exclude 'target/' \
    "$SRC_RO/" "$WORK_SRC/"

# Normalise any CRLF that leaked in from a Windows checkout (text sources only).
find "$WORK_SRC" \( -path '*/build*' -o -path '*/venv' -o -path '*/.git' \) -prune -o -type f \
    \( -name '*.sh' -o -name '*.py' -o -name '*.cpp' -o -name '*.h' -o -name '*.hpp' -o -name '*.in' \
       -o -name '*.txt' -o -name '*.cmake' -o -name '*.diag' -o -name '*.cddl' -o -name '*.c' \
       -o -name '*.json' -o -name '*.md' -o -name 'Makefile' -o -name '*.lds' \) \
    -print0 | xargs -0 -r grep -l $'\r' 2>/dev/null | tr '\n' '\0' | xargs -0 -r sed -i 's/\r$//' || true

echo "source synced to $WORK_SRC"
