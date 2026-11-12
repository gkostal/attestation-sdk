#!/bin/bash
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Run the whole `ctest -L unit` suite and gate on it.
#
# A subset of the existing suite talks to the live NVIDIA services (RIM / OCSP / NRAS) and needs a
# real NVAT_C_SDK_TEST_SERVICE_KEY; without one they fail with HTTP 403 on the unmodified baseline
# too. Those tests are listed in live-service-tests.txt (measured on the baseline commit): they may
# fail, every other test must pass.
#
# Exit status: 0 when no test outside that list failed, 1 otherwise. Prints a summary
# (total / passed / skipped / failed, and how many failures were the expected live-service ones).

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
LOG=/work/unit-tests.log

bash "$HERE/test.sh" "$@" 2>&1 | tee "$LOG" | grep -E 'tests passed|tests failed|\*\*\*(Failed|Skipped|Exception|Timeout)' | sed -E 's/\.{5,}/ ... /' || true

BUILD=/work/src/nv-attestation-sdk-cpp/build
tr -d '\r' < "$HERE/live-service-tests.txt" | sort -u > /work/expected-failures.txt
# LastTestsFailed.log lines look like "123:Suite.Test"
if [ -s "$BUILD/Testing/Temporary/LastTestsFailed.log" ]; then
    sed -E 's/^[0-9]+://' "$BUILD/Testing/Temporary/LastTestsFailed.log" | sort -u > /work/actual-failures.txt
else
    : > /work/actual-failures.txt
fi

unexpected=$(comm -13 /work/expected-failures.txt /work/actual-failures.txt)
expected_hit=$(comm -12 /work/expected-failures.txt /work/actual-failures.txt | wc -l)
failed=$(wc -l < /work/actual-failures.txt)
skipped=$(grep -c '\*\*\*Skipped' "$LOG" || true)
ran=$(sed -nE 's/.*tests passed, ([0-9]+) tests failed out of ([0-9]+).*/\2/p' "$LOG" | tail -1)
ran=${ran:-0}

echo "=== unit test summary: total=$((ran + skipped)) passed=$((ran - failed)) skipped=$skipped failed=$failed" \
     "(expected live-service failures: $expected_hit, unexpected: $((failed - expected_hit)))"
if [ -n "$unexpected" ]; then
    echo "UNEXPECTED FAILURES:" >&2
    echo "$unexpected" >&2
    exit 1
fi
exit 0
