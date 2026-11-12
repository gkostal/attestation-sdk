#!/bin/bash
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Run the unit-test suite (ctest -L unit) from the test build tree.
#
# Extra args are passed to ctest, e.g.:
#   test.sh -R CollateralCb          # only the collateral-callback tests
# Environment:
#   NVAT_C_SDK_TEST_SERVICE_KEY  the unit-test environment refuses to start without a
#                                non-empty key; a dummy value is used when unset (tests
#                                that need a real NVIDIA service key fail/skip by design).
#   CTEST_JOBS                   parallel ctest jobs (default 8)
#   BUILD_DIR                    build tree under nv-attestation-sdk-cpp (default build)

set -uo pipefail

export PATH="/opt/cargo/bin:$PATH"
export NVAT_C_SDK_TEST_SERVICE_KEY="${NVAT_C_SDK_TEST_SERVICE_KEY:-nvat-maa-dummy-service-key}"

cd "/work/src/nv-attestation-sdk-cpp/${BUILD_DIR:-build}"
ctest -L unit --output-on-failure -j"${CTEST_JOBS:-8}" --timeout "${CTEST_TIMEOUT:-600}" "$@"
