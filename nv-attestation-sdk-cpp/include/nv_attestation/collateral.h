// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <functional>
#include <string>
#include <vector>
#include <cstdint>
#include <ctime>
#include "nv_attestation/error.h"

namespace nvattestation {

enum class CollateralKind { Corim = 1, OcspResponse = 2 };
using CollateralCallback = std::function<Error(
    CollateralKind, const std::string&, std::vector<uint8_t>&)>;

struct VerifyCallOptions {
    CollateralCallback collateral;
    bool require_ocsp_nonce = true;
    bool enforce_ocsp_next_update = true;
    time_t verification_time = 0;
};

} // namespace nvattestation
