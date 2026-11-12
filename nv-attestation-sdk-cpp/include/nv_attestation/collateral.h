/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * All rights reserved. SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "nv_attestation/error.h"

namespace nvattestation {

// Kinds of verification collateral a caller can supply instead of libnvat
// fetching it over the network / filesystem. Values match
// nvat_collateral_kind_t.
enum class CollateralKind {
    Corim = 1,
    OcspResponse = 2,
};

// Per-call, caller-owned source of verification collateral. When one is
// supplied (see VerifyCallOptions) the verifier performs no network or file
// I/O of its own: every CoRIM and OCSP response comes through this interface.
// Implementations are invoked synchronously on the verifying thread.
class ICollateralProvider {
  public:
    virtual ~ICollateralProvider() = default;

    // Error::Ok            out_bytes holds the collateral.
    // Error::CacheObjectNotFound  the caller's store has no such item (the
    //                      one "absent" signal; everything else is a failure).
    // any other error      the lookup itself failed.
    virtual Error get_collateral(CollateralKind kind,
                                 const std::string &lookup_key,
                                 std::vector<uint8_t> &out_bytes) const = 0;
};

// Per-call options for LocalCorimVerifier::verify_cmw. A null pointer there
// means "legacy behavior"; a non-null one switches on the knobs below, whose
// defaults differ from legacy only where noted.
struct VerifyCallOptions {
    // Null: libnvat fetches collateral itself (network/filesystem), exactly as
    // without call options.
    const ICollateralProvider *collateral = nullptr;
    // Require the OCSP response nonce to match the request nonce. Cached OCSP
    // responses cannot carry a per-request nonce, so those callers set false.
    bool require_ocsp_nonce = true;
    // Treat an OCSP response whose nextUpdate has passed as untrusted.
    // (Legacy behavior records response_expired but does not enforce it.)
    bool enforce_ocsp_next_update = true;
    // Unix epoch seconds used as "now" for certificate expiry, OCSP response
    // expiry and OCSP responder-chain validation. 0 = wall clock.
    int64_t verification_time = 0;
};

} // namespace nvattestation
