/* SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
 * SPDX-License-Identifier: Apache-2.0 */
#include "nvat.h"

static nvat_rc_t lookup(void* context, nvat_collateral_kind_t kind,
                       const char* key, nvat_byte_buf_t* output) {
    (void)context; (void)kind; (void)key;
    *output = NULL;
    return NVAT_RC_COLLATERAL_NOT_FOUND;
}

int main(void) {
    nvat_verify_call_options_t options = NULL;
    nvat_rc_t rc = nvat_verify_call_options_create(&options);
    if (rc != NVAT_RC_OK) return 1;
    rc = nvat_verify_call_options_set_collateral_callback(options, lookup, NULL);
    if (rc == NVAT_RC_OK)
        rc = nvat_verify_call_options_set_require_ocsp_nonce(options, false);
    if (rc == NVAT_RC_OK)
        rc = nvat_verify_call_options_set_enforce_ocsp_next_update(options, true);
    if (rc == NVAT_RC_OK)
        rc = nvat_verify_call_options_set_verification_time(options, INT64_C(1794577830));
    nvat_verify_call_options_free(&options);
    return rc == NVAT_RC_OK ? 0 : 1;
}
