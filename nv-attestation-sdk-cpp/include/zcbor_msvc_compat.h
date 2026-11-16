/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
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

/*
 * MSVC compatibility for zcbor and its generated decoders. Force-included (/FI) on MSVC into zcbor_lib
 * and every nvat source, ahead of everything else.
 */
#pragma once

#ifdef _MSC_VER

#include <stddef.h>
#include <string.h>

/*
 * zcbor declares, and defines as a weak symbol, its own strnlen() for C libraries that lack one. The
 * MSVC CRT has a (dllimport) strnlen, so zcbor's copy is renamed. <string.h> comes first so that the
 * CRT's own declarations and inline functions keep the real one.
 */
#ifdef __cplusplus
extern "C" {
#endif
size_t zcbor_strnlen(const char *s, size_t maxlen);
#ifdef __cplusplus
}
#endif
#define strnlen zcbor_strnlen

/* The GCC attributes in zcbor's C sources (__weak__, used) need no MSVC counterpart. */
#ifndef __cplusplus
#define __attribute__(x)
#endif

#endif /* _MSC_VER */
