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

#pragma once

// The few POSIX facilities the SDK uses, for Linux and Windows (MSVC).

#include <cerrno>
#include <climits>
#include <ctime>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef _WIN32
#include <dlfcn.h>
#endif

#if defined(_WIN32) && !defined(S_ISDIR)
#define S_ISDIR(mode) (((mode) & S_IFMT) == S_IFDIR)
#endif

#if defined(_WIN32)
#ifndef RTLD_LAZY
#define RTLD_LAZY 0x1
#endif
#ifndef RTLD_LOCAL
#define RTLD_LOCAL 0
#endif
#endif

namespace nvattestation {

#ifdef _WIN32
namespace platform_detail {
// Howard Hinnant's days_from_civil / civil_from_days (public domain): the proleptic Gregorian
// calendar for any year, unlike the CRT's _mkgmtime / gmtime_s, which stop at the year 3000 (the
// NVIDIA certificates expire 9999-12-31T23:59:59Z).
inline long long days_from_civil(long long y, unsigned m, unsigned d) {
    y -= m <= 2 ? 1 : 0;
    const long long era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<long long>(doe) - 719468;
}

inline void civil_from_days(long long z, long long& y, unsigned& m, unsigned& d) {
    z += 719468;
    const long long era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    y = static_cast<long long>(yoe) + era * 400 + (m <= 2 ? 1 : 0);
}

inline long long floor_div(long long a, long long b) {
    return a / b - ((a % b != 0) && ((a < 0) != (b < 0)) ? 1 : 0);
}
} // namespace platform_detail
#endif

// timegm(): a broken-down UTC time to seconds since the epoch (out-of-range fields carry over).
inline time_t timegm_utc(struct tm* utc) {
#ifdef _WIN32
    using namespace platform_detail;
    long long year = 1900LL + utc->tm_year + floor_div(utc->tm_mon, 12);
    const long long month = utc->tm_mon - floor_div(utc->tm_mon, 12) * 12;
    const long long days = days_from_civil(year, static_cast<unsigned>(month + 1), 1) + utc->tm_mday - 1;
    return static_cast<time_t>(days * 86400LL + utc->tm_hour * 3600LL + utc->tm_min * 60LL + utc->tm_sec);
#else
    return timegm(utc);
#endif
}

// gmtime_r(): seconds since the epoch to broken-down UTC time. Returns `out`, or nullptr with errno set.
inline struct tm* gmtime_utc(const time_t* timestamp, struct tm* out) {
#ifdef _WIN32
    using namespace platform_detail;
    const long long seconds = static_cast<long long>(*timestamp);
    const long long days = floor_div(seconds, 86400);
    const long long rest = seconds - days * 86400;
    long long year = 0;
    unsigned month = 0;
    unsigned day = 0;
    civil_from_days(days, year, month, day);
    if (year - 1900 > INT_MAX || year - 1900 < INT_MIN) {
        errno = EOVERFLOW;
        return nullptr;
    }
    *out = {};
    out->tm_year = static_cast<int>(year - 1900);
    out->tm_mon = static_cast<int>(month) - 1;
    out->tm_mday = static_cast<int>(day);
    out->tm_hour = static_cast<int>(rest / 3600);
    out->tm_min = static_cast<int>(rest % 3600 / 60);
    out->tm_sec = static_cast<int>(rest % 60);
    out->tm_wday = static_cast<int>((days + 4) - floor_div(days + 4, 7) * 7); // 1970-01-01 was a Thursday
    out->tm_yday = static_cast<int>(days - days_from_civil(year, 1, 1));
    out->tm_isdst = 0;
    return out;
#else
    return gmtime_r(timestamp, out);
#endif
}

#ifdef _WIN32
// Evidence collection (NVML, NSCQ, corelib) is Linux only. On Windows those libraries are never loaded:
// dlopen always fails, so the collectors report that they are unavailable.
inline void* dlopen(const char* /*file*/, int /*mode*/) { return nullptr; }
inline void* dlsym(void* /*handle*/, const char* /*name*/) { return nullptr; }
inline int dlclose(void* /*handle*/) { return 0; }
inline const char* dlerror() { return "loading the NVML, NSCQ and corelib libraries is not supported on Windows"; }
#endif

} // namespace nvattestation
