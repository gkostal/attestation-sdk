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

// The POSIX functions the unit tests use, for Windows (MSVC: force-included into every test source).

#include <cstdlib>
#include <string>

#ifndef _WIN32
#include <unistd.h>
#endif

#ifdef _WIN32
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <direct.h>
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <sys/stat.h>

#include "nv_attestation/platform.h"

#ifndef PATH_MAX
#define PATH_MAX _MAX_PATH
#endif

// realpath(): an absolute path, or nullptr when the path does not exist.
inline char* realpath(const char* path, char* resolved) {
    struct _stat64 status;
    if (_stat64(path, &status) != 0) {
        return nullptr;
    }
    return _fullpath(resolved, path, PATH_MAX);
}

inline time_t timegm(struct tm* utc) { return nvattestation::timegm_utc(utc); }

inline int setenv(const char* name, const char* value, int overwrite) {
    if (!overwrite && std::getenv(name) != nullptr) {
        return 0;
    }
    return _putenv_s(name, value);
}

inline int unsetenv(const char* name) { return _putenv_s(name, ""); }

inline int mkstemp(char* path_template) {
    if (_mktemp_s(path_template, std::strlen(path_template) + 1) != 0) {
        return -1;
    }
    return _open(path_template, _O_CREAT | _O_EXCL | _O_RDWR | _O_BINARY, _S_IREAD | _S_IWRITE);
}

inline char* mkdtemp(char* path_template) {
    if (_mktemp_s(path_template, std::strlen(path_template) + 1) != 0 || _mkdir(path_template) != 0) {
        return nullptr;
    }
    return path_template;
}

inline FILE* popen(const char* command, const char* mode) { return _popen(command, mode); }
inline int pclose(FILE* stream) { return _pclose(stream); }

#ifndef F_OK
#define F_OK 0
#endif

// strptime() for the fixed numeric formats the tests parse; returns the end of the parsed text, or nullptr.
inline char* strptime(const char* text, const char* format, struct tm* out) {
    std::istringstream in(text);
    in >> std::get_time(out, format);
    if (in.fail()) {
        return nullptr;
    }
    const std::streamoff consumed = in.eof() ? static_cast<std::streamoff>(std::strlen(text)) : static_cast<std::streamoff>(in.tellg());
    return const_cast<char*>(text) + consumed;
}
#endif

// The id of this process (ctest runs every test in its own process).
inline int nvat_test_process_id() {
#ifdef _WIN32
    return _getpid();
#else
    return static_cast<int>(getpid());
#endif
}

// The directory for temporary test files: /tmp, or %TEMP% on Windows.
inline std::string nvat_test_temp_dir() {
#ifdef _WIN32
    const char* temp = std::getenv("TEMP");
    return temp != nullptr && *temp != '\0' ? std::string(temp) : std::string(".");
#else
    return "/tmp";
#endif
}
