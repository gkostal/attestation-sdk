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

#include "local_https_test_server.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>

#ifdef _WIN32

#include <windows.h>

#include <vector>

static std::string quote_argument(const std::string &argument) {
    return "\"" + argument + "\"";
}

bool LocalHttpsTestServer::start(const std::string &jwks_file,
                                 const std::string &capture_headers_file,
                                 const std::string &jwks_redirect_url) {
    const std::string cert = m_cert_dir + "/tls_server_cert.pem";
    const std::string key = m_cert_dir + "/tls_server_key.pem";
    if (_access(cert.c_str(), 4) != 0 || _access(key.c_str(), 4) != 0) {
        std::cerr << "Prepared TLS test certificates are not readable"
                  << std::endl;
        return false;
    }

    // The server binds port 0 (any free port) and reports the port in its READY line: a port probed here
    // could be taken by a parallel test process before the server binds it.
    m_port = 0;
    SECURITY_ATTRIBUTES inherit{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE read_end = nullptr;
    HANDLE write_end = nullptr;
    if (!CreatePipe(&read_end, &write_end, &inherit, 0)) {
        std::cerr << "CreatePipe() failed" << std::endl;
        return false;
    }
    SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0);

    const char* python = std::getenv("NVAT_TEST_PYTHON");
    std::string command = quote_argument(python != nullptr && *python != '\0' ? python : "python");
    for (const std::string &argument : {m_cert_dir + "/https_server.py", std::to_string(m_port), cert, key,
                                        jwks_file, capture_headers_file, jwks_redirect_url}) {
        command += " " + quote_argument(argument);
    }
    std::vector<char> command_line(command.begin(), command.end());
    command_line.push_back('\0');

    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = write_end;
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessA(nullptr, command_line.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                                        nullptr, nullptr, &startup, &process);
    CloseHandle(write_end);
    if (!created) {
        std::cerr << "CreateProcess(" << command << ") failed: " << GetLastError() << std::endl;
        CloseHandle(read_end);
        return false;
    }
    CloseHandle(process.hThread);
    m_process = process.hProcess;

    // Wait up to 20 seconds for the server's "READY <port>" line (parallel test processes start many servers).
    std::string output;
    bool ready = false;
    const ULONGLONG deadline = GetTickCount64() + 20000;
    while (!ready && GetTickCount64() < deadline) {
        DWORD available = 0;
        if (!PeekNamedPipe(read_end, nullptr, 0, nullptr, &available, nullptr)) {
            break;  // the server exited
        }
        if (available == 0) {
            Sleep(20);
            continue;
        }
        char buf[256];
        DWORD got = 0;
        if (!ReadFile(read_end, buf, available < sizeof(buf) ? available : sizeof(buf), &got, nullptr) || got == 0) {
            break;
        }
        output.append(buf, got);
        const size_t ready_at = output.find("READY ");
        if (ready_at != std::string::npos && output.find('\n', ready_at) != std::string::npos) {
            m_port = std::atoi(output.c_str() + ready_at + 6);
            ready = m_port > 0;
        }
    }
    CloseHandle(read_end);

    if (!ready) {
        std::cerr << "HTTPS server did not become ready" << std::endl;
        stop();
        return false;
    }

    return true;
}

void LocalHttpsTestServer::stop() {
    if (m_process != nullptr) {
        TerminateProcess(m_process, 1);
        WaitForSingleObject(m_process, 5000);
        CloseHandle(m_process);
        m_process = nullptr;
    }
}

#else

#include <csignal>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

bool LocalHttpsTestServer::start(const std::string &jwks_file,
                                 const std::string &capture_headers_file,
                                 const std::string &jwks_redirect_url) {
    const std::string cert = m_cert_dir + "/tls_server_cert.pem";
    const std::string key = m_cert_dir + "/tls_server_key.pem";
    if (access(cert.c_str(), R_OK) != 0 || access(key.c_str(), R_OK) != 0) {
        std::cerr << "Prepared TLS test certificates are not readable"
                  << std::endl;
        return false;
    }

    // The server binds port 0 (any free port) and reports the port in its READY line: a port probed here
    // could be taken by a parallel test process before the server binds it.
    m_port = 0;

    // Create pipe so we can read server stdout for READY signal
    int pipefd[2];
    if (pipe(pipefd) < 0) {
        std::cerr << "pipe() failed" << std::endl;
        return false;
    }

    m_pid = fork();
    if (m_pid < 0) {
        std::cerr << "fork() failed" << std::endl;
        close(pipefd[0]);
        close(pipefd[1]);
        return false;
    }

    if (m_pid == 0) {
        // Child: redirect stdout to pipe, exec python server
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);

        std::string port_str = std::to_string(m_port);
        std::string script = m_cert_dir + "/https_server.py";

        execlp("python3", "python3", script.c_str(),
               port_str.c_str(), cert.c_str(), key.c_str(),
               jwks_file.c_str(), capture_headers_file.c_str(),
               jwks_redirect_url.c_str(), nullptr);
        // If exec fails
        _exit(1);
    }

    // Parent: read pipe until READY
    close(pipefd[1]);
    FILE* pipe_stream = fdopen(pipefd[0], "r");
    if (!pipe_stream) {
        std::cerr << "fdopen() failed" << std::endl;
        kill(m_pid, SIGTERM);
        waitpid(m_pid, nullptr, 0);
        return false;
    }

    char buf[256];
    bool ready = false;
    // Wait up to 10 seconds for server to be ready
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(pipefd[0], &fds);
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    if (select(pipefd[0] + 1, &fds, nullptr, nullptr, &tv) > 0) {
        if (fgets(buf, sizeof(buf), pipe_stream)) {
            std::string line(buf);
            const size_t ready_at = line.find("READY ");
            if (ready_at != std::string::npos) {
                m_port = std::atoi(line.c_str() + ready_at + 6);
                ready = m_port > 0;
            }
        }
    }
    fclose(pipe_stream);

    if (!ready) {
        std::cerr << "HTTPS server did not become ready" << std::endl;
        kill(m_pid, SIGTERM);
        waitpid(m_pid, nullptr, 0);
        m_pid = -1;
        return false;
    }

    return true;
}

void LocalHttpsTestServer::stop() {
    if (m_pid > 0) {
        kill(m_pid, SIGTERM);
        waitpid(m_pid, nullptr, 0);
        m_pid = -1;
    }
}

#endif

std::string LocalHttpsTestServer::url() const {
    return "https://127.0.0.1:" + std::to_string(m_port) + "/";
}

std::string LocalHttpsTestServer::cert_path(const std::string &filename) const {
    return m_cert_dir + "/" + filename;
}
