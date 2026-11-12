# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Build environment for the MAA prototype libnvat.so bundle (Ubuntu 22.04 / jammy).
# Mirrors dev/install-deps.sh (clang, rust, cbor-diag-cli, python venv) minus the
# CUDA/NVML/NSCQ packages, which are only needed for on-device collection.
#
# OpenSSL, curl, libxml2 and xmlsec are built from source (and statically linked) by
# the SDK's CMake (USE_SYSTEM_DEPS=OFF); that is why this image needs perl, make and
# network access at configure time.

FROM ubuntu:22.04

ARG RUST_VERSION=1.99.1
ARG CBOR_DIAG_VERSION=0.1.8
ARG CMAKE_VERSION=3.31.6
ARG ZLIB_VERSION=1.3.1
ARG ZLIB_SHA256=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget git rsync pkg-config make ninja-build \
        clang lld llvm binutils file xz-utils unzip \
        g++ perl python3 python3-pip python3-venv \
        zlib1g-dev libxml2-utils \
    && rm -rf /var/lib/apt/lists/*

# cmake >= 3.25 (jammy ships 3.22). Kitware's official binary tarball is used so the
# build does not depend on pip's network state.
RUN curl --proto '=https' --tlsv1.2 -fsSL \
        "https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-x86_64.tar.gz" \
        -o /tmp/cmake.tgz \
    && tar -xzf /tmp/cmake.tgz -C /opt \
    && ln -s /opt/cmake-${CMAKE_VERSION}-linux-x86_64/bin/* /usr/local/bin/ \
    && rm /tmp/cmake.tgz \
    && cmake --version

# Rust toolchain (regorus FFI via corrosion) + cbor-diag (prepare-test-data).
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain ${RUST_VERSION} \
    && cargo install cbor-diag-cli --version ${CBOR_DIAG_VERSION} --locked \
    && rustc --version && cbor-diag --help >/dev/null

# Static, position-independent zlib for the bundle build: the distro's libz.a is not PIC, and
# the bundled libnvat.so must not depend on libz.so.1. Lives in its own prefix (no libz.so there)
# so `-L/opt/zlib-static/lib -lz` resolves to the archive (see container/build.sh bundle).
RUN curl --proto '=https' --tlsv1.2 -fsSL \
        "https://github.com/madler/zlib/releases/download/v${ZLIB_VERSION}/zlib-${ZLIB_VERSION}.tar.gz" \
        -o /tmp/zlib.tgz \
    && echo "${ZLIB_SHA256}  /tmp/zlib.tgz" | sha256sum -c - \
    && tar -xzf /tmp/zlib.tgz -C /tmp \
    && cd /tmp/zlib-${ZLIB_VERSION} \
    && CC=clang CFLAGS="-O2 -fPIC" ./configure --static --prefix=/opt/zlib-static \
    && make -j"$(nproc)" install \
    && rm -rf /tmp/zlib.tgz /tmp/zlib-${ZLIB_VERSION}

# autotools: libxml2/xmlsec/curl tarballs are built with their bundled configure scripts, but a
# timestamp race during extraction can make `make` try to regenerate them (`missing: autoconf`).
RUN apt-get update && apt-get install -y --no-install-recommends autoconf automake libtool m4 \
    && rm -rf /var/lib/apt/lists/*

# Persistent work area (source copy + build trees live on a named docker volume).
WORKDIR /work
CMD ["/bin/bash"]
