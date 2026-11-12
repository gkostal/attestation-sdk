#!/usr/bin/env python3
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Symbol / dependency gate for the bundled libnvat.so.

    check_symbols.py <libnvat.so.2> <nvat.h> <report-dir>

Fails (exit 1) unless
  * every defined dynamic symbol is an nvat_* symbol (no OPENSSL_*, EVP_*, curl_*, spdlog*, zcbor_*,
    ... and no C++ internals),
  * exactly the functions declared in nvat.h are exported (nothing missing, nothing extra),
  * DT_NEEDED contains only core system libraries (libc, libm, libstdc++, libgcc_s, libpthread, libdl,
    librt, ld-linux) -- OpenSSL, curl, libxml2 and zlib must be linked statically,
  * SONAME is libnvat.so.2.
Writes <report-dir>/nm-exported.txt, nm-imported.txt and needed.txt.
"""

import pathlib
import re
import subprocess
import sys

ALLOWED_NEEDED = {
    "libc.so.6", "libm.so.6", "libstdc++.so.6", "libgcc_s.so.1", "libpthread.so.0",
    "libdl.so.2", "librt.so.1", "ld-linux-x86-64.so.2",
}
FORBIDDEN_IMPORT_PREFIXES = ("SSL_", "EVP_", "OPENSSL_", "X509_", "OCSP_", "curl_", "xml", "inflate",
                             "deflate", "ERR_")


def run(*cmd: str) -> str:
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def declared_functions(header: pathlib.Path) -> set:
    text = header.read_text()
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    names = set(re.findall(r"\b(nvat_[A-Za-z0-9_]+)\s*\(", text))
    # Type names followed by "(" in function-pointer typedefs, e.g. "nvat_rc_t (*cb)(".
    return {name for name in names if not name.endswith("_t")}


def main() -> int:
    lib, header, report = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
    report.mkdir(parents=True, exist_ok=True)
    problems = []

    exported = sorted({line.split()[-1].split("@")[0]
                       for line in run("nm", "-D", "--defined-only", str(lib)).splitlines() if line.strip()})
    (report / "nm-exported.txt").write_text("\n".join(exported) + "\n")
    foreign = [name for name in exported if not name.startswith("nvat_")]
    if foreign:
        problems.append("non-nvat_* symbols exported (%d): %s" % (len(foreign), ", ".join(foreign[:20])))

    declared = declared_functions(header)
    missing = sorted(declared - set(exported))
    extra = sorted(set(exported) - declared - set(foreign))
    if missing:
        problems.append("declared in nvat.h but not exported: " + ", ".join(missing))
    if extra:
        problems.append("exported but not declared in nvat.h: " + ", ".join(extra))

    imported = sorted({line.split()[-1].split("@")[0]
                       for line in run("nm", "-D", "--undefined-only", str(lib)).splitlines() if line.strip()})
    (report / "nm-imported.txt").write_text("\n".join(imported) + "\n")
    leaked = [name for name in imported if name.startswith(FORBIDDEN_IMPORT_PREFIXES)]
    if leaked:
        problems.append("imports symbols that must be statically linked: " + ", ".join(leaked[:20]))

    dynamic = run("readelf", "-d", str(lib))
    needed = re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]", dynamic)
    (report / "needed.txt").write_text("\n".join(needed) + "\n")
    unexpected = [name for name in needed if name not in ALLOWED_NEEDED]
    if unexpected:
        problems.append("unexpected DT_NEEDED libraries: " + ", ".join(unexpected))
    soname = re.search(r"\(SONAME\)\s+Library soname: \[([^\]]+)\]", dynamic)
    if not soname or soname.group(1) != "libnvat.so.2":
        problems.append("SONAME is %s, expected libnvat.so.2" % (soname.group(1) if soname else None))

    print("exported symbols: %d (all nvat_*: %s), declared functions: %d, NEEDED: %s" %
          (len(exported), not foreign, len(declared), ", ".join(needed)))
    for problem in problems:
        print("FAIL: " + problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
