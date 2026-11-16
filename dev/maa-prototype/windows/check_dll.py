#!/usr/bin/env python3
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
"""Export / dependency / hardening gate for the bundled nvat.dll (Windows x64).

    check_dll.py <dumpbin.exe> <nvat.dll> <nvat.h> <report-dir>

Fails (exit 1) unless
  * every export is an nvat_* function and exactly the functions declared in nvat.h are exported
    (OpenSSL, curl, libxml2, xmlsec, zcbor, spdlog and regorus stay private);
  * the DLL imports only Windows system DLLs, the Universal CRT (api-ms-win-crt-*) and the Visual C++
    runtime -- OpenSSL, curl, libxml2, xmlsec and zlib are linked statically;
  * it is x64 with ASLR (high entropy), NX, Control Flow Guard and CET shadow-stack compatibility;
  * it points at a PDB (CodeView RSDS debug directory).
Writes <report-dir>/exports.txt, dependents.txt and headers.txt.
"""

import pathlib
import re
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "container"))
from check_symbols import declared_functions  # noqa: E402

ALLOWED_DEPENDENTS = {
    # Visual C++ runtime (dynamic CRT, /MD)
    "msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll",
    # Windows system DLLs used by OpenSSL, curl and the Rust standard library
    "kernel32.dll", "ntdll.dll", "advapi32.dll", "user32.dll", "crypt32.dll", "ws2_32.dll",
    "bcrypt.dll", "bcryptprimitives.dll", "iphlpapi.dll", "userenv.dll", "secur32.dll",
    "dbghelp.dll", "ole32.dll", "shell32.dll",
}
ALLOWED_DEPENDENT_PREFIXES = ("api-ms-win-crt-", "api-ms-win-core-")
REQUIRED_HEADER_FLAGS = {
    "x64": "8664 machine (x64)",
    "ASLR": "Dynamic base",
    "high-entropy ASLR": "High Entropy Virtual Addresses",
    "NX": "NX compatible",
    "Control Flow Guard": "Control Flow Guard",
    "CET shadow stack": "CET compatible",
}


def dumpbin(exe: str, *args: str) -> str:
    return subprocess.run([exe, "/nologo", *args], check=True, capture_output=True, text=True).stdout


def main() -> int:
    exe, dll, header, report = sys.argv[1], pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]), pathlib.Path(sys.argv[4])
    report.mkdir(parents=True, exist_ok=True)
    problems = []

    exports_text = dumpbin(exe, "/exports", str(dll))
    exported = sorted(set(re.findall(r"^\s+\d+\s+[0-9A-F]+\s+[0-9A-F]{8}\s+(\S+)", exports_text, flags=re.M)))
    (report / "exports.txt").write_text("\n".join(exported) + "\n")
    foreign = [name for name in exported if not name.startswith("nvat_")]
    if foreign:
        problems.append("non-nvat_* exports (%d): %s" % (len(foreign), ", ".join(foreign[:20])))
    declared = declared_functions(header)
    missing = sorted(declared - set(exported))
    extra = sorted(set(exported) - declared - set(foreign))
    if missing:
        problems.append("declared in nvat.h but not exported: " + ", ".join(missing))
    if extra:
        problems.append("exported but not declared in nvat.h: " + ", ".join(extra))

    dependents_text = dumpbin(exe, "/dependents", str(dll))
    dependents = re.findall(r"^\s{4}(\S+\.dll)\s*$", dependents_text, flags=re.M | re.I)
    (report / "dependents.txt").write_text("\n".join(dependents) + "\n")
    unexpected = [name for name in dependents
                  if name.lower() not in ALLOWED_DEPENDENTS and not name.lower().startswith(ALLOWED_DEPENDENT_PREFIXES)]
    if unexpected:
        problems.append("unexpected DLL dependencies: " + ", ".join(unexpected))

    headers_text = dumpbin(exe, "/headers", "/loadconfig", str(dll))
    (report / "headers.txt").write_text(headers_text)
    for name, marker in REQUIRED_HEADER_FLAGS.items():
        if marker not in headers_text:
            problems.append("not built with %s (no '%s' in the PE headers)" % (name, marker))
    pdb = re.search(r"Format: RSDS, \{[^}]+\}, \d+, (.+?\.pdb)\s*$", headers_text, flags=re.M | re.I)
    if not pdb:
        problems.append("no PDB reference (CodeView RSDS debug directory)")

    print("exports: %d (all nvat_*: %s), declared functions: %d, dependents: %s, pdb: %s" %
          (len(exported), not foreign, len(declared), ", ".join(dependents), pdb.group(1) if pdb else None))
    for problem in problems:
        print("FAIL: " + problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
