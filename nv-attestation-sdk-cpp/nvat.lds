/*
 * Linker version script for libnvat.so (used when NVAT_HIDE_INTERNAL_SYMBOLS=ON).
 *
 * libnvat statically links OpenSSL, curl, libxml2, xmlsec, spdlog, fmt, zcbor and
 * regorus. Exporting only the public C ABI keeps those copies private so they cannot
 * interpose on (or be interposed by) the host process's own OpenSSL/libstdc++ users.
 *
 * Global: the public C ABI (nvat_*, declared in nvat.h). Everything else is local.
 */
{
  global:
    nvat_*;
  local:
    *;
};
