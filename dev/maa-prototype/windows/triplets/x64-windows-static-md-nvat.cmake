# vcpkg triplet for the third-party libraries of nvat.dll: static libraries that use the dynamic CRT
# (/MD, like nvat.dll itself), compiled with the same hardening as nvat's own code.
set(VCPKG_TARGET_ARCHITECTURE x64)
set(VCPKG_CRT_LINKAGE dynamic)
set(VCPKG_LIBRARY_LINKAGE static)

set(VCPKG_C_FLAGS "/guard:cf /Qspectre")
set(VCPKG_CXX_FLAGS "/guard:cf /Qspectre")
