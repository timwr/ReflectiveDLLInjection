// Embedded payload DLL bytes for the shellcode blob (windows_loader.bin).
//
// This file must come SECOND in the windows_loader target sources (after
// shellcode_entry.c, before windows_loader.c). The generated header declares
// the byte array as `const` with section(".text") so the linker places it in
// the .text section, and the object ordering places it right after the
// entrypoint. See shellcode_entry.c for the required blob layout.
#include "resources/myapplib_dll.h"
