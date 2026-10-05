
cmake_minimum_required(VERSION 3.16)
project(ReflectivePayload LANGUAGES C CXX)

# Pick the DoSyscall trampoline for the target arch and assembler:
# .asm is armasm/MASM syntax (MSVC only), .s is GNU assembler syntax (mingw).
if(MSVC)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
        set(RDI_TRAMPOLINE dll/src/GateTrampolineARM64.asm)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
        set(RDI_TRAMPOLINE dll/src/GateTrampoline64.asm)
    else()
        set(RDI_TRAMPOLINE dll/src/GateTrampoline32.asm)
    endif()
else()
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
        set(RDI_TRAMPOLINE dll/src/GateTrampolineARM64.s)
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
        set(RDI_TRAMPOLINE dll/src/GateTrampoline64.s)
    else()
        set(RDI_TRAMPOLINE dll/src/GateTrampoline32.s)
    endif()
endif()

add_library(reflective_dll
    dll/src/DirectSyscall.c
    dll/src/DirectSyscall.h
    ${RDI_TRAMPOLINE}
    dll/src/ReflectiveDll.c
    dll/src/ReflectiveLoader.c
    dll/src/ReflectiveLoader.h
)

include_directories(common)
include_directories(dll/src)

# 1. Enforce C-linkage and explicitly export the ReflectiveLoader function
target_compile_definitions(reflective_dll PRIVATE REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR)
target_compile_options(reflective_dll PRIVATE -Wno-register)

if(MSVC)
    target_link_options(reflective_dll PRIVATE
        # 2. Tell the linker to explicitly export the loader function 
        "/EXPORT:ReflectiveLoader"
        
        # 3. Disable optimization flags that might alter position-independent code (optional but safer)
        "/OD"
        
        # 4. Ensure a relocation section (.reloc) is generated (Crucial for RDI)
        "/FIXED:NO"
    )
endif()
