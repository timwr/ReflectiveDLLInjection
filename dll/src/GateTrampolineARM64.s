// GateTrampolineARM64.s (GNU assembler syntax for llvm-mingw)
//
// DoSyscall function implementation for 64-bit Windows on ARM64 to perform
// system calls with arguments passed as an array.
//  NTSTATUS DoSyscall(VOID *fn, DWORD dwSyscallNr, ULONG_PTR *lpArgs, DWORD dwNumberOfArgs);
//
// Authors:
//  Alex "xaitax" Hagenah                            - Original implementation
//  Diego Ledda <diego_ledda[at]rapid7[dot]com>      - Argument as array porting and cleanup
//
// GNU as port of GateTrampolineARM64.asm (armasm syntax).

    .text
    .globl  DoSyscall
    .p2align 3

// DoSyscall(x0=function_pointer, x1=syscall_number, x2=args_pointer, x3=arg_count)
DoSyscall:
    // Save callee-saved registers and link register
    stp     x19, x20, [sp, #-16]!
    stp     x21, x22, [sp, #-16]!
    stp     x23, x30, [sp, #-16]!
    mov     x19, sp                // save the current stack pointer in x19

    mov     x20, x0                // save function pointer in x20
    mov     x21, x1                // save syscall number in x21
    mov     x22, x2                // save args pointer in x22
    mov     x23, x3                // save arg count in x23

    // Handle stack arguments (arguments beyond the first 8)
    cmp     x23, #8
    b.le    .Lsetup_registers
    sub     x9, x23, #8            // number of stack arguments
    add     x10, x9, #1
    bic     x10, x10, #1           // round up to even for 16-byte stack alignment
    sub     sp, sp, x10, lsl #3    // allocate stack space
    mov     x11, #0                // index = 0
.Lcopy_stack:
    add     x12, x11, #8           // offset into args array (skip first 8 reg args)
    ldr     x13, [x22, x12, lsl #3]
    str     x13, [sp, x11, lsl #3]
    add     x11, x11, #1
    cmp     x11, x9
    b.lt    .Lcopy_stack

.Lsetup_registers:
    // Load arguments from array into registers x0-x7 based on arg count
    cmp     x23, #8
    b.lt    .Lcheck7
    ldr     x7, [x22, #56]
.Lcheck7:
    cmp     x23, #7
    b.lt    .Lcheck6
    ldr     x6, [x22, #48]
.Lcheck6:
    cmp     x23, #6
    b.lt    .Lcheck5
    ldr     x5, [x22, #40]
.Lcheck5:
    cmp     x23, #5
    b.lt    .Lcheck4
    ldr     x4, [x22, #32]
.Lcheck4:
    cmp     x23, #4
    b.lt    .Lcheck3
    ldr     x3, [x22, #24]
.Lcheck3:
    cmp     x23, #3
    b.lt    .Lcheck2
    ldr     x2, [x22, #16]
.Lcheck2:
    cmp     x23, #2
    b.lt    .Lcheck1
    ldr     x1, [x22, #8]
.Lcheck1:
    cmp     x23, #1
    b.lt    .Ldo_call
    ldr     x0, [x22]

.Ldo_call:
    mov     x8, x21                // move the syscall number into x8
    blr     x20                    // call the function pointer

    mov     sp, x19                // restore the original stack pointer from x19
    ldp     x23, x30, [sp], #16    // restore x23 and link register
    ldp     x21, x22, [sp], #16    // restore x21, x22
    ldp     x19, x20, [sp], #16    // restore x19, x20
    ret
