// Entry stub for the injected shellcode blob (windows_loader.bin).
//
// This file must be the FIRST source of the windows_loader target: the blob is
// laid out as [entrypoint][embedded DLL bytes][loader helpers + entry_function]
// so that (a) execution can start at the very first byte of the blob and
// (b) ReflectiveLoader()'s backward image-base scan finds the embedded MZ
// header (which lives at a lower address than entry_function) before running
// off the front of the blob.
void entry_function();

__attribute__((naked))
void entrypoint(void)
{
#if defined(__x86_64__) || defined(_M_X64)
	asm("push %rsi\n"
			"mov %rsp, %rsi\n"
			"and $-16, %rsp\n"
			"sub $0x20, %rsp\n"
			"call entry_function\n"
			"mov %rsi, %rsp\n"
			"pop %rsi\n"
			"ret\n");
#elif defined(__aarch64__) || defined(_M_ARM64)
	asm(
			"sub sp, sp, #0x30\n"
			"stp x29, x30, [sp, #0x20]\n"
			"bl entry_function\n"
			"ldp x29, x30, [sp, #0x20]\n"
			"add sp, sp, #0x30\n"
			"ret\n"
		 );
#else
	entry_function();
#endif
}
