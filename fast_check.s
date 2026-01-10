/*
 * Filename: fast_check.s
 *
 * Optimized safe pointer validation routine for Sirracha
 * Written in x86_64 Assembly for maximum performance/flex.
 *
 * Copyright (c) 2026 compiledkernel-idk
 */

.intel_syntax noprefix
.global fast_check_ptr

.section .text

/*
 * int fast_check_ptr(void* ptr);
 * 
 * Checks if a pointer is likely valid (canonical and non-null)
 * Arguments:
 *   RDI: ptr (pointer to check)
 * Returns:
 *   RAX: 1 if valid, 0 if invalid
 */
fast_check_ptr:
    # 1. Check for NULL (0x0)
    test rdi, rdi
    jz .invalid

    # 2. Check for low range (usually unmapped page 0-4096)
    cmp rdi, 0x1000
    jb .invalid

    # 3. Check for non-canonical addresses (holes in x64 address space)
    # Valid user-space addresses are usually 0x0000000000000000 - 0x00007FFFFFFFFFFF
    # If the 48th bit is 0, bits 48-63 MUST be 0.
    # A quick way is to check if it's above the user limit.
    mov rax, 0x7FFFFFFFFFFF
    cmp rdi, rax
    ja .invalid
    
    # 4. Alignment check (optional - assume alignment of 8 bytes for pointers)
    # test dil, 7
    # jnz .invalid

    # If we got here, it's structurally valid
    mov rax, 1
    ret

.invalid:
    xor rax, rax
    ret
