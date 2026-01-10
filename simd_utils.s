/*
 * Filename: simd_utils.s
 *
 * Highly Optimized SIMD Memory Operations for Sirracha Executor
 * TARGET: x86_64 AVX2/SSE4.2
 *
 * Copyright (c) 2026 compiledkernel-idk
 * Performance is key.
 */

.intel_syntax noprefix
.global fast_check_ptr
.global simd_memcmp_16
.global simd_memcmp_32
.global simd_scan_byte

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
    mov rax, 0x7FFFFFFFFFFF
    cmp rdi, rax
    ja .invalid
    
    # Validation successful
    mov rax, 1
    ret

.invalid:
    xor rax, rax
    ret

/*
 * int simd_memcmp_16(const void* p1, const void* p2);
 *
 * Compares 16 bytes using SSE XMM registers.
 * Arguments:
 *   RDI: p1
 *   RSI: p2
 * Returns:
 *   RAX: 0 if equal, 1 if not equal
 */
simd_memcmp_16:
    movdqu xmm0, [rdi]
    movdqu xmm1, [rsi]
    pcmpeqb xmm0, xmm1
    pmovmskb eax, xmm0
    cmp eax, 0xFFFF
    jne .not_equal_16
    xor rax, rax
    ret

.not_equal_16:
    mov rax, 1
    ret

/*
 * int simd_memcmp_32(const void* p1, const void* p2);
 *
 * Compares 32 bytes using AVX YMM registers.
 * Arguments:
 *   RDI: p1
 *   RSI: p2
 * Returns:
 *   RAX: 0 if equal, 1 if not equal
 */
simd_memcmp_32:
    vmovdqu ymm0, [rdi]
    vmovdqu ymm1, [rsi]
    vpcmpeqb ymm0, ymm0, ymm1
    vpmovmskb eax, ymm0
    cmp eax, 0xFFFFFFFF
    jne .not_equal_32
    xor rax, rax
    ret

.not_equal_32:
    mov rax, 1
    ret

/*
 * void* simd_scan_byte(const void* start, size_t len, uint8_t target);
 *
 * Scans memory for a specific byte using SSE.
 * Arguments:
 *   RDI: start
 *   RSI: len
 *   DL:  target byte
 */
simd_scan_byte:
    push rbx
    
    # Broadcast target byte to XMM0
    movd xmm0, edx
    punpcklbw xmm0, xmm0
    punpcklwd xmm0, xmm0
    pshufd xmm0, xmm0, 0

    mov rax, rdi
    mov rcx, rsi
    add rcx, rax   # End pointer

.loop_chk:
    cmp rax, rcx
    jae .not_found_byte

    # Try 16 bytes
    mov rbx, rcx
    sub rbx, rax
    cmp rbx, 16
    jb .fallback_byte

    movdqu xmm1, [rax]
    pcmpeqb xmm1, xmm0
    pmovmskb r8d, xmm1
    test r8d, r8d
    jnz .found_in_chunk

    add rax, 16
    jmp .loop_chk

.found_in_chunk:
    bsf r9d, r8d
    add rax, r9
    pop rbx
    ret

.fallback_byte:
    mov bl, [rax]
    cmp bl, dl
    je .done_byte
    inc rax
    jmp .loop_chk

.not_found_byte:
    xor rax, rax
.done_byte:
    pop rbx
    ret
