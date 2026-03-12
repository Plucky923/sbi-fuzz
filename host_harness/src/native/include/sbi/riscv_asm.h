/*
 * Host-only shadow of OpenSBI's riscv_asm.h used by the host_harness crate.
 * It replaces CSR and wfi access with shim callbacks while preserving the
 * constants and helper macros expected by OpenSBI sources.
 */

#ifndef __RISCV_ASM_H__
#define __RISCV_ASM_H__

#include <sbi/riscv_encoding.h>

#ifdef __ASSEMBLER__
#define __ASM_STR(x) x
#else
#define __ASM_STR(x) #x
#endif

#define PAGE_SHIFT (12)
#define PAGE_SIZE (_AC(1, UL) << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define REG_L "ld"
#define REG_S "sd"
#define SZREG "8"
#define LGREG "3"
#define RISCV_PTR ".dword"
#define RISCV_SZPTR "8"
#define RISCV_LGPTR "3"
#define RISCV_INT ".word"
#define RISCV_SZINT "4"
#define RISCV_LGINT "2"
#define RISCV_SHORT ".half"
#define RISCV_SZSHORT "2"
#define RISCV_LGSHORT "1"

#ifndef __ASSEMBLER__

unsigned long sbifuzz_host_csr_read(int csr);
void sbifuzz_host_csr_write(int csr, unsigned long val);
unsigned long csr_read_num(int csr_num);
void csr_write_num(int csr_num, unsigned long val);
int misa_extension_imp(char ext);
int misa_xlen(void);

#define csr_swap(csr, val) ({ \
	unsigned long __old = sbifuzz_host_csr_read((csr)); \
	sbifuzz_host_csr_write((csr), (unsigned long)(val)); \
	__old; \
})

#define csr_read(csr) sbifuzz_host_csr_read((csr))
#define csr_read_relaxed(csr) sbifuzz_host_csr_read((csr))
#define csr_write(csr, val) sbifuzz_host_csr_write((csr), (unsigned long)(val))
#define csr_read_set(csr, val) ({ \
	unsigned long __old = sbifuzz_host_csr_read((csr)); \
	sbifuzz_host_csr_write((csr), __old | (unsigned long)(val)); \
	__old; \
})
#define csr_set(csr, val) sbifuzz_host_csr_write((csr), sbifuzz_host_csr_read((csr)) | (unsigned long)(val))
#define csr_read_clear(csr, val) ({ \
	unsigned long __old = sbifuzz_host_csr_read((csr)); \
	sbifuzz_host_csr_write((csr), __old & ~((unsigned long)(val))); \
	__old; \
})
#define csr_clear(csr, val) sbifuzz_host_csr_write((csr), sbifuzz_host_csr_read((csr)) & ~((unsigned long)(val)))

#define wfi() do { } while (0)
#define ebreak() do { } while (0)
#define current_hartid() ((unsigned int)csr_read_relaxed(CSR_MHARTID))

#define misa_extension(c) \
({ \
	_Static_assert(((c >= 'A') && (c <= 'Z')), "The parameter of misa_extension must be [A-Z]"); \
	misa_extension_imp(c); \
})

#endif

#endif
