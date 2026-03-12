/* Define entry point */
ENTRY(_start)

MEMORY
{
    RAM   (xrw) : ORIGIN = 0x80600000, LENGTH = 0x003FC000
    SHMEM (rw)  : ORIGIN = 0x809FC000, LENGTH = 0x00003000
    STACK (rw)  : ORIGIN = 0x809FF000, LENGTH = 0x00001000
}

/* Define memory layout */
SECTIONS
{
    .text : {
        *(.text)
        *(.text.*)
    } > RAM

    .data : {
        *(.data)
        *(.data.*)
    } > RAM

    .bss : {
        *(.bss)
        *(.bss.*)
        *(COMMON)
    } > RAM

    .sbifuzz_shmem (NOLOAD) : ALIGN(8) {
        KEEP(*(.sbifuzz_shmem))
    } > SHMEM

    .stack (NOLOAD) : {
        . = ALIGN(16);
        _stack_start = .;
        . = . + 0x1000;
        _stack_end = .;
    } > STACK
}

ASSERT(SIZEOF(.sbifuzz_shmem) <= LENGTH(SHMEM), "sbifuzz shared-memory buffer overflow")
