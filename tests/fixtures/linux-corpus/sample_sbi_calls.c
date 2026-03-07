#include <linux/types.h>

static void sample_calls(void)
{
    sbi_ecall(SBI_EXT_HSM, SBI_EXT_HSM_HART_START,
              1, 0x80200000, 0x1234, 0, 0, 0);

    sbi_ecall(SBI_EXT_DBCN, SBI_EXT_DBCN_CONSOLE_WRITE,
              0x40, 0x80001000, 0, 0, 0, 0);

    sbi_ecall(SBI_EXT_PMU, SBI_EXT_PMU_SNAPSHOT_SET_SHMEM,
              0x80002000, 0, 8, 0, 0, 0);
}
