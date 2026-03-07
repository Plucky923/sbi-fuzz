#include <linux/types.h>

static void no_calls_here(void)
{
    int local = 42;
    local++;
}
