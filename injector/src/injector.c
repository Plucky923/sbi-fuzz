#include <stdint.h>

int main(uint64_t hart_id, uint64_t opaque);
#define MAX_HARTS 8
#define HART_STACK_SIZE 4096

static uint8_t HART_STACKS[MAX_HARTS][HART_STACK_SIZE] __attribute__((aligned(16))) = {};

__attribute__((optimize("O0"))) __attribute__((naked)) void _start() {
    asm volatile(
        "mv t0, a0\n"
        "li t1, %0\n"
        "remu t0, t0, t1\n"
        "la t1, HART_STACKS\n"
        "li t2, %1\n"
        "mul t0, t0, t2\n"
        "add t1, t1, t0\n"
        "add sp, t1, t2\n"
        "call main\n"
        "1:\n"
        "j 1b\n"
        :
        : "i"(MAX_HARTS), "i"(HART_STACK_SIZE)
        : "t0", "t1", "t2"
    );
}

int __attribute__((noinline)) BREAKPOINT() {
    for (;;) {}
}

#define FUZZ_INPUT_SIZE 4096
#define EXEC_DATA_SIZE 4096
#define EXEC_MAX_RESULTS 128
#define EXEC_MAX_ARGS 8
#define EXEC_CALL_COUNT 11
#define SBI_COVERAGE_PC_CAPACITY 1024
#define SBI_ORACLE_BUFFER_WORDS 9

#define EXEC_INSTR_EOF ((uint64_t)-1)
#define EXEC_INSTR_COPYIN ((uint64_t)-2)
#define EXEC_INSTR_COPYOUT ((uint64_t)-3)
#define EXEC_INSTR_SET_PROPS ((uint64_t)-4)

#define EXEC_ARG_CONST 0
#define EXEC_ARG_ADDR32 1
#define EXEC_ARG_ADDR64 2
#define EXEC_ARG_RESULT 3
#define EXEC_ARG_DATA 4
#define EXEC_PROP_KIND_SHIFT 56
#define EXEC_PROP_VALUE_MASK ((1ULL << EXEC_PROP_KIND_SHIFT) - 1)
#define EXEC_PROP_TARGET_HART 1
#define EXEC_PROP_BUSY_WAIT 2
#define MAX_BUSY_WAIT_ITERS (1 << 20)
#define EXEC_ORACLE_FAILURE_CODE 0x5342494f52434c45ULL
#define EXEC_ORACLE_KIND_HSM_HART0_STATUS 1
#define EXEC_ORACLE_KIND_PURE_CALL_MISMATCH 2

#define EXEC_NO_COPYOUT ((uint64_t)-1)
#define SBI_EXT_HSM 0x48534D
#define SBI_EXT_HSM_HART_START 0
#define SBI_EXT_BASE 0x10
#define SBI_EXT_BASE_GET_SPEC_VERSION 0
#define SBI_EXT_BASE_GET_IMPL_ID 1
#define SBI_EXT_BASE_GET_IMPL_VERSION 2
#define SBI_EXT_BASE_PROBE_EXTENSION 3
#define SBI_EXT_BASE_GET_MVENDORID 4
#define SBI_EXT_BASE_GET_MARCHID 5
#define SBI_EXT_BASE_GET_MIMPID 6
#define SBI_HSM_STATE_STARTED 0

typedef struct {
    uint8_t valid;
    uint64_t eid;
    uint64_t fid;
    uint64_t args[6];
    uint64_t error;
    uint64_t value;
} pure_call_record_t;

typedef struct {
    uint64_t error;
    uint64_t value;
} sbiret_t;

typedef enum {
    EXEC_CALL_KIND_RAW_ECALL = 0,
    EXEC_CALL_KIND_FIXED = 1,
} exec_call_kind_t;

typedef struct {
    exec_call_kind_t kind;
    uint64_t eid;
    uint64_t fid;
} exec_call_desc_t;

static const uint8_t EXEC_MAGIC[8] = {'S', 'B', 'I', 'E', 'X', 'E', 'C', '1'};

static const exec_call_desc_t EXEC_CALLS[EXEC_CALL_COUNT] = {
    {EXEC_CALL_KIND_RAW_ECALL, 0, 0},
    {EXEC_CALL_KIND_FIXED, 0x54494D45, 0},
    {EXEC_CALL_KIND_FIXED, 0x00735049, 0},
    {EXEC_CALL_KIND_FIXED, 0x48534D, 0},
    {EXEC_CALL_KIND_FIXED, 0x48534D, 1},
    {EXEC_CALL_KIND_FIXED, 0x48534D, 2},
    {EXEC_CALL_KIND_FIXED, 0x48534D, 3},
    {EXEC_CALL_KIND_FIXED, 0x53525354, 0},
    {EXEC_CALL_KIND_FIXED, 0x4442434E, 0},
    {EXEC_CALL_KIND_FIXED, 0x504D55, 8},
    {EXEC_CALL_KIND_FIXED, 0x52464E43, 1},
};

uint8_t FUZZ_INPUT[FUZZ_INPUT_SIZE] = {};
volatile uint64_t SBI_COVERAGE_BUFFER[SBI_COVERAGE_PC_CAPACITY + 1]
    __attribute__((section(".sbifuzz_shmem"))) = {};
volatile uint64_t SBI_ORACLE_FAILURE_BUFFER[SBI_ORACLE_BUFFER_WORDS]
    __attribute__((section(".sbifuzz_shmem"))) = {};
static uint8_t EXEC_DATA[EXEC_DATA_SIZE] = {};
static uint64_t EXEC_RESULTS[EXEC_MAX_RESULTS] = {};
static uint8_t EXEC_RESULTS_VALID[EXEC_MAX_RESULTS] = {};
static uint8_t WORKER_HART_STARTED[MAX_HARTS] = {};
static uint8_t WORKER_HART_READY[MAX_HARTS] = {};
static uint64_t LAST_SBI_ERROR = 0;
static uint64_t LAST_SBI_VALUE = 0;
static pure_call_record_t PURE_CALL_RECORDS[16] = {};

typedef struct {
    volatile uint64_t command_seq;
    volatile uint64_t complete_seq;
    volatile uint64_t target_hart;
    volatile uint64_t busy_wait_iters;
    volatile uint64_t eid;
    volatile uint64_t fid;
    volatile uint64_t args[6];
    volatile uint64_t error;
    volatile uint64_t value;
} hart_dispatch_t;

static hart_dispatch_t HART_DISPATCH = {};

static void reset_sbi_coverage(void) {
    for (int i = 0; i < SBI_COVERAGE_PC_CAPACITY + 1; i++) {
        SBI_COVERAGE_BUFFER[i] = 0;
    }
}

static void reset_sbi_oracle(void) {
    for (int i = 0; i < SBI_ORACLE_BUFFER_WORDS; i++) {
        SBI_ORACLE_FAILURE_BUFFER[i] = 0;
    }
    LAST_SBI_ERROR = 0;
    LAST_SBI_VALUE = 0;
    for (int i = 0; i < 16; i++) {
        PURE_CALL_RECORDS[i].valid = 0;
        PURE_CALL_RECORDS[i].eid = 0;
        PURE_CALL_RECORDS[i].fid = 0;
        PURE_CALL_RECORDS[i].error = 0;
        PURE_CALL_RECORDS[i].value = 0;
        for (int j = 0; j < 6; j++) {
            PURE_CALL_RECORDS[i].args[j] = 0;
        }
    }
}

static sbiret_t sbi_call(uint64_t extension_id, uint64_t function_id, uint64_t arg0,
    uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
    uint64_t arg5) {
    sbiret_t ret;
    asm volatile(
        "mv a0, %2\n"
        "mv a1, %3\n"
        "mv a2, %4\n"
        "mv a3, %5\n"
        "mv a4, %6\n"
        "mv a5, %7\n"
        "mv a6, %8\n"
        "mv a7, %9\n"
        "ecall\n"
        "mv %0, a0\n"
        "mv %1, a1\n"
        : "=r"(ret.error), "=r"(ret.value)
        : "r"(arg0), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5),
          "r"(function_id), "r"(extension_id)
        : "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"
    );
    LAST_SBI_ERROR = ret.error;
    LAST_SBI_VALUE = ret.value;
    return ret;
}

static void memory_barrier(void) {
    asm volatile("fence rw, rw" ::: "memory");
}

static int is_oracle_pure_call(uint64_t eid, uint64_t fid) {
    if (eid != SBI_EXT_BASE) {
        return 0;
    }
    switch (fid) {
    case SBI_EXT_BASE_GET_SPEC_VERSION:
    case SBI_EXT_BASE_GET_IMPL_ID:
    case SBI_EXT_BASE_GET_IMPL_VERSION:
    case SBI_EXT_BASE_PROBE_EXTENSION:
    case SBI_EXT_BASE_GET_MVENDORID:
    case SBI_EXT_BASE_GET_MARCHID:
    case SBI_EXT_BASE_GET_MIMPID:
        return 1;
    default:
        return 0;
    }
}

static void record_oracle_failure(uint64_t kind, uint64_t instr_index, uint64_t arg0,
    uint64_t arg1, uint64_t observed_error, uint64_t observed_value,
    uint64_t expected_error, uint64_t expected_value) {
    SBI_ORACLE_FAILURE_BUFFER[0] = 1;
    SBI_ORACLE_FAILURE_BUFFER[1] = kind;
    SBI_ORACLE_FAILURE_BUFFER[2] = instr_index;
    SBI_ORACLE_FAILURE_BUFFER[3] = arg0;
    SBI_ORACLE_FAILURE_BUFFER[4] = arg1;
    SBI_ORACLE_FAILURE_BUFFER[5] = observed_error;
    SBI_ORACLE_FAILURE_BUFFER[6] = observed_value;
    SBI_ORACLE_FAILURE_BUFFER[7] = expected_error;
    SBI_ORACLE_FAILURE_BUFFER[8] = expected_value;
    LAST_SBI_ERROR = EXEC_ORACLE_FAILURE_CODE;
    LAST_SBI_VALUE = instr_index;
}

static int check_oracles(uint64_t instr_index, uint64_t caller_hart, uint64_t eid,
    uint64_t fid, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5, sbiret_t ret) {
    if (eid == SBI_EXT_HSM && fid == 2 && a0 == 0) {
        if (ret.error != 0 || ret.value != SBI_HSM_STATE_STARTED) {
            record_oracle_failure(
                EXEC_ORACLE_KIND_HSM_HART0_STATUS,
                instr_index,
                a0,
                caller_hart,
                ret.error,
                ret.value,
                0,
                SBI_HSM_STATE_STARTED
            );
            return 1;
        }
    }

    if (!is_oracle_pure_call(eid, fid) || ret.error != 0) {
        return 0;
    }

    uint64_t args[6] = {a0, a1, a2, a3, a4, a5};
    int free_slot = -1;
    for (int i = 0; i < 16; i++) {
        if (!PURE_CALL_RECORDS[i].valid) {
            if (free_slot < 0) {
                free_slot = i;
            }
            continue;
        }
        if (PURE_CALL_RECORDS[i].eid != eid || PURE_CALL_RECORDS[i].fid != fid) {
            continue;
        }

        int same_args = 1;
        for (int j = 0; j < 6; j++) {
            if (PURE_CALL_RECORDS[i].args[j] != args[j]) {
                same_args = 0;
                break;
            }
        }
        if (!same_args) {
            continue;
        }

        if (PURE_CALL_RECORDS[i].error != ret.error || PURE_CALL_RECORDS[i].value != ret.value) {
            record_oracle_failure(
                EXEC_ORACLE_KIND_PURE_CALL_MISMATCH,
                instr_index,
                eid,
                fid,
                ret.error,
                ret.value,
                PURE_CALL_RECORDS[i].error,
                PURE_CALL_RECORDS[i].value
            );
            return 1;
        }
        return 0;
    }

    if (free_slot >= 0) {
        PURE_CALL_RECORDS[free_slot].valid = 1;
        PURE_CALL_RECORDS[free_slot].eid = eid;
        PURE_CALL_RECORDS[free_slot].fid = fid;
        for (int j = 0; j < 6; j++) {
            PURE_CALL_RECORDS[free_slot].args[j] = args[j];
        }
        PURE_CALL_RECORDS[free_slot].error = ret.error;
        PURE_CALL_RECORDS[free_slot].value = ret.value;
    }
    return 0;
}

static void busy_wait(uint64_t iterations) {
    if (iterations > MAX_BUSY_WAIT_ITERS) {
        iterations = MAX_BUSY_WAIT_ITERS;
    }
    for (uint64_t i = 0; i < iterations; i++) {
        asm volatile("" ::: "memory");
    }
}

static void __attribute__((noreturn)) secondary_hart_entry(uint64_t hart_id, uint64_t opaque) {
    (void)opaque;
    uint64_t observed_seq = 0;
    if (hart_id < MAX_HARTS) {
        WORKER_HART_READY[hart_id] = 1;
        memory_barrier();
    }

    for (;;) {
        uint64_t seq = HART_DISPATCH.command_seq;
        memory_barrier();
        if (seq == 0 || seq == observed_seq || HART_DISPATCH.target_hart != hart_id) {
            continue;
        }

        uint64_t busy_wait_iters = HART_DISPATCH.busy_wait_iters;
        uint64_t eid = HART_DISPATCH.eid;
        uint64_t fid = HART_DISPATCH.fid;
        uint64_t a0 = HART_DISPATCH.args[0];
        uint64_t a1 = HART_DISPATCH.args[1];
        uint64_t a2 = HART_DISPATCH.args[2];
        uint64_t a3 = HART_DISPATCH.args[3];
        uint64_t a4 = HART_DISPATCH.args[4];
        uint64_t a5 = HART_DISPATCH.args[5];

        busy_wait(busy_wait_iters);
        sbiret_t ret = sbi_call(eid, fid, a0, a1, a2, a3, a4, a5);
        HART_DISPATCH.error = ret.error;
        HART_DISPATCH.value = ret.value;
        memory_barrier();
        HART_DISPATCH.complete_seq = seq;
        observed_seq = seq;
    }
}

static int ensure_worker_hart_started(uint64_t hart_id) {
    const uint64_t ready_poll_limit = 1 << 18;
    if (hart_id == 0 || hart_id >= MAX_HARTS) {
        return 0;
    }
    if (WORKER_HART_READY[hart_id]) {
        return 1;
    }

    sbiret_t ret = sbi_call(
        SBI_EXT_HSM,
        SBI_EXT_HSM_HART_START,
        hart_id,
        (uint64_t)secondary_hart_entry,
        0,
        0,
        0,
        0
    );
    if (ret.error == 0) {
        for (uint64_t i = 0; i < ready_poll_limit; i++) {
            memory_barrier();
            if (WORKER_HART_READY[hart_id]) {
                WORKER_HART_STARTED[hart_id] = 1;
                return 1;
            }
        }
        WORKER_HART_STARTED[hart_id] = 0;
        return 0;
    }
    if ((ret.error == (uint64_t)-6 || ret.error == (uint64_t)-7) &&
        WORKER_HART_READY[hart_id]) {
        WORKER_HART_STARTED[hart_id] = 1;
        return 1;
    }
    return 0;
}

static sbiret_t dispatch_call(uint64_t target_hart, uint64_t busy_wait_iters, uint64_t eid,
    uint64_t fid, uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
    uint64_t a4, uint64_t a5) {
    if (target_hart == 0 || !ensure_worker_hart_started(target_hart)) {
        busy_wait(busy_wait_iters);
        return sbi_call(eid, fid, a0, a1, a2, a3, a4, a5);
    }

    uint64_t seq = HART_DISPATCH.command_seq + 1;
    HART_DISPATCH.target_hart = target_hart;
    HART_DISPATCH.busy_wait_iters = busy_wait_iters;
    HART_DISPATCH.eid = eid;
    HART_DISPATCH.fid = fid;
    HART_DISPATCH.args[0] = a0;
    HART_DISPATCH.args[1] = a1;
    HART_DISPATCH.args[2] = a2;
    HART_DISPATCH.args[3] = a3;
    HART_DISPATCH.args[4] = a4;
    HART_DISPATCH.args[5] = a5;
    memory_barrier();
    HART_DISPATCH.command_seq = seq;

    while (HART_DISPATCH.complete_seq != seq) {
        asm volatile("" ::: "memory");
    }

    sbiret_t ret = {
        .error = HART_DISPATCH.error,
        .value = HART_DISPATCH.value,
    };
    return ret;
}

static uint64_t read_varint(uint8_t** pos, uint8_t* end) {
    uint64_t value = 0;
    uint32_t shift = 0;
    for (int i = 0; i < 10; i++, shift += 7) {
        if (*pos >= end) {
            return EXEC_INSTR_EOF;
        }
        uint8_t byte = *(*pos)++;
        value |= ((uint64_t)(byte & 0x7f)) << shift;
        if (byte < 0x80) {
            if (value & 1) {
                return ~(value >> 1);
            }
            return value >> 1;
        }
    }
    return EXEC_INSTR_EOF;
}

static int has_exec_magic(void) {
    for (int i = 0; i < 8; i++) {
        if (FUZZ_INPUT[i] != EXEC_MAGIC[i]) {
            return 0;
        }
    }
    return 1;
}

static uint64_t read_result(uint8_t** pos, uint8_t* end) {
    uint64_t index = read_varint(pos, end);
    uint64_t op_div = read_varint(pos, end);
    uint64_t op_add = read_varint(pos, end);
    uint64_t fallback = read_varint(pos, end);
    uint64_t value = fallback;
    if (index < EXEC_MAX_RESULTS && EXEC_RESULTS_VALID[index]) {
        value = EXEC_RESULTS[index];
        if (op_div != 0) {
            value /= op_div;
        }
        value += op_add;
    }
    return value;
}

static uint64_t read_arg(uint8_t** pos, uint8_t* end) {
    uint64_t typ = read_varint(pos, end);
    switch (typ) {
    case EXEC_ARG_CONST:
        read_varint(pos, end);
        return read_varint(pos, end);
    case EXEC_ARG_ADDR32:
    case EXEC_ARG_ADDR64: {
        uint64_t offset = read_varint(pos, end);
        if (offset >= EXEC_DATA_SIZE) {
            offset %= EXEC_DATA_SIZE;
        }
        return (uint64_t)(EXEC_DATA + offset);
    }
    case EXEC_ARG_RESULT:
        read_varint(pos, end);
        return read_result(pos, end);
    default:
        return 0;
    }
}

static void write_value(uint8_t* dst, uint64_t size, uint64_t value) {
    if (size == 0) {
        return;
    }
    if (dst < EXEC_DATA || dst >= EXEC_DATA + EXEC_DATA_SIZE) {
        return;
    }
    if (dst + size > EXEC_DATA + EXEC_DATA_SIZE) {
        return;
    }
    for (uint64_t i = 0; i < size; i++) {
        dst[i] = (uint8_t)(value >> (i * 8));
    }
}

static void handle_copyin(uint8_t** pos, uint8_t* end) {
    uint64_t addr = read_varint(pos, end);
    uint64_t typ = read_varint(pos, end);
    uint8_t* dst = EXEC_DATA + (addr % EXEC_DATA_SIZE);
    switch (typ) {
    case EXEC_ARG_CONST: {
        uint64_t size = read_varint(pos, end);
        uint64_t value = read_varint(pos, end);
        write_value(dst, size, value);
        break;
    }
    case EXEC_ARG_ADDR32:
    case EXEC_ARG_ADDR64: {
        uint64_t offset = read_varint(pos, end) % EXEC_DATA_SIZE;
        uint64_t value = (uint64_t)(EXEC_DATA + offset);
        write_value(dst, typ == EXEC_ARG_ADDR32 ? 4 : 8, value);
        break;
    }
    case EXEC_ARG_RESULT: {
        uint64_t size = read_varint(pos, end);
        uint64_t value = read_result(pos, end);
        write_value(dst, size, value);
        break;
    }
    case EXEC_ARG_DATA: {
        uint64_t size = read_varint(pos, end);
        if (*pos + size > end) {
            size = (uint64_t)(end - *pos);
        }
        if (dst + size <= EXEC_DATA + EXEC_DATA_SIZE) {
            for (uint64_t i = 0; i < size; i++) {
                dst[i] = (*pos)[i];
            }
        }
        *pos += size;
        break;
    }
    default:
        break;
    }
}

static void record_copyout(uint64_t index, uint64_t addr, uint64_t size) {
    if (index >= EXEC_MAX_RESULTS || size == 0 || size > 8) {
        return;
    }
    uint8_t* src = EXEC_DATA + (addr % EXEC_DATA_SIZE);
    if (src + size > EXEC_DATA + EXEC_DATA_SIZE) {
        return;
    }
    uint64_t value = 0;
    for (uint64_t i = 0; i < size; i++) {
        value |= ((uint64_t)src[i]) << (i * 8);
    }
    EXEC_RESULTS[index] = value;
    EXEC_RESULTS_VALID[index] = 1;
}

static void apply_exec_prop(uint64_t value, uint64_t* current_target_hart,
    uint64_t* current_busy_wait_iters) {
    uint64_t kind = value >> EXEC_PROP_KIND_SHIFT;
    uint64_t payload = value & EXEC_PROP_VALUE_MASK;
    switch (kind) {
    case EXEC_PROP_TARGET_HART:
        *current_target_hart = payload % MAX_HARTS;
        break;
    case EXEC_PROP_BUSY_WAIT:
        *current_busy_wait_iters = payload > MAX_BUSY_WAIT_ITERS ? MAX_BUSY_WAIT_ITERS : payload;
        break;
    default:
        break;
    }
}

static void execute_exec_program(void) {
    for (int i = 0; i < EXEC_DATA_SIZE; i++) {
        EXEC_DATA[i] = 0;
    }
    for (int i = 0; i < EXEC_MAX_RESULTS; i++) {
        EXEC_RESULTS[i] = 0;
        EXEC_RESULTS_VALID[i] = 0;
    }

    uint8_t* pos = FUZZ_INPUT + 8;
    uint8_t* end = FUZZ_INPUT + FUZZ_INPUT_SIZE;
    uint64_t current_target_hart = 0;
    uint64_t current_busy_wait_iters = 0;
    uint64_t instr_index = 0;
    read_varint(&pos, end);

    while (pos < end) {
        uint64_t opcode = read_varint(&pos, end);
        if (opcode == EXEC_INSTR_EOF) {
            break;
        }
        if (opcode == EXEC_INSTR_COPYIN) {
            handle_copyin(&pos, end);
            instr_index++;
            continue;
        }
        if (opcode == EXEC_INSTR_COPYOUT) {
            uint64_t index = read_varint(&pos, end);
            uint64_t addr = read_varint(&pos, end);
            uint64_t size = read_varint(&pos, end);
            record_copyout(index, addr, size);
            instr_index++;
            continue;
        }
        if (opcode == EXEC_INSTR_SET_PROPS) {
            uint64_t value = read_varint(&pos, end);
            apply_exec_prop(value, &current_target_hart, &current_busy_wait_iters);
            instr_index++;
            continue;
        }
        if (opcode >= EXEC_CALL_COUNT) {
            break;
        }

        const exec_call_desc_t* desc = &EXEC_CALLS[opcode];
        uint64_t copyout_index = read_varint(&pos, end);
        uint64_t num_args = read_varint(&pos, end);
        uint64_t args[EXEC_MAX_ARGS] = {};
        uint64_t argc = num_args > EXEC_MAX_ARGS ? EXEC_MAX_ARGS : num_args;
        for (uint64_t i = 0; i < argc; i++) {
            args[i] = read_arg(&pos, end);
        }
        for (uint64_t i = argc; i < num_args; i++) {
            (void)read_arg(&pos, end);
        }

        uint64_t eid = desc->eid;
        uint64_t fid = desc->fid;
        uint64_t a0 = 0;
        uint64_t a1 = 0;
        uint64_t a2 = 0;
        uint64_t a3 = 0;
        uint64_t a4 = 0;
        uint64_t a5 = 0;

        if (desc->kind == EXEC_CALL_KIND_RAW_ECALL) {
            eid = args[0];
            fid = args[1];
            a0 = args[2];
            a1 = args[3];
            a2 = args[4];
            a3 = args[5];
            a4 = args[6];
            a5 = args[7];
        } else {
            a0 = args[0];
            a1 = args[1];
            a2 = args[2];
            a3 = args[3];
            a4 = args[4];
            a5 = args[5];
        }

        sbiret_t ret = dispatch_call(
            current_target_hart,
            current_busy_wait_iters,
            eid,
            fid,
            a0,
            a1,
            a2,
            a3,
            a4,
            a5
        );
        if (check_oracles(
                instr_index,
                current_target_hart,
                eid,
                fid,
                a0,
                a1,
                a2,
                a3,
                a4,
                a5,
                ret)) {
            break;
        }
        if (copyout_index != EXEC_NO_COPYOUT && copyout_index < EXEC_MAX_RESULTS) {
            EXEC_RESULTS[copyout_index] = ret.error == 0 ? ret.value : ret.error;
            EXEC_RESULTS_VALID[copyout_index] = 1;
        }
        instr_index++;
    }
}

static void execute_legacy_input(void) {
    uint64_t* raw = (uint64_t*)FUZZ_INPUT;
    sbi_call(raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7]);
}

int main(uint64_t hart_id, uint64_t opaque) {
    (void)opaque;
    if (hart_id != 0) {
        secondary_hart_entry(hart_id, opaque);
    }
    reset_sbi_coverage();
    reset_sbi_oracle();
    if (has_exec_magic()) {
        execute_exec_program();
    } else {
        execute_legacy_input();
    }
    asm volatile(
        "mv a0, %0\n"
        "mv a1, %1\n"
        :
        : "r"(LAST_SBI_ERROR), "r"(LAST_SBI_VALUE)
        : "a0", "a1"
    );
    return BREAKPOINT();
}
