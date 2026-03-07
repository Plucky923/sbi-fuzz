#include <stdint.h>

int main();
extern char _stack_end;

__attribute__((optimize("O0"))) __attribute__((naked)) void _start() {
    asm volatile("la sp, _stack_end");
    main();
    while (1);
}

int __attribute__((noinline)) BREAKPOINT() {
    for (;;) {}
}

#define FUZZ_INPUT_SIZE 4096
#define EXEC_DATA_SIZE 4096
#define EXEC_MAX_RESULTS 128
#define EXEC_MAX_ARGS 8
#define EXEC_CALL_COUNT 11

#define EXEC_INSTR_EOF ((uint64_t)-1)
#define EXEC_INSTR_COPYIN ((uint64_t)-2)
#define EXEC_INSTR_COPYOUT ((uint64_t)-3)
#define EXEC_INSTR_SET_PROPS ((uint64_t)-4)

#define EXEC_ARG_CONST 0
#define EXEC_ARG_ADDR32 1
#define EXEC_ARG_ADDR64 2
#define EXEC_ARG_RESULT 3
#define EXEC_ARG_DATA 4

#define EXEC_NO_COPYOUT ((uint64_t)-1)

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
static uint8_t EXEC_DATA[EXEC_DATA_SIZE] = {};
static uint64_t EXEC_RESULTS[EXEC_MAX_RESULTS] = {};
static uint8_t EXEC_RESULTS_VALID[EXEC_MAX_RESULTS] = {};
static uint64_t LAST_SBI_ERROR = 0;
static uint64_t LAST_SBI_VALUE = 0;

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
    read_varint(&pos, end);

    while (pos < end) {
        uint64_t opcode = read_varint(&pos, end);
        if (opcode == EXEC_INSTR_EOF) {
            break;
        }
        if (opcode == EXEC_INSTR_COPYIN) {
            handle_copyin(&pos, end);
            continue;
        }
        if (opcode == EXEC_INSTR_COPYOUT) {
            uint64_t index = read_varint(&pos, end);
            uint64_t addr = read_varint(&pos, end);
            uint64_t size = read_varint(&pos, end);
            record_copyout(index, addr, size);
            continue;
        }
        if (opcode == EXEC_INSTR_SET_PROPS) {
            read_varint(&pos, end);
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

        sbiret_t ret = sbi_call(eid, fid, a0, a1, a2, a3, a4, a5);
        if (copyout_index != EXEC_NO_COPYOUT && copyout_index < EXEC_MAX_RESULTS) {
            EXEC_RESULTS[copyout_index] = ret.error == 0 ? ret.value : ret.error;
            EXEC_RESULTS_VALID[copyout_index] = 1;
        }
    }
}

static void execute_legacy_input(void) {
    uint64_t* raw = (uint64_t*)FUZZ_INPUT;
    sbi_call(raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7]);
}

int main() {
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
