#include <libfdt.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sbi/riscv_asm.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_domain.h>
#include <sbi/sbi_ecall.h>
#include <sbi/sbi_ecall_interface.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_hsm.h>
#include <sbi/sbi_ipi.h>
#include <sbi/sbi_pmu.h>
#include <sbi/sbi_scratch.h>
#include <sbi/sbi_string.h>
#include <sbi/sbi_tlb.h>
#include <sbi/sbi_timer.h>
#include <sbi/sbi_trap.h>
#include <sbi/sbi_version.h>

#ifdef memmove
#undef memmove
#endif
#ifdef memset
#undef memset
#endif
#ifdef memcpy
#undef memcpy
#endif
#ifdef memcmp
#undef memcmp
#endif
#ifdef memchr
#undef memchr
#endif
#ifdef strchr
#undef strchr
#endif
#ifdef strrchr
#undef strrchr
#endif
#ifdef strncpy
#undef strncpy
#endif
#ifdef strcmp
#undef strcmp
#endif
#ifdef strlen
#undef strlen
#endif

#define SBIFUZZ_FAULT_NONE 0
#define SBIFUZZ_FAULT_SBI_ERROR 1
#define SBIFUZZ_FAULT_RAW_ERROR 2
#define SBIFUZZ_FAULT_VALUE 3

#define SBIFUZZ_HART_UNKNOWN 0
#define SBIFUZZ_HART_STARTED 1
#define SBIFUZZ_HART_STOPPED 2
#define SBIFUZZ_HART_SUSPENDED 3

#define SBIFUZZ_PRIV_USER 0
#define SBIFUZZ_PRIV_SUPERVISOR 1
#define SBIFUZZ_PRIV_MACHINE 2

#define SBIFUZZ_SEED_MINIMAL 0
#define SBIFUZZ_SEED_MISSING_CPUS 1
#define SBIFUZZ_SEED_BAD_COLD_BOOT 2
#define SBIFUZZ_SEED_BAD_HEAP_SIZE 3

struct sbifuzz_host_memory_region {
	uint64_t guest_addr;
	const uint8_t *data_ptr;
	size_t data_len;
	uint8_t read;
	uint8_t write;
	uint8_t execute;
};

struct sbifuzz_platform_fault_profile {
	uint32_t mode;
	int64_t error;
	uint64_t value;
	uint8_t duplicate_side_effects;
};

struct sbifuzz_host_request {
	uint64_t extid;
	uint64_t fid;
	uint64_t args[6];
	uint64_t hart_id;
	uint32_t hart_state;
	uint32_t privilege;
	const struct sbifuzz_host_memory_region *regions_ptr;
	size_t regions_len;
	struct sbifuzz_platform_fault_profile fault;
};

struct sbifuzz_host_response {
	int dispatch_status;
	int64_t sbi_error;
	uint64_t value;
	uint64_t next_mepc;
	uint32_t extension_found;
	uint32_t side_effects;
	uint32_t console_bytes;
	uint64_t timer_value;
};

struct sbifuzz_fdt_response {
	int status;
	uint32_t hart_count;
	uint32_t chosen_present;
	uint32_t opensbi_config_present;
	uint32_t coldboot_hart_count;
	uint32_t heap_size;
	char model[64];
	char failure[96];
};

extern struct sbi_ecall_extension ecall_base;
extern struct sbi_ecall_extension ecall_time;
extern struct sbi_ecall_extension ecall_ipi;
extern struct sbi_ecall_extension ecall_rfence;
extern struct sbi_ecall_extension ecall_hsm;
extern struct sbi_ecall_extension ecall_dbcn;
extern struct sbi_ecall_extension ecall_pmu;

struct sbi_ecall_extension *const sbi_ecall_exts[] = {
	&ecall_base,
	&ecall_time,
	&ecall_ipi,
	&ecall_rfence,
	&ecall_hsm,
	&ecall_dbcn,
	&ecall_pmu,
	NULL,
};

static struct sbi_scratch sbifuzz_scratch;
static struct sbi_domain sbifuzz_domain;
static struct sbifuzz_host_request current_request;
static struct sbifuzz_host_response *current_response;
static unsigned long current_mapped_addr;
static unsigned long current_mapped_size;
static bool ecall_initialized;
static const struct sbi_console_device sbifuzz_console_device = {
	.name = "sbifuzz-host",
};

u32 last_hartindex_having_scratch = 0;
u32 hartindex_to_hartid_table[1];
struct sbi_scratch *hartindex_to_scratch_table[1];
struct sbi_domain root;

static unsigned long sbifuzz_mode_to_mstatus(uint32_t privilege)
{
	switch (privilege) {
	case SBIFUZZ_PRIV_MACHINE:
		return MSTATUS_MPP;
	case SBIFUZZ_PRIV_USER:
		return 0;
	case SBIFUZZ_PRIV_SUPERVISOR:
	default:
		return (1UL << MSTATUS_MPP_SHIFT);
	}
}

static void sbifuzz_record_side_effect(unsigned int multiplier)
{
	unsigned int applied = multiplier ? multiplier : 1;
	if (current_request.fault.duplicate_side_effects)
		applied *= 2;
	if (current_response)
		current_response->side_effects += applied;
}

static int sbifuzz_fault_result(void)
{
	switch (current_request.fault.mode) {
	case SBIFUZZ_FAULT_SBI_ERROR:
	case SBIFUZZ_FAULT_RAW_ERROR:
		return (int)current_request.fault.error;
	default:
		return INT32_MAX;
	}
}

static bool sbifuzz_find_region(unsigned long addr, unsigned long size,
				 unsigned long access_flags,
				 const struct sbifuzz_host_memory_region **out)
{
	size_t i;

	for (i = 0; i < current_request.regions_len; i++) {
		const struct sbifuzz_host_memory_region *region =
			&current_request.regions_ptr[i];
		unsigned long region_start = region->guest_addr;
		unsigned long region_end = region->guest_addr + region->data_len;

		if (addr < region_start || region_end < addr || region_end < addr + size)
			continue;
		if ((access_flags & SBI_DOMAIN_READ) && !region->read)
			continue;
		if ((access_flags & SBI_DOMAIN_WRITE) && !region->write)
			continue;
		if ((access_flags & SBI_DOMAIN_EXECUTE) && !region->execute)
			continue;

		*out = region;
		return true;
	}

	return false;
}

static const uint8_t *sbifuzz_guest_ptr(unsigned long guest_addr,
					   unsigned long size)
{
	const struct sbifuzz_host_memory_region *region = NULL;

	if (!sbifuzz_find_region(guest_addr, size, SBI_DOMAIN_READ, &region))
		return NULL;

	return region->data_ptr + (guest_addr - region->guest_addr);
}

unsigned long sbifuzz_host_csr_read(int csr)
{
	switch (csr) {
	case CSR_MSCRATCH:
		return (unsigned long)(uintptr_t)&sbifuzz_scratch;
	case CSR_MSTATUS:
		return sbifuzz_mode_to_mstatus(current_request.privilege);
	case CSR_MVENDORID:
		return 0x1234;
	case CSR_MARCHID:
		return 0x5678;
	case CSR_MIMPID:
		return 0x9abc;
	case CSR_MHARTID:
		return current_request.hart_id;
	case CSR_HGATP:
		return 0;
	default:
		return 0;
	}
}

void sbifuzz_host_csr_write(int csr, unsigned long val)
{
	(void)csr;
	(void)val;
}

unsigned long csr_read_num(int csr_num)
{
	return sbifuzz_host_csr_read(csr_num);
}

void csr_write_num(int csr_num, unsigned long val)
{
	sbifuzz_host_csr_write(csr_num, val);
}

int misa_extension_imp(char ext)
{
	return ext == 'I' || ext == 'M' || ext == 'A' || ext == 'S' || ext == 'U';
}

int misa_xlen(void)
{
	return 64;
}

int sbi_strcmp(const char *a, const char *b)
{
	while (*a && (*a == *b)) {
		a++;
		b++;
	}
	return (unsigned char)*a - (unsigned char)*b;
}

int sbi_strncmp(const char *a, const char *b, size_t count)
{
	while (count && *a && (*a == *b)) {
		a++;
		b++;
		count--;
	}
	if (!count)
		return 0;
	return (unsigned char)*a - (unsigned char)*b;
}

size_t sbi_strlen(const char *str)
{
	size_t len = 0;
	while (str[len])
		len++;
	return len;
}

char *sbi_strchr(const char *s, int c)
{
	while (*s) {
		if (*s == (char)c)
			return (char *)(uintptr_t)s;
		s++;
	}
	return NULL;
}

char *sbi_strrchr(const char *s, int c)
{
	const char *last = NULL;
	while (*s) {
		if (*s == (char)c)
			last = s;
		s++;
	}
	return (char *)(uintptr_t)last;
}

char *sbi_strncpy(char *dest, const char *src, size_t count)
{
	size_t i;

	for (i = 0; i < count && src[i]; i++)
		dest[i] = src[i];
	for (; i < count; i++)
		dest[i] = '\0';
	return dest;
}

void *sbi_memset(void *s, int c, size_t count)
{
	size_t i;
	unsigned char *out = s;

	for (i = 0; i < count; i++)
		out[i] = (unsigned char)c;
	return s;
}

void *sbi_memcpy(void *dest, const void *src, size_t count)
{
	size_t i;
	unsigned char *out = dest;
	const unsigned char *in = src;

	for (i = 0; i < count; i++)
		out[i] = in[i];
	return dest;
}

void *sbi_memmove(void *dest, const void *src, size_t count)
{
	size_t i;
	unsigned char *out = dest;
	const unsigned char *in = src;

	if (out == in)
		return dest;
	if (out < in) {
		for (i = 0; i < count; i++)
			out[i] = in[i];
	} else {
		for (i = count; i > 0; i--)
			out[i - 1] = in[i - 1];
	}
	return dest;
}

int sbi_memcmp(const void *s1, const void *s2, size_t count)
{
	size_t i;
	const unsigned char *a = s1;
	const unsigned char *b = s2;

	for (i = 0; i < count; i++) {
		if (a[i] != b[i])
			return a[i] - b[i];
	}
	return 0;
}

void *sbi_memchr(const void *s, int c, size_t count)
{
	size_t i;
	const unsigned char *bytes = s;

	for (i = 0; i < count; i++) {
		if (bytes[i] == (unsigned char)c)
			return (void *)(uintptr_t)&bytes[i];
	}
	return NULL;
}

int sbi_snprintf(char *out, u32 out_sz, const char *format, ...)
{
	int written;
	va_list args;

	va_start(args, format);
	written = vsnprintf(out, out_sz, format, args);
	va_end(args);

	return written;
}

int sbi_printf(const char *format, ...)
{
	int written;
	va_list args;

	va_start(args, format);
	written = vfprintf(stderr, format, args);
	va_end(args);

	return written;
}

const struct sbi_console_device *sbi_console_get_device(void)
{
	return &sbifuzz_console_device;
}

void sbi_putc(char ch)
{
	(void)ch;
	sbifuzz_record_side_effect(1);
	if (current_response)
		current_response->console_bytes += current_request.fault.duplicate_side_effects ? 2 : 1;
}

unsigned long sbi_nputs(const char *str, unsigned long len)
{
	const uint8_t *ptr = sbifuzz_guest_ptr((unsigned long)(uintptr_t)str, len);
	unsigned long multiplier = current_request.fault.duplicate_side_effects ? 2 : 1;

	if (!ptr)
		return 0;

	sbifuzz_record_side_effect(1);
	if (current_response)
		current_response->console_bytes += (uint32_t)(len * multiplier);
	return len * multiplier;
}

unsigned long sbi_ngets(char *str, unsigned long len)
{
	unsigned long multiplier = current_request.fault.duplicate_side_effects ? 2 : 1;
	(void)str;
	sbifuzz_record_side_effect(1);
	if (current_response)
		current_response->console_bytes += (uint32_t)(len * multiplier);
	return len * multiplier;
}

struct sbi_domain *sbi_hartindex_to_domain(u32 hartindex)
{
	(void)hartindex;
	return &sbifuzz_domain;
}

void sbi_update_hartindex_to_domain(u32 hartindex, struct sbi_domain *dom)
{
	(void)hartindex;
	(void)dom;
}

u32 sbi_hartid_to_hartindex(u32 hartid)
{
	(void)hartid;
	return 0;
}

bool sbi_domain_check_addr(const struct sbi_domain *dom,
			   unsigned long addr, unsigned long mode,
			   unsigned long access_flags)
{
	const struct sbifuzz_host_memory_region *region = NULL;
	(void)dom;
	(void)mode;
	return sbifuzz_find_region(addr, 1, access_flags, &region);
}

bool sbi_domain_check_addr_range(const struct sbi_domain *dom,
				 unsigned long addr, unsigned long size,
				 unsigned long mode,
				 unsigned long access_flags)
{
	const struct sbifuzz_host_memory_region *region = NULL;
	(void)dom;
	(void)mode;
	return sbifuzz_find_region(addr, size, access_flags, &region);
}

int sbi_hart_map_saddr(unsigned long base, unsigned long size)
{
	current_mapped_addr = base;
	current_mapped_size = size;
	return 0;
}

int sbi_hart_unmap_saddr(void)
{
	current_mapped_addr = 0;
	current_mapped_size = 0;
	return 0;
}

static int sbifuzz_override_error_or_default(int default_result)
{
	int override = sbifuzz_fault_result();
	if (override != INT32_MAX)
		return override;
	return default_result;
}

int sbi_hsm_hart_start(struct sbi_scratch *scratch, const struct sbi_domain *dom,
			 u32 target_hartid, unsigned long saddr,
			 unsigned long smode, unsigned long opaque)
{
	(void)scratch;
	(void)dom;
	(void)target_hartid;
	(void)saddr;
	(void)smode;
	(void)opaque;
	if (sbifuzz_fault_result() != INT32_MAX)
		return sbifuzz_fault_result();
	if (current_request.hart_state == SBIFUZZ_HART_STARTED)
		return SBI_ERR_ALREADY_STARTED;
	sbifuzz_record_side_effect(1);
	return SBI_SUCCESS;
}

int sbi_hsm_hart_stop(struct sbi_scratch *scratch, bool exitnow)
{
	(void)scratch;
	(void)exitnow;
	if (sbifuzz_fault_result() != INT32_MAX)
		return sbifuzz_fault_result();
	if (current_request.hart_state == SBIFUZZ_HART_STOPPED)
		return SBI_ERR_ALREADY_STOPPED;
	sbifuzz_record_side_effect(1);
	return SBI_SUCCESS;
}

int sbi_hsm_hart_get_state(const struct sbi_domain *dom, u32 hartid)
{
	(void)dom;
	(void)hartid;
	if (sbifuzz_fault_result() != INT32_MAX)
		return sbifuzz_fault_result();
	switch (current_request.hart_state) {
	case SBIFUZZ_HART_STOPPED:
		return SBI_HSM_STATE_STOPPED;
	case SBIFUZZ_HART_SUSPENDED:
		return SBI_HSM_STATE_SUSPENDED;
	case SBIFUZZ_HART_STARTED:
	default:
		return SBI_HSM_STATE_STARTED;
	}
}

int sbi_hsm_hart_suspend(struct sbi_scratch *scratch, uint32_t suspend_type,
			   unsigned long resume_addr, unsigned long mode,
			   unsigned long opaque)
{
	(void)scratch;
	(void)suspend_type;
	(void)resume_addr;
	(void)mode;
	(void)opaque;
	if (sbifuzz_fault_result() != INT32_MAX)
		return sbifuzz_fault_result();
	if (current_request.hart_state != SBIFUZZ_HART_STARTED)
		return SBI_ERR_INVALID_STATE;
	sbifuzz_record_side_effect(1);
	return SBI_SUCCESS;
}

int sbi_ipi_send_smode(unsigned long hmask, unsigned long hbase)
{
	(void)hmask;
	(void)hbase;
	if (sbifuzz_fault_result() != INT32_MAX)
		return sbifuzz_fault_result();
	sbifuzz_record_side_effect(1);
	return SBI_SUCCESS;
}

void sbi_timer_event_start(uint64_t next_event)
{
	if (current_response)
		current_response->timer_value = next_event;
	sbifuzz_record_side_effect(1);
}

int sbi_tlb_request(ulong hmask, ulong hbase, struct sbi_tlb_info *tinfo)
{
	(void)hmask;
	(void)hbase;
	(void)tinfo;
	if (sbifuzz_fault_result() != INT32_MAX)
		return sbifuzz_fault_result();
	sbifuzz_record_side_effect(1);
	return SBI_SUCCESS;
}

unsigned long sbi_pmu_num_ctr(void)
{
	if (current_request.fault.mode == SBIFUZZ_FAULT_VALUE)
		return current_request.fault.value;
	return 4;
}

int sbi_pmu_ctr_get_info(uint32_t cidx, unsigned long *ctr_info)
{
	if (sbifuzz_fault_result() != INT32_MAX)
		return sbifuzz_fault_result();
	*ctr_info = 0x100 | cidx;
	return SBI_SUCCESS;
}

int sbi_pmu_ctr_cfg_match(unsigned long cidx_base, unsigned long cidx_mask,
			    unsigned long flags, unsigned long event_idx,
			    uint64_t event_data)
{
	(void)cidx_base;
	(void)cidx_mask;
	(void)flags;
	(void)event_idx;
	(void)event_data;
	if (sbifuzz_fault_result() != INT32_MAX)
		return sbifuzz_fault_result();
	sbifuzz_record_side_effect(1);
	return 1;
}

int sbi_pmu_ctr_fw_read(uint32_t cidx, uint64_t *cval)
{
	if (sbifuzz_fault_result() != INT32_MAX)
		return sbifuzz_fault_result();
	*cval = 0x1000 + cidx;
	return SBI_SUCCESS;
}

int sbi_pmu_ctr_start(unsigned long cidx_base, unsigned long cidx_mask,
			unsigned long flags, uint64_t ival)
{
	(void)cidx_base;
	(void)cidx_mask;
	(void)flags;
	(void)ival;
	return sbifuzz_override_error_or_default(SBI_SUCCESS);
}

int sbi_pmu_ctr_stop(unsigned long cidx_base, unsigned long cidx_mask,
		       unsigned long flag)
{
	(void)cidx_base;
	(void)cidx_mask;
	(void)flag;
	return sbifuzz_override_error_or_default(SBI_SUCCESS);
}

int sbi_pmu_event_get_info(unsigned long shmem_lo, unsigned long shmem_high,
			     unsigned long num_events, unsigned long flags)
{
	(void)shmem_lo;
	(void)shmem_high;
	(void)num_events;
	(void)flags;
	return sbifuzz_override_error_or_default(SBI_SUCCESS);
}

static void sbifuzz_init_runtime(const struct sbifuzz_host_request *req,
				 struct sbifuzz_host_response *resp)
{
	sbi_memset(&sbifuzz_scratch, 0, sizeof(sbifuzz_scratch));
	sbi_memset(&sbifuzz_domain, 0, sizeof(sbifuzz_domain));
	sbifuzz_domain.boot_hartid = (u32)req->hart_id;
	sbifuzz_scratch.hartindex = 0;
	sbifuzz_scratch.platform_addr = 0;
	hartindex_to_hartid_table[0] = (u32)req->hart_id;
	hartindex_to_scratch_table[0] = &sbifuzz_scratch;
	current_request = *req;
	current_response = resp;
	current_mapped_addr = 0;
	current_mapped_size = 0;
}

int sbifuzz_host_ecall_run(const struct sbifuzz_host_request *req,
			     struct sbifuzz_host_response *resp)
{
	struct sbi_trap_context trap_context;

	if (!req || !resp)
		return SBI_EINVAL;

	sbi_memset(resp, 0, sizeof(*resp));
	sbifuzz_init_runtime(req, resp);
	if (!ecall_initialized) {
		int init_rc = sbi_ecall_init();
		if (init_rc)
			return init_rc;
		ecall_initialized = true;
	}

	sbi_memset(&trap_context, 0, sizeof(trap_context));
	trap_context.regs.a0 = req->args[0];
	trap_context.regs.a1 = req->args[1];
	trap_context.regs.a2 = req->args[2];
	trap_context.regs.a3 = req->args[3];
	trap_context.regs.a4 = req->args[4];
	trap_context.regs.a5 = req->args[5];
	trap_context.regs.a6 = req->fid;
	trap_context.regs.a7 = req->extid;
	trap_context.regs.mepc = 0x1000;
	trap_context.regs.mstatus = sbifuzz_mode_to_mstatus(req->privilege);
	resp->extension_found = sbi_ecall_find_extension(req->extid) ? 1 : 0;
	resp->dispatch_status = sbi_ecall_handler(&trap_context);
	resp->sbi_error = (int64_t)trap_context.regs.a0;
	resp->value = trap_context.regs.a1;
	resp->next_mepc = trap_context.regs.mepc;

	return 0;
}

static int sbifuzz_copy_cstr(char *dst, size_t dst_len, const char *src)
{
	if (!dst || !dst_len)
		return 0;
	if (!src) {
		dst[0] = '\0';
		return 0;
	}
	snprintf(dst, dst_len, "%s", src);
	return 0;
}

static int sbifuzz_parse_hart_count(const void *fdt, int cpus_offset,
				      uint32_t *hart_count)
{
	int cpu_offset;
	int len;
	int cell_addr = fdt_address_cells(fdt, cpus_offset);
	uint32_t count = 0;

	if (cell_addr < 1)
		return -FDT_ERR_BADNCELLS;

	fdt_for_each_subnode(cpu_offset, fdt, cpus_offset) {
		const fdt32_t *reg = fdt_getprop(fdt, cpu_offset, "reg", &len);
		const char *status;

		if (!reg || len < cell_addr * (int)sizeof(fdt32_t))
			continue;
		status = fdt_getprop(fdt, cpu_offset, "status", &len);
		if (status && !sbi_strcmp(status, "disabled"))
			continue;
		count++;
	}

	*hart_count = count;
	return 0;
}

static int sbifuzz_parse_coldboot_harts(const void *fdt, int config_offset,
					  uint32_t *count)
{
	const fdt32_t *prop;
	int len, i;
	uint32_t resolved = 0;

	prop = fdt_getprop(fdt, config_offset, "cold-boot-harts", &len);
	if (!prop || len <= 0) {
		*count = 0;
		return 0;
	}

	for (i = 0; i < len / (int)sizeof(fdt32_t); i++) {
		int node = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(prop[i]));
		if (node < 0)
			return node;
		resolved++;
	}

	*count = resolved;
	return 0;
}

int sbifuzz_host_parse_fdt(const uint8_t *blob, size_t blob_len,
			     struct sbifuzz_fdt_response *resp)
{
	const void *fdt = blob;
	int root_offset, cpus_offset, chosen_offset, config_offset, rc, len;
	const char *model;
	const fdt32_t *heap_prop;

	if (!blob || !resp)
		return SBI_EINVAL;

	sbi_memset(resp, 0, sizeof(*resp));
	if (blob_len < sizeof(struct fdt_header)) {
		resp->status = -FDT_ERR_TRUNCATED;
		sbifuzz_copy_cstr(resp->failure, sizeof(resp->failure), "blob too short");
		return 0;
	}

	rc = fdt_check_header(fdt);
	if (rc) {
		resp->status = rc;
		sbifuzz_copy_cstr(resp->failure, sizeof(resp->failure), fdt_strerror(rc));
		return 0;
	}

	root_offset = fdt_path_offset(fdt, "/");
	if (root_offset < 0) {
		resp->status = root_offset;
		sbifuzz_copy_cstr(resp->failure, sizeof(resp->failure), fdt_strerror(root_offset));
		return 0;
	}

	model = fdt_getprop(fdt, root_offset, "model", &len);
	if (model)
		sbifuzz_copy_cstr(resp->model, sizeof(resp->model), model);

	cpus_offset = fdt_path_offset(fdt, "/cpus");
	if (cpus_offset < 0) {
		resp->status = cpus_offset;
		sbifuzz_copy_cstr(resp->failure, sizeof(resp->failure), fdt_strerror(cpus_offset));
		return 0;
	}

	rc = sbifuzz_parse_hart_count(fdt, cpus_offset, &resp->hart_count);
	if (rc) {
		resp->status = rc;
		sbifuzz_copy_cstr(resp->failure, sizeof(resp->failure), fdt_strerror(rc));
		return 0;
	}

	chosen_offset = fdt_path_offset(fdt, "/chosen");
	if (chosen_offset >= 0)
		resp->chosen_present = 1;

	config_offset = (chosen_offset >= 0) ?
		fdt_node_offset_by_compatible(fdt, chosen_offset, "opensbi,config") :
		-FDT_ERR_NOTFOUND;
	if (config_offset >= 0) {
		resp->opensbi_config_present = 1;
		heap_prop = fdt_getprop(fdt, config_offset, "heap-size", &len);
		if (heap_prop && len == (int)sizeof(fdt32_t)) {
			resp->heap_size = fdt32_to_cpu(*heap_prop);
		} else if (heap_prop) {
			resp->status = -FDT_ERR_BADVALUE;
			sbifuzz_copy_cstr(resp->failure, sizeof(resp->failure), fdt_strerror(-FDT_ERR_BADVALUE));
			return 0;
		}

		rc = sbifuzz_parse_coldboot_harts(fdt, config_offset, &resp->coldboot_hart_count);
		if (rc) {
			resp->status = rc;
			sbifuzz_copy_cstr(resp->failure, sizeof(resp->failure), fdt_strerror(rc));
			return 0;
		}
	}

	resp->status = 0;
	return 0;
}

static int sbifuzz_build_seed_tree(uint32_t variant, void *out, size_t out_cap)
{
	int root, cpus = -1, cpu0 = -1, chosen, config;
	uint32_t one = cpu_to_fdt32(1);
	uint32_t zero = cpu_to_fdt32(0);
	uint32_t phandle = cpu_to_fdt32(1);
	uint32_t bad_phandle = cpu_to_fdt32(2);
	uint32_t heap_size = cpu_to_fdt32(0x9000);
	int rc;

	rc = fdt_create_empty_tree(out, out_cap);
	if (rc)
		return rc;

	root = fdt_path_offset(out, "/");
	if (root < 0)
		return root;
	fdt_setprop(out, root, "model", "sbifuzz,qemu-virt",
		   sbi_strlen("sbifuzz,qemu-virt") + 1);
	fdt_setprop(out, root, "compatible", "sbifuzz,host-opensbi",
		   sbi_strlen("sbifuzz,host-opensbi") + 1);

	if (variant != SBIFUZZ_SEED_MISSING_CPUS) {
		cpus = fdt_add_subnode(out, root, "cpus");
		if (cpus < 0)
			return cpus;
		fdt_setprop(out, cpus, "#address-cells", &one, sizeof(one));
		fdt_setprop(out, cpus, "#size-cells", &zero, sizeof(zero));
		cpu0 = fdt_add_subnode(out, cpus, "cpu@0");
		if (cpu0 < 0)
			return cpu0;
		fdt_setprop(out, cpu0, "device_type", "cpu", sbi_strlen("cpu") + 1);
		fdt_setprop(out, cpu0, "compatible", "riscv",
			   sbi_strlen("riscv") + 1);
		fdt_setprop(out, cpu0, "reg", &zero, sizeof(zero));
		fdt_setprop(out, cpu0, "phandle", &phandle, sizeof(phandle));
		fdt_setprop(out, cpu0, "status", "okay", sbi_strlen("okay") + 1);
	}

	chosen = fdt_add_subnode(out, root, "chosen");
	if (chosen < 0)
		return chosen;
	config = fdt_add_subnode(out, chosen, "opensbi-config");
	if (config < 0)
		return config;
	fdt_setprop(out, config, "compatible", "opensbi,config",
		   sbi_strlen("opensbi,config") + 1);

	if (variant == SBIFUZZ_SEED_BAD_HEAP_SIZE)
		fdt_setprop(out, config, "heap-size", "oops", sbi_strlen("oops") + 1);
	else
		fdt_setprop(out, config, "heap-size", &heap_size, sizeof(heap_size));

	if (variant == SBIFUZZ_SEED_BAD_COLD_BOOT)
		fdt_setprop(out, config, "cold-boot-harts", &bad_phandle, sizeof(bad_phandle));
	else if (cpu0 >= 0)
		fdt_setprop(out, config, "cold-boot-harts", &phandle, sizeof(phandle));

	return fdt_pack(out);
}

size_t sbifuzz_host_build_seed_fdt(uint32_t variant, uint8_t *out, size_t out_cap)
{
	int rc;

	if (!out)
		return 0;

	rc = sbifuzz_build_seed_tree(variant, out, out_cap);
	if (rc)
		return 0;

	return (size_t)fdt_totalsize(out);
}
