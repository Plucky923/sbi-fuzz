#include <libfdt.h>
#include <stdbool.h>
#include <stdint.h>

#define SBIFUZZ_RUSTSBI_FDT_MINIMAL 0
#define SBIFUZZ_RUSTSBI_FDT_MISSING_CPUS 1
#define SBIFUZZ_RUSTSBI_FDT_BAD_STDOUT_PATH 2
#define SBIFUZZ_RUSTSBI_FDT_BAD_CONSOLE_COMPAT 3

struct sbifuzz_rustsbi_fdt_response {
	int status;
	uint32_t hart_count;
	uint32_t chosen_present;
	uint32_t stdout_path_present;
	uint32_t console_present;
	uint32_t ipi_present;
	uint32_t reset_present;
	uint64_t memory_start;
	uint64_t memory_end;
	char model[64];
	char failure[96];
};

static unsigned long sbifuzz_strlen(const char *str)
{
	unsigned long len = 0;
	while (str && str[len])
		len++;
	return len;
}

static int sbifuzz_strcmp(const char *a, const char *b)
{
	while (*a && (*a == *b)) {
		a++;
		b++;
	}
	return (unsigned char)*a - (unsigned char)*b;
}

static void sbifuzz_memset(void *dst, int value, unsigned long size)
{
	unsigned char *out = dst;
	unsigned long i;

	for (i = 0; i < size; i++)
		out[i] = (unsigned char)value;
}

static void sbifuzz_copy_cstr(char *dst, unsigned long dst_len, const char *src)
{
	unsigned long i;

	if (!dst || !dst_len)
		return;
	if (!src) {
		dst[0] = '\0';
		return;
	}

	for (i = 0; i + 1 < dst_len && src[i]; i++)
		dst[i] = src[i];
	dst[i] = '\0';
}

static bool sbifuzz_prop_contains_compat(const void *fdt, int nodeoff, const char *compat)
{
	const char *prop;
	int len;
	unsigned long offset = 0;

	prop = fdt_getprop(fdt, nodeoff, "compatible", &len);
	if (!prop || len <= 0)
		return false;

	while (offset < (unsigned long)len) {
		const char *entry = prop + offset;
		unsigned long entry_len = sbifuzz_strlen(entry);
		if (!sbifuzz_strcmp(entry, compat))
			return true;
		offset += entry_len + 1;
	}

	return false;
}

static int sbifuzz_find_compat(const void *fdt, const char *compat)
{
	return fdt_node_offset_by_compatible(fdt, -1, compat);
}

static bool sbifuzz_is_console_compat(const void *fdt, int nodeoff)
{
	return sbifuzz_prop_contains_compat(fdt, nodeoff, "ns16550a") ||
	       sbifuzz_prop_contains_compat(fdt, nodeoff, "snps,dw-apb-uart") ||
	       sbifuzz_prop_contains_compat(fdt, nodeoff, "xlnx,xps-uartlite-1.00.a") ||
	       sbifuzz_prop_contains_compat(fdt, nodeoff, "bflb,bl808-uart");
}

static int sbifuzz_count_enabled_cpus(const void *fdt, int cpus_offset, uint32_t *out_count)
{
	int cpu_offset, len;
	uint32_t count = 0;

	cpu_offset = fdt_first_subnode(fdt, cpus_offset);
	if (cpu_offset < 0 && cpu_offset != -FDT_ERR_NOTFOUND)
		return cpu_offset;

	while (cpu_offset >= 0) {
		const char *name;
		const char *status;

		name = fdt_get_name(fdt, cpu_offset, NULL);
		if (!name || !(name[0] == 'c' && name[1] == 'p' && name[2] == 'u'))
			goto next_cpu;
		status = fdt_getprop(fdt, cpu_offset, "status", &len);
		if (status && !sbifuzz_strcmp(status, "disabled"))
			goto next_cpu;
		count++;
next_cpu:
		cpu_offset = fdt_next_subnode(fdt, cpu_offset);
	}

	*out_count = count;
	return 0;
}

static int sbifuzz_parse_memory(const void *fdt, struct sbifuzz_rustsbi_fdt_response *resp)
{
	int root, node;
	const char *name;
	int len;
	const fdt32_t *reg;
	int addr_cells, size_cells;
	uint64_t addr = 0, size = 0;
	int i;

	root = fdt_path_offset(fdt, "/");
	if (root < 0)
		return root;

	fdt_for_each_subnode(node, fdt, root) {
		name = fdt_get_name(fdt, node, NULL);
		if (!name)
			continue;
		if (name[0] == 'm' && name[1] == 'e' && name[2] == 'm' && name[3] == 'o' &&
		    name[4] == 'r' && name[5] == 'y') {
			addr_cells = fdt_address_cells(fdt, root);
			size_cells = fdt_size_cells(fdt, root);
			reg = fdt_getprop(fdt, node, "reg", &len);
			if (!reg)
				return -FDT_ERR_BADVALUE;
			if (len < (addr_cells + size_cells) * (int)sizeof(fdt32_t))
				return -FDT_ERR_BADVALUE;
			for (i = 0; i < addr_cells; i++)
				addr = (addr << 32) | fdt32_to_cpu(reg[i]);
			for (i = 0; i < size_cells; i++)
				size = (size << 32) | fdt32_to_cpu(reg[addr_cells + i]);
			resp->memory_start = addr;
			resp->memory_end = addr + size;
			return 0;
		}
	}

	return -FDT_ERR_NOTFOUND;
}

static int sbifuzz_stdout_node(const void *fdt, int chosen_offset)
{
	const char *stdout_path;
	int len;
	char path[128];
	int i;

	stdout_path = fdt_getprop(fdt, chosen_offset, "stdout-path", &len);
	if (!stdout_path || len <= 0)
		return -FDT_ERR_NOTFOUND;

	for (i = 0; i + 1 < (int)sizeof(path) && i < len && stdout_path[i] && stdout_path[i] != ':'; i++)
		path[i] = stdout_path[i];
	path[i] = '\0';

	if (!i)
		return -FDT_ERR_NOTFOUND;

	return fdt_path_offset(fdt, path);
}

int sbifuzz_host_parse_rustsbi_fdt(const uint8_t *blob, size_t blob_len,
				   struct sbifuzz_rustsbi_fdt_response *resp)
{
	const void *fdt = blob;
	int root_offset, cpus_offset, chosen_offset, stdout_node, rc;
	const char *model;
	int len;

	if (!blob || !resp)
		return -FDT_ERR_BADVALUE;

	sbifuzz_memset(resp, 0, sizeof(*resp));
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

	rc = sbifuzz_count_enabled_cpus(fdt, cpus_offset, &resp->hart_count);
	if (rc) {
		resp->status = rc;
		sbifuzz_copy_cstr(resp->failure, sizeof(resp->failure), fdt_strerror(rc));
		return 0;
	}

	chosen_offset = fdt_path_offset(fdt, "/chosen");
	if (chosen_offset >= 0) {
		resp->chosen_present = 1;
		stdout_node = sbifuzz_stdout_node(fdt, chosen_offset);
		if (stdout_node >= 0) {
			resp->stdout_path_present = 1;
			if (sbifuzz_is_console_compat(fdt, stdout_node))
				resp->console_present = 1;
		}
	}

	if (sbifuzz_find_compat(fdt, "riscv,clint0") >= 0 ||
	    sbifuzz_find_compat(fdt, "thead,c900-clint") >= 0)
		resp->ipi_present = 1;
	if (sbifuzz_find_compat(fdt, "sifive,test0") >= 0)
		resp->reset_present = 1;

	rc = sbifuzz_parse_memory(fdt, resp);
	if (rc && rc != -FDT_ERR_NOTFOUND) {
		resp->status = rc;
		sbifuzz_copy_cstr(resp->failure, sizeof(resp->failure), fdt_strerror(rc));
		return 0;
	}

	resp->status = 0;
	return 0;
}

static int sbifuzz_set_u32_prop(void *fdt, int nodeoff, const char *name, uint32_t value)
{
	fdt32_t tmp = cpu_to_fdt32(value);
	return fdt_setprop(fdt, nodeoff, name, &tmp, sizeof(tmp));
}

static int sbifuzz_build_rustsbi_tree(uint32_t variant, void *out, size_t out_cap)
{
	int rc, root, cpus = -1, cpu0 = -1, chosen, memory, soc, serial, clint, reset;
	fdt32_t mem_reg[] = {
		cpu_to_fdt32(0),
		cpu_to_fdt32(0x80000000),
		cpu_to_fdt32(0),
		cpu_to_fdt32(0x10000000),
	};
	fdt32_t serial_reg[] = {
		cpu_to_fdt32(0),
		cpu_to_fdt32(0x10000000),
		cpu_to_fdt32(0),
		cpu_to_fdt32(0x100),
	};
	fdt32_t clint_reg[] = {
		cpu_to_fdt32(0),
		cpu_to_fdt32(0x02000000),
		cpu_to_fdt32(0),
		cpu_to_fdt32(0x10000),
	};
	fdt32_t reset_reg[] = {
		cpu_to_fdt32(0),
		cpu_to_fdt32(0x00100000),
		cpu_to_fdt32(0),
		cpu_to_fdt32(0x1000),
	};

	rc = fdt_create_empty_tree(out, out_cap);
	if (rc)
		return rc;

	root = fdt_path_offset(out, "/");
	if (root < 0)
		return root;

	sbifuzz_set_u32_prop(out, root, "#address-cells", 2);
	sbifuzz_set_u32_prop(out, root, "#size-cells", 2);
	fdt_setprop(out, root, "model", "rustsbi,qemu-virt", sizeof("rustsbi,qemu-virt"));
	fdt_setprop(out, root, "compatible", "riscv-virtio,qemu", sizeof("riscv-virtio,qemu"));

	if (variant != SBIFUZZ_RUSTSBI_FDT_MISSING_CPUS) {
		cpus = fdt_add_subnode(out, root, "cpus");
		if (cpus < 0)
			return cpus;
		sbifuzz_set_u32_prop(out, cpus, "#address-cells", 1);
		sbifuzz_set_u32_prop(out, cpus, "#size-cells", 0);
		cpu0 = fdt_add_subnode(out, cpus, "cpu@0");
		if (cpu0 < 0)
			return cpu0;
		fdt_setprop(out, cpu0, "device_type", "cpu", sizeof("cpu"));
		fdt_setprop(out, cpu0, "compatible", "riscv", sizeof("riscv"));
		sbifuzz_set_u32_prop(out, cpu0, "reg", 0);
	}

	memory = fdt_add_subnode(out, root, "memory@80000000");
	if (memory < 0)
		return memory;
	fdt_setprop(out, memory, "device_type", "memory", sizeof("memory"));
	fdt_setprop(out, memory, "reg", mem_reg, sizeof(mem_reg));

	soc = fdt_add_subnode(out, root, "soc");
	if (soc < 0)
		return soc;
	sbifuzz_set_u32_prop(out, soc, "#address-cells", 2);
	sbifuzz_set_u32_prop(out, soc, "#size-cells", 2);
	fdt_setprop(out, soc, "ranges", NULL, 0);

	serial = fdt_add_subnode(out, soc, "serial@10000000");
	if (serial < 0)
		return serial;
	if (variant == SBIFUZZ_RUSTSBI_FDT_BAD_CONSOLE_COMPAT)
		fdt_setprop(out, serial, "compatible", "vendor,bad-uart", sizeof("vendor,bad-uart"));
	else
		fdt_setprop(out, serial, "compatible", "ns16550a", sizeof("ns16550a"));
	fdt_setprop(out, serial, "reg", serial_reg, sizeof(serial_reg));

	clint = fdt_add_subnode(out, soc, "clint@2000000");
	if (clint < 0)
		return clint;
	fdt_setprop(out, clint, "compatible", "riscv,clint0", sizeof("riscv,clint0"));
	fdt_setprop(out, clint, "reg", clint_reg, sizeof(clint_reg));

	reset = fdt_add_subnode(out, soc, "test@100000");
	if (reset < 0)
		return reset;
	fdt_setprop(out, reset, "compatible", "sifive,test0", sizeof("sifive,test0"));
	fdt_setprop(out, reset, "reg", reset_reg, sizeof(reset_reg));

	chosen = fdt_add_subnode(out, root, "chosen");
	if (chosen < 0)
		return chosen;
	if (variant == SBIFUZZ_RUSTSBI_FDT_BAD_STDOUT_PATH)
		fdt_setprop(out, chosen, "stdout-path", "/soc/missing@deadbeef",
			   sizeof("/soc/missing@deadbeef"));
	else
		fdt_setprop(out, chosen, "stdout-path", "/soc/serial@10000000",
			   sizeof("/soc/serial@10000000"));

	return fdt_pack(out);
}

size_t sbifuzz_host_build_rustsbi_seed_fdt(uint32_t variant, uint8_t *out, size_t out_cap)
{
	int rc;

	if (!out)
		return 0;
	rc = sbifuzz_build_rustsbi_tree(variant, out, out_cap);
	if (rc)
		return 0;
	return (size_t)fdt_totalsize(out);
}
