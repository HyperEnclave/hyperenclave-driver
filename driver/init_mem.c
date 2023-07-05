// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <asm/e820/types.h>

#include <linux/kernel.h>
#include <linux/sort.h>

#include <hyperenclave/hypercall.h>
#include <hyperenclave/log.h>

#include "elf.h"
#include "enclave.h"
#include "init_mem.h"

/*
 * The process for generating memory information for Hyper Enclave by the driver is as follows:
 *
 *	From `memmap` in kernel command-line:		From 'e820_table_firmware' provided by kernel:
 *		'memmap_start' and 'memmap_end'			'e820_system_ram' (sort and merge) -> 'conv_mem_ranges'
 *			|						|
 *			|						|
 *			|_______________________________________________|
 *							|
 *							| Get the intersecting parts
 * 		Valid reserved memory regions for <-----|
 * 		Hyper Enclave ('rsrv_mem_ranges')
 * 					|
 * 					| Divided into two parts
 * 				       / \
 * 				      /	  \
 * 	Memory regions for	     /	   \
 * 	hypervisor ('hv_range')  <--/	    \---> Initialized EPC for enclave ('init_epc_ranges')
 */

#define ALIGN_UP(x, align_to) (((x) + ((align_to)-1)) & ~((align_to)-1))
#define MAX_RSRV_MEM_REGIONS MAX_CONV_MEM_REGIONS

#define CMRM_ENTRY_SIZE 24
#define PT_FRAME_SIZE 16
#define VADDR_SIZE 8
#define HV_EXTRA_SIZE SZ_1G

/*
 * The 'e820_table_firmware' records the original firmware version passed to us by the
 * bootloader. It is not modified by kernel.
 */
static struct e820_table *e820_table_firmware;
static struct e820_table **e820_table_firmware_sym;

static struct memory_range e820_system_ram[E820_MAX_ENTRIES];

/* Array of convertible memory regions */
static struct memory_range conv_mem_ranges[MAX_CONV_MEM_REGIONS];
/* Number of valid convertible memory regions in 'conv_mem_ranges' */
static unsigned int nr_conv_mem;
/* The size of convertible memory region */
static unsigned long long conv_mem_size;

/*
 * Array of valid reserved memory regions for Hyper Enclave.
 * It is reserved by 'memmap' in kernel command-line.
 * Driver filters out invalid memory regions for it by using 'conv_mem_ranges'.
 */
struct memory_range rsrv_mem_ranges[MAX_RSRV_MEM_REGIONS];
/* Number of valid reserved memory regions in 'rsrv_mem_ranges' */
unsigned int nr_rsrv_mem;
/* The size of valid reserved memory region */
static unsigned long long rsrv_mem_size;

/* Array of initialized EPC regions */
struct memory_range init_epc_ranges[MAX_INIT_EPC_REGIONS];
/* Number of initialized EPC regions in 'init_epc_ranges' */
unsigned int nr_init_epc;
/* The size of initialized EPC regions */
static unsigned long long init_epc_size;

/* The min address of the convertible memory region */
static unsigned long long conv_mem_start;
/* The max address of the convertible memory region */
static unsigned long long conv_mem_end;

/* The min address of the reserved memmory specified by `memmap` in kernel command-line */
unsigned long long memmap_start;
/* The max address of the reserved memmory specified by `memmap` in kernel command-line */
unsigned long long memmap_end;

/* The size of hypervisor heap */
static unsigned long long hv_heap_size;

static const char *e820_type_to_string(struct e820_entry *entry)
{
	switch (entry->type) {
	case E820_TYPE_RESERVED_KERN: /* Fall-through: */
	case E820_TYPE_RAM:
		return "System RAM";
	case E820_TYPE_ACPI:
		return "ACPI Tables";
	case E820_TYPE_NVS:
		return "ACPI Non-volatile Storage";
	case E820_TYPE_UNUSABLE:
		return "Unusable memory";
	case E820_TYPE_PRAM:
		return "Persistent Memory (legacy)";
	case E820_TYPE_PMEM:
		return "Persistent Memory";
	case E820_TYPE_RESERVED:
		return "Reserved";
	default:
		return "Unknown E820 type";
	}
}

static int cmp_func(const void *a, const void *b)
{
	return ((struct memory_range *)a)->start >
		((struct memory_range *)b)->start ? 1 : -1;
}

int get_convertible_memory(void)
{
	int i, sys_ram_num = 0;
	unsigned long long prev_end;
	unsigned long long start, end;

	RESOLVE_EXTERNAL_SYMBOL(e820_table_firmware);
	e820_table_firmware = *e820_table_firmware_sym;

	for (i = 0; i < e820_table_firmware->nr_entries; i++) {
		struct e820_entry *entry = e820_table_firmware->entries + i;

		he_info("BIOS E820 table from firmware: [0x%016llx -> 0x%016llx], type: %s\n",
			entry->addr, entry->addr + entry->size,
			e820_type_to_string(entry));

		if (entry->type == E820_TYPE_RAM) {
			e820_system_ram[sys_ram_num].start = entry->addr;
			e820_system_ram[sys_ram_num].size = entry->size;
			sys_ram_num++;
		}
	}

	if (sys_ram_num == 0 || sys_ram_num > MAX_CONV_MEM_REGIONS) {
		he_err("The number of \"System RAM\" is invalid: %d\n",
		       sys_ram_num);
		return -ENOMEM;
	}

	/* Sort the 'e820_system_ram'. */
	sort(e820_system_ram, sys_ram_num, sizeof(struct memory_range),
	     cmp_func, NULL);

	/*
	 * Check every entry in 'e820_system_ram' does not
	 * overlap with each other.
	 */
	prev_end = e820_system_ram[0].start + e820_system_ram[0].size;
	i = 1;
	while (i < sys_ram_num) {
		if (prev_end > e820_system_ram[i].start) {
			he_err("The \"System RAM\" region in E820 overlaps, "
			       "prev_end: 0x%llx, cur_start: 0x%llx\n",
			       prev_end, e820_system_ram[i].start);
			return -EINVAL;
		}

		prev_end = e820_system_ram[i].start + e820_system_ram[i].size;
		i++;
	}

	/* Merge and copy the memory block to 'conv_mem_ranges', update 'nr_conv_mem'. */
	nr_conv_mem = 0;
	start = e820_system_ram[0].start;
	end = e820_system_ram[0].start + e820_system_ram[0].size;
	for (i = 1; i < sys_ram_num; i++) {
		if (end == e820_system_ram[i].start) {
			/* The 'e820_system_ram[i]' is contiguous with 'e820_system_ram[i - 1]'. */
			end = e820_system_ram[i].start +
			      e820_system_ram[i].size;
		} else {
			/* Align the address of convertible EPC region to 4kB. */
			start = ALIGN_UP(start, SZ_4K);
			end = ALIGN_DOWN(end, SZ_4K);
			if (start < end) {
				conv_mem_ranges[nr_conv_mem].start = start;
				conv_mem_ranges[nr_conv_mem].size = end - start;
				nr_conv_mem++;
			}

			start = e820_system_ram[i].start;
			end = e820_system_ram[i].start +
			      e820_system_ram[i].size;
		}
	}
	start = ALIGN_UP(start, SZ_4K);
	end = ALIGN_DOWN(end, SZ_4K);
	if (start < end) {
		conv_mem_ranges[nr_conv_mem].start = start;
		conv_mem_ranges[nr_conv_mem].size = end - start;
		nr_conv_mem++;
	}

	conv_mem_start = conv_mem_ranges[0].start;
	conv_mem_end = conv_mem_ranges[nr_conv_mem - 1].start +
		       conv_mem_ranges[nr_conv_mem - 1].size;

	conv_mem_size = 0;
	for (i = 0; i < nr_conv_mem; i++) {
		he_info("Convertible Memory[%2d]: 0x%016llx -> 0x%016llx\n", i,
			conv_mem_ranges[i].start,
			conv_mem_ranges[i].start + conv_mem_ranges[i].size);
		conv_mem_size += conv_mem_ranges[i].size;
	}
	he_info("Convertible Memory size: 0x%llx\n", conv_mem_size);

	return 0;
}

int get_valid_rsrv_mem(void)
{
	int i, start_cmem_idx = -1, end_cmem_idx = -1;
	unsigned long long start, end;

	for (i = 0; i < nr_conv_mem; i++) {
		end = conv_mem_ranges[i].start + conv_mem_ranges[i].size;

		if (end > memmap_start) {
			start_cmem_idx = i;
			break;
		}
	}
	for (i = nr_conv_mem - 1; i >= 0; i--) {
		start = conv_mem_ranges[i].start;

		if (start < memmap_end) {
			end_cmem_idx = i;
			break;
		}
	}
	if (start_cmem_idx == -1 || end_cmem_idx == -1) {
		he_err("Convertible memory range[min: 0x%llx, max: 0x%llx] "
		       "does not intersect with 'memmap' regions in command line[0x%llx -> 0x%llx].",
		       conv_mem_start, conv_mem_end, memmap_start, memmap_end);
		return -EINVAL;
	}
	if (end_cmem_idx - start_cmem_idx + 1 > MAX_RSRV_MEM_REGIONS) {
		he_err("There is no enough space for 'rsrv_mem_ranges' array, needs: %d",
		       end_cmem_idx - start_cmem_idx + 1);
		return -EINVAL;
	}

	nr_rsrv_mem = 0;
	for (i = start_cmem_idx; i <= end_cmem_idx; i++) {
		start = conv_mem_ranges[i].start;
		end = conv_mem_ranges[i].start + conv_mem_ranges[i].size;

		if (i == start_cmem_idx) {
			start = max(start, memmap_start);
		}
		if (i == end_cmem_idx) {
			end = min(end, memmap_end);
		}

		start = ALIGN_UP(start, SZ_1G);
		end = ALIGN_DOWN(end, SZ_1G);
		if (start < end) {
			rsrv_mem_ranges[nr_rsrv_mem].start = start;
			rsrv_mem_ranges[nr_rsrv_mem].size = end - start;
			nr_rsrv_mem++;
		}
	}

	if (nr_rsrv_mem == 0) {
		he_err("There is no valid memory regions in command-line's 'memmap' regions: [0x%llx -> 0x%llx]\n",
		       memmap_start, memmap_end);
		return -EINVAL;
	}

	rsrv_mem_size = 0;
	for (i = 0; i < nr_rsrv_mem; i++) {
		he_info("Reserved Memory[%2d]: 0x%llx -> 0x%llx\n", i,
			rsrv_mem_ranges[i].start,
			rsrv_mem_ranges[i].start + rsrv_mem_ranges[i].size);
		rsrv_mem_size += rsrv_mem_ranges[i].size;
	}
	he_info("Reserved Memory size: 0x%llx\n", rsrv_mem_size);

	return 0;
}

/**
 * init_enclave_page() - Initialize pages for enclave, and update the information for hypervisor's header
 *
 * @header:	Pointer to hypervisor's header
 *
 * Valid reserved memory regions is divided into two parts, one is the allocated for hypervisor,
 * and the remaining part is allocated for all the enclaves as initialized EPC.
 */
void init_enclave_page(struct hyper_header *header)
{
	int i, index;

	init_epc_size = 0;
	index = 0;
	for (i = 0; i < nr_rsrv_mem; i++) {
		if (rsrv_mem_ranges[i].start & 1) {
			init_epc_ranges[index].start =
				rsrv_mem_ranges[i].start - 1;
			init_epc_ranges[index].size = rsrv_mem_ranges[i].size;
			init_epc_size += init_epc_ranges[index].size;
			add_epc_pages(init_epc_ranges[index].start,
				      init_epc_ranges[index].size);
			he_info("epc ranges: [0x%llx-0x%llx], 0x%llx\n",
				init_epc_ranges[index].start,
				init_epc_ranges[index].start +
					init_epc_ranges[index].size,
				init_epc_ranges[index].size);

			header->init_epc_ranges[index].start =
				init_epc_ranges[index].start;
			header->init_epc_ranges[index].size =
				init_epc_ranges[index].size;

			index++;
		}
	}
	nr_init_epc = index;
	header->nr_init_epc = nr_init_epc;
	he_info("Initialized EPC ranges size: 0x%llx\n", init_epc_size);
}

int get_hv_core_and_percpu_size(unsigned long *hv_core_and_percpu_size_ptr,
				const u8 *elf)
{
	const struct hyper_header *header;
	long max_cpus;

	if (!hv_core_and_percpu_size_ptr) {
		he_err("hv_core_and_percpu_size_ptr is null");
		return -EFAULT;
	}

	header = get_header_from_elf(elf);
	if (IS_ERR(header)) {
		he_err("ERR, failed to call get_header_from_elf()");
		return PTR_ERR(header);
	}

	max_cpus = num_possible_cpus();

	*hv_core_and_percpu_size_ptr =
		header->core_size + max_cpus * header->percpu_size;
	return 0;
}

static unsigned long long get_epc_max_limit(void)
{
	return max(conv_mem_size / 2, rsrv_mem_size);
}

static unsigned long long get_hv_heap_size(void)
{
	unsigned long long heap_size;

	/* Heap: enclave gpt/npt frame */
	heap_size = (get_epc_max_limit() >> 30) * 512 * 512 * PT_FRAME_SIZE * 2;
	heap_size += HV_EXTRA_SIZE;
	heap_size = round_up(heap_size, SZ_4K);

	hv_heap_size = heap_size;
	he_info("Hypervisor heap size: 0x%llx\n", heap_size);

	return heap_size;
}

static unsigned long long get_hv_cmrm_size(void)
{
	unsigned long long cmrm_size;

	cmrm_size = ((conv_mem_end - conv_mem_start) >> PAGE_SHIFT) *
		    CMRM_ENTRY_SIZE;
	cmrm_size = round_up(cmrm_size, SZ_4K);
	he_info("Hypervisor cmrm size: 0x%llx\n", cmrm_size);

	return cmrm_size;
}

static unsigned long long get_hv_frame_size(void)
{
	unsigned long long frame_size;

	frame_size = (get_epc_max_limit() >> 30) * 512 * SZ_4K * 2;
	/* Currently the max frame size hypervisor supports is 4GB */
	frame_size = min((unsigned long long)SZ_4G, frame_size);
	frame_size = round_up(frame_size, SZ_4K);
	he_info("Hypervisor frame size: 0x%llx\n", frame_size);

	return frame_size;
}

unsigned long long
get_hypervisor_size(unsigned long long hv_core_and_percpu_size)
{
	unsigned long long hv_size;

	hv_size = hv_core_and_percpu_size + get_hv_heap_size() +
		  get_hv_cmrm_size() + get_hv_frame_size();
	hv_size = round_up(hv_size, SZ_1G);
	he_info("Hv_core_and_percpu_size: 0x%llx, Hypervisor size: 0x%llx\n",
		hv_core_and_percpu_size, hv_size);

	return hv_size;
}

void set_heap_size(struct hyper_header *header)
{
	header->hv_heap_size = hv_heap_size;
}

void set_convertible_mem(struct hyper_header *header)
{
	memcpy(header->conv_mem_ranges, conv_mem_ranges,
	       nr_conv_mem * sizeof(struct memory_range));
	header->nr_conv_mem = nr_conv_mem;
}

int init_cmrm(void)
{
	int ret;
	unsigned long long cur_start, cur_size, remain_size;
	unsigned long long batch_size = 64L * SZ_1G;

	/* Initailize CMRM */
	cur_start = conv_mem_start;
	remain_size = conv_mem_end - conv_mem_start;
	cur_size = min(remain_size, batch_size);
	while (cur_size > 0) {
		ret = hypercall_ret_1(HC_INIT_CMRM, cur_size);
		if (ret) {
			he_err("Initialize [0x%llx -> 0x%llx]'s CMRM error, ret: %d\n",
			       cur_start, cur_start + cur_size, ret);
			return ret;
		}
		he_info("Initialize [0x%llx -> 0x%llx]'s CMRM\n", cur_start,
			cur_start + cur_size);

		cur_start += cur_size;
		remain_size -= cur_size;
		cur_size = min(remain_size, batch_size);
	}

	/* Mark the process of CMRM initialization done */
	ret = hypercall_ret_0(HC_SET_INIT_CMRM_DONE);
	if (ret) {
		he_err("Cannot mark the process of CMRM initialization done, ret: %d\n",
		       ret);
		return ret;
	}

	return 0;
}
