// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <hyperenclave/log.h>

#include "main.h"
#include "init_mem.h"
#include "ioremap.h"
#include "mem_regions.h"

int get_iomem_num(void)
{
	int num;
	struct resource *child;

	num = 0;
	child = iomem_resource.child;
	while (child) {
		num++;
		child = child->sibling;
	}

	return num;
}

static inline unsigned long long mem_region_flag(const char *name)
{
	if (!strcmp(name, "System RAM") || !strcmp(name, "RAM buffer"))
		return HE_MEM_READ | HE_MEM_WRITE | HE_MEM_EXECUTE | HE_MEM_DMA;
	else if (!strcmp(name, "Reserved"))
		return HE_MEM_READ | HE_MEM_WRITE | HE_MEM_EXECUTE;
	else
		return HE_MEM_READ | HE_MEM_WRITE;
}

static void set_mem_region(struct memory_range *res_range, const char *name,
			   struct memory_region *regions, int *num)
{
	unsigned long long s = 0, e = 0, flags = 0;
	unsigned long long l_start = 0, l_end = 0;
	int l_index = 0;

	e = res_range->start + res_range->size - 1;
	s = round_down(res_range->start, PAGE_SIZE);
	e = round_up(e + 1, PAGE_SIZE) - 1;
	if ((*num) == 0) {
		l_start = 0;
		l_end = 0;
	} else {
		l_index = (*num) - 1;
		l_start = regions[l_index].phys_start;
		l_end = regions[l_index].phys_start + regions[l_index].size - 1;
	}
	// check if current region is overlapped with last one
	if (s < l_end) {
		he_debug("overlap last:(0x%llx 0x%llx) now:(0x%llx 0x%llx)\n",
			 l_start, l_end, s, e);
		s = min(s, l_start);
		e = max(e, l_end);
		// the flags of the merged regions should be OR of two flags of regions
		// for example:  SYSRAM merge with RESERVED region, the merged.flags = SYSRAM.flags |  RESERVED.flags
		flags = regions[l_index].flags;
		(*num)--;
	}
	regions[*num].phys_start = s;
	regions[*num].virt_start = s;
	regions[*num].size = e - s + 1;
	regions[*num].flags = flags | mem_region_flag(name);
	he_debug("flag: %llx. num: %d(%llx %llx %llx)\n", regions[*num].flags,
		 *num, regions[*num].phys_start, regions[*num].virt_start,
		 regions[*num].size);
	(*num)++;
}

/*
 * set_mem_regions - Set memory regions for a specified iomem region.
 *
 * For a specified iomem region, set the regions reported to hypervisor
 * and get valid memmap reserved ranges in the specified region.
 *
 * The start and end addr of memory regions must be PAGE_SIZE align
 * and remove memmap reserved regions for hypervisor and EPC use.
 *
 * If exists memmap reserved range in this iomem region, return true,
 * else returns false.
 */
static bool set_mem_regions(struct memory_range *res_range, const char *name,
			    struct memory_region *regions, int *num)
{
	int i;
	unsigned long long last_s, last_e;
	bool flag; /* If memmap reserved region exist */

	flag = false;
	if (strcmp(name, "Reserved")) {
		set_mem_region(res_range, name, regions, num);
		return flag;
	}

	last_s = res_range->start;
	last_e = res_range->start + res_range->size - 1;
	for (i = 0; i < nr_rsrv_mem; i++) {
		if (last_s <= rsrv_mem_ranges[i].start &&
		    last_e >= rsrv_mem_ranges[i].start +
				      rsrv_mem_ranges[i].size - 1) {
			if (last_s < rsrv_mem_ranges[i].start) {
				res_range->start = last_s;
				res_range->size =
					rsrv_mem_ranges[i].start - last_s;
				set_mem_region(res_range, name, regions, num);
			}
			last_s = rsrv_mem_ranges[i].start +
				 rsrv_mem_ranges[i].size;
			flag = true;
			/* Set the least bit 1 to indicate a valid reserved range */
			rsrv_mem_ranges[i].start += 1;
		}
	}
	if (last_s < last_e) {
		res_range->start = last_s;
		res_range->size = last_e - last_s + 1;
		set_mem_region(res_range, name, regions, num);
	}

	return flag;
}

/*
 * get_mem_regions - Get the memory regions reported to hypervisor.
 *
 * The start and end addr of memory regions must be PAGE_SIZE align
 * and remove memmap reserved regions for hypervisor and EPC use.
 * Besides, get the valid memmap reserved ranges.
 *
 * If no memmap reserved regions found, returns -1, else returns the
 * number of reported regions.
 */
int get_mem_regions(struct memory_region *regions)
{
	bool flag; /* If memmap reserved regions exist */
	int num;
	struct resource *child;

	flag = false;
	num = 0;
	child = iomem_resource.child;
	while (child) {
		struct memory_range res_range;

		res_range.start = child->start;
		res_range.size = child->end - child->start + 1;
		he_debug("start:%llx, size:0x%llx\n", res_range.start,
			 res_range.size);
		flag |= set_mem_regions(&res_range, child->name, regions, &num);
		child = child->sibling;
	}

	if (!flag)
		return -1;

	return num;
}

/*
 * get_hypervisor_meminfo - Pick suitable region as the hypervisor memory
 *
 * From the reserved memory regions, pick the first suitable region as the
 * hypervisor memory. The picked region is partitioned to two pieces, hypervisor
 * uses the first piece and the Enclaves owns the rest.
 *
 * Returns true if there is suitable region for hypervisor, else returns false.
 */
bool get_hypervisor_meminfo(void)
{
	bool first;
	int i;
	unsigned long long start, end, epc_size;

	first = true;
	for (i = 0; i < nr_rsrv_mem; i++) {
		if (!(rsrv_mem_ranges[i].start & 1))
			continue;
		if (first) {
			start = rsrv_mem_ranges[i].start - 1;
			first = false;
		}
		end = rsrv_mem_ranges[i].start - 1 + rsrv_mem_ranges[i].size - 1;
	}

	if (first)
		return false;

	epc_size = end - start + 1;

	hv_range.size = get_hypervisor_size(hv_core_and_percpu_size);

	for (i = 0; i < nr_rsrv_mem; i++) {
		if (!(rsrv_mem_ranges[i].start & 1))
			continue;

		if (rsrv_mem_ranges[i].size >= hv_range.size) {
			hv_range.start = rsrv_mem_ranges[i].start - 1;
			if (hv_range.size == rsrv_mem_ranges[i].size)
				/* Just clear the least bit to indicate this range is empty */
				rsrv_mem_ranges[i].start -= 1;
			else {
				rsrv_mem_ranges[i].start += hv_range.size;
				rsrv_mem_ranges[i].size -= hv_range.size;
			}
			return true;
		}
	}

	return false;
}

#ifdef DEBUG
/*
 * Dump the hypervisor memory region and the EPC memory.
 */
static void dump_reserved_meminfo(void)
{
	int i;

	he_info("hypervisor meminfo: [0x%llx-0x%llx], 0x%llx\n", hv_range.start,
		hv_range.start + hv_range.size - 1, hv_range.size);
	for (i = 0; i < nr_init_epc; i++) {
		if (rsrv_mem_ranges[i].start & 1) {
			he_debug(
				"valid initialized EPC ranges: [0x%llx-0x%llx], 0x%llx\n",
				rsrv_mem_ranges[i].start - 1,
				rsrv_mem_ranges[i].start +
					rsrv_mem_ranges[i].size - 2,
				rsrv_mem_ranges[i].size);
		}
	}
}

/*
 * Dump the memory regions info reported to hypervisor.
 */
static void dump_mem_regions(struct memory_region *regions, int n)
{
	int i;

	for (i = 0; i < n; i++) {
		he_debug("region[%d]: [0x%llx - 0x%llx], 0x%llx\n", i + 1,
			 regions[i].phys_start,
			 regions[i].phys_start + regions[i].size - 1,
			 regions[i].size);
	}
}
#endif
