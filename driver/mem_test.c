// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <hyperenclave/log.h>
#include <hyperenclave/sme.h>

#include "main.h"
#include "init_mem.h"
#include "ioremap.h"

static unsigned long gen_magic_num(unsigned long addr)
{
	return addr;
}

bool mem_test(void)
{
	unsigned long sme_mask;
	unsigned long page_attr, magic_num;
	unsigned long phys;
	unsigned long mem_base_addr, *mem_ptr;
	unsigned long remain_size, batch_size, size;
	unsigned long region_idx, ptr_pos;

	if (hyper_enclave_enabled) {
		he_err("Cannot perform memory test with hyper enclave enabled\n");
		return false;
	}

	/* Perform memory test in 8GB granularity */
	batch_size = 8L * 1024 * 1024 * 1024;
	page_attr = pgprot_val(PAGE_KERNEL);
	sme_mask = get_sme_mask();

	for (region_idx = 0; region_idx < nr_rsrv_mem; region_idx++) {
		phys = rsrv_mem_ranges[region_idx].start;
		remain_size = rsrv_mem_ranges[region_idx].size;

		while (remain_size > 0) {
			size = remain_size > batch_size ? batch_size : remain_size;
			mem_base_addr = (unsigned long)he_ioremap(
				phys, (unsigned long)NULL, size, sme_mask);

			he_info("Memory[0x%lx - 0x%lx] test begin\n", phys,
				phys + size);

			/* Set the memory */
			for (ptr_pos = 0; ptr_pos < size;
			     ptr_pos += sizeof(unsigned long)) {
				mem_ptr = (unsigned long *)(mem_base_addr +
							    ptr_pos);
				*mem_ptr = gen_magic_num(phys + ptr_pos);
			}
			wbinvd_on_all_cpus();

			/* Check whether the contents fetched from the memory equal to that written recently */
			for (ptr_pos = 0; ptr_pos < size;
			     ptr_pos += sizeof(unsigned long)) {
				mem_ptr = (unsigned long *)(mem_base_addr +
							    ptr_pos);
				magic_num = gen_magic_num(phys + ptr_pos);
				if (magic_num != *mem_ptr) {
					he_err("Memory test fails, phys addr[0x%lx]: 0x%lx != 0x%lx\n",
					       phys + ptr_pos, *mem_ptr,
					       magic_num);

					vunmap((void *)mem_base_addr);
					return false;
				}
			}

			memset((void *)mem_base_addr, 0, size);
			vunmap((void *)mem_base_addr);
			he_info("Memory[0x%lx - 0x%lx] test pass\n", phys,
				phys + size);

			remain_size -= size;
			phys += size;

			/*
			 * We may loop for a long time for testing the memory.
			 * Allow us to schedule out to avoid softlocking if preempt
			 * is disabled.
			 */
			cond_resched();
		}
	}

	return true;
}
