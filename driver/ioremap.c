// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <asm/tlbflush.h>

#include <hyperenclave/log.h>
#include <hyperenclave/sme.h>

#include "main.h"

void *he_ioremap(phys_addr_t phys, unsigned long virt, unsigned long size,
		 unsigned long sme_flags)
{
	struct vm_struct *vma;
	unsigned long page_attr = pgprot_val(PAGE_KERNEL_EXEC) | sme_flags;

	size = PAGE_ALIGN(size);
	if (virt)
		vma = __get_vm_area(size, VM_IOREMAP, virt,
				    virt + size + PAGE_SIZE);
	else
		vma = __get_vm_area(size, VM_IOREMAP, VMALLOC_START,
				    VMALLOC_END);
	if (!vma) {
		he_err("__get_vm_area return failed\n");
		return NULL;
	}
	vma->phys_addr = phys;
	if (ioremap_page_range_sym((unsigned long)vma->addr,
				   (unsigned long)vma->addr + size, phys,
				   __pgprot(page_attr))) {
		vunmap(vma->addr);
		he_err("ioremap_page_range_sym failed\n");
		return NULL;
	}
#ifdef CONFIG_X86
	if (sme_flags) {
		if (flush_tlb_kernel_range_sym) {
			flush_tlb_kernel_range_sym((unsigned long)vma->addr,
						   TLB_FLUSH_ALL);
			wbinvd_on_all_cpus();
		} else {
			he_warn("flush_tlb_kernel_range_sym is NULL\n");
		}
	}
#endif
	return vma->addr;
}
