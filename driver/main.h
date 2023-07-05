/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_MAIN_H
#define _DRIVER_MAIN_H

#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/kallsyms.h>
#include <asm/tlbflush.h>

#include <hyperenclave/system_config.h>

#define RESOLVE_EXTERNAL_SYMBOL(symbol)                               \
	do {                                                          \
		symbol##_sym = (void *)kallsyms_lookup_name(#symbol); \
		if (!symbol##_sym) {                                  \
			he_err("Can't get symbol %s\n", #symbol);     \
			return -EINVAL;                               \
		}                                                     \
	} while (0)

extern int len_memmap_paras;
extern char *str_memmap[2];

extern struct mutex he_lock;
extern int hyper_enclave_enabled;
extern void *hypervisor_mem;
extern struct memory_range hv_range;
extern unsigned long hv_core_and_percpu_size;

extern typeof(printk_safe_flush) *printk_safe_flush_sym;
extern void (*mmput_async_sym)(struct mm_struct *mm);
extern typeof(ioremap_page_range) *ioremap_page_range_sym;
#ifdef CONFIG_X86
extern typeof(flush_tlb_kernel_range) *flush_tlb_kernel_range_sym;
#endif

void he_ipi_cb(void *info);
int he_cmd_disable(void);
int he_cmd_enable(void);

#endif /* !_DRIVER_MAIN_H */
