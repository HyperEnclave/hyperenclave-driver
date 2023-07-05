/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_MEM_REGIONS_H
#define _DRIVER_MEM_REGIONS_H

#include <linux/types.h>

#define HE_MEM_READ 0x0001
#define HE_MEM_WRITE 0x0002
#define HE_MEM_EXECUTE 0x0004
#define HE_MEM_DMA 0x0008

int get_iomem_num(void);
int get_mem_regions(struct memory_region *regions);
bool get_hypervisor_meminfo(void);

#ifdef DEBUG
void dump_reserved_meminfo(void);
void dump_mem_regions(struct memory_region *regions, int n);
#else
static inline void dump_reserved_meminfo(void)
{
}

static inline void dump_mem_regions(struct memory_region *regions, int n)
{
}
#endif

#endif
