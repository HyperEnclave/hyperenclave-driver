/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_TDM_H
#define _DRIVER_TDM_H

#include <crypto/sm3.h>
#include <linux/string.h>

#include <hyperenclave/memory.h>

extern struct memory_region tdm_hv;
extern unsigned char tdm_hv_digest[SM3_DIGEST_SIZE];

static inline bool is_tdm_info_init(void)
{
	return !!tdm_hv.size;
}

static inline void set_tdm_info(struct memory_region *region)
{
	memcpy(&tdm_hv, region, sizeof(tdm_hv));
}

static inline void clear_tdm_info(void)
{
	memset(&tdm_hv, 0, sizeof(tdm_hv));
}

static inline unsigned long long get_tdm_phys_addr(void)
{
	return tdm_hv.phys_start;
}

static inline unsigned long long get_tdm_virt_addr(void)
{
	return tdm_hv.virt_start;
}

static inline unsigned long long get_tdm_size(void)
{
	return tdm_hv.size;
}

#endif /* _DRIVER_TDM_H */
