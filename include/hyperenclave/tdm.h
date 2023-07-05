/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _HYPERENCLAVE_TDM_H
#define _HYPERENCLAVE_TDM_H

#include <crypto/sm3.h>
#include <linux/string.h>

#include <hyperenclave/memory.h>

struct tdm;

extern struct tdm tdm;
int proc_hypervisorinfo_init(void);
void proc_hypervisorinfo_remove(void);
int measure_image(unsigned char *start_addr, unsigned int size,
		  unsigned char *digest);
void tdm_init(void);

struct tdm_ops {
	int (*proc_init)(void);
	void (*proc_remove)(void);
	void (*measure)(void);
	bool (*is_tdm_info_init)(void);
	void (*set_tdm_info)(struct memory_region *region);
	void (*clear_tdm_info)(void);
	unsigned long long (*get_tdm_phys_addr)(void);
	unsigned long long (*get_tdm_virt_addr)(void);
	unsigned long long (*get_tdm_size)(void);
};

struct tdm {
	struct memory_region hv_mem;
	unsigned char hv_digest[SM3_DIGEST_SIZE];
	const struct tdm_ops *ops;
};

#endif /* _HYPERENCLAVE_TDM_H */
