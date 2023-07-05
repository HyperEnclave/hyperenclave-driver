/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _HYPERENCLAVE_SYSTEM_CONFIG_H
#define _HYPERENCLAVE_SYSTEM_CONFIG_H

#include <asm/hyperenclave/iommu.h>
#include <hyperenclave/memory.h>

/* General descriptor of the system. */
struct system_config {
	/* Hypervisor's location in memory. */
	struct memory_region hypervisor_memory;
	struct {
		struct iommu_info iommu_info;
	} __packed platform_info;
	__u32 num_memory_regions;
} __packed;

#endif /* _HYPERENCLAVE_SYSTEM_CONFIG_H */
