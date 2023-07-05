/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _HYPERENCLAVE_DRIVER_IVRS_H
#define _HYPERENCLAVE_DRIVER_IVRS_H

#include <linux/types.h>
#include <asm/hyperenclave/iommu.h>

#define IVRS_HEADER_LENGTH 48

struct ivhd_header {
	u8 type;
	u8 flags;
	u16 length;
	u16 devid;
	u16 cap_ptr;
	u64 mmio_phys;
	u16 pci_seg;
	u16 info;
	u32 efr_attr;
	/* Following only valid on IVHD type 11h and 40h */
	u64 efr_reg; /* Exact copy of MMIO_EXT_FEATURES */
	u64 res;
} __packed;

#endif /* _HYPERENCLAVE_DRIVER_IVRS_H */
