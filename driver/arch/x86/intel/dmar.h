/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _HYPERENCLAVE_DRIVER_DMAR_H
#define _HYPERENCLAVE_DRIVER_DMAR_H

#include <linux/types.h>
#include <asm/hyperenclave/iommu.h>

#define DMAR_HEADER_LENGTH 48
#define DRHD_TYPE 0
#define RMRR_TYPE 1
#define FAULT_RECORDING_SIZE 16

struct dmar_header { // drhd
	u16 type;
	u16 length;
	u8 flags;
	u8 reserved;
	u16 segment;
	u64 address;
} __packed;

struct rmrr_header {
	u16 type;
	u16 length;
	u16 reserved;
	u16 segment;
	u64 base_address;
	u64 limit_address;
} __packed;

#endif /* _HYPERENCLAVE_DRIVER_DMAR_H */
