/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _ASM_X86_HYPERENCLAVE_IOMMU_H
#define _ASM_X86_HYPERENCLAVE_IOMMU_H

#define HYPERENCLAVE_MAX_IOMMU_UNITS 16
#define HYPERENCLAVE_MAX_RMRR_RANGES 4

struct iommu_range {
	__u64 base;
	__u32 size;
} __packed;

struct rmrr_range {
	__u64 base;
	__u64 limit;
} __packed;

struct iommu_info {
	struct iommu_range iommu_units[HYPERENCLAVE_MAX_IOMMU_UNITS];
	struct rmrr_range rmrr_ranges[HYPERENCLAVE_MAX_RMRR_RANGES];
};
#define ARCH_STRUCT_IOMMU

bool parse_ivrs(struct iommu_info *iommu_info);
bool parse_dmar(struct iommu_info *iommu_info);

#endif /* _ASM_X86_HYPERENCLAVE_IOMMU_H */
