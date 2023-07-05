/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _HYPERENCLAVE_IOMMU_H
#define _HYPERENCLAVE_IOMMU_H

#include <asm/hyperenclave/iommu.h>

#ifndef ARCH_STRUCT_IOMMU
#error ARCH_STRUCT_IOMMU not defined
#endif

bool parse_iommu(struct iommu_info *iommu_info);

#endif /* _HYPERENCLAVE_IOMMU_H */
