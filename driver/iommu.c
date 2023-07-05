// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <linux/cpufeature.h>

#include <hyperenclave/iommu.h>
#include <hyperenclave/log.h>

bool parse_iommu(struct iommu_info *iommu_info)
{
#ifdef CONFIG_X86
	if (boot_cpu_has(X86_FEATURE_SVM))
		return parse_ivrs(iommu_info);
	if (boot_cpu_has(X86_FEATURE_VMX))
		return parse_dmar(iommu_info);
#endif
	he_err("parse iommu not implemented for non-x86 arch\n");
	return false;
}
