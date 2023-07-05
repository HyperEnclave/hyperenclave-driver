// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <hyperenclave/tdm.h>

static void hygon_tdm_measure(void)
{
	measure_image((unsigned char *)tdm.hv_mem.virt_start, tdm.hv_mem.size,
		      tdm.hv_digest);
}

static bool hygon_is_tdm_info_init(void)
{
	return !!tdm.hv_mem.size;
}

static void hygon_set_tdm_info(struct memory_region *region)
{
	memcpy(&tdm.hv_mem, region, sizeof(tdm.hv_mem));
}

static void hygon_clear_tdm_info(void)
{
	memset(&tdm.hv_mem, 0, sizeof(tdm.hv_mem));
}

static unsigned long long hygon_get_tdm_phys_addr(void)
{
	return tdm.hv_mem.phys_start;
}

static unsigned long long hygon_get_tdm_virt_addr(void)
{
	return tdm.hv_mem.virt_start;
}

static unsigned long long hygon_get_tdm_size(void)
{
	return tdm.hv_mem.size;
}

const struct tdm_ops hygon_tdm_ops = {
	.proc_init = proc_hypervisorinfo_init,
	.proc_remove = proc_hypervisorinfo_remove,
	.measure = hygon_tdm_measure,
	.is_tdm_info_init = hygon_is_tdm_info_init,
	.set_tdm_info = hygon_set_tdm_info,
	.clear_tdm_info = hygon_clear_tdm_info,
	.get_tdm_phys_addr = hygon_get_tdm_phys_addr,
	.get_tdm_virt_addr = hygon_get_tdm_virt_addr,
	.get_tdm_size = hygon_get_tdm_size,
};
