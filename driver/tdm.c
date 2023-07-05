// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <hyperenclave/tdm.h>
#include <hyperenclave/vendor.h>

extern const struct tdm_ops hygon_tdm_ops;
struct tdm tdm;

static int generic_proc_init(void)
{
	return 0;
}

static void generic_proc_remove(void)
{
}

static void generic_tdm_measure(void)
{
}

static bool generic_is_tdm_info_init(void)
{
	return false;
}

static void generic_set_tdm_info(struct memory_region *region)
{
}

static void generic_clear_tdm_info(void)
{
}

static unsigned long long generic_get_tdm_phys_addr(void)
{
	return 0;
}

static unsigned long long generic_get_tdm_virt_addr(void)
{
	return 0;
}

static unsigned long long generic_get_tdm_size(void)
{
	return 0;
}

const struct tdm_ops generic_tdm_ops = {
	.proc_init = generic_proc_init,
	.proc_remove = generic_proc_remove,
	.measure = generic_tdm_measure,
	.is_tdm_info_init = generic_is_tdm_info_init,
	.set_tdm_info = generic_set_tdm_info,
	.clear_tdm_info = generic_clear_tdm_info,
	.get_tdm_phys_addr = generic_get_tdm_phys_addr,
	.get_tdm_virt_addr = generic_get_tdm_virt_addr,
	.get_tdm_size = generic_get_tdm_size,
};

void tdm_init(void)
{
	if (vendor == HE_X86_VENDOR_HYGON)
		tdm.ops = &hygon_tdm_ops;
	else
		tdm.ops = &generic_tdm_ops;
}
