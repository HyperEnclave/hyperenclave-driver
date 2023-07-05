// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <linux/processor.h>

#include <hyperenclave/log.h>
#include <hyperenclave/vendor.h>

static const char *cpu_vendor_table[HE_VENDOR_MAX] = {
	"Unknown",
	"GenuineIntel",
	"AuthenticAMD",
	"HygonGenuine",
	"CentaurHauls",
};

enum cpu_vendor vendor;

#ifdef CONFIG_X86
void cpu_vendor_detect(void)
{
	int i;
	int cpuid_level;
	char x86_vendor_id[16] = "";
	/* Get vendor name */
	cpuid(0x00000000, (unsigned int *)&cpuid_level,
	      (unsigned int *)&x86_vendor_id[0],
	      (unsigned int *)&x86_vendor_id[8],
	      (unsigned int *)&x86_vendor_id[4]);

	for (i = 0; i < HE_VENDOR_MAX; i++) {
		if (strstr(x86_vendor_id, cpu_vendor_table[i]))
			vendor = i;
	}
	he_info("Vendor ID: %s\n", cpu_vendor_table[vendor]);
}
#endif
