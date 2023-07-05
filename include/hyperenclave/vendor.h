/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _HYPERENCLAVE_VENDOR_H
#define _HYPERENCLAVE_VENDOR_H

enum cpu_vendor {
	HE_VENDOR_UNKNOWN,
	HE_X86_VENDOR_INTEL,
	HE_X86_VENDOR_AMD,
	HE_X86_VENDOR_HYGON,
	HE_X86_VENDOR_CENTAURHAULS,
	HE_VENDOR_MAX
};

extern enum cpu_vendor vendor;

#ifdef CONFIG_X86
void cpu_vendor_detect(void);
#else
static inline void cpu_vendor_detect(void)
{
}
#endif

#endif /* _HYPERENCLAVE_VENDOR_H */
