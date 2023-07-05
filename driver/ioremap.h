/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_IOREMAP_H
#define _DRIVER_IOREMAP_H

#include <linux/types.h>

void *he_ioremap(phys_addr_t phys, unsigned long virt, unsigned long size,
		 unsigned long sme_flags);

#endif
