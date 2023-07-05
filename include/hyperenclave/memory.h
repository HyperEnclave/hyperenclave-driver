/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _HYPERENCLAVE_MEMORY_H
#define _HYPERENCLAVE_MEMORY_H

struct memory_region {
	__u64 phys_start;
	__u64 virt_start;
	__u64 size;
	__u64 flags;
} __packed;

struct memory_range {
	__u64 start;
	__u64 size;
};

#endif /* _HYPERENCLAVE_MEMORY_H */
