/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_SHARED_MEM_H
#define _DRIVER_SHARED_MEM_H
#include <linux/mmu_notifier.h>
#include <linux/interval_tree.h>

#include "ioctl.h"

enum shmem_status {
	/* @shmem_struct is UNINIT */
	UNINIT = 0x0,
	/* @shmem_struct is INITIALIZED */
	INITIALIZED = 0x1,
	/* @shmem_struct is DESTROY */
	DESTROY = 0x2,
};

struct shmem_struct {
	/* interval tree contains shared memory ranges */
	struct rb_root_cached shmem_tree;
	/* to serialize the @shmem_struct read and write */
	spinlock_t lock;
	/* MMU notifier on mm_struct */
	struct mmu_notifier mmu_notifier;
	/* the number of ranges on the mm_struct is invalidating */
	unsigned long active_invalidate_count;
	/* if mm_struct is invalidating, Add and remove shmem_range are waited
	 * until the last invalidate_range_end happens then they are progressed.
	 */
	wait_queue_head_t wq;
	/* the status of @shmem_struct */
	enum shmem_status status;
};

struct hc_memory_desc {
	__u64 config_addr;
	__u64 start_addr;
	__u64 end_addr;
} __packed;

struct he_enclave;

int he_cmd_add_shared_memory(struct he_memory_info __user *arg);
int he_cmd_remove_shared_memory(struct he_memory_info __user *arg);
int shared_memory_init(struct he_enclave *encl);
void shared_memory_destroy(struct he_enclave *encl);

#endif /* !_DRIVER_SHARED_MEM_H */
