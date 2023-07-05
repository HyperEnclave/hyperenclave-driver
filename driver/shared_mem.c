// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <linux/slab.h>
#include <linux/version.h>
#include "main.h"
#include "stats.h"
#include "enclave.h"
#include "feature.h"

#include <hyperenclave/hypercall.h>
#include <hyperenclave/log.h>

static int insert_shared_memory(struct shmem_struct *shmem, unsigned long start,
				unsigned long end)
{
	struct interval_tree_node *node;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;
	// interval tree like [start;last], while memory range like [start;end)
	// so set 'end - 1' to node->last
	node->start = start;
	node->last = end - 1;

again:
	spin_lock(&shmem->lock);
	if (shmem->active_invalidate_count != 0) {
		spin_unlock(&shmem->lock);
		wait_event(shmem->wq, shmem->active_invalidate_count == 0);
		goto again;
	}
	if (shmem->status != INITIALIZED) {
		spin_unlock(&shmem->lock);
		kfree(node);
		he_err("shmem is not initialized\n");
		return -EINVAL;
	}
	if (interval_tree_iter_first(&shmem->shmem_tree, start, end - 1)) {
		spin_unlock(&shmem->lock);
		kfree(node);
		he_err("insert overlap: start=0x%lx, end=0x%lx\n", start, end);
		return -EINVAL;
	}
	interval_tree_insert(node, &shmem->shmem_tree);
	spin_unlock(&shmem->lock);

	return 0;
}

static int remove_shared_memory(struct shmem_struct *shmem, unsigned long start,
				unsigned long end)
{
	struct interval_tree_node *node;
again:
	spin_lock(&shmem->lock);
	if (shmem->active_invalidate_count != 0) {
		spin_unlock(&shmem->lock);
		wait_event(shmem->wq, shmem->active_invalidate_count == 0);
		goto again;
	}
	if (shmem->status != INITIALIZED) {
		spin_unlock(&shmem->lock);
		he_err("shmem is not initialized\n");
		return -EINVAL;
	}
	node = interval_tree_iter_first(&shmem->shmem_tree, start, end - 1);
	if (!node || node->start != start || node->last != end - 1) {
		spin_unlock(&shmem->lock);
		he_err("can not find range: start=0x%lx, end=0x%lx\n", start,
		       end);
		return -EINVAL;
	}
	interval_tree_remove(node, &shmem->shmem_tree);
	spin_unlock(&shmem->lock);
	kfree(node);

	return 0;
}

int he_cmd_add_shared_memory(struct he_memory_info __user *arg)
{
	struct he_memory_info hmi;
	struct hc_memory_desc memory_add;
	struct he_enclave *encl;
	struct shmem_struct *shmem;
	unsigned long start;
	unsigned long end;
	unsigned long encl_addr;
	int err;

	err = copy_from_user(&hmi, arg, sizeof(hmi));
	if (err) {
		he_err("copy_from_user failed\n");
		return -EINVAL;
	}
	start = hmi.start_addr;
	end = hmi.start_addr + hmi.size;
	encl_addr = hmi.encl_addr;
	err = find_enclave(current->mm, encl_addr, &encl);
	if (err) {
		he_err("Source page does not belong to any existing enclave:"
		       " addr=0x%lx\n",
		       encl_addr);
		return err;
	}
	he_debug("add shared memory: start=0x%lx, end=0x%lx, encl=0x%px\n",
		 start, end, encl);

	shmem = &encl->shmem;
	// add memory to shmem_tree
	err = insert_shared_memory(shmem, start, end);
	if (err)
		return err;
	// vmcall to hypervisor to add memory
	memory_add.start_addr = start;
	memory_add.end_addr = end;
	memory_add.config_addr = (unsigned long)&encl->config;
	err = hypercall_ret_1(HC_ENCL_SHARED_MEMORY_ADD,
			      (unsigned long)&memory_add);
	if (err) {
		he_err("HC_ENCL_SHARED_MEMORY_ADD hypercall failed. err: %d\n",
		       err);
		remove_shared_memory(shmem, start, end);
		return err;
	}
	return err;
}

int he_cmd_remove_shared_memory(struct he_memory_info __user *arg)
{
	struct he_memory_info hmi;
	struct hc_memory_desc memory_remove;
	struct he_enclave *encl;
	struct shmem_struct *shmem;
	unsigned long start;
	unsigned long end;
	unsigned long encl_addr;
	int err;

	err = copy_from_user(&hmi, arg, sizeof(hmi));
	if (err) {
		he_err("copy_from_user failed\n");
		return -EINVAL;
	}
	start = hmi.start_addr;
	end = hmi.start_addr + hmi.size;
	encl_addr = hmi.encl_addr;
	err = find_enclave(current->mm, encl_addr, &encl);
	if (err) {
		he_err("Source page does not belong to any existing enclave:"
		       " addr=0x%lx\n",
		       encl_addr);
		return err;
	}
	he_debug("remove shared memory: start=0x%lx, end=0x%lx, encl=0x%px\n",
		 start, end, encl);

	shmem = &encl->shmem;
	// vmcall to hypervisor to remove memory
	memory_remove.start_addr = start;
	memory_remove.end_addr = end;
	memory_remove.config_addr = (unsigned long)&encl->config;
	err = hypercall_ret_1(HC_ENCL_SHARED_MEMORY_REMOVE,
			      (unsigned long)&memory_remove);
	if (err) {
		he_err("HC_ENCL_SHARED_MEMORY_REMOVE hypercall failed. err: %d\n",
		       err);
		return err;
	}
	// remove memory from shmem_tree
	return remove_shared_memory(shmem, start, end);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)

static int
shared_memory_mn_invalidate_range_start(struct mmu_notifier *mn,
					const struct mmu_notifier_range *range)
#else
static int shared_memory_mn_invalidate_range_start(struct mmu_notifier *mn,
						   struct mm_struct *mm,
						   unsigned long start,
						   unsigned long end,
						   bool blockable)
#endif
{
	struct shmem_struct *shmem;
	struct interval_tree_node *node;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	unsigned long start = range->start;
	unsigned long end = range->end;
#endif

	shmem = container_of(mn, struct shmem_struct, mmu_notifier);
	spin_lock(&shmem->lock);
	if (shmem->status != INITIALIZED) {
		spin_unlock(&shmem->lock);
		return 0;
	}
	shmem->active_invalidate_count++;
	node = interval_tree_iter_first(&shmem->shmem_tree, start, end - 1);
	spin_unlock(&shmem->lock);

	if (node) {
		int err = 0;
		struct he_enclave *encl;
		struct hc_memory_desc memory_invalid;

		encl = container_of(shmem, struct he_enclave, shmem);
		memory_invalid.start_addr = start;
		memory_invalid.end_addr = end;
		memory_invalid.config_addr = (unsigned long)&encl->config;
		err = hypercall_ret_1(HC_ENCL_SHARED_MEMORY_INVALID_START,
				      (unsigned long)&memory_invalid);
		if (err) {
			he_err("%d. shared memory sync failed\n", err);
		}
		he_debug("invalid start=0x%lx, end=0x%lx\n", start, end);
	}
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static void
shared_memory_mn_invalidate_range_end(struct mmu_notifier *mn,
				      const struct mmu_notifier_range *range)
#else
static void shared_memory_mn_invalidate_range_end(struct mmu_notifier *mn,
						  struct mm_struct *mm,
						  unsigned long start,
						  unsigned long end)
#endif
{
	struct shmem_struct *shmem;
	struct interval_tree_node *node;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	unsigned long start = range->start;
	unsigned long end = range->end;
#endif
	bool last_end = false;

	shmem = container_of(mn, struct shmem_struct, mmu_notifier);
	spin_lock(&shmem->lock);
	if (shmem->status != INITIALIZED) {
		spin_unlock(&shmem->lock);
		return;
	}
	if (--shmem->active_invalidate_count == 0)
		last_end = true;
	node = interval_tree_iter_first(&shmem->shmem_tree, start, end - 1);
	spin_unlock(&shmem->lock);

	if (node) {
		int err = 0;
		struct he_enclave *encl;

		encl = container_of(shmem, struct he_enclave, shmem);
		err = hypercall_ret_1(HC_ENCL_SHARED_MEMORY_INVALID_END,
				      (unsigned long)&encl->config);
		if (err) {
			he_err("%d. shared memory sync failed\n", err);
		}
	}
	if (last_end)
		wake_up_all(&shmem->wq);
}

const struct mmu_notifier_ops mmu_notifier_ops = {
	.invalidate_range_start = shared_memory_mn_invalidate_range_start,
	.invalidate_range_end = shared_memory_mn_invalidate_range_end,
};

int shared_memory_init(struct he_enclave *encl)
{
	int err = 0;
	struct shmem_struct *shmem;

	shmem = &encl->shmem;
	shmem->shmem_tree = RB_ROOT_CACHED;
	shmem->active_invalidate_count = 0;
	spin_lock_init(&shmem->lock);
	init_waitqueue_head(&shmem->wq);
	shmem->status = INITIALIZED;
	// register mmu notifier
	if (!shmem_pinned) {
		shmem->mmu_notifier.ops = &mmu_notifier_ops;
		err = mmu_notifier_register(&shmem->mmu_notifier, encl->mm);
	}
	return err;
}

void shared_memory_destroy(struct he_enclave *encl)
{
	struct rb_node *it;
	struct interval_tree_node *node;
	struct shmem_struct *shmem;

	shmem = &encl->shmem;
	// free shmem_tree
	// ensure invalidate_range_start/end are called in pair before free shmem_tree.
again:
	spin_lock(&shmem->lock);
	if (shmem->active_invalidate_count != 0) {
		spin_unlock(&shmem->lock);
		wait_event(shmem->wq, shmem->active_invalidate_count == 0);
		goto again;
	}
	while ((it = shmem->shmem_tree.rb_leftmost)) {
		node = rb_entry(it, struct interval_tree_node, rb);
		interval_tree_remove(node, &shmem->shmem_tree);
		kfree(node);
	}
	shmem->status = DESTROY;
	spin_unlock(&shmem->lock);

	// unregister mmu notifier
	// It's ok to unregister mmu notifier when invalidate_range_end is not reached, since
	// invalidate_range_start can't do anything when shmem->status = DESTROY
	if (!shmem_pinned && encl->mm) {
		mmu_notifier_unregister(&shmem->mmu_notifier, encl->mm);
		he_info("mmu_notifier_unregister\n");
	}
}
