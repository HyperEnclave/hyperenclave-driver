// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sysctl.h>
#include <hyperenclave/hypercall.h>
#include <hyperenclave/log.h>
#include <hyperenclave/tdm.h>

#include "edmm.h"
#include "enclave.h"
#include "feature.h"
#include "hhbox.h"
#include "main.h"
#include "reclaim.h"
#include "sysfs.h"
#include "tpm.h"

static int he_get_hypercall_opcode(void __user *arg)
{
	struct he_hypercall_opcode params;

	if (use_vmcall) {
		params.opcode = 0xc1010f;
	} else {
		params.opcode = 0xd9010f;
	}

	if (copy_to_user(arg, &params, sizeof(params))) {
		return -EFAULT;
	}

	return 0;
}

static long he_ioctl(struct file *file, unsigned int ioctl, unsigned long arg)
{
	long err = 0;

	switch (ioctl) {
	case HE_IOC_HYPERCALL_OPCODE:
		err = he_get_hypercall_opcode((void __user *)arg);
		break;
	case HE_IOC_ENCLAVE_CREATE:
		err = he_cmd_encl_create((struct he_encl_create __user *)arg);
		break;
	case HE_IOC_ENCLAVE_INIT:
		err = he_cmd_encl_init((struct he_encl_init __user *)arg);
		break;
	case HE_IOC_ENCLAVE_ADD_PAGE:
		err = he_cmd_encl_add_page(
			(struct he_encl_add_page __user *)arg);
		break;
	case HE_IOC_ENCLAVE_ADD_SHARED_MEMORY:
		if (shmem_pinned) {
			err = he_cmd_pin_memory(
				(struct he_memory_info __user *)arg);
		}
		if (!err) {
			err = he_cmd_add_shared_memory(
				(struct he_memory_info __user *)arg);
		}
		break;
	case HE_IOC_ENCLAVE_REMOVE_SHARED_MEMORY:
		if (shmem_pinned) {
			err = he_cmd_unpin_memory(
				(struct he_memory_info __user *)arg);
		}
		if (!err) {
			err = he_cmd_remove_shared_memory(
				(struct he_memory_info __user *)arg);
		}
		break;
	case HE_IOC_ENCLAVE_RESET_STATS:
		err = he_cmd_encl_reset_stats(
			(struct he_encl_reset_stats __user *)arg);
		break;
	case HE_IOC_EDMM_ENABLED:
		err = he_cmd_edmm_enabled((void __user *)arg);
		break;
	case HE_IOC_ENCLAVE_RESTRICT_PERMISSIONS:
		err = he_cmd_encl_restrict_permissions((void __user *)arg);
		break;
	case HE_IOC_ENCLAVE_MODIFY_TYPES:
		err = he_cmd_encl_modify_types((void __user *)arg);
		break;
	case HE_IOC_ENCLAVE_REMOVE_PAGES:
		err = he_cmd_encl_remove_pages((void __user *)arg);
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}

void he_vma_open(struct vm_area_struct *vma)
{
	if (vma->vm_flags & VM_PFNMAP)
		kref_get(&((struct he_enclave *)(vma->vm_private_data))->refcount);
}

static vm_fault_t he_vma_fault(struct vm_fault *vmf)
{
	vm_fault_t ret;
	unsigned long addr;
	struct vm_area_struct *vma;
	struct encl_page *encl_page;
	struct he_enclave *encl;
	cycles_t time_s, time_get_lock, time_pre, time_map_s, time_map_e;

	addr = (unsigned long)vmf->address;
	vma = vmf->vma;
	encl = vma->vm_private_data;

	if (unlikely(!encl)) {
		return VM_FAULT_SIGBUS;
	}

	time_s = stats_get_cycles(STATS_PF_HANDLER);
	mutex_lock(&encl->lock);
	time_get_lock = stats_get_cycles(STATS_PF_HANDLER_GET_LOCK);

	encl_page = radix_tree_lookup(&encl->page_tree, addr >> PAGE_SHIFT);
	if (!encl_page) {
		mutex_unlock(&encl->lock);
		return he_encl_aug_page(vma, encl, addr);
	}

	encl_page = he_encl_load_page_in_pf_handler(encl, addr, &time_pre);
	if (IS_ERR(encl_page)) {
		mutex_unlock(&encl->lock);

		if (PTR_ERR(encl_page) == -EBUSY)
			return VM_FAULT_NOPAGE;

		return VM_FAULT_SIGBUS;
	}

	time_map_s = stats_get_cycles(STATS_PF_HANDLER_MAP);
	ret = vmf_insert_pfn(vma, addr,
			     PFN_DOWN(encl_page->epc_page->desc & PAGE_MASK));
	if (ret != VM_FAULT_NOPAGE) {
		return VM_FAULT_SIGBUS;
	}
	time_map_e = stats_get_cycles(STATS_PF_HANDLER);

	mutex_unlock(&encl->lock);

	stats_add(encl, STATS_PF_HANDLER_GET_LOCK, time_get_lock - time_s);
	stats_add(encl, STATS_PF_HANDLER_PRE, time_pre - time_get_lock);
	stats_add(encl, STATS_PF_HANDLER_MAP, time_map_e - time_map_s);
	stats_add(encl, STATS_PF_HANDLER, time_map_e - time_s);

	return VM_FAULT_NOPAGE;
}

void he_vma_close(struct vm_area_struct *vma)
{
	struct he_enclave *encl;

	if (!vma) {
		he_info("vma is NULL\n");
		return;
	}

	encl = vma->vm_private_data;
	if (!(vma->vm_flags & VM_PFNMAP) || (vma->vm_end <= vma->vm_start) ||
	    !encl) {
		he_info("vma vm_flags 0x%lx, vm_start 0x%lx , vm_end 0x%lx\n",
			vma->vm_flags, vma->vm_start, vma->vm_end);
		return;
	}

	/*
	 * Execution flow: __vm_munmap -> __do_munmap -> remove_vma_list
	 * -> remove_vma -> he_vma_close.
	 * And remove_vma_list is called with the mm semaphore held, so
	 * there is no need to hold mmap_sem read lock.
	 */
	zap_vma_ptes(vma, vma->vm_start, vma->vm_end - vma->vm_start);
	vma->vm_private_data = NULL;

	kref_put(&encl->refcount, he_encl_cleanup);
}

const struct vm_operations_struct he_vm_ops = {
	.close = he_vma_close,
	.open = he_vma_open,
	.fault = he_vma_fault,
};

static int he_mmap(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &he_vm_ops;
	vma->vm_flags |= VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP | VM_IO |
			 VM_DONTCOPY;
	return 0;
}

static const struct file_operations he_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = he_ioctl,
	.compat_ioctl = he_ioctl,
	.mmap = he_mmap,
};

struct miscdevice he_misc_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "hyperenclave",
	.fops = &he_fops,
};

static int hypervisorinfo_proc_show(struct seq_file *m, void *v)
{
	int i;

	if (hyper_enclave_enabled && tdm.ops->is_tdm_info_init()) {
		seq_printf(m, "phys_start: %llx\n",
			   tdm.ops->get_tdm_phys_addr());
		seq_printf(m, "phys_size: %llx\n", tdm.ops->get_tdm_size());
	} else {
		seq_printf(m, "phys_start: 0\n");
		seq_printf(m, "phys_size: 0\n");
		return 0;
	}
	seq_printf(m, "expected_measurement: ");
	for (i = 0; i < ARRAY_SIZE(tdm.hv_digest); i++)
		seq_printf(m, "%02x", tdm.hv_digest[i]);
	seq_printf(m, "\n");

	return 0;
}

int __init proc_hypervisorinfo_init(void)
{
	proc_create_single("hypervisorinfo", 0, NULL, hypervisorinfo_proc_show);

	return 0;
}

void proc_hypervisorinfo_remove(void)
{
	remove_proc_entry("hypervisorinfo", NULL);
}

int hypervisor_log_sysctl(struct ctl_table *table, int write,
			  void __user *buffer, size_t *lenp, loff_t *ppos)
{
	char c;

	if (!hhbox_log_enabled)
		return -EPERM;

	if (get_user(c, (char __user *)buffer))
		return -EFAULT;

	switch (c) {
	case 'd':
		/* Dump hypervisor log to main logbuf */
		printk_safe_flush_sym();
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int hyper_enclave_enable_sysctl(struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp, loff_t *ppos)
{
	bool update;
	int old, new, ret;

	update = false;
	if (mutex_lock_interruptible(&he_lock) != 0)
		return -EINTR;
	old = hyper_enclave_enabled;
	ret = proc_dointvec_minmax(table, write, buffer, lenp, ppos);
	new = hyper_enclave_enabled;
	if (ret || !write || (old == new))
		goto out;

	if (new) {
		ret = he_cmd_enable() || !enable_epc_reclaimer();
	} else {
		ret = he_cmd_disable();
	}
	if (ret)
		hyper_enclave_enabled = old;
	else
		update = true;

out:
	mutex_unlock(&he_lock);
	/*
	 * Update tpm chip ops outside of hyperenclave lock, otherwise there may be
	 * ABBA dead lock for he_lock and chip->ops_sem;
	 */
	if (update) {
		if (hyper_enclave_enabled) {
			tpm_chip_ops_update();
			register_vmm_check_wq();
			register_flush_hv_log_work();
		} else {
			tpm_chip_ops_cleanup();
			deregister_vmm_check_wq();
			deregister_flush_hv_log_work();
			disable_epc_reclaimer();
		}
	}
	return ret;
}

static int zero;
static int one = 1;
static struct ctl_table hyper_enclave_table[] = {
	{
		.procname = "enabled",
		.data = &hyper_enclave_enabled,
		.maxlen = sizeof(int),
		.mode = 0644,
		.proc_handler = hyper_enclave_enable_sysctl,
		.extra1 = &zero,
		.extra2 = &one,
	},
	{
		.procname = "hypervisor_log",
		.maxlen = sizeof(char),
		.mode = 0200,
		.proc_handler = hypervisor_log_sysctl,
	},
	{}
};

static struct ctl_table hyper_enclave_dir_table[] = {
	{
		.procname = "hyper_enclave",
		.mode = 0555,
		.child = hyper_enclave_table,
	},
	{}
};

struct ctl_table hyper_enclave_root_table[] = {
	{ .procname = "dev", .mode = 0555, .child = hyper_enclave_dir_table },
	{}
};

struct ctl_table_header *hyper_enclave_table_header;
