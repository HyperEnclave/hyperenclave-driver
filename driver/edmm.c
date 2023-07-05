// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <linux/mm.h>
#include <linux/slab.h>

#include <hyperenclave/hypercall.h>
#include <hyperenclave/log.h>

#include "enclave.h"
#include "feature.h"
#include "reclaim.h"
#include "ioctl.h"

/**
 * he_encl_aug_page() - Dynamically add page to an initialized enclave
 * @vma:	VMA obtained from fault info from where page is accessed
 * @encl:	enclave accessing the page
 * @addr:	address that triggered the page fault
 *
 * When an initialized enclave accesses a page with no backing EPC page
 * then the EPC can be added dynamically via HYPERCALL[AUG].
 *
 * Return: If PTE was installed successfully,
 * or there is no free EPC page for the enclave, VM_FAULT_NOPAGE is returned.
 * On error, VM_FAULT_SIGBUS or VM_FAULT_OOM is returned.
 */
vm_fault_t he_encl_aug_page(struct vm_area_struct *vma, struct he_enclave *encl,
			    unsigned long addr)
{
	vm_fault_t vmret = VM_FAULT_SIGBUS;
	int err;
	struct hc_encl_aug_page_desc hc_page_desc;
	struct epc_page *epc_page;
	struct encl_page *encl_page;
	struct va_page *va_page;

	if (!edmm_enabled)
		return vmret;

	encl_page = kzalloc(sizeof(*encl_page), GFP_KERNEL);
	if (!encl_page) {
		return VM_FAULT_OOM;
	}
	encl_page->desc = addr & PAGE_MASK;
	encl_page->page_type = HE_SECINFO_REG;
	encl_page->encl = encl;

	epc_page = alloc_enclave_page(false);
	if (IS_ERR(epc_page)) {
		if (PTR_ERR(epc_page) == -EBUSY) {
			vmret = VM_FAULT_NOPAGE;
			goto err_free_encl_page;
		} else if (PTR_ERR(epc_page) == -ENOMEM) {
			vmret = VM_FAULT_OOM;
			goto err_free_encl_page;
		} else {
			vmret = VM_FAULT_SIGBUS;
			goto err_free_encl_page;
		}
	}
	encl_page->epc_page = epc_page;
	epc_page->encl_page = encl_page;

	va_page = alloc_va_page(encl, false);
	if (IS_ERR(va_page)) {
		if (PTR_ERR(va_page) == -EBUSY) {
			vmret = VM_FAULT_NOPAGE;
			goto err_free_epc_page;
		} else if (PTR_ERR(va_page) == -ENOMEM) {
			vmret = VM_FAULT_OOM;
			goto err_free_epc_page;
		} else {
			vmret = VM_FAULT_SIGBUS;
			goto err_free_epc_page;
		}
	}

	mutex_lock(&encl->lock);

	/* Insert va_page(if not NULL) to `encl->va_page` first,
	 * since we may invoke free_va_page() if encounter error,
	 * and free_va_page() removes va_page(if not NULL) from `encl->va_page`.
	 */
	if (va_page)
		list_add(&va_page->list, &encl->va_pages);

	err = radix_tree_insert(&encl->page_tree, encl_page->desc >> PAGE_SHIFT,
				encl_page);
	if (err) {
		he_err("encl=0x%px, radix_tree_insert failed, err=%d, index=0x%lx.\n",
		       encl, err, encl_page->desc >> PAGE_SHIFT);
		mutex_unlock(&encl->lock);
		vmret = VM_FAULT_SIGBUS;
		goto err_free_va_page;
	}

	encl->epc_page_cnt++;
	mutex_unlock(&encl->lock);

	hc_page_desc.config_addr = (__u64)&encl->config;
	hc_page_desc.enclave_lin_addr = addr;
	hc_page_desc.epc_page_pa = epc_page->desc;
	hc_page_desc.sec_info = 0;
	err = hypercall_ret_1(HC_ENCL_AUG_PAGE, (unsigned long)&hc_page_desc);
	if (err) {
		he_err("augment page failed, config_addr=0x%px, lin_addr=0x%lx, err=%d.\n",
		       encl, addr, err);
		vmret = VM_FAULT_SIGBUS;
		goto err_del_encl_in_page_tree;
	}

	vmret = vmf_insert_pfn(vma, addr, PFN_DOWN(epc_page->desc));
	if (vmret != VM_FAULT_NOPAGE) {
		he_err("vmf_insert_pfn() failed. config_addr=0x%px, addr=0x%lx, pa=0x%lx, vmret=%d\n",
		       encl, addr, epc_page->desc, vmret);
		vmret = VM_FAULT_SIGBUS;
		goto err_del_encl_in_page_tree;
	}

	mark_page_reclaimable(epc_page);

	return vmret;

err_del_encl_in_page_tree:
	mutex_lock(&encl->lock);
	encl->epc_page_cnt--;
	radix_tree_delete(&encl->page_tree, encl_page->desc >> PAGE_SHIFT);
	mutex_unlock(&encl->lock);
err_free_va_page:
	free_va_page(encl, va_page);
err_free_epc_page:
	free_enclave_page(epc_page);
err_free_encl_page:
	kfree(encl_page);

	return vmret;
}

int he_cmd_edmm_enabled(void __user *arg)
{
	struct he_edmm_enabled params;

	params.flags = (unsigned long)edmm_enabled;
	if (copy_to_user(arg, &params, sizeof(params))) {
		return -EFAULT;
	}

	return 0;
}

static int he_enclave_track(struct he_enclave *encl)
{
	int ret;

	ret = encl_track(encl);
	if (ret) {
		he_err("encl_track() return 0x%x", ret);
		return ret;
	}
	on_each_cpu_mask(mm_cpumask(encl->mm), he_ipi_cb, NULL, 1);

	return 0;
}

static int he_validate_offset_length(struct he_enclave *encl,
				     unsigned long start_address,
				     unsigned long length)
{
	if (!IS_ALIGNED(start_address, PAGE_SIZE))
		return -EINVAL;

	if (!length || !IS_ALIGNED(length, PAGE_SIZE))
		return -EINVAL;

	if (start_address + length > encl->config.start_gva + encl->config.size)
		return -EINVAL;

	return 0;
}

static int emodpr(struct he_enclave *encl, unsigned long addr,
		  struct he_encl_restrict_permissions *modp)
{
	struct hc_encl_modpr_page_desc hc_page_desc;
	int err;

	if (!hyper_enclave_enabled) {
		he_err("please enable hypervisor before restrict enclave's permission\n");
		return -EAGAIN;
	}

	hc_page_desc.config_addr = (__u64)&encl->config;
	hc_page_desc.enclave_lin_addr = addr;
	hc_page_desc.sec_info = modp->permissions;

	mutex_lock(&encl->etrack_lock);
	err = hypercall_ret_1(HC_ENCL_RESTRICT_PERM_PAGE,
			      (unsigned long)&hc_page_desc);

	if (err) {
		he_err("Failed to restrict enclave pages, "
		       "config_address=0x%llx, linear address=0x%llx, err_code=%d\n",
		       encl->config.start_gva, hc_page_desc.enclave_lin_addr,
		       err);
		mutex_unlock(&encl->etrack_lock);
		modp->result = err;
		return -EFAULT;
	}

	err = he_enclave_track(encl);
	if (err) {
		mutex_unlock(&encl->etrack_lock);
		modp->result = err;
		return -EFAULT;
	}

	mutex_unlock(&encl->etrack_lock);
	return 0;
}

static int
he_encl_restrict_permissions(struct he_enclave *encl,
			     struct he_encl_restrict_permissions *modp)
{
	struct encl_page *encl_page;
	unsigned long c;
	unsigned long addr;
	int ret, err;

	for (c = 0; c < modp->length; c += PAGE_SIZE) {
		addr = modp->start_addr + c;

		// `he_encl_load_page()` at following may allocate free EPC for the `encl_page`
		// if its `epc_page` is swapped out of EPC. Such function ensures there are enough
		// free EPC pages for swapped `encl_page`.
		trigger_reclaim();

		mutex_lock(&encl->lock);

		encl_page = he_encl_load_page(encl, addr);
		if (IS_ERR(encl_page)) {
			err = PTR_ERR(encl_page);
			if (err == -EBUSY)
				ret = -EAGAIN;
			else
				ret = -EFAULT;

			goto out_unlock;
		}

		if (encl_page->page_type != HE_SECINFO_REG) {
			he_err("only support restrcit permissions with regular page"
			       "config_address=0x%lx, linear address=0x%lx\n",
			       (unsigned long)encl, addr);
			ret = -EFAULT;
			goto out_unlock;
		}
		if (unmark_page_reclaimable(encl_page->epc_page)) {
			ret = -EBUSY;
			goto out_unlock;
		}

		mutex_unlock(&encl->lock);

		err = emodpr(encl, addr, modp);
		if (err) {
			ret = err;
			goto out_unlock;
		}

		mutex_lock(&encl->lock);
		mark_page_reclaimable(encl_page->epc_page);
		mutex_unlock(&encl->lock);
	}

	ret = 0;
	goto out;

out_unlock:
	mutex_unlock(&encl->lock);
out:
	modp->count = c;

	return ret;
}

int he_cmd_encl_restrict_permissions(void __user *arg)
{
	struct he_enclave *encl;
	struct he_encl_restrict_permissions params;
	int ret;

	if (!edmm_enabled) {
		he_err("please enable EDMM for driver using feature mask\n");
		return -EFAULT;
	}

	if (copy_from_user(&params, arg, sizeof(params)))
		return -EFAULT;

	if (params.permissions & ~HE_SECINFO_PERMISSION_MASK)
		return -EINVAL;

	if ((params.permissions & HE_SECINFO_W) &&
	    !(params.permissions & HE_SECINFO_R))
		return -EINVAL;

	if (params.result || params.count)
		return -EINVAL;

	ret = find_enclave(current->mm, params.start_addr, &encl);
	if (ret) {
		he_err("start_address page does not belong to any existing enclave:"
		       "start_address=0x%llx\n",
		       params.start_addr);
		return ret;
	}

	if (!kref_get_unless_zero(&encl->refcount)) {
		he_err("the refcount of encl(=0x%px) is 0\n", encl);
		return -EFAULT;
	}

	if (he_validate_offset_length(encl, params.start_addr, params.length)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = he_encl_restrict_permissions(encl, &params);

	if (copy_to_user(arg, &params, sizeof(params))) {
		ret = -EFAULT;
		goto err_out;
	}

err_out:
	kref_put(&encl->refcount, he_encl_cleanup);
	return ret;
}

static int emodt(struct he_enclave *encl, unsigned long addr,
		 struct he_encl_modify_types *modt)
{
	struct hc_encl_modt_page_desc hc_page_desc;
	int err;

	if (!hyper_enclave_enabled) {
		he_err("please enable hypervisor before restrict enclave's permission\n");
		return -EAGAIN;
	}

	hc_page_desc.config_addr = (__u64)&encl->config;
	hc_page_desc.enclave_lin_addr = addr;
	hc_page_desc.sec_info = modt->page_type
				<< HE_PAGE_TYPE_SHIFT_IN_SECINFO;

	mutex_lock(&encl->etrack_lock);
	err = hypercall_ret_1(HC_ENCL_MODIFY_PAGE_TYPE,
			      (unsigned long)&hc_page_desc);

	if (err) {
		he_err("Failed to modify enclave pages, "
		       "config_address=0x%llx, linear address=0x%llx, err_code=%d\n",
		       encl->config.start_gva, hc_page_desc.enclave_lin_addr,
		       err);
		mutex_unlock(&encl->etrack_lock);
		modt->result = err;
		return -EFAULT;
	}

	err = he_enclave_track(encl);
	if (err) {
		mutex_unlock(&encl->etrack_lock);
		modt->result = err;
		return -EFAULT;
	}

	mutex_unlock(&encl->etrack_lock);
	return 0;
}

static int he_encl_modify_types(struct he_enclave *encl,
				struct he_encl_modify_types *modt)
{
	struct encl_page *encl_page;
	unsigned long c, addr;
	unsigned long page_type;
	bool reg_to_tcs, reg_to_trim, tcs_to_trim;
	int ret, err;

	page_type = modt->page_type << HE_PAGE_TYPE_SHIFT_IN_SECINFO;

	for (c = 0; c < modt->length; c += PAGE_SIZE) {
		addr = modt->start_addr + c;

		trigger_reclaim();

		mutex_lock(&encl->lock);

		encl_page = he_encl_load_page(encl, addr);
		if (IS_ERR(encl_page)) {
			err = PTR_ERR(encl_page);
			if (err == -EBUSY)
				ret = -EAGAIN;
			else
				ret = -EFAULT;

			goto out_unlock;
		}

		reg_to_tcs = encl_page->page_type == HE_SECINFO_REG &&
			     page_type == HE_SECINFO_TCS;
		reg_to_trim = encl_page->page_type == HE_SECINFO_REG &&
			      page_type == HE_SECINFO_TRIM;
		tcs_to_trim = encl_page->page_type == HE_SECINFO_TCS &&
			      page_type == HE_SECINFO_TRIM;

		if (!reg_to_tcs && !reg_to_trim && !tcs_to_trim) {
			ret = -EINVAL;
			goto out_unlock;
		}

		if (reg_to_tcs || reg_to_trim) {
			if (unmark_page_reclaimable(encl_page->epc_page)) {
				ret = -EBUSY;
				goto out_unlock;
			}
		}
		mutex_unlock(&encl->lock);

		err = emodt(encl, addr, modt);
		if (err) {
			ret = err;
			goto out_unlock;
		}

		mutex_lock(&encl->lock);

		if (tcs_to_trim || reg_to_trim)
			mark_page_reclaimable(encl_page->epc_page);

		encl_page->page_type = page_type;

		mutex_unlock(&encl->lock);
	}

	ret = 0;
	goto out;

out_unlock:
	mutex_unlock(&encl->lock);
out:
	modt->count = c;

	return ret;
}

int he_cmd_encl_modify_types(void __user *arg)
{
	struct he_enclave *encl;
	struct he_encl_modify_types params;
	int ret;

	if (!edmm_enabled) {
		he_err("please enable EDMM for driver using feature mask\n");
		return -EFAULT;
	}

	if (copy_from_user(&params, arg, sizeof(params)))
		return -EFAULT;

	if (params.page_type != HE_PAGE_TYPE_TCS &&
	    params.page_type != HE_PAGE_TYPE_TRIM) {
		he_err("Invalid page_type: %lld\n", params.page_type);
		return -EINVAL;
	}

	if (params.result || params.count)
		return -EINVAL;

	ret = find_enclave(current->mm, params.start_addr, &encl);
	if (ret) {
		he_err("start_address page does not belong to any existing enclave:"
		       "start_address=0x%llx\n",
		       params.start_addr);
		return ret;
	}

	if (!kref_get_unless_zero(&encl->refcount)) {
		he_err("the refcount of encl(=0x%px) is 0\n", encl);
		return -EFAULT;
	}

	if (he_validate_offset_length(encl, params.start_addr, params.length)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = he_encl_modify_types(encl, &params);

	if (copy_to_user(arg, &params, sizeof(params))) {
		ret = -EINVAL;
		goto err_out;
	}

err_out:
	kref_put(&encl->refcount, he_encl_cleanup);
	return ret;
}

static int remove_enclave_page_at_runtime(struct he_enclave *encl,
					  struct encl_page *encl_page)
{
	struct hc_encl_remove_page_at_runtime_desc hc_page_desc;
	int err;

	if (!hyper_enclave_enabled) {
		he_err("please enable hypervisor before restrict enclave's permission\n");
		return -EAGAIN;
	}

	hc_page_desc.config_addr = (__u64)&encl->config;
	hc_page_desc.enclave_lin_addr = encl_page->desc & PAGE_MASK;
	err = hypercall_ret_1(HC_ENCL_REMOVE_AT_RUNTIME,
			      (unsigned long)&hc_page_desc);
	if (err) {
		he_err("Failed to remove enclave pages at runtime, "
		       "encl=0x%px, linear address=0x%llx, err_code=%d\n",
		       encl, hc_page_desc.enclave_lin_addr, err);
		return err;
	}

	free_enclave_page(encl_page->epc_page);
	return 0;
}

static int he_encl_remove_pages(struct he_enclave *encl,
				struct he_encl_remove_pages *params)
{
	struct encl_page *encl_page;
	struct epc_page *epc_page;
	unsigned long c;
	unsigned long addr;
	int ret, err;

	for (c = 0; c < params->length; c += PAGE_SIZE) {
		addr = params->start_addr + c;

		trigger_reclaim();

		mutex_lock(&encl->lock);

		encl_page = he_encl_load_page(encl, addr);
		if (IS_ERR(encl_page)) {
			err = PTR_ERR(encl_page);
			if (err == -EBUSY)
				ret = -EAGAIN;
			else
				ret = -EFAULT;

			goto out_unlock;
		}
		epc_page = encl_page->epc_page;
		if (unmark_page_reclaimable(epc_page)) {
			ret = -EBUSY;
			goto out_unlock;
		}

		/*
		 * Do not keep `encl->lock` because of lock order is
		 * `mmap_lock` -> `encl->lock`.
		 * The `mmap_lock` is acquired in he_zap_enclave_ptes().
		 */
		mutex_unlock(&encl->lock);

		he_zap_enclave_ptes(encl, addr);

		err = remove_enclave_page_at_runtime(encl, encl_page);
		if (err) {
			ret = -EFAULT;
			goto out_unlock;
		}

		mutex_lock(&encl->lock);

		radix_tree_delete(&encl->page_tree,
				  encl_page->desc >> PAGE_SHIFT);
		kfree(encl_page);
		encl->epc_page_cnt--;

		mutex_unlock(&encl->lock);

		free_va_page(encl, NULL);
	}

	ret = 0;
	goto out;

out_unlock:
	mutex_unlock(&encl->lock);
out:
	params->count = c;

	return 0;
}

int he_cmd_encl_remove_pages(void __user *arg)
{
	struct he_enclave *encl;
	struct he_encl_remove_pages params;
	int ret;

	if (!edmm_enabled) {
		he_err("please enable EDMM for driver using feature mask\n");
		return -EFAULT;
	}

	if (copy_from_user(&params, arg, sizeof(params)))
		return -EFAULT;

	if (params.count)
		return -EINVAL;

	ret = find_enclave(current->mm, params.start_addr, &encl);
	if (ret) {
		he_err("start_address page does not belong to any existing enclave: "
		       "start_address=0x%llx\n",
		       params.start_addr);
		return ret;
	}

	if (!kref_get_unless_zero(&encl->refcount)) {
		he_err("the refcount of encl(=0x%px) is 0\n", encl);
		return -EFAULT;
	}

	if (he_validate_offset_length(encl, params.start_addr, params.length)) {
		ret = -EINVAL;
		goto err_out;
	}

	ret = he_encl_remove_pages(encl, &params);

	if (copy_to_user(arg, &params, sizeof(params))) {
		ret = -EFAULT;
		goto err_out;
	}

err_out:
	kref_put(&encl->refcount, he_encl_cleanup);
	return ret;
}
