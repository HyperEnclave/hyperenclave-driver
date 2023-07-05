// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <linux/sched/mm.h>
#include <linux/shmem_fs.h>
#include <linux/version.h>
#include <hyperenclave/hypercall.h>
#include <hyperenclave/log.h>

#include "enclave.h"
#include "feature.h"
#include "main.h"
#include "reclaim.h"
#include "sysfs.h"

LIST_HEAD(epc_free_list);
DEFINE_SPINLOCK(epc_free_list_lock);
unsigned int nr_free_epc_pages;
unsigned int nr_total_epc_pages;

void add_epc_pages(__u64 epc_phys, __u64 epc_size)
{
	unsigned long i = 0;
	struct epc_page *new_epc_page = NULL;

	for (i = 0; i < epc_size; i += PAGE_SIZE) {
		new_epc_page = kzalloc(sizeof(*new_epc_page), GFP_KERNEL);
		if (!new_epc_page) {
			he_err("kzalloc failed\n");
			break;
		}
		new_epc_page->desc = epc_phys + i;
		spin_lock(&epc_free_list_lock);
		list_add_tail(&new_epc_page->list, &epc_free_list);
		nr_free_epc_pages++;
		nr_total_epc_pages++;
		spin_unlock(&epc_free_list_lock);
	}
	he_info("total_epc_pages: 0x%x, free_epc_pages: 0x%x\n",
		nr_total_epc_pages, nr_free_epc_pages);
}

void free_epc_pages(void)
{
	spin_lock(&epc_free_list_lock);
	while (!list_empty(&epc_free_list)) {
		struct epc_page *entry;

		entry = list_first_entry(&epc_free_list, struct epc_page, list);
		list_del(&entry->list);
		kfree(entry);
	}
	spin_unlock(&epc_free_list_lock);
}

/**
 * alloc_enclave_page() - allocate an EPC page from epc_free_list
 *
 * @reclaim: Indicate if trigger direct EPC memory reclaim when allocate an EPC page failed
 */
struct epc_page *alloc_enclave_page(bool reclaim)
{
	struct epc_page *entry;

	for (;;) {
		spin_lock(&epc_free_list_lock);
		if (!list_empty(&epc_free_list)) {
			entry = list_first_entry(&epc_free_list,
						 struct epc_page, list);
			list_del(&entry->list);
			nr_free_epc_pages--;
		}
		spin_unlock(&epc_free_list_lock);

		if (entry) {
			break;
		}

		if (list_empty(&epc_reclaimer_list))
			return ERR_PTR(-ENOMEM);

		if (!reclaim) {
			entry = ERR_PTR(-EBUSY);
			break;
		}

		reclaim_epc_pages();
		cond_resched();
	}

	if (should_reclaim_epc_pages(NR_LOW_EPC_PAGES))
		wake_up(&kheswapd_wq);

	return entry;
}

void free_enclave_page(struct epc_page *epc_page)
{
	WARN_ON_ONCE(epc_page->desc & EPC_PAGE_RECLAIMER_TRACKED);
	epc_page->encl_page = NULL;

	spin_lock(&epc_free_list_lock);
	list_add_tail(&epc_page->list, &epc_free_list);
	nr_free_epc_pages++;
	spin_unlock(&epc_free_list_lock);
}

struct va_page *alloc_va_page(struct he_enclave *encl, bool reclaim)
{
	int err;
	unsigned long config_address, va_paddr;
	struct va_page *va_page;
	struct epc_page *epc_page;

	va_page = NULL;
	mutex_lock(&encl->lock);
	if (encl->page_cnt % VA_SLOT_COUNT) {
		mutex_unlock(&encl->lock);
		goto out;
	}
	mutex_unlock(&encl->lock);

	va_page = kzalloc(sizeof(*va_page), GFP_KERNEL);
	if (!va_page) {
		return ERR_PTR(-ENOMEM);
	}
	epc_page = alloc_enclave_page(reclaim);
	if (IS_ERR(epc_page)) {
		kfree(va_page);
		return ERR_CAST(epc_page);
	}
	va_page->epc_page = epc_page;

	config_address = (unsigned long)&encl->config;
	va_paddr = va_page->epc_page->desc;

	if (!hyper_enclave_enabled) {
		err = -EAGAIN;
		he_err("please enable hypervisor before vmcall\n");
		goto err_cleanup;
	}
	err = hypercall_ret_2(HC_ENCL_ADD_VERSION_ARRAY, config_address,
			      va_paddr);
	if (err) {
		he_err("EPA failed. config_address: 0x%lx, va_paddr: 0x%lx, err: %d\n",
		       config_address, va_paddr, err);
		goto err_cleanup;
	}
	mutex_lock(&encl->lock);
	encl->epc_page_cnt++;
	mutex_unlock(&encl->lock);
	goto out;

err_cleanup:
	free_enclave_page(va_page->epc_page);
	kfree(va_page);
	return ERR_PTR(err);

out:
	mutex_lock(&encl->lock);
	encl->page_cnt++;
	mutex_unlock(&encl->lock);

	return va_page;
}

void free_va_page(struct he_enclave *encl, struct va_page *va_page)
{
	mutex_lock(&encl->lock);
	encl->page_cnt--;
	mutex_unlock(&encl->lock);

	if (va_page) {
		free_enclave_page(va_page->epc_page);

		mutex_lock(&encl->lock);
		list_del(&va_page->list);
		mutex_unlock(&encl->lock);
		kfree(va_page);
	}
}

int find_enclave(struct mm_struct *mm, unsigned long addr,
		 struct he_enclave **encl)
{
	struct vm_area_struct *vma;

	down_read(&mm->mmap_sem);
	vma = find_vma(mm, addr);
	if (!vma || vma->vm_ops != &he_vm_ops || addr < vma->vm_start) {
		up_read(&mm->mmap_sem);
		he_err("find_vma failed\n");
		return -EINVAL;
	}

	*encl = vma->vm_private_data;
	up_read(&mm->mmap_sem);

	return *encl ? 0 : -ENOENT;
}

int he_cmd_encl_create(struct he_encl_create __user *arg)
{
	int err;
	struct he_enclave *encl;
	struct he_encl_create params;
	void __user *user_config;
	struct vm_area_struct *vma;
	struct file *backing;

	err = copy_from_user(&params, arg, sizeof(params));
	if (err) {
		he_err("copy_from_user arg failed\n");
		return -EFAULT;
	}
	user_config = (void __user *)params.config_address;
	encl = kzalloc(sizeof(*encl), GFP_KERNEL);
	if (!encl) {
		he_err("kzalloc failed\n");
		return -ENOMEM;
	} else {
		he_info("encl: 0x%px", encl);
	}
	encl->owner = current;
	err = copy_from_user(&encl->config, user_config, sizeof(encl->config));
	if (err) {
		err = -EFAULT;
		he_err("copy_from_user user_config failed\n");
		goto out_destroy_encl;
	}
	if (!hyper_enclave_enabled) {
		err = -EAGAIN;
		he_err("encl: 0x%px, please enable hypervisor before vmcall\n",
		       encl);
		goto out_destroy_encl;
	}

	/* File backing size consists of total enclave pages's size and PCMD size */
	backing = shmem_file_setup("HE backing",
				   encl->config.size + (encl->config.size / PCMD_COUNT),
				   VM_NORESERVE);
	if (IS_ERR(backing)) {
		err = PTR_ERR(backing);
		he_err("encl: 0x%px, create backing file failed\n", encl);
		goto out_destroy_encl;
	}
	encl->backing = backing;
	INIT_LIST_HEAD(&encl->va_pages);
	INIT_RADIX_TREE(&encl->page_tree, GFP_KERNEL);
	mutex_init(&encl->lock);
	mutex_init(&encl->etrack_lock);
	kref_init(&encl->refcount);
	stats_init(encl);
	/* memory map enclave gva to gpa */
	he_info("encl: 0x%px, encl.start_gva=0x%llx, encl_size: 0x%llx\n", encl,
		encl->config.start_gva, encl->config.size);

	err = hypercall_ret_1(HC_ENCL_CREATE, (unsigned long)&encl->config);
	if (err) {
		he_err("Enclave create error, err=%d\n", err);
		goto out_destroy_backing;
	}

	encl->mm = current->mm;
	down_read(&current->mm->mmap_sem);
	vma = find_vma(current->mm, encl->config.start_gva);
	if (vma) {
		vma->vm_private_data = encl;
		up_read(&current->mm->mmap_sem);
	} else {
		up_read(&current->mm->mmap_sem);
		err = -EINVAL;
		he_err("encl: 0x%px, find_vma failed\n", encl);
		goto out_destroy_backing;
	}

	err = shared_memory_init(encl);
	if (err) {
		he_err("init shared memory failed, err=%d\n", err);
		goto out_destroy_backing;
	}

	return err;

out_destroy_backing:
	fput(encl->backing);
	encl->backing = NULL;
out_destroy_encl:
	kfree(encl);

	return err;
}

int he_cmd_encl_add_page(struct he_encl_add_page __user *arg)
{
	struct he_encl_add_page eap;
	struct he_enclave *encl;
	struct hc_encl_new_page_desc page_desc;
	unsigned long source_address;
	unsigned long enclave_lin_addr;
	int err;
	unsigned long epc_page_pa;
	struct epc_page *epc_entry = NULL;
	void *data;
	struct page *data_page;
	struct encl_page *encl_page;
	unsigned long source_page_k_pa;
	struct vm_area_struct *vma;
	unsigned long sec_info;
	struct va_page *va_page;

	err = copy_from_user(&eap, arg, sizeof(eap));
	if (err) {
		he_err("copy_from_user arg failed\n");
		return -EFAULT;
	}
	source_address = (unsigned long)eap.source_address;
	enclave_lin_addr = (unsigned long)eap.enclave_lin_addr;
	sec_info = eap.flags;
	/*
	 * A simple sanity check to make sure the page being added belongs to
	 * the calling process's address space.
	 * TODO: Should we also verify the mapping flags (arg->flags)? E.g.,
	 * should we allow the process to map a read-only page as writable in
	 * enclave mode?
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
	if (!access_ok((void __user *)source_address, PAGE_SIZE)) {
#else
	/*
	 * Note that the first parameter of access_ok() (i.e. access type) is
	 * actually ignored by the kernel, and has been removed from the latest
	 * (5.x) kernel code. Here VERIFY_READ is just an arbitrary value.
	 */
	if (!access_ok(VERIFY_READ, (void __user *)source_address, PAGE_SIZE)) {
#endif
		he_err("Source page is located in kernel space:"
		       " source_address=0x%lx\n",
		       source_address);
		return -EFAULT;
	}

	err = find_enclave(current->mm, enclave_lin_addr, &encl);
	if (err) {
		he_err("Source page does not belong to any existing enclave:"
		       " enclave_lin_addr=0x%lx\n",
		       enclave_lin_addr);
		return -ENOENT;
	}

	/*
	 * FIXME: should learn from sgx driver to manage free EPC page pool
	 * offset = enclave_lin_addr - encl->config.start_gva;
	 * epc_page_pa = g_epc_base_gpa + offset;
	 */
	epc_entry = alloc_enclave_page(true);
	if (IS_ERR(epc_entry)) {
		he_err("encl: 0x%px, allocate enclave page failed. nr_free_epc_pages: %u\n",
		       encl, nr_free_epc_pages);
		return PTR_ERR(epc_entry);
	}

	va_page = alloc_va_page(encl, true);
	if (IS_ERR(va_page)) {
		err = PTR_ERR(va_page);
		goto err_free_epc_page;
	}

	if (va_page) {
		mutex_lock(&encl->lock);
		list_add(&va_page->list, &encl->va_pages);
		mutex_unlock(&encl->lock);
	}

	down_read(&current->mm->mmap_sem);
	vma = find_vma(current->mm, enclave_lin_addr);
	if (!vma || vma->vm_ops != &he_vm_ops ||
	    enclave_lin_addr < vma->vm_start) {
		up_read(&current->mm->mmap_sem);
		he_err("encl: 0x%px, find_vma failed\n", encl);
		err = -EINVAL;
		goto err_free_va_page;
	}

	epc_page_pa = epc_entry->desc;
	err = vmf_insert_pfn(vma, enclave_lin_addr, PFN_DOWN(epc_page_pa));
	up_read(&current->mm->mmap_sem);
	if (err != VM_FAULT_NOPAGE) {
		he_err("encl: 0x%px, insert_pfn failed\n", encl);
		goto err_free_va_page;
	}

	encl_page = kzalloc(sizeof(*encl_page), GFP_KERNEL);
	if (!encl_page) {
		err = -ENOMEM;
		he_err("encl: 0x%px, kzalloc encl_page failed\n", encl);
		goto err_free_va_page;
	}
	encl_page->desc = enclave_lin_addr;
	encl_page->page_type = sec_info & HE_SECINFO_PERMISSION_PAGE_TYPE_MASK;
	encl_page->epc_page = epc_entry;
	encl_page->encl = encl;
	epc_entry->encl_page = encl_page;

	mutex_lock(&encl->lock);
	encl->epc_page_cnt++;
	if (radix_tree_lookup(&encl->page_tree,
			      encl_page->desc >> PAGE_SHIFT)) {
		err = -EEXIST;
		mutex_unlock(&encl->lock);
		he_err("encl: 0x%px, item exist, failed\n", encl);
		goto err_free_encl_page;
	}
	err = radix_tree_insert(&encl->page_tree, encl_page->desc >> PAGE_SHIFT,
				encl_page);
	mutex_unlock(&encl->lock);
	if (err) {
		he_err("encl: 0x%px, radix_tree_insert failed\n", encl);
		goto err_free_encl_page;
	}

	data_page = alloc_page(GFP_HIGHUSER);
	if (!data_page) {
		err = -ENOMEM;
		he_err("encl: 0x%px, alloc_page\n", encl);
		goto err_del_node;
	}

	data = kmap(data_page);
	err = copy_from_user(data, (void __user *)source_address, PAGE_SIZE);
	if (err) {
		he_err("copy_from_user source_address failed\n");
		err = -EFAULT;
		goto err_free_data_page;
	}
	source_page_k_pa = __pa(data);

	page_desc.config_address = (unsigned long)&encl->config;
	page_desc.source_address = source_page_k_pa;
	page_desc.enclave_lin_addr = enclave_lin_addr;
	page_desc.epc_page_pa = epc_page_pa;
	page_desc.metadata = (unsigned long)&sec_info;
	page_desc.attr = eap.attr;
	if (!hyper_enclave_enabled) {
		he_err("please enable hypervisor before vmcall\n");
		err = -EAGAIN;
		goto err_free_data_page;
	}

	err = hypercall_ret_1(HC_ENCL_ADD_PAGE, (unsigned long)&page_desc);
	if (err)
		goto err_free_data_page;

	if (encl_page->page_type != HE_SECINFO_TCS) {
		mark_page_reclaimable(epc_entry);
	}

	kunmap(data_page);
	__free_page(data_page);
	return err;

err_free_data_page:
	kunmap(data_page);
	__free_page(data_page);
err_del_node:
	mutex_lock(&encl->lock);
	radix_tree_delete(&encl->page_tree, encl_page->desc >> PAGE_SHIFT);
	mutex_unlock(&encl->lock);
err_free_encl_page:
	kfree(encl_page);
	mutex_lock(&encl->lock);
	encl->epc_page_cnt--;
	mutex_unlock(&encl->lock);
err_free_va_page:
	free_va_page(encl, va_page);
err_free_epc_page:
	free_enclave_page(epc_entry);

	return err;
}

int he_cmd_encl_init(struct he_encl_init __user *arg)
{
	struct he_encl_init einit;
	struct hc_encl_init_desc einit_desc;
	struct he_sigstruct *sigstruct;
	struct page *initp_page;
	struct he_enclave *encl;
	unsigned long source_address;
	int ret;

	ret = copy_from_user(&einit, arg, sizeof(einit));
	if (ret) {
		he_err("copy_from_user failed\n");
		return -EINVAL;
	}

	initp_page = alloc_page(GFP_KERNEL);
	if (!initp_page)
		return -ENOMEM;

	sigstruct = kmap(initp_page);
	if (copy_from_user(sigstruct, (void __user *)einit.sigstruct,
			   sizeof(*sigstruct))) {
		ret = -EFAULT;
		goto out;
	}

	// secs.base
	source_address = einit.addr;
	ret = find_enclave(current->mm, source_address, &encl);
	if (ret) {
		he_err("source page does not belong to any existing enclave:"
		       "source_address :0x%lx\n",
		       source_address);
		ret = -EINVAL;
		goto out;
	}
	einit_desc.config_address = (unsigned long)&encl->config;
	einit_desc.sigstruct = (unsigned long)sigstruct;
	ret = hypercall_ret_1(HC_ENCL_INIT, (unsigned long)&einit_desc);

out:
	kunmap(initp_page);
	__free_page(initp_page);
	return ret;
}

static int he_pin_pages(unsigned long addr, int nr_pages, struct page **pages)
{
	int npages;

	npages = get_user_pages_unlocked(addr, nr_pages, pages, FOLL_WRITE);
	if (npages > 0 && npages < nr_pages) {
		while (npages--)
			put_page(pages[npages]);
		return -EFAULT;
	} else if (npages == 0) {
		return -EFAULT;
	}

	return 0;
}

static void he_unpin_pages(struct pinned_memory_area *pma)
{
	while (pma->nr_pages--) {
		if (!pma->pages[pma->nr_pages]) {
			he_err("NULL page, nr_pages: %d\n", pma->nr_pages);
			dump_stack();
			continue;
		}
		put_page(pma->pages[pma->nr_pages]);
	}
}

int he_cmd_pin_memory(struct he_memory_info __user *arg)
{
	int err;
	unsigned long pin_addr, pin_size, encl_addr;
	struct he_memory_info hmi;
	struct he_enclave *encl;
	struct pinned_memory_area *pma;

	err = copy_from_user(&hmi, arg, sizeof(hmi));
	if (err) {
		he_err("copy_from_user failed\n");
		return -EFAULT;
	}
	pin_addr = hmi.start_addr;
	pin_size = hmi.size;
	encl_addr = hmi.encl_addr;
	he_info("pin_addr: 0x%lx, pin_size: 0x%lx, encl_addr: 0x%lx\n",
		pin_addr, pin_size, encl_addr);
	if (pin_addr & ~PAGE_MASK || !pin_size)
		return -EINVAL;

	err = find_enclave(current->mm, encl_addr, &encl);
	if (err) {
		he_err("Source page does not belong to any existing enclave:"
		       " addr=0x%lx\n",
		       encl_addr);
		return err;
	}

	pma = kzalloc(sizeof(*pma), GFP_KERNEL);
	if (!pma)
		return -ENOMEM;
	pma->addr = pin_addr;
	pma->nr_pages = PAGE_ALIGN(pin_size) >> PAGE_SHIFT;
	pma->pages = kvcalloc(pma->nr_pages, sizeof(char *), GFP_KERNEL);
	if (!pma->pages) {
		err = -ENOMEM;
		goto err_free_pma;
	}

	mutex_lock(&encl->lock);
	if (encl->pma) {
		mutex_unlock(&encl->lock);
		he_err("encl 0x%px has pinned address 0x%lx\n", encl,
		       encl->pma->addr);
		err = -EEXIST;
		goto err_free_pages;
	}
	encl->pma = pma;
	mutex_unlock(&encl->lock);

	err = he_pin_pages(pma->addr, pma->nr_pages, pma->pages);
	if (err) {
		he_err("pin pages failed\n");
		goto err_encl_cleanup;
	}

	return err;

err_encl_cleanup:
	mutex_lock(&encl->lock);
	encl->pma = NULL;
	mutex_unlock(&encl->lock);
err_free_pages:
	kvfree(pma->pages);
err_free_pma:
	kfree(pma);

	return err;
}

int he_cmd_unpin_memory(struct he_memory_info __user *arg)
{
	int err;
	unsigned long pin_addr, encl_addr;
	struct he_memory_info hmi;
	struct he_enclave *encl;
	struct pinned_memory_area *pma;

	err = copy_from_user(&hmi, arg, sizeof(hmi));
	if (err) {
		he_err("copy_from_user failed\n");
		return -EFAULT;
	}
	pin_addr = hmi.start_addr;
	encl_addr = hmi.encl_addr;
	he_info("unpin_addr: 0x%lx, encl_addr: 0x%lx\n", pin_addr, encl_addr);
	if (pin_addr & ~PAGE_MASK)
		return -EINVAL;

	err = find_enclave(current->mm, encl_addr, &encl);
	if (err) {
		he_err("Source page does not belong to any existing enclave:"
		       " addr=0x%lx\n",
		       encl_addr);
		return err;
	}

	mutex_lock(&encl->lock);
	if (!encl->pma || encl->pma->addr != pin_addr) {
		mutex_unlock(&encl->lock);
		he_err("addr 0x%lx not pinned. encl: 0x%px\n", pin_addr, encl);
		return -EFAULT;
	}
	pma = encl->pma;
	mutex_unlock(&encl->lock);

	he_unpin_pages(pma);
	mutex_lock(&encl->lock);
	encl->pma = NULL;
	mutex_unlock(&encl->lock);
	kvfree(pma->pages);
	kfree(pma);

	return err;
}

int he_cmd_encl_reset_stats(struct he_encl_reset_stats __user *arg)
{
	struct he_encl_reset_stats ers;
	struct he_enclave *encl;
	unsigned long secs_base, config_address;
	int err;

	if (!stats_level)
		return 0;

	err = copy_from_user(&ers, arg, sizeof(ers));
	if (err) {
		he_err("copy_from_user failed\n");
		return -EINVAL;
	}
	secs_base = ers.elrange_base_addr;
	err = find_enclave(current->mm, secs_base, &encl);
	if (err) {
		he_err("secs_base 0x%lx does not belong to any existing enclave",
		       secs_base);
		return err;
	}

	config_address = (unsigned long)&encl->config;
	if (!hyper_enclave_enabled) {
		he_err("please enable hypervisor before vmcall\n");
		return -EAGAIN;
	}
	err = hypercall_ret_1(HC_ENCL_RESET_STATS, config_address);
	if (err) {
		he_err("encl: 0x%px. Failed to reset enclave stats:"
		       " err=%d\n",
		       encl, err);
		return err;
	}

	encl_reset_stats(encl);

	return 0;
}

/**
 * __remove_pages_at_destroy() - Remove EPC pages in batch at enclave's destroy.
 * and then free the `epc_page` the removed pages.
 *
 * @encl:		The owner the pages need to be removed.
 * @batch_size:		The size of the pages to be removed.
 * @remove_desc:	The descriptor recording the physical address of every pages.
 * 			Hypervisor stops removing pages at `i` when `pages_desc_gva->physaddr[i] = 0`.
 * 			It is cleared at the end of this function.
 * @remove_ret:		The descriptor for hypervisor to write the return value of every removed page.
 * 			It is cleared at the end of this function.
 * @epc_page_array:	The array recording `struct epc_page *` for every pages need to be removed.
 * 			This function free the it at the end.
 * 			It is cleared at the end of this function.
 *
 * Context: To speed up page removing at enlave's destroy, callers need to preallocate memory for `remove_ret`.
 * So `__remove_pages_at_destroy()` does not need to allocate memory for `remove_ret` at its every invocation.
 */
static void __remove_pages_at_destroy(
	struct he_enclave *encl,
	struct hc_encl_remove_pages_at_destroy_page_array *remove_page_array,
	struct hc_encl_remove_pages_at_destroy_res_array *res_array,
	struct epc_page **epc_page_array, int batch_size)
{
	struct hc_encl_remove_pages_at_destroy_desc remove_desc;
	int err, i;

	WARN_ON_ONCE(batch_size > REMOVE_PAGES_MAX_BATCH);
	memset(res_array, 0, batch_size * sizeof(__u64));

	remove_desc.config_address = (unsigned long)&encl->config;
	remove_desc.page_array_addr = (unsigned long)remove_page_array;
	remove_desc.res_array_addr = (unsigned long)res_array;
	remove_desc.batch_size = (unsigned long)batch_size;
	err = hypercall_ret_1(HC_ENCL_REMOVE_PAGES_AT_DESTROY,
			      (unsigned long)&remove_desc);
	if (err) {
		he_err("Failed to remove enclave pages at enclave's destroy, "
		       "config_address=0x%lx, batch_size=%d, err: %d\n",
		       (unsigned long)&encl->config, batch_size, err);
	}

	for (i = 0; i < batch_size; i++) {
		err = res_array->val[i];
		if (err == 0) {
			encl->epc_page_cnt--;
			free_enclave_page(epc_page_array[i]);
		} else {
			he_err("Failed to remove pages at enclave's destroy, "
			       "config_address=0x%lx, phys_addr: 0x%llx, err: %d\n",
			       (unsigned long)&encl->config,
			       remove_page_array->physaddr[i], err);
		}

		remove_page_array->physaddr[i] = 0;
		res_array->val[i] = 0;
		epc_page_array[i] = NULL;
	}
}

/**
 * encl_remove_pages_at_destroy() - Remove all the EPC pages, and free all the
 * 	enclave's resources related to enclave pages.
 *
 * @encl: The enclave.
 *
 * Context: Enclave mutex (&enc->lock) must be held.
 */
static void encl_remove_pages_at_destroy(struct he_enclave *encl)
{
	int num;
	struct radix_tree_iter iter;
	void **slot;
	struct encl_page *encl_page;
	struct va_page *va_page;
	struct epc_page **epc_page_array;
	struct hc_encl_remove_pages_at_destroy_page_array *remove_page_array;
	struct hc_encl_remove_pages_at_destroy_res_array *res_array;

	remove_page_array = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!remove_page_array) {
		he_err("Allocate memory for remove_page_array failed\n");
		return;
	}

	res_array = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!res_array) {
		he_err("Allocate memory for res_array failed.\n");
		goto err_free_remove_page_array;
	}

	epc_page_array = kzalloc(
		sizeof(struct epc_page *) * REMOVE_PAGES_MAX_BATCH, GFP_KERNEL);
	if (!epc_page_array) {
		he_err("Allocate memory for epc_page_array failed\n");
		goto err_free_res_array;
	}

	num = 0;
	// Remove regular page
	radix_tree_for_each_slot(slot, &encl->page_tree, &iter, 0) {
		encl_page = *slot;
		radix_tree_delete(&encl->page_tree,
				  encl_page->desc >> PAGE_SHIFT);

		if (encl_page->epc_page) {
			if (encl_page->page_type != HE_PAGE_TYPE_TCS) {
				if (unmark_page_reclaimable(
					    encl_page->epc_page) == -EBUSY) {
					he_err("Bug, "
					       "EPC cannot be in EPC and be held by reclaimer simultaneously when cleanup, pa=0x%lx\n",
					       encl_page->epc_page->desc &
						       PAGE_MASK);
				}
			}

			epc_page_array[num] = encl_page->epc_page;
			remove_page_array->physaddr[num++] =
				encl_page->epc_page->desc;
			if (num == REMOVE_PAGES_MAX_BATCH) {
				__remove_pages_at_destroy(encl,
							  remove_page_array,
							  res_array,
							  epc_page_array, num);
				num = 0;
			}

			encl_page->epc_page = NULL;
		}
		encl_put_backing(encl_page);
		kfree(encl_page);
	}

	// Remove VA page
	while (!list_empty(&encl->va_pages)) {
		va_page =
			list_first_entry(&encl->va_pages, struct va_page, list);
		list_del(&va_page->list);
		if (!va_page->epc_page) {
			he_err("Driver do not reclaim va_page\n");
			kfree(va_page);
			continue;
		}

		epc_page_array[num] = va_page->epc_page;
		remove_page_array->physaddr[num++] = va_page->epc_page->desc;
		if (num == REMOVE_PAGES_MAX_BATCH) {
			__remove_pages_at_destroy(encl, remove_page_array,
						  res_array, epc_page_array,
						  num);
			num = 0;
		}

		kfree(va_page);
	}
	if (num) {
		__remove_pages_at_destroy(encl, remove_page_array, res_array,
					  epc_page_array, num);
		num = 0;
	}

	kfree(epc_page_array);
err_free_res_array:
	kfree(res_array);
err_free_remove_page_array:
	kfree(remove_page_array);
}

static void encl_remove_shmem_at_destroy(struct he_enclave *encl)
{
	// Unpin pma
	if (shmem_pinned && encl->pma) {
		he_info("unpin_addr: 0x%lx, encl: 0x%px\n", encl->pma->addr,
			encl);
		he_unpin_pages(encl->pma);
		kvfree(encl->pma->pages);
		kfree(encl->pma);
		encl->pma = NULL;
	}

	shared_memory_destroy(encl);
}

/*
 * Used together with kref_put(), free the encl resources and the
 * instance itself.
 */
void he_encl_cleanup(struct kref *ref)
{
	int err;
	unsigned long config_address;
	struct he_enclave *encl;

	encl = container_of(ref, struct he_enclave, refcount);
	config_address = (unsigned long)&encl->config;
	if (!hyper_enclave_enabled) {
		he_err("Please enable hypervisor before vmcall\n");
		return;
	}

	if (!encl) {
		he_err("encl is not valid\n");
		return;
	}

	mutex_lock(&encl->lock);
	err = hypercall_ret_1(HC_ENCL_PREPARE_DESTROY, config_address);
	if (err == -ENCLAVE_ACT) {
		he_warn("Still exist threads executing in enclave mode.\n");

		on_each_cpu_mask(mm_cpumask(encl->mm), he_ipi_cb, NULL, 1);
		err = hypercall_ret_1(HC_ENCL_PREPARE_DESTROY, config_address);
		if (err == -ENCLAVE_ACT) {
			he_warn("Still exist threads executing in enclave mode after sending IPI.\n");
			err = -EBUSY;
		}
	}

	if (err) {
		he_err("Failed to prepare enclave's destroy:"
		       " encl=0x%px, config_address=0x%lx err=%d\n",
		       encl, config_address, err);
		encl_remove_shmem_at_destroy(encl);
		mutex_unlock(&encl->lock);
		return;
	}

	encl_remove_shmem_at_destroy(encl);
	encl_remove_pages_at_destroy(encl);

	if (encl->epc_page_cnt != 0) {
		he_err("epc_page_cnt=%d, not zero, try to destroy enclave\n",
		       encl->epc_page_cnt);
	}
	err = hypercall_ret_1(HC_ENCL_FINISH_DESTROY, config_address);
	if (err) {
		he_err("Failed to finish destroy enclave:"
		       " encl=0x%px. config_address=0x%lx err=%d\n",
		       encl, config_address, err);
		mutex_unlock(&encl->lock);
		return;
	}
	mutex_unlock(&encl->lock);

	if (encl->backing)
		fput(encl->backing);

	he_info("nr_free_epc_page: 0x%x, encl: 0x%px\n", nr_free_epc_pages,
		encl);

	print_stats(encl);
	kfree(encl);
}

/**
 * he_encl_load_page_stat() - Load the enclave page from main memory into EPC, and record the timestamp
 *
 * @encl:	Target enclave
 * @addr:	The linear address specifies the enclave page
 *
 * Return the `encl_page` specified by `addr`.
 * - If its `epc_page` lays in the EPC, return `encl_page` directly.
 * - If its `epc_page` is being loaded or written back by other threads, return -EBUSY.
 * - Otherwise (its `epc_page` has been swapped out of EPC), such function allocates a free EPC page from EPC pool,
 *   then loads the content from regular main memory.
 *
 * Context: Enclave mutex (&enc->lock) must be held at its invocation and return. 
 */
static struct encl_page *he_encl_load_page_stat(struct he_enclave *encl,
						unsigned long addr,
						cycles_t *time_pre_load_ptr)
{
	struct encl_page *encl_page;
	struct epc_page *epc_page;
	unsigned long va_offset;
	cycles_t time_pre_load;
	int err;

	encl_page = radix_tree_lookup(&encl->page_tree, addr >> PAGE_SHIFT);
	if (!encl_page) {
		he_err("Cannot get the encl_page entry for address: 0x%lx\n",
		       addr);
		return ERR_PTR(-EFAULT);
	}

	if (encl_page->epc_page) {
		/* Check whether the page is in the process of reclaim,
		 * or whether another thread has arrived here first to loading EPC from main memory. */
		if ((encl_page->desc & ENCL_PAGE_STATUS_MASK) ==
			    ENCL_PAGE_BEING_RECLAIMED ||
		    (encl_page->desc & ENCL_PAGE_STATUS_MASK) ==
			    ENCL_PAGE_BEING_LOADED)
			return ERR_PTR(-EBUSY);

		return encl_page;
	}

	/* The epc_page is swapped out of EPC */
	epc_page = alloc_enclave_page(false);
	if (IS_ERR(epc_page))
		return ERR_CAST(epc_page);

	encl_page->epc_page = epc_page;
	set_encl_page_status(encl_page, ENCL_PAGE_BEING_LOADED);
	epc_page->encl_page = encl_page;
	mutex_unlock(&encl->lock);
	time_pre_load = stats_get_cycles(STATS_PF_HANDLER_PRE);

	err = encl_load_unblocked(encl_page, epc_page);
	if (err) {
		he_err("encl_load_unblocked(), addr=0x%lx\n",
		       encl_page->desc & PAGE_MASK);
		mutex_lock(&encl->lock);
		free_enclave_page(epc_page);
		encl_page->epc_page = NULL;
		set_encl_page_status(encl_page, ENCL_PAGE_UNMANIPULATED);
		return ERR_PTR(err);
	}

	mutex_lock(&encl->lock);

	va_offset = encl_page->desc & ENCL_PAGE_VA_OFFSET_MASK;
	free_va_slot(encl_page->va_page, va_offset);
	list_move(&encl_page->va_page->list, &encl->va_pages);

	set_encl_page_va_offset(encl_page, 0);
	set_encl_page_status(encl_page, ENCL_PAGE_UNMANIPULATED);

	encl_put_backing(encl_page);
	encl->epc_page_cnt++;

	mark_page_reclaimable(epc_page);

	if (time_pre_load_ptr)
		*time_pre_load_ptr = time_pre_load;
	return encl_page;
}

struct encl_page *he_encl_load_page_in_pf_handler(struct he_enclave *encl,
						  unsigned long addr,
						  cycles_t *time_pre_load_ptr)
{
	return he_encl_load_page_stat(encl, addr, time_pre_load_ptr);
}

struct encl_page *he_encl_load_page(struct he_enclave *encl, unsigned long addr)
{
	return he_encl_load_page_stat(encl, addr, NULL);
}

/**
 * he_zap_enclave_ptes() - Remove PTE mapping the address from address
 *
 * @encl: The enclave
 * @addr: Page aligned pointer to the signle page whose PTE needs to be removed
 */
void he_zap_enclave_ptes(struct he_enclave *encl, unsigned long addr)
{
	struct vm_area_struct *vma;

	/*
	 * If u-RTS munmap enclave address space failed, which will
	 * be freed by exit. In this case, to make sure the mm_struct
	 * doesn't go away when exit, use mmget_not_zero() to pin the
	 * address space to avoid the use-after-free of vma.
	 * Here is the detailed scenario:
	 *
	 * exit			reclaimer/EDMM handler
	 *
	 * exit_mmap
	 *     			write_back_page/remove_page_at_runtime/...
	 *     			    vma1 = find_vma
	 *     remove_vma1
	 *     			    zap_vma_ptes(vma1) // vma1 use-after-free
	 *     remove_vma2
	 *
	 *     ...
	 *     remove_vma_n
	 *         desroy enclave
	 */
	if (!mmget_not_zero(encl->mm)) {
		return;
	}

	down_read(&encl->mm->mmap_sem);
	vma = find_vma(encl->mm, addr);
	if (vma && encl == vma->vm_private_data) {
		zap_vma_ptes(vma, addr, PAGE_SIZE);
	}
	up_read(&encl->mm->mmap_sem);
	mmput_async_sym(encl->mm);
}

int encl_track(struct he_enclave *encl)
{
	unsigned long config_address;

	config_address = (unsigned long)&encl->config;

	if (!hyper_enclave_enabled) {
		he_err("please enable hypervisor before vmcall\n");
		return -EAGAIN;
	}

	return hypercall_ret_1(HC_ENCL_TRACK, config_address);
}
