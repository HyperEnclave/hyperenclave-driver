// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <linux/freezer.h>
#include <linux/shmem_fs.h>

#include <hyperenclave/hypercall.h>
#include <hyperenclave/log.h>

#include "main.h"
#include "stats.h"
#include "reclaim.h"

static struct task_struct *kheswapd_tsk;

DECLARE_WAIT_QUEUE_HEAD(kheswapd_wq);
LIST_HEAD(epc_reclaimer_list);
DEFINE_SPINLOCK(reclaimer_list_lock); /* Protect epc_reclaimer_list. */

#ifdef DEBUG
static void print_reclaimer_page_desc(struct reclaimer_page_desc *pages_desc)
{
	int i;

	for (i = 0; i < NR_RECLAIM_EPC_PAGES; i++) {
		if (pages_desc[i].encl_addr) {
			he_info("pages_desc[%d]. gva: 0x%lx, encl_addr: 0x%lx, valid: %u",
				i, pages_desc[i].gva, pages_desc[i].encl_addr,
				(unsigned int)pages_desc[i].valid);
		} else {
			break;
		}
	}
}

static void print_backing(struct reclaimer_backing *backing)
{
	u8 *cv, *pv_raw, *pv;

	cv = (u8 *)kmap_atomic(backing->contents);
	he_info("contents: %x %x %x %x %x %x %x %x\n", cv[0], cv[1], cv[2],
		cv[3], cv[4], cv[5], cv[6], cv[7]);

	pv_raw = (u8 *)((unsigned long)kmap_atomic(backing->pcmd) +
			backing->pcmd_offset);
	pv = pv_raw + 16;
	he_info("pcmd mac: %x %x %x %x %x %x %x %x\n", pv[0], pv[1], pv[2],
		pv[3], pv[4], pv[5], pv[6], pv[7]);

	kunmap_atomic(cv);
	kunmap_atomic(pv_raw);
}
#else
static void print_reclaimer_page_desc(struct reclaimer_page_desc *pages_desc)
{
}

static void print_backing(struct reclaimer_backing *backing)
{
}
#endif

static int kheswapd(void *p)
{
	set_freezable();
	while (!kthread_should_stop()) {
		wait_event_freezable(
			kheswapd_wq,
			kthread_should_stop() ||
				should_reclaim_epc_pages(NR_HIGH_EPC_PAGES));

		if (should_reclaim_epc_pages(NR_HIGH_EPC_PAGES)) {
			reclaim_epc_pages();
		}

		cond_resched();
	}

	return 0;
}

/* Create the kthread "kheswapd", which used to do the background reclaim. */
bool enable_epc_reclaimer(void)
{
	kheswapd_tsk = kthread_run(kheswapd, NULL, "kheswapd");
	if (IS_ERR(kheswapd_tsk))
		return false;

	return true;
}

/* Stop kthread "kheswapd". */
void disable_epc_reclaimer(void)
{
	kthread_stop(kheswapd_tsk);
}

/* Check if need to wake up kthread "kheswapd" or do reclaim_epc_pages. */
bool should_reclaim_epc_pages(unsigned int pages)
{
	return nr_free_epc_pages < pages && !list_empty(&epc_reclaimer_list);
}

/* Allocate a VA slot from a va_page. */
unsigned int alloc_va_slot(struct va_page *va_page)
{
	int slot = find_first_zero_bit(va_page->slots, VA_SLOT_COUNT);

	WARN_ON(slot >= VA_SLOT_COUNT);
	set_bit(slot, va_page->slots);

	return slot << 3;
}

/* Free a VA slot to va_page. */
void free_va_slot(struct va_page *va_page, unsigned int offset)
{
	clear_bit(offset >> 3, va_page->slots);
}

/* Check if a va_page is full. */
bool is_va_page_full(struct va_page *va_page)
{
	int slot = find_first_zero_bit(va_page->slots, VA_SLOT_COUNT);

	return slot == VA_SLOT_COUNT;
}

/* Mark a page in EPC as Blocked state. */
static int encl_block(struct epc_page *epc_page)
{
	int err;
	struct he_enclave *encl;
	struct hc_encl_new_page_desc page_desc;

	encl = epc_page->encl_page->encl;
	page_desc.enclave_lin_addr = epc_page->encl_page->desc & PAGE_MASK;
	page_desc.epc_page_pa = epc_page->desc & PAGE_MASK;
	page_desc.config_address = (unsigned long)&encl->config;

	if (!hyper_enclave_enabled) {
		he_err("please enable hypervisor before vmcall\n");
		return -EAGAIN;
	}

	mutex_lock(&encl->etrack_lock);
	err = hypercall_ret_1(HC_ENCL_BLOCK, (unsigned long)&page_desc);
	mutex_unlock(&encl->etrack_lock);
	if (err) {
		he_debug("eblock failed. va: %lx, pa: %lx\n",
			 epc_page->encl_page->desc & PAGE_MASK,
			 epc_page->desc & PAGE_MASK);
		return err;
	}

	return 0;
}

/* Reclaim an EPC Page and Write out to Main Memory. */
static int encl_write_back(struct hc_encl_new_page_desc *page_desc,
			   unsigned long va_slot_pa)
{
	if (!hyper_enclave_enabled) {
		he_err("please enable hypervisor before vmcall\n");
		return -EAGAIN;
	}

	return hypercall_ret_2(HC_ENCL_WRITE_BACK, (unsigned long)page_desc,
			       va_slot_pa);
}

static int write_back_page(struct epc_page *epc_page)
{
	int err;
	unsigned long contents_va;
	unsigned int va_offset;
	unsigned long va_slot_pa;
	struct he_enclave *encl;
	struct encl_page *encl_page;
	struct hc_encl_new_page_desc page_desc;
	struct va_page *va_page;
	struct reclaimer_backing *backing;
	cycles_t time_s, time_get_lock, time_main, time_unmap_s, time_unmap_e;

	encl_page = epc_page->encl_page;
	encl = encl_page->encl;
	backing = encl_page->backing;
	contents_va = (unsigned long)kmap_atomic(backing->contents);
	page_desc.config_address = (unsigned long)&encl->config;
	page_desc.source_address = __pa(contents_va);
	page_desc.enclave_lin_addr = encl_page->desc & PAGE_MASK;
	page_desc.epc_page_pa = epc_page->desc & PAGE_MASK;
	page_desc.metadata = (unsigned long)kmap_atomic(backing->pcmd) +
			     backing->pcmd_offset;

	mutex_lock(&encl->lock);
	va_page = list_first_entry(&encl->va_pages, struct va_page, list);
	va_offset = alloc_va_slot(va_page);
	va_slot_pa = va_page->epc_page->desc + va_offset;
	if (is_va_page_full(va_page)) {
		list_move_tail(&va_page->list, &encl->va_pages);
	}
	stats_ewb_try_inc(encl, 1);
	mutex_unlock(&encl->lock);

	time_s = stats_get_cycles(STATS_WRITE_BACK_PAGE_GET_LOCK);
	mutex_lock(&encl->etrack_lock);
	time_get_lock = stats_get_cycles(STATS_WRITE_BACK_PAGE_GET_LOCK);
	err = encl_write_back(&page_desc, va_slot_pa);
	if (err == -NOT_TRACKED) {
		cycles_t time_track_s, time_track_e;

		he_debug("direct ewb failed. vaddr: 0x%lx, pa: 0x%lx\n",
			 encl_page->desc & PAGE_MASK,
			 epc_page->desc & PAGE_MASK);
		time_track_s = stats_get_cycles(STATS_TRACK);
		err = encl_track(encl);
		if (err) {
			he_debug("etrack failed. encl: %px\n", encl);
		}
		time_track_e = stats_get_cycles(STATS_TRACK);
		stats_add(encl, STATS_TRACK, time_track_e - time_track_s);

		stats_ewb_try_inc(encl, 2);
		err = encl_write_back(&page_desc, va_slot_pa);
		if (err == -NOT_TRACKED) {
			cycles_t time_ipi_s, time_ipi_e;

			time_ipi_s =
				stats_get_cycles(STATS_WRITE_BACK_PAGE_IPI);
			on_each_cpu_mask(mm_cpumask(encl->mm), he_ipi_cb, NULL, 1);
			time_ipi_e =
				stats_get_cycles(STATS_WRITE_BACK_PAGE_IPI);
			stats_add(encl, STATS_WRITE_BACK_PAGE_IPI,
				  time_ipi_e - time_ipi_s);
			stats_ewb_try_inc(encl, 3);
			err = encl_write_back(&page_desc, va_slot_pa);
			if (err == -NOT_TRACKED) {
				he_err("ewb retry failed. vaddr=0x%lx, pa=0x%lx\n",
				       encl_page->desc,
				       epc_page->desc & PAGE_MASK);
			}
		}
	}
	if (err) {
		he_debug("ewb failed. vaddr=0x%lx, pa=0x%lx, err=%d\n",
			 encl_page->desc, epc_page->desc & PAGE_MASK, err);
		mutex_unlock(&encl->etrack_lock);
		mutex_lock(&encl->lock);
		set_encl_page_status(encl_page, ENCL_PAGE_UNMANIPULATED);
		free_va_slot(va_page, va_offset);
		list_move(&va_page->list, &encl->va_pages);
		mutex_unlock(&encl->lock);
		goto out;
	}
	mutex_unlock(&encl->etrack_lock);

	mutex_lock(&encl->lock);
	set_encl_page_status(encl_page, ENCL_PAGE_UNMANIPULATED);

	encl_page->va_page = va_page;
	set_encl_page_va_offset(encl_page, va_offset);

	encl_page->epc_page = NULL;
	encl->epc_page_cnt--;
	mutex_unlock(&encl->lock);

	time_main = stats_get_cycles(STATS_WRITE_BACK_PAGE_MAIN);
	stats_add(encl, STATS_WRITE_BACK_PAGE_GET_LOCK, time_get_lock - time_s);
	stats_add(encl, STATS_WRITE_BACK_PAGE_MAIN, time_main - time_get_lock);

	time_unmap_s = stats_get_cycles(STATS_WRITE_BACK_PAGE_UNMAP);
	he_zap_enclave_ptes(encl, page_desc.enclave_lin_addr);
	time_unmap_e = stats_get_cycles(STATS_WRITE_BACK_PAGE_UNMAP);
	stats_add(encl, STATS_WRITE_BACK_PAGE_UNMAP,
		  time_unmap_e - time_unmap_s);

out:
	kunmap_atomic((void *)(unsigned long)contents_va);
	kunmap_atomic((void *)(unsigned long)(page_desc.metadata -
					      backing->pcmd_offset));

	return err;
}

/* Load a reclaimed EPC page from regular main memory to the EPC. */
int encl_load_unblocked(struct encl_page *encl_page, struct epc_page *epc_page)
{
	int err;
	unsigned long contents_va;
	unsigned long va_offset;
	unsigned long va_slot_pa;
	struct he_enclave *encl;
	struct reclaimer_backing *backing;
	struct hc_encl_new_page_desc page_desc;
	cycles_t time_s, time_backing, time_eldu;

	time_s = stats_get_cycles(STATS_PF_HANDLER_GET_BACKING);
	encl = encl_page->encl;
	backing = encl_page->backing;
	contents_va = (unsigned long)kmap_atomic(backing->contents);
	page_desc.config_address = (unsigned long)&encl->config;
	page_desc.enclave_lin_addr = encl_page->desc & PAGE_MASK;
	page_desc.epc_page_pa = epc_page->desc;
	page_desc.source_address = __pa(contents_va);
	page_desc.metadata = (unsigned long)kmap_atomic(backing->pcmd) +
			     backing->pcmd_offset;

	va_offset = encl_page->desc & ENCL_PAGE_VA_OFFSET_MASK;
	va_slot_pa = encl_page->va_page->epc_page->desc + va_offset;
	time_backing = stats_get_cycles(STATS_PF_HANDLER_GET_BACKING);

	if (!hyper_enclave_enabled) {
		err = -EAGAIN;
		he_err("please enable hypervisor before vmcall\n");
		goto err_cleanup;
	}
	err = hypercall_ret_2(HC_ENCL_LOAD_UNBLOCKED, (unsigned long)&page_desc,
			      va_slot_pa);
	time_eldu = stats_get_cycles(STATS_PF_HANDLER_ELDU);
	stats_add(encl, STATS_PF_HANDLER_GET_BACKING, time_backing - time_s);
	stats_add(encl, STATS_PF_HANDLER_ELDU, time_eldu - time_backing);

err_cleanup:
	kunmap_atomic((void *)contents_va);
	kunmap_atomic((void *)(page_desc.metadata - backing->pcmd_offset));

	return err;
}

/*
 * `trigger_reclaim()` triggers reclaiming EPC procedure manually.
 * It can be used to ensure there is enough EPC resources for caller
 * to proceed operations.
 *
 * Context: Enclave mutex (&enc->lock) must **not** be held at its invocation,
 * since `relcaim_epc_page()` may acquire different Enclave mutex (&enc->lock) of the system.
 */
void trigger_reclaim(void)
{
	if (should_reclaim_epc_pages(NR_LOW_EPC_PAGES))
		reclaim_epc_pages();
}

/* Batch reclaim EPC pages. */
void reclaim_epc_pages(void)
{
	int i, cnt, err;
	struct epc_page *epc_page;
	struct encl_page *encl_page;
	struct he_enclave *encl;
	struct reclaimer_page_desc pages_desc[NR_RECLAIM_EPC_PAGES] = { 0 };
	struct epc_page *reclaimer_epc_pages[NR_RECLAIM_EPC_PAGES] = { 0 };
	cycles_t time_s, time_e;

	cnt = 0;
	spin_lock(&reclaimer_list_lock);
	for (i = 0; i < NR_RECLAIM_EPC_PAGES; i++) {
		if (list_empty(&epc_reclaimer_list)) {
			break;
		}

		epc_page = list_first_entry(&epc_reclaimer_list,
					    struct epc_page, list);
		list_del_init(&epc_page->list);
		encl_page = epc_page->encl_page;
		/*
		 * Add enclave refcount to avoid encl_page freed by enclave destroy
		 * when the page is being reclaimed.
		 */
		if (kref_get_unless_zero(&encl_page->encl->refcount)) {
			reclaimer_epc_pages[cnt] = epc_page;
			pages_desc[cnt].gva = encl_page->desc;
			pages_desc[cnt].gpa = epc_page->desc & PAGE_MASK;
			pages_desc[cnt++].encl_addr =
				(unsigned long)encl_page->encl;
		} else
			epc_page->desc &= ~EPC_PAGE_RECLAIMER_TRACKED;
	}
	spin_unlock(&reclaimer_list_lock);

	print_reclaimer_page_desc(pages_desc);
	if (!cnt) {
		return;
	}

	if (!hyper_enclave_enabled) {
		err = -EAGAIN;
		he_err("please enable hypervisor before vmcall\n");
		goto err_cleanup;
	}
	time_s = stats_get_cycles(STATS_RECLAIM_PAGES);
	err = hypercall_ret_1(HC_RECLAIM_PAGES, (unsigned long)pages_desc);
	time_e = stats_get_cycles(STATS_RECLAIM_PAGES);
	if (err) {
		he_err("HC_RECLAIM_PAGES hypercall failed. err: %d\n", err);
		goto err_cleanup;
	}
	stats_add((struct he_enclave *)(pages_desc[0].encl_addr),
		  STATS_RECLAIM_PAGES, time_e - time_s);
	print_reclaimer_page_desc(pages_desc);

	for (i = 0; i < cnt; i++) {
		if (!pages_desc[i].valid) {
			continue;
		}

		encl = (struct he_enclave *)(pages_desc[i].encl_addr);
		encl_page = reclaimer_epc_pages[i]->encl_page;

		mutex_lock(&encl->lock);
		set_encl_page_status(encl_page, ENCL_PAGE_BEING_RECLAIMED);
		mutex_unlock(&encl->lock);

		err = encl_get_backing(encl_page);
		if (err) {
			he_err("get_backing failed\n");
			pages_desc[i].valid = 0;

			mutex_lock(&encl->lock);
			set_encl_page_status(encl_page,
					     ENCL_PAGE_UNMANIPULATED);
			mutex_unlock(&encl->lock);
		}
	}

	for (i = 0; i < cnt; i++) {
		if (!pages_desc[i].valid) {
			continue;
		}

		encl = (struct he_enclave *)(pages_desc[i].encl_addr);
		encl_page = reclaimer_epc_pages[i]->encl_page;
		time_s = stats_get_cycles(STATS_BLOCK);
		err = encl_block(reclaimer_epc_pages[i]);
		time_e = stats_get_cycles(STATS_BLOCK);
		if (err) {
			pages_desc[i].valid = 0;
			encl_put_backing(encl_page);

			mutex_lock(&encl->lock);
			set_encl_page_status(encl_page,
					     ENCL_PAGE_UNMANIPULATED);
			mutex_unlock(&encl->lock);
		}
		stats_add(encl, STATS_BLOCK, time_e - time_s);
	}

	for (i = 0; i < cnt; i++) {
		if (!pages_desc[i].valid) {
			continue;
		}

		time_s = stats_get_cycles(STATS_WRITE_BACK_PAGE);
		encl = (struct he_enclave *)(pages_desc[i].encl_addr);
		encl_page = reclaimer_epc_pages[i]->encl_page;
		err = write_back_page(reclaimer_epc_pages[i]);
		if (err) {
			pages_desc[i].valid = 0;
			encl_put_backing(encl_page);
			continue;
		}
		time_e = stats_get_cycles(STATS_WRITE_BACK_PAGE);
		stats_add(encl, STATS_WRITE_BACK_PAGE, time_e - time_s);

		print_backing(encl_page->backing);
		kref_put(&encl->refcount, he_encl_cleanup);

		reclaimer_epc_pages[i]->desc &= ~EPC_PAGE_RECLAIMER_TRACKED;
		free_enclave_page(reclaimer_epc_pages[i]);
	}

err_cleanup:
	for (i = 0; i < cnt; i++) {
		encl = (struct he_enclave *)(pages_desc[i].encl_addr);
		if (!pages_desc[i].valid) {
			spin_lock(&reclaimer_list_lock);
			list_add_tail(&reclaimer_epc_pages[i]->list,
				      &epc_reclaimer_list);
			spin_unlock(&reclaimer_list_lock);
			kref_put(&encl->refcount, he_encl_cleanup);
		}
	}
}

static struct page *encl_get_backing_page(struct he_enclave *encl,
					  pgoff_t index)
{
	struct inode *inode = encl->backing->f_path.dentry->d_inode;
	struct address_space *mapping = inode->i_mapping;
	gfp_t gfpmask = mapping_gfp_mask(mapping);

	return shmem_read_mapping_page_gfp(mapping, index, gfpmask);
}

/*
 * Allocate backing pages for storing the encrypted contents and Paging
 * Crypto MetaData (PCMD) of an enclave page.
 */
int encl_get_backing(struct encl_page *encl_page)
{
	struct page *contents;
	struct page *pcmd;
	struct reclaimer_backing *backing;
	struct he_enclave *encl = encl_page->encl;
	pgoff_t page_index =
		PFN_DOWN(encl_page->desc - encl_page->encl->config.start_gva);
	pgoff_t pcmd_index = PFN_DOWN(encl->config.size) + (page_index >> 6);

	backing = kzalloc(sizeof(*backing), GFP_KERNEL);
	if (!backing) {
		return -ENOMEM;
	}
	contents = encl_get_backing_page(encl, page_index);
	if (IS_ERR(contents)) {
		kfree(backing);
		return PTR_ERR(contents);
	}

	pcmd = encl_get_backing_page(encl, pcmd_index);
	if (IS_ERR(pcmd)) {
		kfree(backing);
		put_page(contents);
		return PTR_ERR(pcmd);
	}

	backing->page_index = page_index;
	backing->contents = contents;
	backing->pcmd = pcmd;
	backing->pcmd_offset =
		(page_index & (PAGE_SIZE / sizeof(struct pcmd) - 1)) *
		sizeof(struct pcmd);
	encl_page->backing = backing;

	return 0;
}

/* Free backing pages for an enclave page. */
void encl_put_backing(struct encl_page *encl_page)
{
	struct reclaimer_backing *backing;

	backing = encl_page->backing;
	if (backing) {
		put_page(backing->pcmd);
		put_page(backing->contents);
		encl_page->backing = NULL;
		kfree(backing);
	}
}

/**
 * mark_page_reclaimable() - Mark the page can be reclaimed by reclaimer.
 *
 * @epc_page:	EPC page
 *
 * Mark a page as reclaimable and add it to the reclaimer list.
 */
void mark_page_reclaimable(struct epc_page *epc_page)
{
	WARN_ON_ONCE(epc_page->desc & EPC_PAGE_RECLAIMER_TRACKED);
	spin_lock(&reclaimer_list_lock);
	list_add_tail(&epc_page->list, &epc_reclaimer_list);
	epc_page->desc |= EPC_PAGE_RECLAIMER_TRACKED;
	spin_unlock(&reclaimer_list_lock);
}

/**
 * unmark_page_reclaimable() - Mark the page cannot be reclaimed by reclaimer.
 *
 * @epc_page:	EPC page
 *
 * Mark a page as unreclaimable. Reclaimer only reclaims the pages in the reclaimer list.
 */
int unmark_page_reclaimable(struct epc_page *epc_page)
{
	spin_lock(&reclaimer_list_lock);
	if (epc_page->desc & EPC_PAGE_RECLAIMER_TRACKED) {
		if (list_empty(&epc_page->list)) {
			/* The page is picked by reclaimer. */
			spin_unlock(&reclaimer_list_lock);
			return -EBUSY;
		}

		list_del(&epc_page->list);
		epc_page->desc &= ~EPC_PAGE_RECLAIMER_TRACKED;
	}
	spin_unlock(&reclaimer_list_lock);

	return 0;
}
