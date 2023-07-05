/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_ENCLAVE_H
#define _DRIVER_ENCLAVE_H

#include <linux/kref.h>

#include <hyperenclave/enclave_config.h>

#include "ioctl.h"
#include "main.h"
#include "stats.h"
#include "shared_mem.h"

struct pinned_memory_area {
	unsigned long addr;
	int nr_pages;
	struct page **pages;
};
struct he_enclave {
	struct he_encl_desc config;
	struct task_struct *owner;
	unsigned int flags;
	struct mutex lock;
	struct radix_tree_root page_tree;
	struct pinned_memory_area *pma; /* pinned memory area */
	struct kref refcount;
	unsigned int page_cnt;
	unsigned int epc_page_cnt;
	struct list_head va_pages;
	struct file *backing;
	struct shmem_struct shmem;
	struct mm_struct *mm;
	struct stats_struct stats;
	/*
	 * Used to manage concurrency of different events that update the TLB flush track state:
	 * EBLOCK, EWB, EMODPR and EMODT.
	 */
	struct mutex etrack_lock;
};

/* The status in `epc_page->desc`, marking that the page is being tracked by the page reclaimer. */
#define EPC_PAGE_RECLAIMER_TRACKED BIT(0)

struct epc_page {
	/*
	 * desc: The descriptor of the epc_page.
	 *	bit 63 - 12: The physical address of the EPC page.
	 *	bit       0: The status of the page.
	 */
	unsigned long desc;
	struct list_head list;
	struct encl_page *encl_page;
};

/* Bit mask to generate the VA (version array) page offset from `encl->desc`  */
#define ENCL_PAGE_VA_OFFSET_MASK GENMASK_ULL(11, 3)

#define ENCL_PAGE_STATUS_MASK GENMASK_ULL(1, 0)
/* The status in `encl_page->desc`, marking that the page is being reclaimed. */
enum encl_page_status {
	/* Default status for the page. */
	ENCL_PAGE_UNMANIPULATED = 0x0,
	/* The page is being written back from EPC to main memory. */
	ENCL_PAGE_BEING_RECLAIMED = 0x1,
	/* The page is being loaded back to EPC from main memory. */
	ENCL_PAGE_BEING_LOADED = 0x2,
};

struct encl_page {
	/*
	 * desc: The descriptor of the encl_page.
	 *	bit 47 - 12: The virtual address (userspace) of the enclave page.
	 *	bit 11 -  3: The offset of the va slot (If its `epc_page` is swapped out).
	 *	bit  1 -  0: The status of the page.
	 */
	unsigned long desc;
	unsigned long page_type;
	struct epc_page *epc_page;
	struct va_page *va_page;
	/*
	 * For SME's en-decryption on HYGON platform, the physical address of
	 * backing page must remain unchanged.
	 */
	struct reclaimer_backing *backing;
	struct he_enclave *encl;
};

enum encl_flags {
	ENCL_INITIALIZED = BIT(0),
	ENCL_DEBUG = BIT(1),
	ENCL_SECS_EVICTED = BIT(2),
	ENCL_SUSPEND = BIT(3),
	ENCL_DEAD = BIT(4),
};

extern unsigned int nr_free_epc_pages;

static inline void set_encl_page_status(struct encl_page *encl_page,
					enum encl_page_status status)
{
	encl_page->desc &= ~ENCL_PAGE_STATUS_MASK;
	encl_page->desc |= status;
}

static inline void set_encl_page_va_offset(struct encl_page *encl_page,
					   unsigned long va_offset)
{
	encl_page->desc &= ~ENCL_PAGE_VA_OFFSET_MASK;
	encl_page->desc |= va_offset;
}

int he_cmd_encl_create(struct he_encl_create __user *arg);
int he_cmd_encl_add_page(struct he_encl_add_page __user *arg);
int he_cmd_encl_init(struct he_encl_init __user *arg);
int he_cmd_pin_memory(struct he_memory_info __user *arg);
int he_cmd_unpin_memory(struct he_memory_info __user *arg);
int he_cmd_encl_reset_stats(struct he_encl_reset_stats __user *arg);

void he_encl_cleanup(struct kref *ref);
void add_epc_pages(__u64 epc_phys, __u64 epc_size);
void free_epc_pages(void);

struct epc_page *alloc_enclave_page(bool reclaim);
struct va_page *alloc_va_page(struct he_enclave *encl, bool reclaim);

void free_enclave_page(struct epc_page *epc_page);
void free_va_page(struct he_enclave *encl, struct va_page *va_page);

int find_enclave(struct mm_struct *mm, unsigned long addr,
		 struct he_enclave **encl);
int encl_track(struct he_enclave *encl);
void he_ipi_cb(void *info);

struct encl_page *he_encl_load_page_in_pf_handler(struct he_enclave *encl,
						  unsigned long addr,
						  cycles_t *time_pre_load_ptr);
struct encl_page *he_encl_load_page(struct he_enclave *encl,
				    unsigned long addr);

void he_zap_enclave_ptes(struct he_enclave *encl, unsigned long addr);

#endif
