/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_RECLAIM_H
#define _DRIVER_RECLAIM_H

#include "enclave.h"

/* When the number of free EPC pages falls below low watermark, trigger background reclaim */
#define NR_LOW_EPC_PAGES 32
/* When the number of free EPC pages falls above high watermark, stop background reclaim */
#define NR_HIGH_EPC_PAGES 64
/* The number of batch reclaimed pages */
#define NR_RECLAIM_EPC_PAGES 16

struct va_page {
	struct epc_page *epc_page;
	DECLARE_BITMAP(slots, VA_SLOT_COUNT);
	struct list_head list;
};

struct reclaimer_page_desc {
	unsigned long gva;
	unsigned long gpa;
	unsigned long encl_addr;
	unsigned char valid;
} __packed;

struct reclaimer_backing {
	pgoff_t page_index;
	struct page *contents;
	struct page *pcmd;
	unsigned long pcmd_offset;
};

extern wait_queue_head_t kheswapd_wq;
extern struct list_head epc_reclaimer_list;
extern spinlock_t reclaimer_list_lock;

bool enable_epc_reclaimer(void);
void disable_epc_reclaimer(void);
bool should_reclaim_epc_pages(unsigned int pages);
unsigned int alloc_va_slot(struct va_page *va_page);
void free_va_slot(struct va_page *va_page, unsigned int offset);
bool is_va_page_full(struct va_page *va_page);

void reclaim_epc_pages(void);
void trigger_reclaim(void);
int encl_load_unblocked(struct encl_page *encl_page, struct epc_page *epc_page);
int encl_get_backing(struct encl_page *encl_page);
void encl_put_backing(struct encl_page *encl_page);

void mark_page_reclaimable(struct epc_page *epc_page);
int unmark_page_reclaimable(struct epc_page *epc_page);

#endif
