/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_STATS_H
#define _DRIVER_STATS_H

#define MAX_ENCLAVE_NUM 16

struct stats_value {
	atomic64_t count;
	atomic64_t sum;
};

enum statstype {
	STATS_RECLAIM_PAGES,
	STATS_BLOCK,
	STATS_TRACK,
	STATS_WRITE_BACK_PAGE,
	STATS_WRITE_BACK_PAGE_GET_LOCK,
	STATS_WRITE_BACK_PAGE_IPI,
	STATS_WRITE_BACK_PAGE_MAIN,
	STATS_WRITE_BACK_PAGE_UNMAP,
	STATS_PF_HANDLER,
	STATS_PF_HANDLER_GET_LOCK,
	STATS_PF_HANDLER_PRE,
	STATS_PF_HANDLER_GET_BACKING,
	STATS_PF_HANDLER_ELDU,
	STATS_PF_HANDLER_MAP,
	STATS_TYPES
};

struct ewb_try_info {
	unsigned long cnt[3];
};

struct stats_struct {
	struct stats_value stats[STATS_TYPES];
	struct ewb_try_info ewb_info;
	struct timespec64 start;
};

struct he_enclave;

cycles_t stats_get_cycles(enum statstype type);
void stats_init(struct he_enclave *encl);
void stats_add(struct he_enclave *encl, enum statstype type, unsigned long sum);
void stats_ewb_try_inc(struct he_enclave *encl, int num);
void print_stats(struct he_enclave *encl);
void encl_reset_stats(struct he_enclave *encl);

#endif
