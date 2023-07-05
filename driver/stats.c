// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <hyperenclave/log.h>

#include "enclave.h"
#include "feature.h"
#include "main.h"
#include "stats.h"

char *statstype_str[STATS_TYPES] = {
	"Reclaim_pages",
	"Block",
	"Track",
	"Write_back_page",
	"Write_back_page_get_lock",
	"Write_back_page_ipi",
	"Write_back_page_main",
	"Write_back_page_unmap",
	"PF_handler",
	"PF_handler_get_lock",
	"PF_handler_pre",
	"PF_handler_get_backing",
	"PF_handler_eldu",
	"PF_handler_map",
};

cycles_t stats_get_cycles(enum statstype type)
{
	if (!stats_level)
		return 0;

	if ((stats_level == 1 &&
	     (type == STATS_WRITE_BACK_PAGE || type == STATS_PF_HANDLER)) ||
	    (stats_level == 2))
		return get_cycles();
	else
		return 0;
}

void stats_init(struct he_enclave *encl)
{
	if (!stats_level)
		return;

	ktime_get_real_ts64(&encl->stats.start);
}

void stats_add(struct he_enclave *encl, enum statstype type, unsigned long sum)
{
	if (!stats_level)
		return;

	if ((stats_level == 1 &&
	     (type == STATS_WRITE_BACK_PAGE || type == STATS_PF_HANDLER)) ||
	    (stats_level == 2)) {
		atomic64_inc(&(encl->stats.stats[type].count));
		atomic64_add(sum, &(encl->stats.stats[type].sum));
	}
}

void stats_ewb_try_inc(struct he_enclave *encl, int num)
{
	encl->stats.ewb_info.cnt[num - 1]++;
}

void print_stats(struct he_enclave *encl)
{
	int i;
	unsigned long ewb_cnt, eldu_cnt;
	unsigned long count, sum, avg;
	unsigned long first, second, third, total;
	struct timespec64 ts;
	unsigned long elapsed_time;

	if (!stats_level)
		return;

	ktime_get_real_ts64(&ts);
	elapsed_time = ts.tv_sec + ts.tv_nsec / NSEC_PER_SEC -
		       (encl->stats.start.tv_sec +
			encl->stats.start.tv_nsec / NSEC_PER_SEC);
	he_info("encl 0x%px stats:\n", encl);
	he_info("    elapsed time: %lu(s)\n", elapsed_time);

	/* EPC overcommit stats. */
	ewb_cnt = atomic64_read(
		&(encl->stats.stats[STATS_WRITE_BACK_PAGE].count));
	eldu_cnt = atomic64_read(&(encl->stats.stats[STATS_PF_HANDLER].count));
	he_info("    EWB page cnt: %lu(%luM), ELDU page cnt: %lu(%luM)\n",
		ewb_cnt, ewb_cnt / 256, eldu_cnt, eldu_cnt / 256);

	if (stats_level == 1)
		return;

	/* Three EWB try info. */
	first = encl->stats.ewb_info.cnt[0] - encl->stats.ewb_info.cnt[1];
	second = encl->stats.ewb_info.cnt[1] - encl->stats.ewb_info.cnt[2];
	third = encl->stats.ewb_info.cnt[2];
	total = encl->stats.ewb_info.cnt[0];

	if (encl->stats.ewb_info.cnt[0]) {
		he_info("    EWB first: %lu, second: %lu, third: %lu\n", first,
			second, third);
		he_info("    EWB first percent: %lu%%, second percent: %lu%%, third percent: %lu%%\n",
			first * 100 / total, second * 100 / total,
			third * 100 / total);
	}

	/* EPC overcommit time stats. */
	for (i = 0; i < STATS_TYPES; i++) {
		count = atomic64_read(&(encl->stats.stats[i].count));
		sum = atomic64_read(&(encl->stats.stats[i].sum));
		avg = (count == 0 ? 0 : sum / count);
		he_info("    %s: count = %lu, sum = %lu, avg = %lu\n",
			statstype_str[i], count, sum, avg);
	}
}

void encl_reset_stats(struct he_enclave *encl)
{
	int i;

	print_stats(encl);

	if (!stats_level)
		return;

	/* Reset start time. */
	ktime_get_real_ts64(&encl->stats.start);

	/* Clear EPC overcommit stats. */
	atomic64_set(&(encl->stats.stats[STATS_WRITE_BACK_PAGE].count), 0);
	atomic64_set(&(encl->stats.stats[STATS_PF_HANDLER].count), 0);

	if (stats_level == 1)
		return;

	/* Clear three EWB try info EPC overcommit time stats. */
	memset(&(encl->stats.ewb_info), 0, sizeof(encl->stats.ewb_info));
	for (i = 0; i < STATS_TYPES; i++) {
		atomic64_set(&(encl->stats.stats[i].count), 0);
		atomic64_set(&(encl->stats.stats[i].sum), 0);
	}
}
