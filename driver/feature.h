/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_FEATURE_H
#define _DRIVER_FEATURE_H

#include <linux/bits.h>
#include <linux/const.h>
#include <linux/types.h>

/*
 * Bits 0 of module param feature_mask indicates if enable HHBox log feature:
 * 	0: off
 * 	1: on
 */
#define HHBOX_LOG_SHIFT (0)
/*
 * Bits 1 of module param feature_mask indicates if enable HHBox crash feature:
 * 	0: off
 * 	1: on
 */
#define HHBOX_CRASH_SHIFT (1)

#define HHBOX_LOG_MASK (UL(1) << HHBOX_LOG_SHIFT)
#define HHBOX_CRASH_MASK (UL(1) << HHBOX_CRASH_SHIFT)

/*
 * Bits 2-3 of module param feature_mask indicates the reclaim crypto algorithm:
 * 	00: HmacSW-then-EncHW(default)
 * 	01: EncSW-then-HmacSW
 * 	10: EncHW
 * 	11: reserved
 */

#define RECLAIM_CRYPTO_ALG_SHIFT 2
#define RECLAIM_CRYPTO_ALG_MASK GENMASK_ULL(3, 2)
#define get_reclaim_crypto_alg(val) \
	(((val)&RECLAIM_CRYPTO_ALG_MASK) >> RECLAIM_CRYPTO_ALG_SHIFT)

/*
 * Bits 4-5 of module param feature_mask indicates stats level:
 * 	00: level 0, nothing(default)
 * 	01: level 1, EPC overcommit stats
 * 	10: level 2, EPC overcommit stats and related operation time stats
 * 	11: reserved
 */
#define STATS_LEVEL_MAX 2
#define STATS_SHIFT (4)
#define STATS_MASK GENMASK_ULL(5, 4)
#define get_stats_level(val) (((val)&STATS_MASK) >> STATS_SHIFT)

/*
 * Bits 6 of module param feature_mask indicates if shared memory is pinned:
 * 	0: unpin(dynamic)
 * 	1: pin
 */
#define PIN_SHARED_MEMORY_SHIFT (6)
#define PIN_SHARED_MEMORY_MASK (UL(1) << PIN_SHARED_MEMORY_SHIFT)

/*
 * Bits 7 of module param feature_mask indicates whether to turn off EDMM:
 * 	0: keep EDMM on
 * 	1: turn off EDMM
 */
#define EDMM_OFF_SHIFT (7)
#define EDMM_OFF_MASK (UL(1) << EDMM_OFF_SHIFT)

/*
 * Bits 8 of module param feature_mask indicates whether to turn on fake TPM:
 * 	0: keep fake TPM off
 * 	1: turn on fake TPM
 */
#define FAKE_TPM_SHIFT (8)
#define FAKE_TPM_MASK (UL(1) << FAKE_TPM_SHIFT)

#define FEATURE_MASK_INVALID (-1)
#define FEATURE_MASK_DEFAULT (0x1)

/*
 * Bits 9 of module param feature_mask indicates whether to perform memory test before
 *     starting hypervisor:
 * 	0: disable memory test
 * 	1: enable memory test
 */
#define MEM_TEST_SHIFT (9)
#define MEM_TEST_MASK (UL(1) << MEM_TEST_SHIFT)

unsigned long long feature_init(unsigned long long mask);

/*
 * HHBox log feature: record hypervisor log when system is normal,
 * default enable.
 */
extern bool hhbox_log_enabled;

/*
 * HHBox crash feature: cope hypervisor panic and record hypervisor log when
 * hypervisor is abnormal, default disable. Besides, HHBox crash feature is
 * based on log feature, so if enable crash feature, log feature is enabled
 * default.
 */
extern bool hhbox_crash_enabled;

/*
 * Shared memory feature: used to tansfer data between app and enclave
 * Shared memory is unpinned by default
 */
extern bool shmem_pinned;

/* Configurable reclaim crypto algorithm, default is HmacSW-then-EncHW */
enum reclaim_crypto_alg {
	RECLAIM_CRYPTO_HmacSW_EncHW,
	RECLAIM_CRYPTO_EncSW_HmacSW,
	RECLAIM_CRYPTO_EncHW,
	RECLAIM_CRYPTO_TYPES
};

/*
 * Stats level to control which to record, default is level 0, record nothing.
 * Level 1 record EPC overcommit stats, level 2 record EPC overcommit stats and
 * related operation time stats.
 */
extern int stats_level;

/*
 * EDMM feature: Enclave Dynamic Memory Management,
 * default enable.
 */
extern bool edmm_enabled;

/*
 * TPM feature: fake a TPM in a scenario without HW TPM and FTPM
 * default disable.
 */
extern bool fake_tpm;

/*
 * Memory test feature: Perform memory test before starting hypervisor,
 * default enabled.
 */
extern bool memory_test_enabled;

#endif
