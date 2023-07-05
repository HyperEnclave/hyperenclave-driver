// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <hyperenclave/log.h>

#include "feature.h"

/*
 * HHBox log feature: record hypervisor log when system is normal,
 * default enable.
 */
bool hhbox_log_enabled = true;

/*
 * HHBox crash feature: cope hypervisor panic and record hypervisor log when
 * hypervisor is abnormal, default disable. Besides, HHBox crash feature is
 * based on log feature, so if enable crash feature, log feature is enabled
 * default.
 */
bool hhbox_crash_enabled = false;

/*
 * Stats level to control which to record, default is level 0, record nothing.
 * Level 1 record EPC overcommit stats, level 2 record EPC overcommit stats and
 * related operation time stats.
 */
int stats_level = 0;

/*
 * shmem_pinned to control whether shared memory is pinned, default is false,
 * unpin shared memory. shmem_pinned = true means pin shared memory.
 */
bool shmem_pinned = false;

/*
 * EDMM feature: Enclave Dynamic Memory Management,
 * default enable.
 */
bool edmm_enabled = true;

/*
 * TPM feature: fake a TPM in a scenario without HW TPM and FTPM
 * default disable.
 */
bool fake_tpm = false;

/*
 * Memory test feature: Perform memory test before starting hypervisor,
 * default disable.
 */
bool memory_test_enabled = false;

unsigned long long feature_init(unsigned long long mask)
{
	if (mask == FEATURE_MASK_INVALID)
		return FEATURE_MASK_DEFAULT;

	if (mask & HHBOX_LOG_MASK)
		hhbox_log_enabled = true;
	else
		hhbox_log_enabled = false;

	if (mask & HHBOX_CRASH_MASK) {
		hhbox_log_enabled = true;
		hhbox_crash_enabled = true;
		mask |= HHBOX_LOG_MASK;
	} else
		hhbox_crash_enabled = false;

	if (get_reclaim_crypto_alg(mask) >= RECLAIM_CRYPTO_TYPES) {
		he_info("Invalid reclaim crypto algorithm configuration, use default HmacSW-then-EncHW");
		mask &= ~RECLAIM_CRYPTO_ALG_MASK;
	}

	stats_level = get_stats_level(mask);
	if (stats_level > 2) {
		stats_level = 0;
	}

	if (mask & PIN_SHARED_MEMORY_MASK)
		shmem_pinned = true;
	else
		shmem_pinned = false;

	if (mask & EDMM_OFF_MASK)
		edmm_enabled = false;

	if (mask & FAKE_TPM_MASK)
		fake_tpm = true;

	if (mask & MEM_TEST_MASK)
		memory_test_enabled = true;

	return mask;
}
