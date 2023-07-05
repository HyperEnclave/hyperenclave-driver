// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <hyperenclave/log.h>

#include "main.h"
#include "init_mem.h"
#include "param_parser.h"

static void print_module_usage(char *s)
{
	he_info("%s\n", s);
	he_info("module usage:\n");
	he_info("\tinsmod hyper_enclave.ko str_memmap=start1,size1 feature_mask=mask\n");
	he_info("\tstr_memmap: contain only one memory region reserved by 'memmap' in kernel command-line, "
		" driver filters out the invalid memory region using E820 table provided by firmware\n");
	he_info("\tfeature_mask:\n");
	he_info("\t\tmask Bit[0] indicates if support HHBox log feature\n");
	he_info("\t\t\t\t0 = HHBox log feature is disabled\n");
	he_info("\t\t\t\t1 = HHBox log feature is enabled(default)\n");
	he_info("\t\tmask Bit[1] indicates if support HHBox crash feature\n");
	he_info("\t\t\t\t0 = HHBox crash feature is disabled(default)\n");
	he_info("\t\t\t\t1 = HHBox crash feature is enabled\n");
	he_info("\t\tmask Bits[3:2] indicates reclaim crypto algorithm\n");
	he_info("\t\t\t\t00 = HmacSW-then-EncHW(default)\n");
	he_info("\t\t\t\t01 = EncSW-then-HmacSW\n");
	he_info("\t\t\t\t10 = EncHW\n");
	he_info("\t\t\t\t11 = reserved\n");
	he_info("\t\tmask Bits[5:4] indicates stats level\n");
	he_info("\t\t\t\t00 = stats is disabled(default)\n");
	he_info("\t\t\t\t01 = EPC overcommit stats\n");
	he_info("\t\t\t\t10 = EPC overcommit stats and related operation time stats\n");
	he_info("\t\t\t\t11 = reserved\n");
	he_info("\t\tmask Bit[6] indicates if shared memory is pinned\n");
	he_info("\t\t\t\t0 = do not pin the shared memory(dynamic)\n");
	he_info("\t\t\t\t1 = pin the shared memory\n");
	he_info("\t\tmask Bit[7] indicates whether to turn off EDMM(Enclave Dynamic Memory Management)\n");
	he_info("\t\t\t\t0 = keep EDMM on\n");
	he_info("\t\t\t\t1 = turn off EDMM\n");
	he_info("\t\tmask Bit[8] indicates whether to turn on fake TPM\n");
	he_info("\t\t\t\t0 = keep fake TPM off\n");
	he_info("\t\t\t\t1 = turn on fake TPM\n");
	he_info("\t\tmask Bit[9] indicates whether to perform memory test before starting hypervisor\n");
	he_info("\t\t\t\t0 = disable memory test\n");
	he_info("\t\t\t\t1 = enable memory test\n");
}

/*
 * Get memmap ranges.
 */
bool get_memmap_paras(void)
{
	unsigned long long memmap_size;

	if (len_memmap_paras != 2) {
		print_module_usage("ERROR, invalid reserved regions number");
		return false;
	}

	memmap_start = memparse(str_memmap[0], NULL);
	memmap_size = memparse(str_memmap[1], NULL);
	if (!memmap_size || !IS_ALIGNED(memmap_size, SZ_1G) ||
	    !IS_ALIGNED(memmap_size, SZ_1G)) {
		print_module_usage(
			"ERROR, invalid reserved memory size/offset");
		return false;
	}
	memmap_end = memmap_start + memmap_size;

	return true;
}
