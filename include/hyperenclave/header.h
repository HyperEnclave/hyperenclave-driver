/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2013-2017
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

// Modified by The HyperEnclave Project in 2020
/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _HYPERENCLAVE_HEADER_H_
#define _HYPERENCLAVE_HEADER_H_

#include <linux/types.h>

#include <asm/hyperenclave/header.h>
#include <hyperenclave/memory.h>

#define HE_SIGNATURE "HYPERENC"

/* Max numbuer of convertible memory regions */
#define MAX_CONV_MEM_REGIONS 32

/* Max numbuer of initialized EPC regions */
#define MAX_INIT_EPC_REGIONS MAX_CONV_MEM_REGIONS

#define HYP_STUB_ABI_LEGACY 0
#define HYP_STUB_ABI_OPCODE 1

/**
 * Hypervisor description.
 * Located at the beginning of the hypervisor binary image and loaded by
 * the driver (which also initializes some fields).
 */
struct hyper_header {
	/** Signature "HYPERENC" used for basic validity check of the
	 * hypervisor image.
	 * @note Filled at build time.
	 */
	char signature[8];
	/** Size of hypervisor core.
	 * It starts with the hypervisor's header and ends after its bss
	 * section. Rounded up to page boundary.
	 * @note Filled at build time.
	 */
	unsigned long core_size;
	/** Size of the per-CPU data structure.
	 * @note Filled at build time.
	 */
	unsigned long percpu_size;
	/** Entry point (arch_entry()).
	 * @note Filled at build time.
	 */
	int (*entry)(unsigned int);

	/** Configured maximum logical CPU ID + 1.
	 * @note Filled by Linux loader driver before entry.
	 */
	unsigned int max_cpus;
	/** Number of online CPUs that will call the entry function.
	 * @note Filled by Linux loader driver before entry.
	 */
	unsigned int online_cpus;

	/** Physical address of Linux's hyp-stubs.
	 * @note Filled by Linux loader driver before entry.
	 */
	unsigned long long arm_linux_hyp_vectors;
	/** Denotes hyp-stub ABI for arm and arm64:
	 * @note Filled by Linux loader driver before entry.
	 */
	unsigned int arm_linux_hyp_abi;

	unsigned int tpm_type;
	unsigned int tpm_mmio_size;
	unsigned long long tpm_mmio_pa;

	/* Percpu buffer safe_print_seq info */
	unsigned long long safe_print_seq_start_pa;
	unsigned long long percpu_offset_pa;

	/* Used for recored vmm states */
	unsigned long long vmm_states_pa;

	unsigned long long feature_mask;

	/* The size of hypervisor's heap (in bytes), must 4kB aligned. */
	unsigned long long hv_heap_size;

	/* Array of convertible memory regions. */
	struct memory_range conv_mem_ranges[MAX_CONV_MEM_REGIONS];
	/* Number of valid convertible memorys regions in 'conv_mem_ranges'. */
	unsigned int nr_conv_mem;

	/* Array of initialized EPC regions. */
	struct memory_range init_epc_ranges[MAX_INIT_EPC_REGIONS];
	/* Number of initialized EPC regions in 'init_epc_ranges'. */
	unsigned int nr_init_epc;
};

#endif /* _HYPERENCLAVE_HEADER_H_ */
