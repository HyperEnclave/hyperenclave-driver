/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _HYPERENCLAVE_HYPERCALL_H
#define _HYPERENCLAVE_HYPERCALL_H

#include <hyperenclave/enclave_config.h>

/*
 * Deactivate VMM.
 *
 * arg1: unsigned long flags, indicates if deactivate VMM on all cpus,
 *	 0: deactivate VMM on current cpu
 *	 1: deactivate VMM on all cpus
 */
#define HC_DISABLE 0

/*
 * Creates an enclave.
 *
 * arg1: unsigned long config_gva, a gVA pointing to the configuration page
 * 	 (struct he_encl_desc) of the enclave to be created.
 */
#define HC_ENCL_CREATE 0x10

/*
 * Adds a page to an enclave.
 *
 * arg1: unsigned long page_desc_gva, a gVA pointing to the descriptor
 * 	 (struct hc_encl_new_page_desc) of the page to be added.
 */
#define HC_ENCL_ADD_PAGE 0x11

/*
 * Init an enclave.
 *
 * arg1: unsigned long einit_desc_gva, the gVA pointing to destriciptor
 * 	 (struct he_encl_init_desc) of the enclave.
 */
#define HC_ENCL_INIT 0x12

/*
 * Set the state enclave to in destroy. When the enlave is in detroy state,
 * no thread can be in enclave mode.
 *
 * arg1: unsigned long config_gva, a gVA pointing to the configuration page
 */
#define HC_ENCL_PREPARE_DESTROY 0x13

/*
 * Destroy enclave actually, and release its all resources.
 *
 * arg1: unsigned long config_gva, the gVA pointing to the configuration page.
 */
#define HC_ENCL_FINISH_DESTROY 0x14

/*
 * Acquire/release TPM lock.
 *
 * arg1: unsigned long flags, indicates acquire or release TPM lock,
 *	 0: release TPM lock
 *	 1: acquire TPM lock
 */
#define HC_TPM_CMD_SYNC 0x16

/*
 * Create an empty version array page.
 * arg1: unsigned long config_gva, the gVA pointing to the configuration page.
 * arg2: unsigned long epc_page_pa, the gPA of the newly added version array page.
 *
 */
#define HC_ENCL_ADD_VERSION_ARRAY 0x18
/*
 * Mark a page in EPC as Blocked state.
 * arg1: unsigned long page_desc_gva, a gVA pointing to the descriptor
 * 	 (struct hc_encl_new_page_desc) of the page to be blocked.
 */
#define HC_ENCL_BLOCK 0x19
/*
 * Load a reclaimed EPC page from regular main memory to the EPC.
 * arg1: unsigned long page_desc_gva, a gVA pointing to the descriptor
 * 	 (struct hc_encl_new_page_desc) of the page to be loaded.
 * arg2: unsigned long va_slot_pa, phys addr of va_slot used by reclaimed
 * 	 EPC page.
 */
#define HC_ENCL_LOAD_UNBLOCKED 0x20
/*
 * Activate a TLB tracking cycle, track that software has completed the
 * equired TLB address clears successfully.
 * arg1: unsigned long config_gva, a gVA pointing to the configuration page
 * 	 (struct he_encl_desc) of the enclave to be tracked.
 */
#define HC_ENCL_TRACK 0x21
/*
 * Reclaim an EPC Page and Write out to Main Memory.
 * arg1: unsigned long page_desc_gva, a gVA pointing to the descriptor
 * 	 (struct hc_encl_new_page_desc) of the page to be reclaimed.
 * arg2: unsigned long va_slot_pa, phys addr of va_slot used by reclaimed
 * 	 EPC page.
 */
#define HC_ENCL_WRITE_BACK 0x22
/*
 * Pick the EPC pages to be reclaimed.
 * arg1: unsigned long pages_desc_gva, a gva pointing to the descriptors
 * 	 (struct reclaimer_page_desc pages_desc[NR_RECLAIM_EPC_PAGES]) of
 * 	 the pages to be reclaimed.
 */
#define HC_RECLAIM_PAGES 0x23

/*
 * Dynamically adding a page to an initialized enclave.
 *
 * arg1:	Pointer to `hc_encl_aug_page_desc`. See its definition for details.
 *
 */
#define HC_ENCL_AUG_PAGE 0x24

/*
 * Dynamically modifying enclave page type.
 *
 * arg1:	Pointer to `hc_encl_modt_page_desc`. See its definition for details.
 */
#define HC_ENCL_MODIFY_PAGE_TYPE 0x25

/*
 * Dynamically restricting enclave page permission.
 *
 * arg1:	Pointer to `hc_encl_modpr_page_desc`. See its definition for details.
 */
#define HC_ENCL_RESTRICT_PERM_PAGE 0x26

/*
 * Dynamically removing enclave page at runtime.
 *
 * arg1:	Pointer to `hc_encl_remove_page_at_runtime_desc`. See its definition for details.
 */
#define HC_ENCL_REMOVE_AT_RUNTIME 0x27

/*
 * Remove the enclave's EPC page at its destroy.
 *
 * arg1: unsigned long config_gva, a gVA pointing to the configuration page.
 *
 * arg2: unsigned long pages_desc_gva, the gVA pointing to the descriptor
 * 	 (struct hc_encl_remove_pages_at_destroy_desc), which specifies the
 * 	 physical address of the pages needed to be removed.
 * 	 Hypervisor stops removing pages at `i` when `pages_desc_gva->physaddr[i] = 0`.
 *
 * arg3: (outpout)
 * 	 unsigned long res_desc_gva, the gVA pointing to the (output) descriptor
 * 	 (struct hc_encl_remove_pages_at_destroy_res), hypervisor sets the
 * 	 return value of every pages to be removed in it.
 * 	 For example, we can get the return value of the first removed page from `res_desc_gva->val[0]`,
 * 	 and the return value of the second removed page from `res_desc_gva->val[1]` ......
 *
 * retval: (output)
 * 	   - If success, `retval` is zero;
 * 	   - If hypervisor encounters other errors at sanity check phase
 * 	     (For example, enclave's state is invalid,  `pages_desc_gva` is not PAGE_SIZE aligned),
 * 	     it writes the error code in `retval`;
 * 	   - If hypervisor encounters at removing the enclave pages phase,
 * 	     `retval` is zero but hypervisor writes the error code to the descriptor
 * 	      pointed by `res_desc_gva`. It is caller's responsibility to check it.
 */
#define HC_ENCL_REMOVE_PAGES_AT_DESTROY 0x28

/*
 * Clear enclave's stats.
 *
 * arg1: unsigned long config_gva, a gVA pointing to the configuration page
 * 	 (struct he_encl_desc) of the enclave to be reset.
 */
#define HC_ENCL_RESET_STATS 0x100

/*
 * Add shared memory range.
 * arg1: unsigned long memory_add_gva, a gVA pointing to the descriptor
 * (struct hc_memory_desc) of the range to be added.
 */
#define HC_ENCL_SHARED_MEMORY_ADD 0x101
/*
 * Remove shared memory range.
 * arg1: unsigned long memory_remove_gva, a gVA pointing to the descriptor
 * (struct hc_memory_desc) of the range to be removed.
 */
#define HC_ENCL_SHARED_MEMORY_REMOVE 0x102
/*
 * Linux prepares to invalidate shared memory, and notifies to Enclave.
 * arg1: unsigned long memory_invalid_gva, a gVA pointing to the descriptor
 * (struct hc_memory_desc) of the range to be invalid.
 */
#define HC_ENCL_SHARED_MEMORY_INVALID_START 0x103
/*
 * Linux finishes invalidating shared memory, and notifies to Enclave.
 * arg1: unsigned long config_gva, a gVA pointing to the configuration page
 * 	 (struct he_encl_desc) of the enclave to be tracked.
*/
#define HC_ENCL_SHARED_MEMORY_INVALID_END 0x104

/*
 * Initialize CMRM afer starting hypervisor.
 * Every CMRM entry should be initialized once and only once before we use it.
 *
 * arg1: unsigned long size, the size of physical region (in bytes) initialized in this round.
 */
#define HC_INIT_CMRM 0x200

/*
 * Mark the process of CMRM initialization done.
 */
#define HC_SET_INIT_CMRM_DONE 0x201

#include <asm/hyperenclave/hypercall.h>

struct hc_encl_new_page_desc {
	__u64 config_address;
	__u64 source_address;
	__u64 enclave_lin_addr;
	__u64 epc_page_pa;
	// addr of a SECINFO or PCMD instance
	__u64 metadata;
	__u32 attr;
} __packed;

struct hc_encl_remove_pages_at_destroy_desc {
	__u64 config_address;
	__u64 page_array_addr;
	__u64 res_array_addr;
	__u64 batch_size;
};

struct hc_encl_init_desc {
	__u64 config_address;
	__u64 sigstruct;
} __packed;

struct hc_encl_remove_pages_at_destroy_page_array {
	__u64 physaddr[REMOVE_PAGES_MAX_BATCH];
} __aligned(4096);

struct hc_encl_remove_pages_at_destroy_res_array {
	__u64 val[REMOVE_PAGES_MAX_BATCH];
} __aligned(4096);

struct hc_encl_aug_page_desc {
	__u64 config_addr;
	__u64 enclave_lin_addr;
	__u64 epc_page_pa;
	__u64 sec_info;
} __aligned(64);

struct hc_encl_modpr_page_desc {
	__u64 config_addr;
	__u64 enclave_lin_addr;
	__u64 sec_info;
} __aligned(64);

struct hc_encl_modt_page_desc {
	__u64 config_addr;
	__u64 enclave_lin_addr;
	__u64 sec_info;
} __aligned(64);

struct hc_encl_remove_page_at_runtime_desc {
	__u64 config_addr;
	__u64 enclave_lin_addr;
} __aligned(64);

#endif /* !_HYPERCALL_H */
