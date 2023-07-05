/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _INIT_MEM_H
#define _INIT_MEM_H

#include <hyperenclave/header.h>
#include "main.h"

extern struct memory_range rsrv_mem_ranges[MAX_INIT_EPC_REGIONS];
extern unsigned int nr_rsrv_mem;

extern unsigned long long memmap_start;
extern unsigned long long memmap_end;

int get_convertible_memory(void);
int get_valid_rsrv_mem(void);
void init_enclave_page(struct hyper_header *header);

int get_hv_core_and_percpu_size(unsigned long *hv_core_and_percpu_size_ptr,
				const u8 *elf);
unsigned long long
get_hypervisor_size(unsigned long long hv_core_and_percpu_size);
void set_heap_size(struct hyper_header *header);
void set_convertible_mem(struct hyper_header *header);

/* Initialize the CMRM after starting hypervisor */
int init_cmrm(void);

#endif /* !_INIT_MEM_H */
