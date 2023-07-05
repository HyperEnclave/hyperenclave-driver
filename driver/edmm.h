/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_EDMM_H
#define _DRIVER_EDMM_H

#include "enclave.h"

vm_fault_t he_encl_aug_page(struct vm_area_struct *vma, struct he_enclave *encl,
			    unsigned long addr);

int he_cmd_edmm_enabled(void __user *arg);

int he_cmd_encl_restrict_permissions(void __user *arg);
int he_cmd_encl_modify_types(void __user *arg);
int he_cmd_encl_remove_pages(void __user *arg);

#endif
