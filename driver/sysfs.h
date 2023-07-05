/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_SYSFS_H
#define _DRIVER_SYSFS_H

#include <linux/miscdevice.h>

extern struct ctl_table hyper_enclave_root_table[];
extern struct ctl_table_header *hyper_enclave_table_header;
extern struct miscdevice he_misc_dev;
extern const struct vm_operations_struct he_vm_ops;

int __init proc_hypervisorinfo_init(void);
void proc_hypervisorinfo_remove(void);

#endif /* _DRIVER_SYSFS_H */
