/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_HHBOX_H
#define _DRIVER_HHBOX_H

#include <linux/cpumask.h>
#include <linux/workqueue.h>

#define HHBOX_LOG_HEARTBEAT_MS 10000
#define HHBOX_CRASH_HEARTBEAT_MS 8000

extern cpumask_t *vmm_states;
extern cpumask_t initial_vmm_states;

extern struct workqueue_struct *vmm_check_wq;
DECLARE_PER_CPU(struct delayed_work, vmm_check_work);

extern struct delayed_work flush_hv_log_work;

void register_vmm_check_wq(void);
void deregister_vmm_check_wq(void);
bool alloc_vmm_check_wq(void);
void dealloc_vmm_check_wq(void);

void register_flush_hv_log_work(void);
void deregister_flush_hv_log_work(void);

#endif
