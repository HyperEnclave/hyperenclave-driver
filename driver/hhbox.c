// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <hyperenclave/hypercall.h>

#include "feature.h"
#include "hhbox.h"
#include "main.h"

cpumask_t *vmm_states;
cpumask_t initial_vmm_states;

struct workqueue_struct *vmm_check_wq;
DEFINE_PER_CPU(struct delayed_work, vmm_check_work);

struct delayed_work flush_hv_log_work;

static void vmm_check_work_func(struct work_struct *work)
{
	bool equal;
	unsigned int cpu;

	equal = cpumask_equal(&initial_vmm_states, vmm_states);
	cpu = smp_processor_id();
	if (hyper_enclave_enabled && !equal) {
		printk_safe_flush_sym();
		if (cpumask_test_cpu(cpu, vmm_states)) {
			hypercall_ret_1(HC_DISABLE, 0);
		}
		panic("VMM abnormal");
	}

	queue_delayed_work_on(cpu, vmm_check_wq, this_cpu_ptr(&vmm_check_work),
			      msecs_to_jiffies(HHBOX_CRASH_HEARTBEAT_MS));
}

bool alloc_vmm_check_wq(void)
{
	if (!hhbox_crash_enabled)
		return false;

	vmm_check_wq = alloc_workqueue("vmm_check_wq", 0, 0);

	return true;
}

void dealloc_vmm_check_wq(void)
{
	if (!hhbox_crash_enabled)
		return;

	destroy_workqueue(vmm_check_wq);
}

void register_vmm_check_wq(void)
{
	int cpu;

	if (!hhbox_crash_enabled)
		return;

	cpumask_copy(&initial_vmm_states, vmm_states);
	for_each_online_cpu(cpu) {
		struct delayed_work *dw = &per_cpu(vmm_check_work, cpu);

		INIT_DELAYED_WORK(dw, vmm_check_work_func);
		queue_delayed_work_on(
			cpu, vmm_check_wq, dw,
			msecs_to_jiffies(HHBOX_CRASH_HEARTBEAT_MS));
	}
}

void deregister_vmm_check_wq(void)
{
	int cpu;

	if (!hhbox_crash_enabled)
		return;

	cpumask_clear(&initial_vmm_states);
	for_each_online_cpu(cpu) {
		cancel_delayed_work(&per_cpu(vmm_check_work, cpu));
	}
}

static void flush_hv_log_work_func(struct work_struct *work)
{
	printk_safe_flush_sym();
	schedule_delayed_work(&flush_hv_log_work,
			      msecs_to_jiffies(HHBOX_LOG_HEARTBEAT_MS));
}

void register_flush_hv_log_work(void)
{
	if (!hhbox_log_enabled)
		return;

	INIT_DELAYED_WORK(&flush_hv_log_work, flush_hv_log_work_func);
	schedule_delayed_work(&flush_hv_log_work,
			      msecs_to_jiffies(HHBOX_LOG_HEARTBEAT_MS));
}

void deregister_flush_hv_log_work(void)
{
	if (!hhbox_log_enabled)
		return;

	cancel_delayed_work(&flush_hv_log_work);
}
