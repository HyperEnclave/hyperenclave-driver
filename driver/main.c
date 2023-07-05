/*
 * Jailhouse, a Linux-based partitioning hypervisor
 *
 * Copyright (c) Siemens AG, 2013-2017
 * Copyright (c) Valentine Sinitsyn, 2014
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *  Valentine Sinitsyn <valentine.sinitsyn@gmail.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

// Modified by The HyperEnclave Project in 2020
// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <linux/device.h>
#include <linux/firmware.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/version.h>
#include <asm/barrier.h>
#include <asm/cacheflush.h>
#ifdef CONFIG_ARM
#include <asm/virt.h>
#endif
#ifdef CONFIG_X86
#include <asm/msr.h>
#endif

#include <generated/version.h>
#include <hyperenclave/header.h>
#include <hyperenclave/hypercall.h>
#include <hyperenclave/iommu.h>
#include <hyperenclave/log.h>
#include <hyperenclave/sme.h>
#include <hyperenclave/tdm.h>
#include <hyperenclave/vendor.h>

#include "crypto.h"
#include "edmm.h"
#include "elf.h"
#include "enclave.h"
#include "feature.h"
#include "hhbox.h"
#include "init_mem.h"
#include "ioremap.h"
#include "main.h"
#include "mem_regions.h"
#include "mem_test.h"
#include "param_parser.h"
#include "reclaim.h"
#include "stats.h"
#include "sysfs.h"
#include "tpm.h"

#ifdef CONFIG_X86_32
#error 64-bit kernel required!
#endif

#ifdef CONFIG_X86
#define HE_AMD_FW_NAME "rust-hypervisor-amd"
#define HE_INTEL_FW_NAME "rust-hypervisor-intel"
#else
#define HE_FW_NAME "rust-hypervisor"
#endif

MODULE_DESCRIPTION("Management driver for HyperEnclave hypervisor");
MODULE_LICENSE("GPL");
#ifdef CONFIG_X86
MODULE_FIRMWARE(HE_AMD_FW_NAME);
MODULE_FIRMWARE(HE_INTEL_FW_NAME);
#else
MODULE_FIRMWARE(HE_FW_NAME);
#endif
MODULE_VERSION(HE_VERSION);

/*
 * memmap_ranges are reserved physical memory regions which are used for
 * hypervisor and EPC memory.
 */
struct memory_range hv_range;

char *str_memmap[2];
int len_memmap_paras;
module_param_array(str_memmap, charp, &len_memmap_paras, S_IRUGO);
MODULE_PARM_DESC(str_memmap, "The memmap reserved ranges in string");

static ulong feature_mask = FEATURE_MASK_INVALID;
module_param(feature_mask, ulong, S_IRUGO);
MODULE_PARM_DESC(feature_mask, "HyperEnclave feature mask");

DEFINE_MUTEX(he_lock);
int hyper_enclave_enabled;
void *hypervisor_mem;
unsigned long hv_core_and_percpu_size;

static struct device *hyperenclave_dev;
static int enter_hv_cpus;
static atomic_t call_done;
static int error_code;
static unsigned long long hv_feature_mask;
#define MAX_HASH_SIZE 32

typeof(ioremap_page_range) *ioremap_page_range_sym;
#ifdef CONFIG_X86
typeof(flush_tlb_kernel_range) *flush_tlb_kernel_range_sym;
#endif
#ifdef CONFIG_ARM
static typeof(__boot_cpu_mode) *__boot_cpu_mode_sym;
#endif
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
static typeof(__hyp_stub_vectors) *__hyp_stub_vectors_sym;
#endif

typeof(printk_safe_flush) *printk_safe_flush_sym;
void (*mmput_async_sym)(struct mm_struct *mm);

#ifdef CONFIG_X86
bool use_vmcall;

static void init_hypercall(void)
{
	use_vmcall = boot_cpu_has(X86_FEATURE_VMX);
}
#else /* !CONFIG_X86 */
static void init_hypercall(void)
{
}
#endif

/*
 * Called for each cpu by the sysctl dev.hyper_enclave.enabled.
 * It jumps to the entry point set in the header, reports the result and
 * signals completion to the main thread that invoked it.
 */
static void enter_hypervisor(void *info)
{
	struct hyper_header *header = info;
	unsigned int cpu = smp_processor_id();
	int (*entry)(unsigned int);
	int err;

	entry = header->entry + (unsigned long)hypervisor_mem;

	if (cpu < header->max_cpus)
		/* either returns 0 or the same error code across all CPUs */
		err = entry(cpu);
	else
		err = -EINVAL;

	if (err)
		error_code = err;

#if defined(CONFIG_X86) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
	/* on Intel, VMXE is now on - update the shadow */
	cr4_init_shadow();
#endif

	atomic_inc(&call_done);
}

static inline const char *he_get_fw_name(void)
{
#ifdef CONFIG_X86
	if (boot_cpu_has(X86_FEATURE_SVM))
		return HE_AMD_FW_NAME;
	if (boot_cpu_has(X86_FEATURE_VMX))
		return HE_INTEL_FW_NAME;
	return NULL;
#else
	return HE_FW_NAME;
#endif
}

static void he_firmware_free(void)
{
	vunmap(hypervisor_mem);
	hypervisor_mem = NULL;
}

void he_ipi_cb(void *info)
{
}

int he_cmd_enable(void)
{
	const struct firmware *hypervisor;
	struct system_config *config;
	struct hyper_header *header;
	unsigned long remap_addr = 0;
	unsigned long config_size;
	const char *fw_name;
	long max_cpus;
	int err;
	unsigned long sme_mask = 0;
	unsigned long long tpm_mmio_pa = 0;
	unsigned int tpm_mmio_size = 0, tpm_type = 0;
	unsigned char digest[SM3_DIGEST_SIZE];
	int pcr_index = 12, m_size = 0;

	int num_iomem, num_mem_regions;
	struct memory_region *mem_regions;
	struct system_config *config_header;
	int len_config_header;
	void *load_addr;

	void *safe_print_seq_sym;
	unsigned long long safe_print_seq_start_va, safe_print_seq_start_pa;
	unsigned long long percpu_offset_pa;

	memset(digest, 0, sizeof(digest));
	fw_name = he_get_fw_name();
	if (!fw_name) {
		he_err("Missing or unsupported HVM technology\n");
		return -ENODEV;
	}

	if (!try_module_get(THIS_MODULE))
		return -EBUSY;

#ifdef CONFIG_ARM
	/* open-coded is_hyp_mode_available to use __boot_cpu_mode_sym */
	if ((*__boot_cpu_mode_sym & MODE_MASK) != HYP_MODE ||
	    (*__boot_cpu_mode_sym) & BOOT_CPU_MODE_MISMATCH) {
		he_err("HYP mode not available\n");
		err = -ENODEV;
		goto error_put_module;
	}
#endif
#ifdef CONFIG_X86
	if (boot_cpu_has(X86_FEATURE_VMX)) {
		u64 features;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0) || \
	LINUX_VERSION_CODE <= KERNEL_VERSION(4, 9, 0)
		rdmsrl(MSR_IA32_FEATURE_CONTROL, features);
#else
		rdmsrl(MSR_IA32_FEAT_CTL, features);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0) || \
	LINUX_VERSION_CODE <= KERNEL_VERSION(4, 9, 0)
		if ((features & FEATURE_CONTROL_VMXON_ENABLED_OUTSIDE_SMX) == 0)
#else
		if ((features & FEAT_CTL_VMX_ENABLED_OUTSIDE_SMX) == 0)
#endif
		{
			he_err("VT-x disabled by Firmware/BIOS\n");
			err = -ENODEV;
			goto error_put_module;
		}
	}
#endif

	/* Load hypervisor image */
	err = request_firmware(&hypervisor, fw_name, hyperenclave_dev);
	if (err) {
		he_err("Missing hypervisor image %s\n", fw_name);
		goto error_put_module;
	}

	err = get_hv_core_and_percpu_size(&hv_core_and_percpu_size,
					  hypervisor->data);
	if (err) {
		he_err("Err: Cannot get hv core and per cpu size\n");
		goto error_release_fw;
	}

	num_iomem = get_iomem_num();
	/*
	 * memmap region should be removed from iomem regions,
	 * so the max num of mem_regions is iomem_num + nr_rsrv_mem.
	 */
	mem_regions = kvmalloc(sizeof(*mem_regions) * (num_iomem + nr_rsrv_mem),
			       GFP_KERNEL);
	if (!mem_regions) {
		err = -ENOMEM;
		goto error_release_fw;
	}
	num_mem_regions = get_mem_regions(mem_regions);
	if (num_mem_regions == -1) {
		err = -ENOMEM;
		he_err("Please reserve regions with memmap.\n");
		goto error_release_fw;
	}
	dump_mem_regions(mem_regions, num_mem_regions);

	if (!get_hypervisor_meminfo()) {
		err = -ENOMEM;
		he_err("The memmap reserved regions aren't valid.\n");
		goto error_release_fw;
	}
	he_info("hypervisor size: 0x%llx\n", hv_range.size);
	dump_reserved_meminfo();

	/* Map physical memory region reserved for hyperenclave hypervisor. */
	remap_addr = HYPERENCLAVE_BASE;
	sme_mask = get_sme_mask();
	hypervisor_mem =
		he_ioremap(hv_range.start, remap_addr, hv_range.size, sme_mask);
	if (!hypervisor_mem) {
		err = -ENOMEM;
		he_err("Unable to map RAM reserved for hypervisor "
		       "at %08lx\n",
		       (unsigned long)hv_range.start);
		goto error_free_mem_regions;
	}

	/*
	 * Copy hypervisor's binary image at beginning of the memory region
	 * and clear the rest to zero.
	 */
	memset(hypervisor_mem, 0, hv_range.size);
	if (!load_elf_and_parse_tdm_info(hypervisor_mem, hypervisor->data,
					 hv_range.start, sme_mask)) {
		err = -EINVAL;
		goto error_unmap;
	}

	header = (struct hyper_header *)hypervisor_mem;

	set_convertible_mem(header);
	set_heap_size(header);

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	header->arm_linux_hyp_vectors = virt_to_phys(*__hyp_stub_vectors_sym);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	header->arm_linux_hyp_abi = HYP_STUB_ABI_LEGACY;
#else
	header->arm_linux_hyp_abi = HYP_STUB_ABI_OPCODE;
#endif
#endif

	err = -EINVAL;
	if (memcmp(header->signature, HE_SIGNATURE,
		   sizeof(header->signature)) != 0 ||
	    hypervisor->size >= hv_range.size)
		goto error_unmap;

	max_cpus = num_possible_cpus();
	config_size =
		sizeof(*config_header) + num_mem_regions * sizeof(*mem_regions);
	he_info("config_size: %lu\n", config_size);
	if (hv_core_and_percpu_size >= hv_range.size ||
	    config_size >= hv_range.size - hv_core_and_percpu_size)
		goto error_unmap;

	init_enclave_page(header);

	/*
	 * ARMv8 requires to clean D-cache and invalidate I-cache for memory
	 * containing new instructions. On x86 this is a NOP. On ARMv7 the
	 * firmware does its own cache maintenance, so it is an
	 * extraneous (but harmless) flush.
	 */
	flush_icache_range((unsigned long)hypervisor_mem,
			   (unsigned long)(hypervisor_mem + header->core_size));

	/*
	 * Copy system configuration to its target address in hypervisor
	 * memory region.
	 *
	 * Layout of system config:
	 * [header, mem_regions].
	 *
	 * Layout of config header:
	 * [hypervisor_memory, platform_info, num_memory_regions].
	 */
	config = (struct system_config *)(hypervisor_mem +
					  hv_core_and_percpu_size);

	/* Copy config header */
	load_addr = config;
	he_info("config_header load_addr: 0x%px\n", load_addr);
	len_config_header = sizeof(*config_header);
	config_header = kvzalloc(len_config_header, GFP_KERNEL);
	if (!config_header) {
		err = -ENOMEM;
		goto error_unmap;
	}
	config_header->hypervisor_memory.virt_start = HYPERENCLAVE_BASE;
	config_header->hypervisor_memory.phys_start = hv_range.start;
	config_header->hypervisor_memory.size = hv_range.size;
	config_header->num_memory_regions = num_mem_regions;

	if (!parse_iommu(&(config_header->platform_info.iommu_info))) {
		kvfree(config_header);
		he_err("failed to parse iommu\n");
		err = -ENODATA;
		goto error_unmap;
	}

	memcpy(load_addr, config_header, len_config_header);
	load_addr += len_config_header;
	he_info("mem_region load_addr: 0x%px\n", load_addr);
	kvfree(config_header);

	/* Copy mem regions */
	memcpy(load_addr, mem_regions, sizeof(*mem_regions) * num_mem_regions);

	tpm_mmio_size = inspect_tpm(&tpm_mmio_pa, &tpm_type);
	he_info("tpm mmio type=%x,size=%x pa=%llx\n", tpm_type, tpm_mmio_size,
		tpm_mmio_pa);
	if (!tpm_mmio_size && tpm_type != TPM_TYPE_FAKE) {
		he_err("inspect_tpm failed\n");
		err = -EFAULT;
		goto error_unmap;
	}
	header->tpm_type = tpm_type;
	header->tpm_mmio_size = tpm_mmio_size;
	header->tpm_mmio_pa = tpm_mmio_pa;

	/* Get percpu buffer safe_print_seq info */
	percpu_offset_pa = __pa_symbol(__per_cpu_offset);
	RESOLVE_EXTERNAL_SYMBOL(safe_print_seq);
	safe_print_seq_start_va = (u64)safe_print_seq_sym + __per_cpu_offset[0];
	safe_print_seq_start_pa = virt_to_phys((void *)safe_print_seq_start_va);

	header->safe_print_seq_start_pa = safe_print_seq_start_pa;
	header->percpu_offset_pa = percpu_offset_pa;

	/* Vmm stats info */
	vmm_states = kzalloc(sizeof(*vmm_states), GFP_KERNEL);
	if (!vmm_states) {
		err = -ENOMEM;
		goto error_unmap;
	}
	he_debug("vmm_states pa: %llx\n", virt_to_phys(vmm_states));
	header->vmm_states_pa = virt_to_phys(vmm_states);

	header->feature_mask = hv_feature_mask;

	/* Measure hypervisor image when hypervisor enable. */
	m_size = measure_image((unsigned char *)hypervisor->data,
			       hypervisor->size, digest);
	extend_pcr(digest, sizeof(digest), pcr_index);

	/* Get the measurement of hypervisor(including TEXT and RODATA) for TDM. */
	tdm.ops->measure();
	/*
	 * exclude header->max_cpus and online_cpu before measurement
	 * for we cannot predict them in build time
	 */
	header->max_cpus = max_cpus;

	error_code = 0;
	preempt_disable();

	header->online_cpus = num_online_cpus();
	atomic_set(&call_done, 0);
	on_each_cpu(enter_hypervisor, header, 0);
	while (atomic_read(&call_done) != num_online_cpus())
		cpu_relax();

	preempt_enable();

	if (error_code) {
		err = error_code;
		he_err("error_code: %d\n", error_code);
		goto error_free_vmm_stat;
	}

	err = init_cmrm();
	if (err) {
		he_err("Initialize CMRM fail, err: %d\n", err);
		goto error_free_vmm_stat;
	}

	kvfree(mem_regions);
	release_firmware(hypervisor);

	enter_hv_cpus = atomic_read(&call_done);

	he_info("The hyperenclave is opening.\n");
	return 0;

error_free_vmm_stat:
	kfree(vmm_states);

error_unmap:
	he_firmware_free();

error_free_mem_regions:
	kvfree(mem_regions);

error_release_fw:
	release_firmware(hypervisor);

error_put_module:
	module_put(THIS_MODULE);

	return err;
}

static void leave_hypervisor(void *info)
{
	void *page;
	int err;

	/* Touch each hypervisor page we may need during the switch so that
	 * the active mm definitely contains all mappings. At least x86 does
	 * not support taking any faults while switching worlds.
	 */
	for (page = hypervisor_mem;
	     page < hypervisor_mem + hv_core_and_percpu_size; page += PAGE_SIZE)
		readl((void __iomem *)page);

	/* either returns 0 or the same error code across all CPUs */
	err = hypercall_ret_1(HC_DISABLE, 1);
	if (err)
		error_code = err;

#if defined(CONFIG_X86) && LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
	/* on Intel, VMXE is now off - update the shadow */
	cr4_init_shadow();
#endif

	atomic_inc(&call_done);
}

int he_cmd_disable(void)
{
	int err;

	error_code = 0;

	preempt_disable();

	if (num_online_cpus() != enter_hv_cpus) {
		/*
		 * Not all assigned CPUs are currently online. If we disable
		 * now, we will lose the offlined ones.
		 */
		preempt_enable();

		err = -EBUSY;
		goto out;
	}

#ifdef CONFIG_ARM
	/*
	 * This flag has been set when onlining a CPU under hyperenclave
	 * supervision into SVC instead of HYP mode.
	 */
	*__boot_cpu_mode_sym &= ~BOOT_CPU_MODE_MISMATCH;
#endif

	atomic_set(&call_done, 0);
	on_each_cpu(leave_hypervisor, NULL, 0);
	while (atomic_read(&call_done) != num_online_cpus())
		cpu_relax();

	preempt_enable();

	err = error_code;
	if (err) {
		he_warn("Failed to disable hypervisor: %d\n", err);
		goto out;
	}

	tdm.ops->clear_tdm_info();
	module_put(THIS_MODULE);
	he_info("The hyperenclave was closed.\n");

out:
	return err;
}

static int he_shutdown_notify(struct notifier_block *unused1,
			      unsigned long unused2, void *unused3)
{
	int err;

	if (mutex_lock_interruptible(&he_lock) != 0) {
		pr_emerg("hyperenclave: ordered shutdown failed!\n");
		return NOTIFY_DONE;
	}

	if (hyper_enclave_enabled) {
		err = he_cmd_disable();
		if (err)
			pr_emerg("hyperenclave: ordered shutdown failed!\n");
		else
			hyper_enclave_enabled = 0;
	}

	mutex_unlock(&he_lock);

	return NOTIFY_DONE;
}

static struct notifier_block he_shutdown_nb = {
	.notifier_call = he_shutdown_notify,
};

static int __init he_init(void)
{
	int err;

	RESOLVE_EXTERNAL_SYMBOL(ioremap_page_range);
	RESOLVE_EXTERNAL_SYMBOL(flush_tlb_kernel_range);
#ifdef CONFIG_ARM
	RESOLVE_EXTERNAL_SYMBOL(__boot_cpu_mode);
#endif
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
	RESOLVE_EXTERNAL_SYMBOL(__hyp_stub_vectors);
#endif
	RESOLVE_EXTERNAL_SYMBOL(printk_safe_flush);
	RESOLVE_EXTERNAL_SYMBOL(mmput_async);

	cpu_vendor_detect();
	tdm_init();

	if (!get_memmap_paras())
		return -EINVAL;

	if ((err = get_convertible_memory()) != 0)
		return err;

	if ((err = get_valid_rsrv_mem()) != 0)
		return err;

	hv_feature_mask = feature_init(feature_mask);

	if (memory_test_enabled) {
		if (!mem_test()) {
			he_err("Memory test failed, please validate the reserved region\n");
			return -EINVAL;
		}
	} else {
		he_warn("Do not perform memory test, it is user's responsibility to ensure the "
			"reserved memory region is valid\n");
	}

	err = misc_register(&he_misc_dev);
	if (err)
		return err;

	register_reboot_notifier(&he_shutdown_nb);

	init_hypercall();

	hyper_enclave_table_header =
		register_sysctl_table(hyper_enclave_root_table);
	if (!hyper_enclave_table_header) {
		he_err("Unable to register hyper_enclave sysctl\n");
		err = -ENOMEM;
		goto exit_reboot_notifier;
	}

	if (alloc_vmm_check_wq()) {
		if (!vmm_check_wq) {
			he_err("alloc_workqueue failed\n");
			err = -ENOMEM;
			goto exit_alloc_wq;
		}
	}

	tdm.ops->proc_init();

	return 0;

exit_alloc_wq:
	unregister_sysctl_table(hyper_enclave_table_header);

exit_reboot_notifier:
	unregister_reboot_notifier(&he_shutdown_nb);
	misc_deregister(&he_misc_dev);

	return err;
}

static void __exit he_exit(void)
{
	unregister_reboot_notifier(&he_shutdown_nb);
	misc_deregister(&he_misc_dev);
	he_firmware_free();
	unregister_sysctl_table(hyper_enclave_table_header);
	tdm.ops->proc_remove();
	dealloc_vmm_check_wq();
	kfree(vmm_states);
	free_epc_pages();
}

module_init(he_init);
module_exit(he_exit);
