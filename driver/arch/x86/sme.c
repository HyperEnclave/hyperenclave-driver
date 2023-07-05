// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <asm/msr.h>
#include <linux/processor.h>

#include <hyperenclave/log.h>
#include <hyperenclave/vendor.h>

/*
 * SME reference:
 * https://www.kernel.org/doc/html/latest/x86/amd-memory-encryption.html
 */
#define HE_MSR_K8_SYSCFG 0xc0010010
#define HE_MSR_K8_SYSCFG_MEM_ENCRYPT (1 << 23)
#define HE_CPUID_GUEST_MODE (1 << 31)

unsigned long get_sme_mask(void)
{
	unsigned int eax, ebx, ecx, edx;
	unsigned long sme_mask;
	unsigned long msr;

	if (vendor != HE_X86_VENDOR_AMD && vendor != HE_X86_VENDOR_HYGON)
		return 0;

	/* SME in guest mode is not supported */
	eax = 1;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	if (ecx & HE_CPUID_GUEST_MODE) {
		he_info("SME in guest mode is not supported\n");
		return 0;
	}

	/* Check for the SME support leaf */
	eax = 0x80000000;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	if (eax < 0x8000001f)
		return 0;
	/*
	 * Check if CPU has SME feature:
	 *   CPUID Fn8000_001F[EAX] - Bit 0
	 *     Secure Memory Encryption support
	 *   CPUID Fn8000_001F[EBX] - Bits 5:0
	 *     Pagetable bit position used to indicate encryption
	 */
	eax = 0x8000001f;
	ecx = 0;
	native_cpuid(&eax, &ebx, &ecx, &edx);
	if (!(eax & 1)) {
		he_info("CPU does not has SME feature\n");
		return 0;
	}
	/* Check if SME is enabled */
	msr = __rdmsr(HE_MSR_K8_SYSCFG);
	if (!(msr & HE_MSR_K8_SYSCFG_MEM_ENCRYPT)) {
		he_info("CPU does not enable SME\n");
		return 0;
	}
	/* Obtain C-bit position in PTE */
	sme_mask = 1UL << (ebx & 0x3f);
	he_info("SME mask: [0x%lx]\n", sme_mask);
	return sme_mask;
}
