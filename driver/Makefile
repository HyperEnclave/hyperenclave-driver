# SPDX-License-Identifier: GPL-2.0
#
# HyperEnclave kernel module.
#
# Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.

obj-m := hyper_enclave.o

ccflags-y := -I$(src)/../include/arch/$(SRCARCH) \
	     -I$(src)/../include

hyper_enclave-y := edmm.o enclave.o init_mem.o main.o elf.o debug.o \
	hhbox.o feature.o reclaim.o stats.o shared_mem.o tdm.o crypto.o \
	sysfs.o param_parser.o mem_regions.o vendor.o iommu.o ioremap.o \
	mem_test.o
hyper_enclave-$(CONFIG_PCI) += tpm.o

ifeq ($(SRCARCH),x86)
hyper_enclave-y += arch/x86/hygon/tdm.o
hyper_enclave-y += arch/x86/sme.o
hyper_enclave-y += arch/x86/amd/ivrs.o
hyper_enclave-y += arch/x86/intel/dmar.o
endif
