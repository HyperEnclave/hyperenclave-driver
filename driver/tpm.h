/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_TPM_H_
#define _DRIVER_TPM_H_

#ifndef PCI_VENDOR_ID_HYGON
#define PCI_VENDOR_ID_HYGON 0x002c
#endif

#define TPM_TYPE_HARDWARE 0
#define TPM_TYPE_HYGON_FTPM 4
#define TPM_TYPE_FAKE 8

#define HW_TPM_MMIO_PA 0xFED40000
#define HW_TPM_MMIO_SIZE 0x5000
#define PSP_BDF_INVALID 0xffff

#define FAKE_TPM_PA 0xffffffff
#define FAKE_TPM_SIZE 0

unsigned int inspect_tpm(unsigned long long *phy_addr, unsigned int *tpm_type);
void tpm_chip_ops_update(void);
void tpm_chip_ops_cleanup(void);
bool extend_pcr(unsigned char *digest, int size, int pcr_index);

#endif
