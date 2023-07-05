// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <linux/pci.h>
#include <linux/tpm.h>
#include <linux/version.h>
#include <crypto/sm3.h>

#include <hyperenclave/hypercall.h>
#include <hyperenclave/log.h>

#include "main.h"
#include "feature.h"
#include "tpm.h"

#if defined(CONFIG_ACPI)
#define DEVICE_IS_TPM2 1
static const struct acpi_device_id tpm_acpi_tbl[] = {
	{ "MSFT0101", DEVICE_IS_TPM2 },
	{ "NTZ0755", DEVICE_IS_TPM2 },
	{ "ANT0322", DEVICE_IS_TPM2 },
	{},
};
static bool detect_hw_tpm(void)
{
	int i;

	for (i = 0; tpm_acpi_tbl[i].id[0]; i++) {
		if (acpi_dev_found(tpm_acpi_tbl[i].id))
			return true;
	}

	return false;
}
#else
static bool detect_hw_tpm(void)
{
	return false;
}
#endif

static unsigned int __inspect_tpm(unsigned long long *phy_addr,
				  unsigned int *tpm_type)
{
	struct pci_dev *pdev = NULL, *mpsp_dev = NULL;
	unsigned short bdf_cur = 0;
	unsigned short bdf_min = PSP_BDF_INVALID;

	if (!phy_addr || !tpm_type)
		return 0;
	if (detect_hw_tpm()) {
		*tpm_type = TPM_TYPE_HARDWARE;
		*phy_addr = HW_TPM_MMIO_PA;
		he_info("using hardware tpm\n");
		return HW_TPM_MMIO_SIZE;
	} else {
		for_each_pci_dev(pdev) {
			if (pdev->vendor != PCI_VENDOR_ID_HYGON ||
			    pdev->device != 0x1456)
				continue;
			if (pdev->devfn > 0xff) {
				he_err("pci device %p has unexpected pci devfn: %x\n",
				       pdev, pdev->devfn);
				return 0;
			}
			if (!pdev->bus) {
				he_err("pci device %p has no bus info\n", pdev);
				return 0;
			}
			bdf_cur = ((unsigned short)pdev->bus->number << 8) |
				  (unsigned char)pdev->devfn;
			if (bdf_cur < bdf_min) {
				bdf_min = bdf_cur;
				mpsp_dev = pdev;
			}
		}
		*tpm_type = TPM_TYPE_HYGON_FTPM;
		*phy_addr = mpsp_dev->resource[2].start;
		he_info("using firmware tpm\n");
		return mpsp_dev->resource[2].end - mpsp_dev->resource[2].start + 1;
	}
}

static struct tpm_chip *chip;
static struct tpm_class_ops *tpm_c_ops_old;
static struct tpm_class_ops tpm_c_ops_new;

static void tpm_clk_enable_lock(bool value)
{
	mutex_lock(&he_lock);

	if (hyper_enclave_enabled) {
		he_debug("value: %d\n", value);
		hypercall_ret_1(HC_TPM_CMD_SYNC, value);
	}

	mutex_unlock(&he_lock);
}

static void tpm_clk_enable_wrapper(struct tpm_chip *chip, bool value)
{
	if (value) {
		/* Acquire tpm lock */
		tpm_clk_enable_lock(value);
		if (tpm_c_ops_old->clk_enable)
			tpm_c_ops_old->clk_enable(chip, value);
	} else {
		if (tpm_c_ops_old->clk_enable)
			tpm_c_ops_old->clk_enable(chip, value);
		/* Release tpm lock */
		tpm_clk_enable_lock(value);
	}
}

static void __tpm_chip_ops_update(void)
{
	chip = tpm_default_chip();
	if (!chip) {
		he_warn("no tpm chip found\n");
		return;
	}

	down_write(&chip->ops_sem);
	if (!chip->ops)
		goto out_lock;
	tpm_c_ops_old = (struct tpm_class_ops *)chip->ops;
	memcpy(&tpm_c_ops_new, tpm_c_ops_old, sizeof(tpm_c_ops_new));
	tpm_c_ops_new.clk_enable = tpm_clk_enable_wrapper;
	chip->ops = &tpm_c_ops_new;

out_lock:
	up_write(&chip->ops_sem);
}

static void __tpm_chip_ops_cleanup(void)
{
	if (!chip)
		return;

	down_write(&chip->ops_sem);
	if (!chip->ops)
		goto out;
	chip->ops = tpm_c_ops_old;

out:
	up_write(&chip->ops_sem);
	put_device(&chip->dev);
}

static void set_sm3_digest(unsigned char *digest, struct tpm_digest *ptds,
			   struct tpm_chip *chip)
{
	int i, b;
	struct tpm_digest *td;

	b = 0;
	for (i = 0; i < chip->nr_allocated_banks; i++) {
		td = ptds + i;
		td->alg_id = chip->allocated_banks[i].alg_id;
		if (td->alg_id == TPM_ALG_SM3_256)
			b = i;
	}
	td = ptds + b;
	memcpy(td->digest, digest, SM3_DIGEST_SIZE);
}

static bool __extend_pcr(unsigned char *digest, int size, int pcr_index)
{
	struct tpm_chip *tpm_chip = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 91)
	struct tpm_digest tds[6];
#endif
	int result;

	if (size > SM3_DIGEST_SIZE || size <= 0 || !digest) {
		he_err("Invalid data to extend\n");
		return false;
	}
	print_hex_dump(KERN_INFO, "extended to PCR 12: ", DUMP_PREFIX_NONE, 16,
		       1, digest, size, 0);
	tpm_chip = tpm_default_chip();
	if (!tpm_chip) {
		he_err("No tpm chip is found\n");
		return false;
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 19, 91)
	memset((char *)&tds[0], 0, sizeof(tds));
	set_sm3_digest(digest, &tds[0], tpm_chip);
	result = tpm_pcr_extend(tpm_chip, pcr_index, &tds[0]);
#else
	result = tpm_pcr_extend(tpm_chip, pcr_index, digest);
#endif
	he_info("tpm_pcr_extend result=%d\n", result);
	return true;
}

unsigned int inspect_tpm(unsigned long long *phy_addr, unsigned int *tpm_type)
{
	if (fake_tpm) {
		*tpm_type = TPM_TYPE_FAKE;
		*phy_addr = FAKE_TPM_PA;
		he_info("using fake tpm\n");
		return FAKE_TPM_SIZE;
	} else {
		return __inspect_tpm(phy_addr, tpm_type);
	}
}

void tpm_chip_ops_update(void)
{
	if (!fake_tpm)
		__tpm_chip_ops_update();
}

void tpm_chip_ops_cleanup(void)
{
	if (!fake_tpm)
		__tpm_chip_ops_cleanup();
}

bool extend_pcr(unsigned char *digest, int size, int pcr_index)
{
	if (fake_tpm)
		return true;
	else
		return __extend_pcr(digest, size, pcr_index);
}
