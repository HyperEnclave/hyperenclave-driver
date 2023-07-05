// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <linux/acpi.h>
#include <linux/sizes.h>

#include <hyperenclave/log.h>

#include "ivrs.h"

static int __init check_ivrs_checksum(struct acpi_table_header *table)
{
	int i;
	u8 checksum = 0, *p = (u8 *)table;

	for (i = 0; i < table->length; ++i)
		checksum += p[i];
	if (checksum != 0) {
		/* ACPI table corrupt */
		he_err(FW_BUG "IVRS invalid checksum\n");
		return -ENODEV;
	}
	return 0;
}

bool parse_ivrs(struct iommu_info *iommu_info)
{
	int target_ivhd_type;
	struct acpi_table_header *ivrs_base;
	acpi_status status;
	u8 *p, *end;
	struct ivhd_header *h;
	int count_iommu = 0;
	int i;
	bool ret = false;
	const char *err;
	void *mmio_base;

	target_ivhd_type = 0x11;
	status = acpi_get_table("IVRS", 0, &ivrs_base);

	if (status == AE_NOT_FOUND) {
		he_err("IVRS acpi_table AE_NOT_FOUND\n");
		goto out;
	} else if (ACPI_FAILURE(status)) {
		err = acpi_format_exception(status);
		he_err("IVRS table: %s\n", err);
		goto out;
	}

	if (check_ivrs_checksum(ivrs_base)) {
		he_err("IVRS checksum wrong\n");
		goto out;
	}
	p = (u8 *)ivrs_base;
	end = (u8 *)ivrs_base;
	p += IVRS_HEADER_LENGTH;
	end += ivrs_base->length;
	while (p < end) {
		h = (struct ivhd_header *)p;

		/* Check. */
		if (h->type == target_ivhd_type) {
			iommu_info->iommu_units[count_iommu].base =
				h->mmio_phys;

			/*
			 * Reference: AMD iommu spec, Capability Offset 04h:
			 * IOMMU Base Address Low Register.
			 * Use ioremap to access MMIO offset 0x30[PCsup(bit 9)]:
			 * 1: 512KB(aligned) 0:16KB(aligned).
			 */
			mmio_base = ioremap(
				h->mmio_phys, /* Pass MEM_MAP into it. */
				SZ_4K);
			/* Read and determine mmio size. */
			if (!mmio_base) {
				he_err("Fail to map iommu control registers\n");
				goto out;
			} else {
				u32 extended_feature = readl(mmio_base + 0x30);

				if (extended_feature & (1 << 9)) {
					iommu_info->iommu_units[count_iommu]
						.size = SZ_512K;
				} else {
					iommu_info->iommu_units[count_iommu]
						.size = SZ_16K;
				}
			}
			iounmap(mmio_base);

			++count_iommu;
		}
		p += h->length;
	}
	for (i = count_iommu; i < HYPERENCLAVE_MAX_IOMMU_UNITS; ++i) {
		iommu_info->iommu_units[count_iommu].base = 0;
		iommu_info->iommu_units[count_iommu].size = 0;
	}
	ret = true;
out:
	acpi_put_table(ivrs_base);
	return ret;
}
