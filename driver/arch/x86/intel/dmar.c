// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <linux/acpi.h>
#include <linux/sizes.h>

#include <hyperenclave/log.h>

#include "dmar.h"

static int __init check_dmar_checksum(struct acpi_table_header *table)
{
	int i;
	u8 checksum = 0, *p = (u8 *)table;

	for (i = 0; i < table->length; ++i)
		checksum += p[i];
	if (checksum != 0) {
		/* ACPI table corrupt */
		he_err(FW_BUG "DMAR invalid checksum\n");
		return -ENODEV;
	}
	return 0;
}

bool parse_dmar(struct iommu_info *iommu_info)
{
	struct acpi_table_header *dmar_base;
	acpi_status status;
	u8 *p, *end;
	struct dmar_header *h;
	struct rmrr_header *r;
	int count_iommu = 0, count_rmrr = 0;
	int i;
	bool ret = false;
	const char *err;
	u8 *mmio_base;
	u64 capability, extended_capability, fro, nfr, iro;
	/* fault recording offset, number of fault recording, iotlb register offset. */
	u64 mmio_upper, mmio_size;

	status = acpi_get_table("DMAR", 0, &dmar_base);

	if (status == AE_NOT_FOUND) {
		he_err("DMAR acpi_table AE_NOT_FOUND\n");
		goto out;
	} else if (ACPI_FAILURE(status)) {
		err = acpi_format_exception(status);
		he_err("DMAR table: %s\n", err);
		goto out;
	}

	if (check_dmar_checksum(dmar_base)) {
		he_err("DMAR checksum wrong\n");
		goto out;
	}
	p = (u8 *)dmar_base;
	end = (u8 *)dmar_base;
	p += DMAR_HEADER_LENGTH;
	end += dmar_base->length;
	while (p < end) {
		h = (struct dmar_header *)p;

		/* Check. */
		if (h->type == DRHD_TYPE) {
			iommu_info->iommu_units[count_iommu].base = h->address;
			mmio_base =
				ioremap(h->address, /* Pass MEM_MAP into it. */
					SZ_4K);
			/* Read and determine mmio size. */
			if (!mmio_base) {
				he_err("Fail to map iommu control registers\n");
				goto out;
			} else {
				/*
				 * Get the IOTLB & Fault Recording register offset &
				 * calc the MMIO mapping size.
				 */
				capability = readq(mmio_base + 0x8);
				extended_capability = readq(mmio_base + 0x10);

				/* Fault recording offset, [33:24],10bit. */
				fro = 16 * (capability >> 24) & ((1 << 10) - 1);

				/* Number of fault recording, [47:40],8bit. */
				nfr = 1 + ((capability >> 40) & ((1 << 8) - 1));

				/* IOTLB register offset, [17:8],10bit. */
				iro = 16 * (extended_capability >> 8) &
				      ((1 << 10) - 1);

				mmio_upper = fro + nfr * FAULT_RECORDING_SIZE;

				/* 16: size of IOTLB registers(16 bytes). */
				if (iro + 16 > mmio_upper) {
					mmio_upper = iro + 16;
				}

				mmio_size = SZ_4K;
				while (mmio_size < mmio_upper &&
				       mmio_size < SZ_4M) {
					mmio_size = mmio_size * 2;
				}

				iommu_info->iommu_units[count_iommu].size =
					mmio_size;
			}
			iounmap(mmio_base);

			++count_iommu;
		} else if (h->type == RMRR_TYPE) {
			/* Pass some RMRR information to hypervisor? */
			r = (struct rmrr_header *)p;
			iommu_info->rmrr_ranges[count_rmrr].base =
				r->base_address;
			iommu_info->rmrr_ranges[count_rmrr].limit =
				r->limit_address;
			++count_rmrr;
		}
		p += h->length;
	}
	for (i = count_rmrr; i < HYPERENCLAVE_MAX_RMRR_RANGES; ++i) {
		iommu_info->rmrr_ranges[i].base = 0;
		iommu_info->rmrr_ranges[i].limit = 0;
	}
	for (i = count_iommu; i < HYPERENCLAVE_MAX_IOMMU_UNITS; ++i) {
		iommu_info->iommu_units[i].base = 0;
		iommu_info->iommu_units[i].size = 0;
	}
	ret = true;
out:
	acpi_put_table(dmar_base);
	return ret;
}
