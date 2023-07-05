// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <hyperenclave/header.h>
#include <hyperenclave/log.h>
#include <hyperenclave/tdm.h>

#include "debug.h"
#include "elf.h"
#include "main.h"

bool load_elf_and_parse_tdm_info(u8 *dst, const u8 *src, u64 phys,
				 unsigned long sme_flags)
{
	struct u_elf64_hdr elf;
	struct elf64_proghdr ph;
	ulong va_base = 0;
	uint i, off;
	struct memory_region hv_mem;
	struct memory_region ph_mem[NR_PH] = { 0 };

	memcpy((u8 *)&elf, src, sizeof(elf));
	if (elf.magic != ELF_MAGIC) {
		he_err("Not ELF File\n");
		return false;
	}

	for (i = 0, off = elf.phoff; i < elf.phnum; i++, off += sizeof(ph)) {
		memcpy((u8 *)&ph, (u8 *)(src + off), sizeof(ph));

		if (ph.memsz == 0)
			continue;
		if (ph.memsz < ph.filesz || ph.vaddr + ph.memsz < ph.vaddr) {
			he_info("{memsz, filesz, vaddr} : {0x%llx 0x%llx 0x%llx} not valid\n",
				ph.memsz, ph.filesz, ph.vaddr);
			return false;
		}

		if (i == 0) {
			va_base = ph.vaddr;
		}

		ph_mem[i].virt_start = (u64)(dst + ph.vaddr - va_base);
		ph_mem[i].size = ph.filesz;
		if (ph.vaddr - va_base + ph.filesz > hv_range.size) {
			he_err("System epc and hypervisor epc size doesn't match\n");
			return false;
		}
		memcpy(dst + ph.vaddr - va_base, src + ph.off, ph.filesz);
	}

	/*
	 * Get the tdm measurement content: hypervisor TEXT and RODATA. TEXT and
	 * RODATA segments are adjacent, to simplify, regard them as one segment,
	 * that is, the measure range is [PH_TEXT.start, PH_RODATA.end].
	 */
	if (!ph_mem[PH_TEXT].size || !ph_mem[PH_RODATA].size) {
		he_warn("text size: %llx. rodata size: %llx\n",
			ph_mem[PH_TEXT].size, ph_mem[PH_RODATA].size);
	}
	hv_mem.virt_start = ph_mem[PH_TEXT].virt_start;
	hv_mem.size = ph_mem[PH_RODATA].virt_start + ph_mem[PH_RODATA].size -
		      ph_mem[PH_TEXT].virt_start;
	hv_mem.phys_start = (hv_mem.virt_start - (u64)dst + phys) | sme_flags;
	tdm.ops->set_tdm_info(&hv_mem);

	return true;
}

const struct hyper_header *get_header_from_elf(const u8 *src)
{
	struct u_elf64_hdr elf_header;
	struct elf64_proghdr ph;

	memcpy((void *)&elf_header, src, sizeof(elf_header));
	if (elf_header.magic != ELF_MAGIC) {
		he_err("Err: It's Not ELF File\n");
		return ERR_PTR(-EINVAL);
	}

	if (elf_header.phnum == 0) {
		he_err("Err: The number of ELF's header is 0\n");
		return ERR_PTR(-EINVAL);
	}

	memcpy((void *)&ph, (void *)(src + elf_header.phoff), sizeof(ph));
	if (ph.filesz < sizeof(struct hyper_header)) {
		he_err("Err: The file size of program header 0 (0x%llx) is smaller than header's size\n",
		       ph.filesz);
		return ERR_PTR(-EINVAL);
	}

	return (const struct hyper_header *)(src + ph.off);
}
