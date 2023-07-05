/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_ELF_H
#define _DRIVER_ELF_H

#include <linux/types.h>

bool load_elf_and_parse_tdm_info(u8 *dst, const u8 *src, u64 phys,
				 unsigned long sme_flags);
const struct hyper_header *get_header_from_elf(const u8 *src);

#define ELF_MAGIC 0x464C457FU // "\x7FELF" in little endian

enum ph_type { PH_HEADER_BSS, PH_TEXT, PH_RODATA, PH_DATA_GOT, PH_GOT, NR_PH };

struct u_elf64_hdr {
	u32 magic; // must equal ELF_MAGIC
	u8 elf[12];
	u16 type;
	u16 machine;
	u32 version;
	u64 entry;
	u64 phoff;
	u64 shoff;
	u32 flags;
	u16 ehsize;
	u16 phentsize;
	u16 phnum;
	u16 shentsize;
	u16 shnum;
	u16 shstrndx;
};

// Program section header
struct elf64_proghdr {
	u32 type;
	u32 flags;
	u64 off;
	u64 vaddr;
	u64 paddr;
	u64 filesz;
	u64 memsz;
	u64 align;
};

#endif
