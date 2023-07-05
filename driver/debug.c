// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <hyperenclave/log.h>

#include "debug.h"

void dump_hex(u8 *buffer, u64 size)
{
	u64 i = 0;

	for (i = 1; i <= size; i++) {
		he_debug("%2X ", buffer[i - 1]);
		if (i % 16 == 0)
			he_debug("\n");
	}
}

void dump_elf(struct u_elf64_hdr *elf)
{
	he_debug("magic: 0x%X\n", elf->magic);
	he_debug("phoff: %lld\n", elf->phoff);
	he_debug("phnum: %d\n", elf->phnum);
}

void dump_ph(struct elf64_proghdr *ph)
{
	he_debug("dump program header:\n");
	he_debug("type : 0x%x\n", ph->type);
	he_debug("flag : 0x%x\n", ph->flags);
	he_debug("off : 0x%llx\n", ph->off);
	he_debug("vaddr : 0x%llx\n", ph->vaddr);
	he_debug("paddr : 0x%llx\n", ph->paddr);
	he_debug("filesz : 0x%llx\n", ph->filesz);
	he_debug("memsz : 0x%llx\n", ph->memsz);
	he_debug("align : 0x%llx\n", ph->align);
}
