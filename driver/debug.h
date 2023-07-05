/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_DEBUG_H
#define _DRIVER_DEBUG_H

#include <linux/types.h>

#include "elf.h"

void dump_hex(u8 *buffer, u64 size);
void dump_elf(struct u_elf64_hdr *elf);
void dump_ph(struct elf64_proghdr *ph);

#endif
