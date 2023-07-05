/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _HYPERENCLAVE_SME_H
#define _HYPERENCLAVE_SME_H

#ifdef CONFIG_X86
unsigned long get_sme_mask(void);
#else
unsigned long get_sme_mask(void)
{
}
#endif

#endif /* _HYPERENCLAVE_SME_H */
