/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _HYPERENCLAVE_LOG_H
#define _HYPERENCLAVE_LOG_H

#include <linux/printk.h>

#undef pr_fmt
#define pr_fmt(fmt) "HE: %s: %d. " fmt, __func__, __LINE__

#define he_debug(fmt...) pr_debug(fmt)
#define he_info(fmt...) pr_info(fmt)
#define he_warn(fmt...) pr_warn("HE_WARN. " fmt)
#define he_err(fmt...) pr_err("HE_ERROR. " fmt)

#endif
