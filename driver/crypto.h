/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_CRYPTO_H
#define _DRIVER_CRYPTO_H

int measure_image(unsigned char *start_addr, unsigned int size,
		  unsigned char *digest);

#endif /* _DRIVER_CRYPTO_H */
