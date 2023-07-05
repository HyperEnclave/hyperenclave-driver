// SPDX-License-Identifier: GPL-2.0
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#include <crypto/sm3_base.h>
#include <linux/crypto.h>

#include <hyperenclave/log.h>

struct sdesc {
	struct shash_desc shash;
	char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
	struct sdesc *sdesc;
	int size;

	size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
	sdesc = kmalloc(size, GFP_KERNEL);
	if (!sdesc) {
		he_info("fail to kmalloc sdesc\n");
		return ERR_PTR(-ENOMEM);
	}
	sdesc->shash.tfm = alg;
	return sdesc;
}

static int calc_hash(struct crypto_shash *alg, const unsigned char *data,
		     unsigned int datalen, unsigned char *digest)
{
	struct sdesc *sdesc;
	int ret;

	sdesc = init_sdesc(alg);
	if (IS_ERR(sdesc)) {
		he_info("can't alloc sdesc\n");
		return PTR_ERR(sdesc);
	}
	ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
	kfree(sdesc);
	return ret;
}

int measure_image(unsigned char *start_addr, unsigned int size,
		  unsigned char *digest)
{
	struct crypto_shash *alg;
	char *sha_alg_name = "sm3";
	int ret = 0;

	alg = crypto_alloc_shash(sha_alg_name, 0, 0);
	if (IS_ERR(alg)) {
		he_info("can't alloc the required hash alg\n");
		return 0;
	}
	ret = calc_hash(alg, start_addr, size, digest);
	if (ret < 0) {
		he_info("failed to do the hash calculation\n");
		ret = 0;
	} else {
		ret = SM3_DIGEST_SIZE;
	}
	crypto_free_shash(alg);
	return ret;
}
