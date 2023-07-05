/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _HYPERENCLAVE_ENCLAVE_CONFIG_H
#define _HYPERENCLAVE_ENCLAVE_CONFIG_H

#include <asm/page_types.h>
#include <linux/types.h>

/* The modulus size for 3072-bit RSA keys. */
#define HE_MODULUS_SIZE 384
#define SHA256_HASH_SIZE 32

// Each enclave descriptor occupies exactly one page, as does the SGX SECS.
// Unlike the SECS, this page is not hidden from either N or S world, since no
// secret is stored in it yet. However, if we do decide to store sensitive
// information (such as the enclave's measurement) in it later, we can simply
// unmap this page from EPT-N and EPT-S.
#define SGX_SECS_RESERVED1_SIZE 24
#define SGX_SECS_RESERVED2_SIZE 32
#define SGX_SECS_RESERVED3_SIZE 32
#define SGX_SECS_RESERVED4_SIZE 3834

#define REMOVE_PAGES_MAX_BATCH (PAGE_SIZE / sizeof(__u64))

struct he_sigstruct_header {
	__u8 header1[12];
	__u32 types;
	__u32 module_vendor;
	__u32 date;
	__u8 header2[16];
	__u32 hw_version;
	__u8 reserved1[84];
};

struct he_sigstruct_key {
	__u8 modules[HE_MODULUS_SIZE];
	__u8 exponent[4];
	__u8 signature[HE_MODULUS_SIZE];
};

struct he_sigstruct_body {
	__u32 miscselect;
	__u32 misc_mask;
	__u8 reserved[4];
	__u8 isv_family_id[16];
	__u8 attributes[16];
	__u8 attributes_mask[16];
	__u8 mr_enclave[SHA256_HASH_SIZE];
	__u8 reserved2[16];
	__u8 isvext_prod_id[16];
	__u16 isv_prod_id;
	__u16 isv_svn;
};

struct he_sigstruct_buffer {
	__u8 reserved[12];
	__u8 q1[HE_MODULUS_SIZE];
	__u8 q2[HE_MODULUS_SIZE];
};

struct he_sigstruct {
	struct he_sigstruct_header header;
	struct he_sigstruct_key key;
	struct he_sigstruct_body body;
	struct he_sigstruct_buffer buffer;
};

struct he_encl_desc {
	__u64 size;
	__u64 start_gva;
	__u32 ssa_frame_size;
	__u32 miscselect;
	__u8 reserved1[SGX_SECS_RESERVED1_SIZE];
	__u64 attributes;
	__u64 xfrm;
	__u32 mrenclave[8];
	__u8 reserved2[SGX_SECS_RESERVED2_SIZE];
	__u32 mrsigner[8];
	__u32 configid[16];
	__u8 reserved3[SGX_SECS_RESERVED3_SIZE];
	__u16 isvvprodid;
	__u16 isvsvn;
	__u16 configsvn;
	__u8 reserved4[SGX_SECS_RESERVED4_SIZE];
} __aligned(4096);

struct pcmd {
	__u64 secinfo;
	__u64 enclave_id;
	__u32 mac[8];
	__u8 reserved[16];
} __packed;

#define VA_SLOT_COUNT 512

#define PCMD_COUNT (PAGE_SIZE / sizeof(struct pcmd))

enum he_page_type {
	HE_PAGE_TYPE_SECS = 0x00,
	HE_PAGE_TYPE_TCS = 0x01,
	HE_PAGE_TYPE_REG = 0x02,
	HE_PAGE_TYPE_VA = 0x03,
	HE_PAGE_TYPE_TRIM = 0x04,
	HE_PAGE_TYPE_NUM = 0x05,
};

#define HE_PAGE_TYPE_SHIFT_IN_SECINFO (8)

#define HE_SECINFO_PERMISSION_MASK GENMASK_ULL(2, 0)
#define HE_SECINFO_PERMISSION_PAGE_TYPE_MASK GENMASK_ULL(15, 8)

enum he_secinfo_flags {
	HE_SECINFO_R = 0x01,
	HE_SECINFO_W = 0x02,
	HE_SECINFO_X = 0x04,
	HE_SECINFO_SECS = (HE_PAGE_TYPE_SECS << HE_PAGE_TYPE_SHIFT_IN_SECINFO),
	HE_SECINFO_TCS = (HE_PAGE_TYPE_TCS << HE_PAGE_TYPE_SHIFT_IN_SECINFO),
	HE_SECINFO_REG = (HE_PAGE_TYPE_REG << HE_PAGE_TYPE_SHIFT_IN_SECINFO),
	HE_SECINFO_TRIM = (HE_PAGE_TYPE_TRIM << HE_PAGE_TYPE_SHIFT_IN_SECINFO),
};

enum he_return_code {
	NOT_TRACKED = 0x4000000b,
	ENCLAVE_ACT = 0x4000000e,
	PREV_TRK_INCMPL = 0x40000011,
	CANCEL_RECLAIM = 0x4000001d,
};

#endif /* _HYPERENCLAVE_ENCLAVE_CONFIG_H */
