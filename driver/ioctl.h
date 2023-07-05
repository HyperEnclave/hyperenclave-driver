/* SPDX-License-Identifier: GPL-2.0 */
/*
 * HyperEnclave kernel module.
 *
 * Copyright (C) 2020-2023 The HyperEnclave Project. All rights reserved.
 */

#ifndef _DRIVER_IOCTL_H
#define _DRIVER_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

struct he_encl_create {
	__u64 config_address;
};

struct he_encl_add_page {
	__u64 source_address; /* Gva of source page */
	__u64 enclave_lin_addr; /* Gva of target page */
	__u64 flags;
	__u32 attr;
};

struct he_encl_init {
	__u64 addr;
	__u64 sigstruct;
	__u64 einittoken;
};

struct he_memory_info {
	unsigned long start_addr;
	unsigned long size;
	unsigned long encl_addr;
};

struct he_encl_reset_stats {
	__u64 elrange_base_addr;
};

/**
 * struct he_edmm_enabled - parames for ioctl
 *                            %HE_IOC_EDMM_ENABLED
 * @flags:	(output) Whether EDMM is enabled, 1 for enabled, 0 for disabled
 */
struct he_edmm_enabled {
	__u64 flags;
};

/**
 * struct he_hypercall_opcode - parames for ioctl
 *                                %HE_IOC_HYPERCALL_OPCODE
 * @opcode:	(output) The operation code of hyper call on this platform
 */
struct he_hypercall_opcode {
	__u64 opcode;
};

/**
 * struct he_encl_restrict_permissions - parameters for ioctl
 *                                       %HE_IOC_ENCLAVE_RESTRICT_PERMISSIONS
 * @start_addr:	starting linear address (page aligned)
 * @length:	length of memory in bytes (page aligned)
 * @permissions:new permission bits for pages in range described by @start_addr
 *              and @length
 * @result:	(output) HYPER ENCLAVE result code of ENCLS[EMODPR] function
 * @count: 	(output) bytes successfully changed (multiple of page size)
 */
struct he_encl_restrict_permissions {
	__u64 start_addr;
	__u64 length;
	__u64 permissions;
	__u64 result;
	__u64 count;
};

/**
 * struct he_encl_modify_types - parameters for ioctl
 *                               %HE_IOC_ENCLAVE_MODIFY_TYPES
 * @start_addr:	starting linear address (page aligned)
 * @length:	length of memory in bytes (page aligned)
 * @page_type:	new type for pages in range described by @addr and @length
 * @result:	(output) HYPER ENCLAVE result code of ENCLS[EMODT] function
 * @count:	(output) bytes successfully changed (multiple of page size)
 */
struct he_encl_modify_types {
	__u64 start_addr;
	__u64 length;
	__u64 page_type;
	__u64 result;
	__u64 count;
};

/**
 * struct he_encl_remove_pages - %HE_IOC_ENCLAVE_REMOVE_PAGES parameters
 * @start_addr:	starting linear address (page aligned)
 * @length:	length of memory in bytes (page aligned)
 * @count:	(output) bytes successfully changed (multiple of page size)
 *
 * Regular (PT_REG) or TCS (PT_TCS) can be removed from an initialized
 * enclave if the system supports EDMM. First, the %HE_IOC_ENCLAVE_MODIFY_TYPE
 * ioctl() should be used to change the page type to PT_TRIM. After that
 * succeeds ENCLU[EACCEPT] should be run from within the enclave and then
 * %HE_IOC_ENCLAVE_REMOVE_PAGES can be used to complete the page removal.
 */
struct he_encl_remove_pages {
	__u64 start_addr;
	__u64 length;
	__u64 count;
};

#define TEE_MAGIC (0x0)

#define HE_IOC_HYPERCALL_OPCODE _IOW(TEE_MAGIC, 0, struct he_hypercall_opcode)

#define HE_IOC_ENCLAVE_CREATE _IOW(TEE_MAGIC, 7, struct he_encl_create)
#define HE_IOC_ENCLAVE_ADD_PAGE _IOW(TEE_MAGIC, 8, struct he_encl_add_page)
#define HE_IOC_ENCLAVE_INIT _IOW(TEE_MAGIC, 9, struct he_encl_init)

#define HE_IOC_ENCLAVE_ADD_SHARED_MEMORY \
	_IOW(TEE_MAGIC, 12, struct he_memory_info)
#define HE_IOC_ENCLAVE_REMOVE_SHARED_MEMORY \
	_IOW(TEE_MAGIC, 13, struct he_memory_info)
#define HE_IOC_ENCLAVE_RESET_STATS \
	_IOW(TEE_MAGIC, 14, struct he_encl_reset_stats)

#define HE_IOC_EDMM_ENABLED _IOW(TEE_MAGIC, 0x19, struct he_edmm_enabled)
#define HE_IOC_ENCLAVE_RESTRICT_PERMISSIONS \
	_IOW(TEE_MAGIC, 0x20, struct he_encl_restrict_permissions)
#define HE_IOC_ENCLAVE_MODIFY_TYPES \
	_IOW(TEE_MAGIC, 0x21, struct he_encl_modify_types)
#define HE_IOC_ENCLAVE_REMOVE_PAGES \
	_IOW(TEE_MAGIC, 0x22, struct he_encl_remove_pages)

#endif /* !_DRIVER_IOCTL_H */
