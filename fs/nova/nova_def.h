/*
 * FILE NAME include/linux/nova_fs.h
 *
 * BRIEF DESCRIPTION
 *
 * Definitions for the NOVA filesystem.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */
#ifndef _LINUX_NOVA_DEF_H
#define _LINUX_NOVA_DEF_H

#include <linux/types.h>
#include <linux/magic.h>

#define	NOVA_SUPER_MAGIC	0x4E4F5641	/* NOVA */

/*
 * The NOVA filesystem constants/structures
 */

/*
 * Mount flags
 */
#define NOVA_MOUNT_PROTECT      0x000001    /* wprotect CR0.WP */
#define NOVA_MOUNT_XATTR_USER   0x000002    /* Extended user attributes */
#define NOVA_MOUNT_POSIX_ACL    0x000004    /* POSIX Access Control Lists */
#define NOVA_MOUNT_DAX          0x000008    /* Direct Access */
#define NOVA_MOUNT_ERRORS_CONT  0x000010    /* Continue on errors */
#define NOVA_MOUNT_ERRORS_RO    0x000020    /* Remount fs ro on errors */
#define NOVA_MOUNT_ERRORS_PANIC 0x000040    /* Panic on errors */
#define NOVA_MOUNT_HUGEMMAP     0x000080    /* Huge mappings with mmap */
#define NOVA_MOUNT_HUGEIOREMAP  0x000100    /* Huge mappings with ioremap */
#define NOVA_MOUNT_FORMAT       0x000200    /* was FS formatted on mount? */
#define NOVA_MOUNT_DATA_COW     0x000400    /* Copy-on-write for data integrity */

/*
 * Maximal count of links to a file
 */
#define NOVA_LINK_MAX          32000

#define NOVA_DEF_BLOCK_SIZE_4K 4096

#define NOVA_INODE_BITS   7
#define NOVA_INODE_SIZE   128    /* must be power of two */

#define NOVA_NAME_LEN 255

#define MAX_CPUS 1024

/* NOVA supported data blocks */
#define NOVA_BLOCK_TYPE_4K     0
#define NOVA_BLOCK_TYPE_2M     1
#define NOVA_BLOCK_TYPE_1G     2
#define NOVA_BLOCK_TYPE_MAX    3

#define META_BLK_SHIFT 9

/*
 * Play with this knob to change the default block type.
 * By changing the NOVA_DEFAULT_BLOCK_TYPE to 2M or 1G,
 * we should get pretty good coverage in testing.
 */
#define NOVA_DEFAULT_BLOCK_TYPE NOVA_BLOCK_TYPE_4K


/* ======================= Write ordering ========================= */

#define CACHELINE_SIZE  (64)
#define CACHELINE_MASK  (~(CACHELINE_SIZE - 1))
#define CACHELINE_ALIGN(addr) (((addr)+CACHELINE_SIZE-1) & CACHELINE_MASK)


static inline bool arch_has_clwb(void)
{
	return static_cpu_has(X86_FEATURE_CLWB);
}

extern int support_clwb;

#define _mm_clflush(addr)\
	asm volatile("clflush %0" : "+m" (*(volatile char *)(addr)))
#define _mm_clflushopt(addr)\
	asm volatile(".byte 0x66; clflush %0" : "+m" \
		     (*(volatile char *)(addr)))
#define _mm_clwb(addr)\
	asm volatile(".byte 0x66; xsaveopt %0" : "+m" \
		     (*(volatile char *)(addr)))

/* Provides ordering from all previous clflush too */
static inline void PERSISTENT_MARK(void)
{
	/* TODO: Fix me. */
}

static inline void PERSISTENT_BARRIER(void)
{
	asm volatile ("sfence\n" : : );
}

static inline void nova_flush_buffer(void *buf, uint32_t len, bool fence)
{
	uint32_t i;

	len = len + ((unsigned long)(buf) & (CACHELINE_SIZE - 1));
	if (support_clwb) {
		for (i = 0; i < len; i += CACHELINE_SIZE)
			_mm_clwb(buf + i);
	} else {
		for (i = 0; i < len; i += CACHELINE_SIZE)
			_mm_clflush(buf + i);
	}
	/* Do a fence only if asked. We often don't need to do a fence
	 * immediately after clflush because even if we get context switched
	 * between clflush and subsequent fence, the context switch operation
	 * provides implicit fence.
	 */
	if (fence)
		PERSISTENT_BARRIER();
}

/* =============== Integrity and Recovery Parameters =============== */
#define	NOVA_META_CSUM_LEN	(4)
#define	NOVA_DATA_CSUM_LEN	(4)

/* This is to set the initial value of checksum state register.
 * For CRC32C this should not matter and can be set to any value.
 */
#define	NOVA_INIT_CSUM		(1)

#define	ADDR_ALIGN(p, bytes)	((void *) (((unsigned long) p) & ~(bytes - 1)))

/* Data stripe size in bytes and shift.
 * In NOVA this size determines the size of a checksummed stripe, and it
 * equals to the affordable lost size of data per block (page).
 * Its value should be no less than the poison radius size of media errors.
 *
 * Support NOVA_STRIPE_SHIFT <= PAGE_SHIFT (NOVA file block size shift).
 */
#define POISON_RADIUS		(512)
#define POISON_MASK		(~(POISON_RADIUS - 1))
#define NOVA_STRIPE_SHIFT	(9) /* size should be no less than PR_SIZE */
#define NOVA_STRIPE_SIZE	(1 << NOVA_STRIPE_SHIFT)

/* NOVA DEDUP KHJ */
#define NOVA_FACT_ENTRY_SIZE 64

#endif /* _LINUX_NOVA_DEF_H */
