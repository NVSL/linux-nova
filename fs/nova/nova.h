/*
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
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */
#ifndef __NOVA_H
#define __NOVA_H

#include <linux/fs.h>
#include <linux/dax.h>
#include <linux/init.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/backing-dev.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/rcupdate.h>
#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/radix-tree.h>
#include <linux/version.h>
#include <linux/kthread.h>
#include <linux/buffer_head.h>
#include <linux/uio.h>
#include <linux/iomap.h>
#include <linux/crc32c.h>
#include <asm/tlbflush.h>
#include <linux/version.h>
#include <linux/pfn_t.h>
#include <linux/pagevec.h>

#include <linux/rwsem.h>

#include "nova_def.h"
#include "stats.h"
#include "snapshot.h"
#include "debug.h"
#include "vpmem.h"
// #include "bdev.h"

#define PAGE_SHIFT_2M 21
#define PAGE_SHIFT_1G 30

/* Tiering */
/* The maximum size of mini-buffer is the maximum size of kmalloc,
 * which is defined in /include/linux/slab.h (1024 pages).
 */ 
#define	BDEV_BUFFER_PAGES 512
#define	MINI_BUFFER_PAGES 512
#define	MINI_BUFFER_PAGES_BIT 9
#define IO_BLOCK_SIZE 4096
#define IO_BLOCK_SIZE_BIT 12
#define BIO_ASYNC 0
#define BIO_SYNC 1

#define RWSEM_UP 0
#define RWSEM_DOWN 1

/* 
 * Tiering level number
 * If we have 3 block device, then TIER_BDEV_HIGH = 3
 * Assume I/O speed 1>2>3
 */
#define TIER_PMEM 		0
#define TIER_BDEV_LOW 	1
// #define TIER_BDEV_HIGH 	2
#define TIER_DRAM 	 	254
#define TIER_MIGRATING 	255
#define BDEV_COUNT_MAX 	5

#define MIGRATION_ROTATE 1
#define MIGRATION_DOWNWARD 2
#define MIGRATION_POLICY 2

#define BM_THREAD_SLEEP_TIME 1000
#define USAGE_THREAD_SLEEP_TIME 100

/*
 * Debug code
 */
#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif

/* #define nova_dbg(s, args...)		pr_debug(s, ## args) */
#define nova_dbg(s, args ...)		pr_info(s, ## args)
#define nova_dbg1(s, args ...)
#define nova_err(sb, s, args ...)	nova_error_mng(sb, s, ## args)
#define nova_warn(s, args ...)		pr_warn(s, ## args)
#define nova_info(s, args ...)		pr_info(s, ## args)

extern unsigned int nova_dbgmask;
#define NOVA_DBGMASK_MMAPHUGE	       (0x00000001)
#define NOVA_DBGMASK_MMAP4K	       (0x00000002)
#define NOVA_DBGMASK_MMAPVERBOSE       (0x00000004)
#define NOVA_DBGMASK_MMAPVVERBOSE      (0x00000008)
#define NOVA_DBGMASK_VERBOSE	       (0x00000010)
#define NOVA_DBGMASK_TRANSACTION       (0x00000020)

#define nova_dbg_mmap4k(s, args ...)		 \
	((nova_dbgmask & NOVA_DBGMASK_MMAP4K) ? nova_dbg(s, args) : 0)
#define nova_dbg_mmapv(s, args ...)		 \
	((nova_dbgmask & NOVA_DBGMASK_MMAPVERBOSE) ? nova_dbg(s, args) : 0)
#define nova_dbg_mmapvv(s, args ...)		 \
	((nova_dbgmask & NOVA_DBGMASK_MMAPVVERBOSE) ? nova_dbg(s, args) : 0)

#define nova_dbg_verbose(s, args ...)		 \
	((nova_dbgmask & NOVA_DBGMASK_VERBOSE) ? nova_dbg(s, ##args) : 0)
#define nova_dbgv(s, args ...)	nova_dbg_verbose(s, ##args)
#define nova_dbg_trans(s, args ...)		 \
	((nova_dbgmask & NOVA_DBGMASK_TRANSACTION) ? nova_dbg(s, ##args) : 0)

#define NOVA_ASSERT(x) do {\
			       if (!(x))\
				       nova_warn("assertion failed %s:%d: %s\n", \
			       __FILE__, __LINE__, #x);\
		       } while (0)

#define nova_set_bit		       __test_and_set_bit_le
#define nova_clear_bit		       __test_and_clear_bit_le
#define nova_find_next_zero_bit	       find_next_zero_bit_le

#define clear_opt(o, opt)	(o &= ~NOVA_MOUNT_ ## opt)
#define set_opt(o, opt)		(o |= NOVA_MOUNT_ ## opt)
#define test_opt(sb, opt)	(NOVA_SB(sb)->s_mount_opt & NOVA_MOUNT_ ## opt)

#define NOVA_LARGE_INODE_TABLE_SIZE    (0x200000)
/* NOVA size threshold for using 2M blocks for inode table */
#define NOVA_LARGE_INODE_TABLE_THREASHOLD    (0x20000000)
/*
 * nova inode flags
 *
 * NOVA_EOFBLOCKS_FL	There are blocks allocated beyond eof
 */
#define NOVA_EOFBLOCKS_FL      0x20000000
/* Flags that should be inherited by new inodes from their parent. */
#define NOVA_FL_INHERITED (FS_SECRM_FL | FS_UNRM_FL | FS_COMPR_FL | \
			    FS_SYNC_FL | FS_NODUMP_FL | FS_NOATIME_FL |	\
			    FS_COMPRBLK_FL | FS_NOCOMP_FL | \
			    FS_JOURNAL_DATA_FL | FS_NOTAIL_FL | FS_DIRSYNC_FL)
/* Flags that are appropriate for regular files (all but dir-specific ones). */
#define NOVA_REG_FLMASK (~(FS_DIRSYNC_FL | FS_TOPDIR_FL))
/* Flags that are appropriate for non-directories/regular files. */
#define NOVA_OTHER_FLMASK (FS_NODUMP_FL | FS_NOATIME_FL)
#define NOVA_FL_USER_VISIBLE (FS_FL_USER_VISIBLE | NOVA_EOFBLOCKS_FL)

/* IOCTLs */
#define	NOVA_PRINT_TIMING		0xBCD00010
#define	NOVA_CLEAR_STATS		0xBCD00011
#define	NOVA_PRINT_LOG			0xBCD00013
#define	NOVA_PRINT_LOG_BLOCKNODE	0xBCD00014
#define	NOVA_PRINT_LOG_PAGES		0xBCD00015
#define	NOVA_PRINT_FREE_LISTS		0xBCD00018


#define	READDIR_END			(ULONG_MAX)
#define	INVALID_CPU			(-1)
#define	ANY_CPU				(65536)
#define	FREE_BATCH			(16)
#define	DEAD_ZONE_BLOCKS		(256)

extern int measure_timing;
extern int metadata_csum;
extern int unsafe_metadata;
extern int inplace_data_updates;
extern int wprotect;
extern int data_csum;
extern int data_parity;
extern int dram_struct_csum;

extern int TIER_BDEV_HIGH;
extern int MIGRATION_DOWN_PMEM_PERC;
extern int VPMEM_MAX_PAGES_QTR;
extern int BDEV_OPT_SIZE_BIT;

extern unsigned int blk_type_to_shift[NOVA_BLOCK_TYPE_MAX];
extern unsigned int blk_type_to_size[NOVA_BLOCK_TYPE_MAX];



#define	MMAP_WRITE_BIT	0x20UL	// mmaped for write
#define	IS_MAP_WRITE(p)	((p) & (MMAP_WRITE_BIT))
#define	MMAP_ADDR(p)	((p) & (PAGE_MASK))


/* Mask out flags that are inappropriate for the given type of inode. */
static inline __le32 nova_mask_flags(umode_t mode, __le32 flags)
{
	flags &= cpu_to_le32(NOVA_FL_INHERITED);
	if (S_ISDIR(mode))
		return flags;
	else if (S_ISREG(mode))
		return flags & cpu_to_le32(NOVA_REG_FLMASK);
	else
		return flags & cpu_to_le32(NOVA_OTHER_FLMASK);
}

/* Update the crc32c value by appending a 64b data word. */
#define nova_crc32c_qword(qword, crc) do { \
	asm volatile ("crc32q %1, %0" \
		: "=r" (crc) \
		: "r" (qword), "0" (crc)); \
	} while (0)

static inline u32 nova_crc32c(u32 crc, const u8 *data, size_t len)
{
	u8 *ptr = (u8 *) data;
	u64 acc = crc; /* accumulator, crc32c value in lower 32b */
	u32 csum;

	/* x86 instruction crc32 is part of SSE-4.2 */
	if (static_cpu_has(X86_FEATURE_XMM4_2)) {
		/* This inline assembly implementation should be equivalent
		 * to the kernel's crc32c_intel_le_hw() function used by
		 * crc32c(), but this performs better on test machines.
		 */
		while (len > 8) {
			asm volatile(/* 64b quad words */
				"crc32q (%1), %0"
				: "=r" (acc)
				: "r"  (ptr), "0" (acc)
			);
			ptr += 8;
			len -= 8;
		}

		while (len > 0) {
			asm volatile(/* trailing bytes */
				"crc32b (%1), %0"
				: "=r" (acc)
				: "r"  (ptr), "0" (acc)
			);
			ptr++;
			len--;
		}

		csum = (u32) acc;
	} else {
		/* The kernel's crc32c() function should also detect and use the
		 * crc32 instruction of SSE-4.2. But calling in to this function
		 * is about 3x to 5x slower than the inline assembly version on
		 * some test machines.
		 */
		csum = crc32c(crc, data, len);
	}

	return csum;
}

/* uses CPU instructions to atomically write up to 8 bytes */
static inline void nova_memcpy_atomic(void *dst, const void *src, u8 size)
{
	switch (size) {
	case 1: {
		volatile u8 *daddr = dst;
		const u8 *saddr = src;
		*daddr = *saddr;
		break;
	}
	case 2: {
		volatile __le16 *daddr = dst;
		const u16 *saddr = src;
		*daddr = cpu_to_le16(*saddr);
		break;
	}
	case 4: {
		volatile __le32 *daddr = dst;
		const u32 *saddr = src;
		*daddr = cpu_to_le32(*saddr);
		break;
	}
	case 8: {
		volatile __le64 *daddr = dst;
		const u64 *saddr = src;
		*daddr = cpu_to_le64(*saddr);
		break;
	}
	default:
		nova_dbg("error: memcpy_atomic called with %d bytes\n", size);
		//BUG();
	}
}

static inline int memcpy_to_pmem_nocache(void *dst, const void *src,
	unsigned int size)
{
	int ret;
	
	ret = __copy_from_user_inatomic_nocache(dst, src, size);

	return ret;
}


/* assumes the length to be 4-byte aligned */
static inline void memset_nt(void *dest, uint32_t dword, size_t length)
{
	uint64_t dummy1, dummy2;
	uint64_t qword = ((uint64_t)dword << 32) | dword;

	asm volatile ("movl %%edx,%%ecx\n"
		"andl $63,%%edx\n"
		"shrl $6,%%ecx\n"
		"jz 9f\n"
		"1:	 movnti %%rax,(%%rdi)\n"
		"2:	 movnti %%rax,1*8(%%rdi)\n"
		"3:	 movnti %%rax,2*8(%%rdi)\n"
		"4:	 movnti %%rax,3*8(%%rdi)\n"
		"5:	 movnti %%rax,4*8(%%rdi)\n"
		"8:	 movnti %%rax,5*8(%%rdi)\n"
		"7:	 movnti %%rax,6*8(%%rdi)\n"
		"8:	 movnti %%rax,7*8(%%rdi)\n"
		"leaq 64(%%rdi),%%rdi\n"
		"decl %%ecx\n"
		"jnz 1b\n"
		"9:	movl %%edx,%%ecx\n"
		"andl $7,%%edx\n"
		"shrl $3,%%ecx\n"
		"jz 11f\n"
		"10:	 movnti %%rax,(%%rdi)\n"
		"leaq 8(%%rdi),%%rdi\n"
		"decl %%ecx\n"
		"jnz 10b\n"
		"11:	 movl %%edx,%%ecx\n"
		"shrl $2,%%ecx\n"
		"jz 12f\n"
		"movnti %%eax,(%%rdi)\n"
		"12:\n"
		: "=D"(dummy1), "=d" (dummy2)
		: "D" (dest), "a" (qword), "d" (length)
		: "memory", "rcx");
}

#include "super.h" // Remove when we factor out these and other functions.

/* Translate an offset the beginning of the Nova instance to a PMEM address.
 *
 * If this is part of a read-modify-write of the block,
 * nova_memunlock_block() before calling!
 */

static inline bool is_logical_offset(struct nova_sb_info *sbi, unsigned long block) {
	if (block >= (sbi->num_blocks << PAGE_SHIFT)) return true;
	else return false;
}

static inline void *nova_get_block(struct super_block *sb, u64 block)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *ps = nova_get_super(sb);
	if (is_logical_offset(sbi, le64_to_cpu(block))){
		return block ? ((void *)block_to_virt(le64_to_cpu(block))) : NULL;
	}
	else
		return block ? ((void *)ps + block) : NULL;
}

static inline int nova_get_reference(struct super_block *sb, u64 block,
	void *dram, void **nvmm, size_t size)
{
	int rc;

	*nvmm = nova_get_block(sb, block);
	rc = memcpy_mcsafe(dram, *nvmm, size);
	return rc;
}

/* TODOzsa: 
 * 		This is no longer correct in tiering NOVA.
 * 		However, if we only have data blocks in BDEV, 
 * 		this function will not cause any trouble.
 */
static inline u64
nova_get_addr_off(struct nova_sb_info *sbi, void *addr)
{
	// NOVA_ASSERT((addr >= sbi->virt_addr) &&
	// 		(addr < (sbi->virt_addr + sbi->initsize)));
	return (u64)(addr - sbi->virt_addr);
}

// Change block number to a logical offset
static inline u64
nova_get_block_off(struct super_block *sb, unsigned long blocknr,
		    unsigned short btype)
{
	return (u64)blocknr << PAGE_SHIFT;
}


static inline u64 nova_get_epoch_id(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	return sbi->s_epoch_id;
}

static inline void nova_print_curr_epoch_id(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u64 ret;

	ret = sbi->s_epoch_id;
	nova_dbg("Current epoch id: %llu\n", ret);
}

#include "inode.h"
static inline int nova_get_head_tail(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih)
{
	struct nova_inode fake_pi;
	int rc;

	rc = memcpy_mcsafe(&fake_pi, pi, sizeof(struct nova_inode));
	if (rc)
		return rc;

	sih->i_blk_type = fake_pi.i_blk_type;
	sih->log_head = fake_pi.log_head;
	sih->log_tail = fake_pi.log_tail;
	sih->alter_log_head = fake_pi.alter_log_head;
	sih->alter_log_tail = fake_pi.alter_log_tail;

	return rc;
}

struct nova_range_node_lowhigh {
	__le64 range_low;
	__le64 range_high;
};

#define	RANGENODE_PER_PAGE	254

/* A node in the RB tree representing a range of pages */
struct nova_range_node {
	struct rb_node node;
	struct vm_area_struct *vma;
	unsigned long mmap_entry;
	unsigned long range_low;
	unsigned long range_high;
	u32	csum;		/* Protect vma, range low/high */
};

struct vma_item {
	/* Reuse header of nova_range_node struct */
	struct rb_node node;
	struct vm_area_struct *vma;
	unsigned long mmap_entry;
};

static inline u32 nova_calculate_range_node_csum(struct nova_range_node *node)
{
	u32 crc;

	crc = nova_crc32c(~0, (__u8 *)&node->vma,
			(unsigned long)&node->csum - (unsigned long)&node->vma);

	return crc;
}

static inline int nova_update_range_node_checksum(struct nova_range_node *node)
{
	if (dram_struct_csum)
		node->csum = nova_calculate_range_node_csum(node);

	return 0;
}

static inline bool nova_range_node_checksum_ok(struct nova_range_node *node)
{
	bool ret;

	if (dram_struct_csum == 0)
		return true;

	ret = node->csum == nova_calculate_range_node_csum(node);
	if (!ret) {
		nova_dbg("%s: checksum failure, vma %p, range low %lu, range high %lu, csum 0x%x\n",
			 __func__, node->vma, node->range_low, node->range_high,
			 node->csum);
	}

	return ret;
}


enum bm_type {
	BM_4K = 0,
	BM_2M,
	BM_1G,
};

struct single_scan_bm {
	unsigned long bitmap_size;
	unsigned long *bitmap;
};

struct scan_bitmap {
	struct single_scan_bm scan_bm_4K;
	struct single_scan_bm scan_bm_2M;
	struct single_scan_bm scan_bm_1G;
};

struct inode_map {
	struct mutex		inode_table_mutex;
	struct rb_root		inode_inuse_tree;
	unsigned long		num_range_node_inode;
	struct nova_range_node *first_inode_range;
	int			allocated;
	int			freed;
};

/* Old entry is freeable if it is appended after the latest snapshot */
static inline int old_entry_freeable(struct super_block *sb, u64 epoch_id)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (epoch_id == sbi->s_epoch_id)
		return 1;

	return 0;
}

static inline int pass_mount_snapshot(struct super_block *sb, u64 epoch_id)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (epoch_id > sbi->mount_snapshot_epoch_id)
		return 1;

	return 0;
}


// BKDR String Hash Function
static inline unsigned long BKDRHash(const char *str, int length)
{
	unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
	unsigned long hash = 0;
	int i;

	for (i = 0; i < length; i++)
		hash = hash * seed + (*str++);

	return hash;
}

// Tiering

inline unsigned long nova_get_bdev_block_start(struct nova_sb_info *sbi, int tier);
inline unsigned long nova_get_bdev_block_end(struct nova_sb_info *sbi, int tier);

static inline bool is_tier_dram(int tier) {
	return (tier == TIER_PMEM);
}

static inline bool is_tier_pmem(int tier) {
	return (tier == TIER_PMEM);
}

static inline bool is_tier_bdev_low(int tier) {
	return (tier == TIER_BDEV_LOW);
}

static inline bool is_tier_bdev(int tier) {
	return (tier >= TIER_BDEV_LOW && tier <= TIER_BDEV_HIGH);
}

static inline unsigned long global_block_index(struct nova_sb_info *sbi,
	int tier, unsigned long local_block_index) {
	if (is_tier_pmem(tier)) return local_block_index;
	if (is_tier_bdev(tier)) {
		return nova_get_bdev_block_start(sbi, tier) + local_block_index;
	}
}

static inline unsigned long nova_tier_start_block(struct nova_sb_info *sbi,
	int tier) {
	if (is_tier_pmem(tier)) return 0;
	if (is_tier_bdev(tier)) {
		return nova_get_bdev_block_start(sbi, tier);
	}
	return 0;
}

static inline unsigned long nova_tier_end_block(struct nova_sb_info *sbi,
	int tier) {
	if (is_tier_pmem(tier)) return sbi->num_blocks;
	if (is_tier_bdev(tier)) {
		return nova_get_bdev_block_end(sbi, tier);
	}
	return 0;
}

// Background migration thread
struct nova_kthread {
	struct task_struct *nova_task;
	int index;
	int stage;
	wait_queue_head_t wait_queue_head;
};

#include "mprotect.h"

#include "log.h"

#include "balloc.h"

static inline struct nova_file_write_entry *
nova_get_or_lock_write_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long blocknr, int lock)
{
	struct nova_file_write_entry *entry;
	void **entryp;

	rcu_read_lock();
repeat:
	entry = NULL;
	entryp = radix_tree_lookup_slot(&sih->tree, blocknr);
	if (entryp) {
		entry = radix_tree_deref_slot(entryp);
		if (unlikely(!entry))
			goto out;

		if (radix_tree_exception(entry)) {
			if (radix_tree_deref_retry(entry)) {
				goto repeat;
			}

			/* FIXME: What to do here? */
			entry = NULL;
			goto out;
		}

		if (lock) {
			if (!lock_write_entry(entry)) {
				goto repeat;
			}
		} else {
			if (!get_write_entry(entry)) {
				goto repeat;
			}
		}

		if (unlikely(entry != *entryp)) {
			put_write_entry(entry);
			goto repeat;
		}
	}
out:
	rcu_read_unlock();

	return entry;
}

static inline struct nova_file_write_entry *
nova_get_write_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long blocknr)
{
	return nova_get_or_lock_write_entry(sb, sih, blocknr, 0);
}

static inline struct nova_file_write_entry *
nova_lock_write_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long blocknr)
{
	return nova_get_or_lock_write_entry(sb, sih, blocknr, 1);
}

static inline struct nova_file_write_entry *
nova_get_write_entry_lockfree(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long blocknr)
{
	struct nova_file_write_entry *entry;

	entry = radix_tree_lookup(&sih->tree, blocknr);

	return entry;
}


int buffer_data_block_from_bdev_range(struct nova_sb_info *sbi, int tier, int blockoff, int length);
void nova_update_entry_csum(void *entry);
int get_tier(struct nova_sb_info *sbi, unsigned long blocknr);
inline int get_entry_tier(struct nova_file_write_entry *entry);
void print_a_write_entry(struct super_block *sb, struct nova_file_write_entry *entry, int n);
void print_a_write_entry_data(struct super_block *sb, void* addr, int n);
void print_a_page(void* addr);

/*
 * Find data at a file offset (pgoff) in the data pointed to by a write log
 * entry.
 */
static unsigned long get_nvmm(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry, unsigned long pgoff)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long ret = 0;

	/* entry is already verified before this call and resides in dram
	 * or we can do memcpy_mcsafe here but have to avoid double copy and
	 * verification of the entry.
	 */
	
retry:
	if (unlikely(nova_get_entry_type(entry) == FILE_WRITE && entry->updating == 1)) {
		// This should not happen
		nova_info("Error: get_nvmm(): Entry is being updated\n");
		msleep(500);
		goto retry;
	}

	if ( get_entry_tier(entry) != TIER_PMEM ) {
		if (DEBUG_GET_NVMM) nova_info("[Get_nvmm] Get from TIER_BDEV\n");
		ret = (unsigned long) (entry->block >> PAGE_SHIFT) + pgoff
			- entry->pgoff;
		if (DEBUG_GET_NVMM) nova_info("ret %lu %lx block %llu num %d\n", ret,
			(unsigned long)sbi->vpmem,entry->block >> PAGE_SHIFT,entry->num_pages);
		return ret;
	}
	else {
		if (DEBUG_GET_NVMM) nova_info("[Get_nvmm] Get from TIER_PMEM\n");
		if (entry->pgoff > pgoff || (unsigned long) entry->pgoff +
				(unsigned long) entry->num_pages <= pgoff) {
			struct nova_sb_info *sbi = NOVA_SB(sb);
			u64 curr;
			if (DEBUG_GET_NVMM) {
				nova_info("Entry: %p", entry);
				print_a_write_entry(sb, entry, -2);
			}
			
			curr = nova_get_addr_off(sbi, entry);
			nova_dbg("Entry ERROR: inode %lu, curr 0x%llx(%p), pgoff %lu, entry pgoff %llu, num %u\n",
				sih->ino,
				curr, entry, pgoff, entry->pgoff, entry->num_pages);
			nova_print_nova_log_pages(sb, sih);
			nova_print_nova_log(sb, sih);
			NOVA_ASSERT(0);
		}

		return (unsigned long) (entry->block >> PAGE_SHIFT) + pgoff
			- entry->pgoff;
	}
	return 0;
}

bool nova_verify_entry_csum(struct super_block *sb, void *entry, void *entryc);

static inline u64 nova_find_nvmm_block(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	unsigned long blocknr)
{
	unsigned long nvmm;
	struct nova_file_write_entry *entryc, entry_copy;

	if (!entry) {
		entry = nova_get_write_entry_lockfree(sb, sih, blocknr);
		if (!entry)
			return 0;
	}

	/* Don't check entry here as someone else may be modifying it
	 * when called from reset_vma_csum_parity
	 */
	entryc = &entry_copy;
	if (memcpy_mcsafe(entryc, entry,
			sizeof(struct nova_file_write_entry)) < 0)
		return 0;

	nvmm = get_nvmm(sb, sih, entryc, blocknr);
	return nvmm << PAGE_SHIFT;
}



static inline unsigned long
nova_get_numblocks(unsigned short btype)
{
	unsigned long num_blocks;

	if (btype == NOVA_BLOCK_TYPE_4K) {
		num_blocks = 1;
	} else if (btype == NOVA_BLOCK_TYPE_2M) {
		num_blocks = 512;
	} else {
		//btype == NOVA_BLOCK_TYPE_1G
		num_blocks = 0x40000;
	}
	return num_blocks;
}

static inline unsigned long
nova_get_blocknr(struct super_block *sb, u64 block, unsigned short btype)
{
	return block >> PAGE_SHIFT;
}

static inline unsigned long nova_get_pfn(struct super_block *sb, u64 block)
{
	return (NOVA_SB(sb)->phys_addr + block) >> PAGE_SHIFT;
}

static inline u64 next_log_page(struct super_block *sb, u64 curr)
{
	struct nova_inode_log_page *curr_page;
	u64 next = 0;
	int rc;

	curr = BLOCK_OFF(curr);
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr);
	rc = memcpy_mcsafe(&next, &curr_page->page_tail.next_page,
				sizeof(u64));
	if (rc)
		return rc;

	return next;
}

static inline u64 alter_log_page(struct super_block *sb, u64 curr)
{
	struct nova_inode_log_page *curr_page;
	u64 next = 0;
	int rc;

	if (metadata_csum == 0)
		return 0;

	curr = BLOCK_OFF(curr);
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr);
	rc = memcpy_mcsafe(&next, &curr_page->page_tail.alter_page,
				sizeof(u64));
	if (rc)
		return rc;

	return next;
}

#if 0
static inline u64 next_log_page(struct super_block *sb, u64 curr_p)
{
	void *curr_addr = nova_get_block(sb, curr_p);
	unsigned long page_tail = BLOCK_OFF((unsigned long)curr_addr)
					+ LOG_BLOCK_TAIL;
	return ((struct nova_inode_page_tail *)page_tail)->next_page;
}

static inline u64 alter_log_page(struct super_block *sb, u64 curr_p)
{
	void *curr_addr = nova_get_block(sb, curr_p);
	unsigned long page_tail = BLOCK_OFF((unsigned long)curr_addr)
					+ LOG_BLOCK_TAIL;
	if (metadata_csum == 0)
		return 0;

	return ((struct nova_inode_page_tail *)page_tail)->alter_page;
}
#endif

static inline u64 alter_log_entry(struct super_block *sb, u64 curr_p)
{
	u64 alter_page;
	void *curr_addr = nova_get_block(sb, curr_p);
	unsigned long page_tail = BLOCK_OFF((unsigned long)curr_addr)
					+ LOG_BLOCK_TAIL;
	if (metadata_csum == 0)
		return 0;

	alter_page = ((struct nova_inode_page_tail *)page_tail)->alter_page;
	return alter_page + ENTRY_LOC(curr_p);
}

static inline void nova_set_next_page_flag(struct super_block *sb, u64 curr_p)
{
	void *p;

	if (ENTRY_LOC(curr_p) >= LOG_BLOCK_TAIL)
		return;

	p = nova_get_block(sb, curr_p);
	nova_set_entry_type(p, NEXT_PAGE);
	nova_flush_buffer(p, CACHELINE_SIZE, 1);
}

static inline void nova_set_next_page_address(struct super_block *sb,
	struct nova_inode_log_page *curr_page, u64 next_page, int fence)
{
	curr_page->page_tail.next_page = next_page;
	nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);
	if (fence)
		PERSISTENT_BARRIER();
}

static inline void nova_set_page_num_entries(struct super_block *sb,
	struct nova_inode_log_page *curr_page, int num, int flush)
{
	curr_page->page_tail.num_entries = num;
	if (flush)
		nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);
}

static inline void nova_set_page_invalid_entries(struct super_block *sb,
	struct nova_inode_log_page *curr_page, int num, int flush)
{
	curr_page->page_tail.invalid_entries = num;
	if (flush)
		nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);
}

static inline void nova_inc_page_num_entries(struct super_block *sb,
	u64 curr)
{
	struct nova_inode_log_page *curr_page;

	curr = BLOCK_OFF(curr);
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr);

	curr_page->page_tail.num_entries++;
	nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);
}

u64 nova_print_log_entry(struct super_block *sb, u64 curr);

static inline void nova_inc_page_invalid_entries(struct super_block *sb,
	u64 curr)
{
	struct nova_inode_log_page *curr_page;
	u64 old_curr = curr;

	curr = BLOCK_OFF(curr);
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr);

	curr_page->page_tail.invalid_entries++;
	if (curr_page->page_tail.invalid_entries >
			curr_page->page_tail.num_entries) {
		nova_dbg("Page 0x%llx has %u entries, %u invalid\n",
				curr,
				curr_page->page_tail.num_entries,
				curr_page->page_tail.invalid_entries);
		nova_print_log_entry(sb, old_curr);
	}

	nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);
}

static inline void nova_set_alter_page_address(struct super_block *sb,
	u64 curr, u64 alter_curr)
{
	struct nova_inode_log_page *curr_page;
	struct nova_inode_log_page *alter_page;

	if (metadata_csum == 0)
		return;

	curr_page = nova_get_block(sb, BLOCK_OFF(curr));
	alter_page = nova_get_block(sb, BLOCK_OFF(alter_curr));

	curr_page->page_tail.alter_page = alter_curr;
	nova_flush_buffer(&curr_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);

	alter_page->page_tail.alter_page = curr;
	nova_flush_buffer(&alter_page->page_tail,
				sizeof(struct nova_inode_page_tail), 0);
}

#define	CACHE_ALIGN(p)	((p) & ~(CACHELINE_SIZE - 1))

static inline bool is_last_entry(u64 curr_p, size_t size)
{
	unsigned int entry_end;

	entry_end = ENTRY_LOC(curr_p) + size;

	return entry_end > LOG_BLOCK_TAIL;
}

static inline bool goto_next_page(struct super_block *sb, u64 curr_p)
{
	void *addr;
	u8 type;
	int rc;

	/* Each kind of entry takes at least 32 bytes */
	if (ENTRY_LOC(curr_p) + 32 > LOG_BLOCK_TAIL)
		return true;

	addr = nova_get_block(sb, curr_p);
	rc = memcpy_mcsafe(&type, addr, sizeof(u8));

	if (rc < 0)
		return true;

	if (type == NEXT_PAGE)
		return true;

	return false;
}

static inline int is_dir_init_entry(struct super_block *sb,
	struct nova_dentry *entry)
{
	if (entry->name_len == 1 && strncmp(entry->name, ".", 1) == 0)
		return 1;
	if (entry->name_len == 2 && strncmp(entry->name, "..", 2) == 0)
		return 1;

	return 0;
}

/* Checksum methods */
static inline void *nova_get_data_csum_addr(struct super_block *sb, u64 strp_nr,
	int replica)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	unsigned long blocknr;
	void *data_csum_addr;
	u64 blockoff;
	int index;
	int BLOCK_SHIFT = PAGE_SHIFT - NOVA_STRIPE_SHIFT;

	if (!data_csum) {
		nova_dbg("%s: Data checksum is disabled!\n", __func__);
		return NULL;
	}

	blocknr = strp_nr >> BLOCK_SHIFT;
	index = blocknr / sbi->per_list_blocks;

	if (index >= sbi->cpus) {
		nova_dbg("%s: Invalid blocknr %lu\n", __func__, blocknr);
		return NULL;
	}

	strp_nr -= (index * sbi->per_list_blocks) << BLOCK_SHIFT;
	free_list = nova_get_free_list(sb, index);
	if (replica == 0)
		blockoff = free_list->csum_start << PAGE_SHIFT;
	else
		blockoff = free_list->replica_csum_start << PAGE_SHIFT;

	/* Range test */
	if (((NOVA_DATA_CSUM_LEN * strp_nr) >> PAGE_SHIFT) >=
			free_list->num_csum_blocks) {
		nova_dbg("%s: Invalid strp number %llu, free list %d\n",
				__func__, strp_nr, free_list->index);
		return NULL;
	}

	data_csum_addr = (u8 *) nova_get_block(sb, blockoff)
				+ NOVA_DATA_CSUM_LEN * strp_nr;

	return data_csum_addr;
}

static inline void *nova_get_parity_addr(struct super_block *sb,
	unsigned long blocknr)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	void *data_csum_addr;
	u64 blockoff;
	int index;
	int BLOCK_SHIFT = PAGE_SHIFT - NOVA_STRIPE_SHIFT;

	if (data_parity == 0) {
		nova_dbg("%s: Data parity is disabled!\n", __func__);
		return NULL;
	}

	index = blocknr / sbi->per_list_blocks;

	if (index >= sbi->cpus) {
		nova_dbg("%s: Invalid blocknr %lu\n", __func__, blocknr);
		return NULL;
	}

	free_list = nova_get_free_list(sb, index);
	blockoff = free_list->parity_start << PAGE_SHIFT;

	/* Range test */
	if (((blocknr - free_list->block_start) >> BLOCK_SHIFT) >=
			free_list->num_parity_blocks) {
		nova_dbg("%s: Invalid blocknr %lu, free list %d\n",
				__func__, blocknr, free_list->index);
		return NULL;
	}

	data_csum_addr = (u8 *) nova_get_block(sb, blockoff) +
				((blocknr - free_list->block_start)
				 << NOVA_STRIPE_SHIFT);

	return data_csum_addr;
}

/* Function Prototypes */

/* balloc.c */
int nova_free_blocks(struct super_block *sb, unsigned long blocknr,
	int num, unsigned short btype, int log_page);
long nova_alloc_blocks_in_free_list(struct super_block *sb,
	struct free_list *free_list, unsigned short btype,
	enum alloc_type atype, unsigned long num_blocks,
	unsigned long *new_blocknr, enum nova_alloc_direction from_tail,
	bool contiguous);
int nova_new_blocks(struct super_block *sb, unsigned long *blocknr,
	unsigned int num, unsigned short btype, int zero,
	enum alloc_type atype, int cpuid, enum nova_alloc_direction from_tail,
	bool contiguous);
	
/* bbuild.c */
inline void set_bm(unsigned long bit, struct scan_bitmap *bm,
	enum bm_type type);
inline int get_cpuid(struct nova_sb_info *sbi, unsigned long blocknr);
void nova_save_blocknode_mappings_to_log(struct super_block *sb);
void nova_save_inode_list_to_log(struct super_block *sb);
void nova_init_header(struct super_block *sb,
	struct nova_inode_info_header *sih, u16 i_mode);
int nova_recovery(struct super_block *sb);

/* bdev.c */
int nova_init_bio(void);
int nova_destroy_bio(void);
int nova_init_tiering_stat(struct super_block *sb);
int flush_bal_entry(struct nova_sb_info *sbi);
int nova_alloc_bdev_block_free_lists(struct super_block *sb);
void nova_init_bdev_blockmap(struct super_block *sb, int recovery);
unsigned long get_start_offset_of_tier(struct nova_sb_info *sbi, int tier);
long nova_new_blocks_from_bdev(struct super_block *sb, int tier, 
	unsigned long *blocknr,	unsigned int num_blocks, int cpuid, 
	enum nova_alloc_direction from_tail, bool cache);
int get_bfl_index(struct nova_sb_info *sbi, unsigned long blocknr);
int get_tier_cpu(struct nova_sb_info *sbi, unsigned long blocknr);
inline int get_tier_range_node(struct nova_sb_info *sbi, 
	struct nova_range_node* nrn);
int get_suitable_tier(struct super_block *sb, unsigned long num_blocks);
inline unsigned long get_raw_from_blocknr(struct nova_sb_info *sbi, 
	unsigned long blocknr);
inline unsigned long get_blocknr_from_raw(struct nova_sb_info *sbi, int tier, 
	unsigned long blocknr);
int nova_bdev_write_block(struct nova_sb_info *sbi, struct block_device *device, 
	unsigned long offset, unsigned long size, struct page *page, bool sync);
inline int nova_bdev_write_block_range(struct nova_sb_info *sbi, struct block_device *device, 
	unsigned long offset, int count, struct page **page, bool sync);
int nova_bdev_read_block(struct nova_sb_info *sbi, struct block_device *device,
	unsigned long offset, unsigned long size, struct page *page, bool sync);
inline int nova_bdev_read_block_range(struct nova_sb_info *sbi, struct block_device *device, 
	unsigned long offset, int count, struct page **page, bool sync);
int nova_bdev_write_blockoff(struct nova_sb_info *sbi, unsigned long blockoff, 
	unsigned long size, struct page *page, bool sync);
int nova_bdev_read_blockoff(struct nova_sb_info *sbi, unsigned long blockoff, 
	unsigned long size, struct page *page, bool sync);
int nova_free_blocks_from_bdev(struct nova_sb_info *sbi, unsigned long blocknr,
	unsigned long num_blocks);
int nova_bdev_free_blocks(struct nova_sb_info *sbi, int tier, unsigned long blocknr,
	unsigned long num_blocks);
int nova_free_blocks_tier(struct nova_sb_info *sbi, unsigned long blocknr,
	unsigned long num_blocks);
int reclaim_get_nvmm(struct super_block *sb, unsigned long nvmm,
	struct nova_file_write_entry *entry, unsigned long pgoff);
void print_all_bfl(struct super_block *sb);
long nova_alloc_block_tier(struct nova_sb_info *sbi, int tier, int cpuid, unsigned long *blocknr,
	unsigned int num_blocks, enum nova_alloc_direction from_tail, bool cache);

/* checksum.c */
void nova_update_entry_csum(void *entry);
int nova_update_block_csum(struct super_block *sb,
	struct nova_inode_info_header *sih, u8 *block, unsigned long blocknr,
	size_t offset, size_t bytes, int zero);
int nova_update_alter_entry(struct super_block *sb, void *entry);
int nova_check_inode_integrity(struct super_block *sb, u64 ino, u64 pi_addr,
	u64 alter_pi_addr, struct nova_inode *pic, int check_replica);
int nova_update_pgoff_csum(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	unsigned long pgoff, int zero);
bool nova_verify_data_csum(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long blocknr,
	size_t offset, size_t bytes);
int nova_update_truncated_block_csum(struct super_block *sb,
	struct inode *inode, loff_t newsize);

/*
 * Inodes and files operations
 */

/* dax.c */
int nova_cleanup_incomplete_write(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long blocknr,
	int allocated, u64 begin_tail, u64 end_tail);
void nova_init_file_write_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	u64 epoch_id, u64 pgoff, int num_pages, u64 blocknr, u32 time,
	u64 size);
int nova_reassign_file_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 begin_tail, bool free);
unsigned long nova_check_existing_entry(struct super_block *sb,
	struct inode *inode, unsigned long num_blocks, unsigned long start_blk,
	struct nova_file_write_entry **ret_entry,
	struct nova_file_write_entry *ret_entryc, int check_next, u64 epoch_id,
	int *inplace, int locked);
int nova_dax_get_blocks(struct inode *inode, sector_t iblock,
	unsigned long max_blocks, u32 *bno, bool *new, bool *boundary,
	int create, bool taking_lock);
int nova_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
	unsigned int flags, struct iomap *iomap, bool taking_lock);
int nova_iomap_end(struct inode *inode, loff_t offset, loff_t length,
	ssize_t written, unsigned int flags, struct iomap *iomap);
int nova_insert_write_vma(struct vm_area_struct *vma);

int nova_check_overlap_vmas(struct super_block *sb,
			    struct nova_inode_info_header *sih,
			    unsigned long pgoff, unsigned long num_pages);
int nova_handle_head_tail_blocks(struct super_block *sb,
				 struct inode *inode, loff_t pos,
				 size_t count, void *kmem);
int nova_protect_file_data(struct super_block *sb, struct inode *inode,
	loff_t pos, size_t count, const char __user *buf, unsigned long blocknr,
	bool inplace);
ssize_t nova_inplace_file_write(struct file *filp, const char __user *buf,
				size_t len, loff_t *ppos);
ssize_t do_nova_inplace_file_write(struct file *filp, const char __user *buf,
				   size_t len, loff_t *ppos);

extern const struct vm_operations_struct nova_dax_vm_ops;


/* dir.c */
extern const struct file_operations nova_dir_operations;
int nova_insert_dir_radix_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, const char *name,
	int namelen, struct nova_dentry *direntry);
int nova_remove_dir_radix_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, const char *name, int namelen,
	int replay, struct nova_dentry **create_dentry);
int nova_append_dentry(struct super_block *sb, struct nova_inode *pi,
	struct inode *dir, struct dentry *dentry, u64 ino,
	unsigned short de_len, struct nova_inode_update *update,
	int link_change, u64 epoch_id);
int nova_append_dir_init_entries(struct super_block *sb,
	struct nova_inode *pi, u64 self_ino, u64 parent_ino, u64 epoch_id);
int nova_add_dentry(struct dentry *dentry, u64 ino, int inc_link,
	struct nova_inode_update *update, u64 epoch_id);
int nova_remove_dentry(struct dentry *dentry, int dec_link,
	struct nova_inode_update *update, u64 epoch_id);
int nova_invalidate_dentries(struct super_block *sb,
	struct nova_inode_update *update);
void nova_print_dir_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long ino);
void nova_delete_dir_tree(struct super_block *sb,
	struct nova_inode_info_header *sih);
struct nova_dentry *nova_find_dentry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode, const char *name,
	unsigned long name_len);

/* file.c */
extern const struct inode_operations nova_file_inode_operations;
extern const struct file_operations nova_dax_file_operations;
extern const struct file_operations nova_wrap_file_operations;


/* gc.c */
int nova_inode_log_fast_gc(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	u64 curr_tail, u64 new_block, u64 alter_new_block, int num_pages,
	int force_thorough);
int nova_inode_log_fast_gc_to_bdev(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	u64 curr_tail, u64 new_block, u64 alter_new_block, int num_pages,
	int force_thorough);

/* ioctl.c */
extern long nova_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
#ifdef CONFIG_COMPAT
extern long nova_compat_ioctl(struct file *file, unsigned int cmd,
	unsigned long arg);
#endif


/* migration.c */
int init_dram_buffer(struct nova_sb_info *sbi);
int print_file_write_entries(struct super_block *sb, struct nova_inode_info_header *sih);
int buffer_data_block_from_bdev(struct nova_sb_info *sbi, int tier, unsigned long blockoff);
inline int clear_dram_buffer(struct nova_sb_info *sbi, unsigned long number);
inline int put_dram_buffer(struct nova_sb_info *sbi, unsigned long number);
inline int clear_dram_buffer_range(unsigned long blockoff, unsigned long length);
inline int put_dram_buffer_range(unsigned long blockoff, unsigned long length);
inline bool is_dram_buffer_addr(void *addr);
int migrate_a_file(struct inode *inode, int to, bool force);
int migrate_a_file_to_tier(struct inode *inode, int to, bool force);
inline int migrate_a_file_to_pmem(struct inode *inode);
inline int migrate_a_file_to_pmem_partial(struct inode *inode, pgoff_t index, pgoff_t end_index, bool sync);
int do_migrate_a_file_rotate(struct inode *inode);
int do_migrate_a_file_downward(struct super_block *sb, int cpu);
int get_lowest_tier(struct super_block *sb);
int get_available_tier(struct super_block *sb, int tier);
unsigned int valid_index_range(struct super_block *sb, struct nova_inode_info_header *sih, pgoff_t index);

int nova_update_usage(struct super_block *sb);
unsigned long nova_pmem_used(struct nova_sb_info *sbi);
unsigned long nova_pmem_total(struct nova_sb_info *sbi);
unsigned long nova_bdev_used(struct nova_sb_info *sbi, int tier);
unsigned long nova_bdev_total(struct nova_sb_info *sbi, int tier);
inline bool is_tier_usage_really_high(struct nova_sb_info *sbi, int tier);
inline bool is_tier_usage_quite_high(struct nova_sb_info *sbi, int tier);
inline bool is_pmem_usage_too_high(struct nova_sb_info *sbi);
int start_bm_thread(struct nova_sb_info *sbi);
void stop_bm_thread(struct nova_sb_info *sbi);
int start_usage_thread(struct nova_sb_info *sbi);
void stop_usage_thread(struct nova_sb_info *sbi);

/* mprotect.c */
extern int nova_dax_mem_protect(struct super_block *sb,
				 void *vaddr, unsigned long size, int rw);
int nova_get_vma_overlap_range(struct super_block *sb,
	struct nova_inode_info_header *sih, struct vm_area_struct *vma,
	unsigned long entry_pgoff, unsigned long entry_pages,
	unsigned long *start_pgoff, unsigned long *num_pages);
int nova_mmap_to_new_blocks(struct vm_area_struct *vma,
	unsigned long address);
bool nova_find_pgoff_in_vma(struct inode *inode, unsigned long pgoff);
int nova_set_vmas_readonly(struct super_block *sb);

/* namei.c */
extern const struct inode_operations nova_dir_inode_operations;
extern const struct inode_operations nova_special_inode_operations;
extern struct dentry *nova_get_parent(struct dentry *child);

/* parity.c */
int nova_update_pgoff_parity(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	unsigned long pgoff, int zero);
int nova_update_block_csum_parity(struct super_block *sb,
	struct nova_inode_info_header *sih, u8 *block, unsigned long blocknr,
	size_t offset, size_t bytes);
int nova_restore_data(struct super_block *sb, unsigned long blocknr,
	unsigned int badstrip_id, void *badstrip, int nvmmerr, u32 csum0,
	u32 csum1, u32 *csum_good);
int nova_update_truncated_block_parity(struct super_block *sb,
	struct inode *inode, loff_t newsize);

/* profile.c */
inline int nova_sih_increase_wcount(struct super_block *sb, struct nova_inode_info_header *sih, 
	size_t len);
inline bool nova_sih_is_sync(struct nova_inode_info_header *sih);
inline bool nova_sih_judge_sync(struct nova_inode_info_header *sih);
inline bool nova_prof_judge_sync(struct file *file);
unsigned int nova_get_prev_seq_count(struct super_block *sb, struct nova_inode_info_header *sih, 
    unsigned long pgoff, int num_pages);
inline bool nova_prof_judge_seq(unsigned int seq_count);
inline bool nova_entry_judge_seq(struct nova_file_write_entry *entry);
int nova_alloc_inode_lru_lists(struct super_block *sb);
inline struct list_head *nova_get_inode_lru_lists(struct nova_sb_info *sbi, int tier, int cpu);
inline bool is_inode_lru_list_empty(struct nova_sb_info *sbi, int tier, int cpu);
inline struct mutex *nova_get_inode_lru_mutex(struct nova_sb_info *sbi, int tier, int cpu);
int nova_update_avg_atime(struct super_block *sb, struct nova_inode_info_header *sih, 
    unsigned long len);
int nova_update_sih_tier(struct super_block *sb, struct nova_inode_info_header *sih, 
    int tier, int mode);
int nova_unlink_inode_lru_list(struct nova_sb_info *sbi, struct nova_inode_info_header *sih);
int nova_update_stat(struct nova_sb_info *sbi, size_t len, bool read);

/* rebuild.c */
int nova_reset_csum_parity_range(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	unsigned long start_pgoff, unsigned long end_pgoff, int zero,
	int check_entry);
int nova_reset_mapping_csum_parity(struct super_block *sb,
	struct inode *inode, struct address_space *mapping,
	unsigned long start_pgoff, unsigned long end_pgoff);
int nova_reset_vma_csum_parity(struct super_block *sb,
	struct vma_item *item);
int nova_rebuild_dir_inode_tree(struct super_block *sb,
	struct nova_inode *pi, u64 pi_addr,
	struct nova_inode_info_header *sih);
int nova_rebuild_inode(struct super_block *sb, struct nova_inode_info *si,
	u64 ino, u64 pi_addr, int rebuild_dir);
int nova_restore_snapshot_table(struct super_block *sb, int just_init);

/* snapshot.c */
int nova_encounter_mount_snapshot(struct super_block *sb, void *addr,
	u8 type);
int nova_save_snapshots(struct super_block *sb);
int nova_destroy_snapshot_infos(struct super_block *sb);
int nova_restore_snapshot_entry(struct super_block *sb,
	struct nova_snapshot_info_entry *entry, u64 curr_p, int just_init);
int nova_mount_snapshot(struct super_block *sb);
int nova_append_data_to_snapshot(struct super_block *sb,
	struct nova_file_write_entry *entry, u64 nvmm, u64 num_pages,
	u64 delete_epoch_id);
int nova_append_inode_to_snapshot(struct super_block *sb,
	struct nova_inode *pi);
int nova_print_snapshots(struct super_block *sb, struct seq_file *seq);
int nova_print_snapshot_lists(struct super_block *sb, struct seq_file *seq);
int nova_delete_dead_inode(struct super_block *sb, u64 ino);
int nova_create_snapshot(struct super_block *sb);
int nova_delete_snapshot(struct super_block *sb, u64 epoch_id);
int nova_snapshot_init(struct super_block *sb);


/* symlink.c */
int nova_block_symlink(struct super_block *sb, struct nova_inode *pi,
	struct inode *inode, const char *symname, int len, u64 epoch_id);
extern const struct inode_operations nova_symlink_inode_operations;

/* sysfs.c */
extern const char *proc_dirname;
extern struct proc_dir_entry *nova_proc_root;
void nova_sysfs_init(struct super_block *sb);
void nova_sysfs_exit(struct super_block *sb);

/* nova_stats.c */
void nova_get_timing_stats(void);
void nova_get_IO_stats(void);
void nova_print_timing_stats(struct super_block *sb);
void nova_clear_stats(struct super_block *sb);
void nova_print_inode(struct nova_inode *pi);
void nova_print_inode_log(struct super_block *sb, struct inode *inode);
void nova_print_inode_log_pages(struct super_block *sb, struct inode *inode);
int nova_check_inode_logs(struct super_block *sb, struct nova_inode *pi);
void nova_print_free_lists(struct super_block *sb);

/* super.c */
int nova_get_bdev_info(struct nova_sb_info *sbi);

/* vpmem.c */
int vpmem_setup(struct nova_sb_info *sbi, unsigned long);

/* perf.c */
int nova_test_perf(struct super_block *sb, unsigned int func_id,
	unsigned int poolmb, size_t size, unsigned int disks);

#endif /* __NOVA_H */
