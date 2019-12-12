/*
 * NOVA journaling facility.
 *
 * This file contains journaling code to guarantee the atomicity of directory
 * operations that span multiple inodes (unlink, rename, etc).
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin St - Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/vfs.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/sched.h>
#include "nova.h"
#include "journal.h"

/**************************** Lite journal ******************************/

static inline void
nova_print_lite_transaction(struct nova_lite_journal_entry *entry)
{
	nova_dbg("Entry %p: Type %llu, data1 0x%llx, data2 0x%llx\n, checksum %u\n",
			entry, entry->type,
			entry->data1, entry->data2, entry->csum);
}

static inline int nova_update_journal_entry_csum(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	u32 crc = 0;

	crc = nova_crc32c(~0, (__u8 *)entry,
			(sizeof(struct nova_lite_journal_entry)
			 - sizeof(__le32)));

	entry->csum = cpu_to_le32(crc);
	return 0;
}

static inline int nova_check_entry_integrity(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	u32 crc = 0;

	crc = nova_crc32c(~0, (__u8 *)entry,
			(sizeof(struct nova_lite_journal_entry)
			 - sizeof(__le32)));

	if (entry->csum == cpu_to_le32(crc))
		return 0;
	else
		return 1;
}

// Get the next journal entry.  Journal entries are stored in a circular
// buffer.  They live a 1-page circular buffer.
//
// TODO: Add check to ensure that the journal doesn't grow too large.
static inline u64 next_lite_journal(u64 curr_p)
{
	size_t size = sizeof(struct nova_lite_journal_entry);

	if ((curr_p & (PAGE_SIZE - 1)) + size >= PAGE_SIZE)
		return (curr_p & PAGE_MASK);

	return curr_p + size;
}

// Walk the journal for one CPU, and verify the checksum on each entry.
static int nova_check_journal_entries(struct super_block *sb,
	struct journal_ptr_pair *pair)
{
	struct nova_lite_journal_entry *entry;
	u64 temp;
	int ret;

	temp = pair->journal_head;
	while (temp != pair->journal_tail) {
		entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
									temp);
		ret = nova_check_entry_integrity(sb, entry);
		if (ret) {
			nova_dbg("Entry %p checksum failure\n", entry);
			nova_print_lite_transaction(entry);
			return ret;
		}
		temp = next_lite_journal(temp);
	}

	return 0;
}

/**************************** Journal Recovery ******************************/

static void nova_undo_journal_inode(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	struct nova_inode *pi, *alter_pi;
	u64 pi_addr, alter_pi_addr;

	if (metadata_csum == 0)
		return;

	pi_addr = le64_to_cpu(entry->data1);
	alter_pi_addr = le64_to_cpu(entry->data2);

	pi = (struct nova_inode *)nova_get_block(sb, pi_addr);
	alter_pi = (struct nova_inode *)nova_get_block(sb, alter_pi_addr);

	memcpy_to_pmem_nocache(pi, alter_pi, sizeof(struct nova_inode));
}

static void nova_undo_journal_entry(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	u64 addr, value;

	addr = le64_to_cpu(entry->data1);
	value = le64_to_cpu(entry->data2);

	*(u64 *)nova_get_block(sb, addr) = (u64)value;
	nova_flush_buffer((void *)nova_get_block(sb, addr), CACHELINE_SIZE, 0);
}

static void nova_undo_lite_journal_entry(struct super_block *sb,
	struct nova_lite_journal_entry *entry)
{
	u64 type;

	type = le64_to_cpu(entry->type);

	switch (type) {
	case JOURNAL_INODE:
		nova_undo_journal_inode(sb, entry);
		break;
	case JOURNAL_ENTRY:
		nova_undo_journal_entry(sb, entry);
		break;
	default:
		nova_dbg("%s: unknown data type %llu\n", __func__, type);
		break;
	}
}

/* Roll back all journal enries */
static int nova_recover_lite_journal(struct super_block *sb,
	struct journal_ptr_pair *pair)
{
	struct nova_lite_journal_entry *entry;
	u64 temp;

	nova_memunlock_journal(sb);
	temp = pair->journal_head;
	while (temp != pair->journal_tail) {
		entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
									temp);
		nova_undo_lite_journal_entry(sb, entry);
		temp = next_lite_journal(temp);
	}

	pair->journal_tail = pair->journal_head;
	nova_memlock_journal(sb);
	nova_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1);

	return 0;
}

/**************************** Create/commit ******************************/

static u64 nova_append_replica_inode_journal(struct super_block *sb,
	u64 curr_p, struct inode *inode)
{
	struct nova_lite_journal_entry *entry;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;

	entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							curr_p);
	entry->type = cpu_to_le64(JOURNAL_INODE);
	// entry->padding = 0;
	entry->data1 = cpu_to_le64(sih->pi_addr);
	entry->data2 = cpu_to_le64(sih->alter_pi_addr);
	nova_update_journal_entry_csum(sb, entry);

	curr_p = next_lite_journal(curr_p);
	return curr_p;
}

/* Create and append an undo entry for a small update to PMEM. */
static u64 nova_append_entry_journal(struct super_block *sb,
	u64 curr_p, void *field)
{
	struct nova_lite_journal_entry *entry;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u64 *aligned_field;
	u64 addr;

	entry = (struct nova_lite_journal_entry *)nova_get_block(sb,
							curr_p);
	entry->type = cpu_to_le64(JOURNAL_ENTRY);
	// entry->padding = 0;
	/* Align to 8 bytes */
	aligned_field = (u64 *)((unsigned long)field & ~7UL);
	/* Store the offset from the start of Nova instead of the pointer */
	addr = (u64)nova_get_addr_off(sbi, aligned_field);
	entry->data1 = cpu_to_le64(addr);
	entry->data2 = cpu_to_le64(*aligned_field);
	nova_update_journal_entry_csum(sb, entry);

	curr_p = next_lite_journal(curr_p);
	return curr_p;
}

static u64 nova_journal_inode_tail(struct super_block *sb,
	u64 curr_p, struct nova_inode *pi)
{
	curr_p = nova_append_entry_journal(sb, curr_p, &pi->log_tail);
	if (metadata_csum)
		curr_p = nova_append_entry_journal(sb, curr_p,
						&pi->alter_log_tail);
	return curr_p;
}

/* Create and append undo log entries for creating a new file or directory. */
static u64 nova_append_inode_journal(struct super_block *sb,
	u64 curr_p, struct inode *inode, int new_inode,
	int invalidate, int is_dir)
{
	struct nova_inode *pi = nova_get_inode(sb, inode);

	if (metadata_csum)
		return nova_append_replica_inode_journal(sb, curr_p, inode);

	if (!pi) {
		nova_err(sb, "%s: get inode failed\n", __func__);
		return curr_p;
	}

	if (is_dir)
		return nova_journal_inode_tail(sb, curr_p, pi);

	if (new_inode) {
		curr_p = nova_append_entry_journal(sb, curr_p,
						&pi->valid);
	} else {
		curr_p = nova_journal_inode_tail(sb, curr_p, pi);
		if (invalidate) {
			curr_p = nova_append_entry_journal(sb, curr_p,
						&pi->valid);
			curr_p = nova_append_entry_journal(sb, curr_p,
						&pi->delete_epoch_id);
		}
	}

	return curr_p;
}

static u64 nova_append_dentry_journal(struct super_block *sb,
	u64 curr_p, struct nova_dentry *dentry)
{
	curr_p = nova_append_entry_journal(sb, curr_p, &dentry->ino);
	curr_p = nova_append_entry_journal(sb, curr_p, &dentry->csum);
	return curr_p;
}

void nova_flush_journal_in_batch(struct super_block *sb, 
	u64 head, u64 tail)
{
	void *journal_entry;

	/* flush journal log entries in batch */
	if (head < tail) {
		journal_entry = nova_get_block(sb, head);
		nova_flush_buffer(journal_entry, tail - head, 0);

	} else {    // circular
		// head to end
		journal_entry = nova_get_block(sb, head);
		nova_flush_buffer(journal_entry,
			PAGE_SIZE - (head & ~PAGE_MASK), 0);

		// start to tail
		journal_entry = nova_get_block(sb, tail);
		nova_flush_buffer((void*)((u64)journal_entry & PAGE_MASK),
			tail & ~PAGE_MASK, 0);
	}
	PERSISTENT_BARRIER();
}

/* Journaled transactions for inode creation */
u64 nova_create_inode_transaction(struct super_block *sb,
	struct inode *inode, struct inode *dir, int cpu,
	int new_inode, int invalidate)
{
	struct journal_ptr_pair *pair;
	u64 temp;

	pair = nova_get_journal_pointers(sb, cpu);
	if (pair->journal_head == 0 ||
			pair->journal_head != pair->journal_tail)
		BUG();

	temp = pair->journal_head;

	temp = nova_append_inode_journal(sb, temp, inode,
					new_inode, invalidate, 0);

	temp = nova_append_inode_journal(sb, temp, dir,
					new_inode, invalidate, 1);

	nova_flush_journal_in_batch(sb, pair->journal_head, temp);
	pair->journal_tail = temp;
	nova_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1);

	nova_dbgv("%s: head 0x%llx, tail 0x%llx\n",
			__func__, pair->journal_head, pair->journal_tail);
	return temp;
}

/* Journaled transactions for rename operations */
u64 nova_create_rename_transaction(struct super_block *sb,
	struct inode *old_inode, struct inode *old_dir, struct inode *new_inode,
	struct inode *new_dir, struct nova_dentry *father_entry,
	int invalidate_new_inode, int cpu)
{
	struct journal_ptr_pair *pair;
	u64 temp;

	pair = nova_get_journal_pointers(sb, cpu);
	if (pair->journal_head == 0 ||
			pair->journal_head != pair->journal_tail)
		BUG();

	temp = pair->journal_head;

	/* Journal tails for old inode */
	temp = nova_append_inode_journal(sb, temp, old_inode, 0, 0, 0);

	/* Journal tails for old dir */
	temp = nova_append_inode_journal(sb, temp, old_dir, 0, 0, 1);

	if (new_inode) {
		/* New inode may be unlinked */
		temp = nova_append_inode_journal(sb, temp, new_inode, 0,
					invalidate_new_inode, 0);
	}

	if (new_dir)
		temp = nova_append_inode_journal(sb, temp, new_dir, 0, 0, 1);

	if (father_entry)
		temp = nova_append_dentry_journal(sb, temp, father_entry);

	nova_flush_journal_in_batch(sb, pair->journal_head, temp);
	pair->journal_tail = temp;
	nova_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1);

	nova_dbgv("%s: head 0x%llx, tail 0x%llx\n",
			__func__, pair->journal_head, pair->journal_tail);
	return temp;
}

/* For log entry inplace update */
u64 nova_create_logentry_transaction(struct super_block *sb,
	void *entry, enum nova_entry_type type, int cpu)
{
	struct journal_ptr_pair *pair;
	size_t size = 0;
	int i, count;
	u64 temp;

	pair = nova_get_journal_pointers(sb, cpu);
	if (pair->journal_head == 0 ||
			pair->journal_head != pair->journal_tail)
		BUG();

	size = nova_get_log_entry_size(sb, type);

	temp = pair->journal_head;

	count = size / 8;
	for (i = 0; i < count; i++) {
		temp = nova_append_entry_journal(sb, temp,
						(char *)entry + i * 8);
	}
	nova_flush_journal_in_batch(sb, pair->journal_head, temp);
	pair->journal_tail = temp;
	nova_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1);

	nova_dbgv("%s: head 0x%llx, tail 0x%llx\n",
			__func__, pair->journal_head, pair->journal_tail);
	return temp;
}

/* Commit the transactions by dropping the journal entries */
void nova_commit_lite_transaction(struct super_block *sb, u64 tail, int cpu)
{
	struct journal_ptr_pair *pair;

	pair = nova_get_journal_pointers(sb, cpu);
	if (pair->journal_tail != tail)
		BUG();

	pair->journal_head = tail;
	nova_flush_buffer(&pair->journal_head, CACHELINE_SIZE, 1);
}

/**************************** Initialization ******************************/

// Initialized DRAM journal state, validate, and recover
int nova_lite_journal_soft_init(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct journal_ptr_pair *pair;
	int i;
	int ret = 0;

	sbi->journal_locks = kcalloc(sbi->cpus, sizeof(spinlock_t),
				     GFP_KERNEL);
	if (!sbi->journal_locks)
		return -ENOMEM;

	for (i = 0; i < sbi->cpus; i++)
		spin_lock_init(&sbi->journal_locks[i]);

	for (i = 0; i < sbi->cpus; i++) {
		pair = nova_get_journal_pointers(sb, i);
		if (pair->journal_head == pair->journal_tail)
			continue;

		/* Ensure all entries are genuine */
		ret = nova_check_journal_entries(sb, pair);
		if (ret) {
			nova_err(sb, "Journal %d checksum failure\n", i);
			ret = -EINVAL;
			break;
		}

		ret = nova_recover_lite_journal(sb, pair);
	}

	return ret;
}

/* Initialized persistent journal state */
int nova_lite_journal_hard_init(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info_header sih;
	struct journal_ptr_pair *pair;
	unsigned long blocknr = 0;
	int allocated;
	int i;
	u64 block;

	sih.ino = NOVA_LITEJOURNAL_INO;
	sih.i_blk_type = NOVA_BLOCK_TYPE_4K;

	for (i = 0; i < sbi->cpus; i++) {
		pair = nova_get_journal_pointers(sb, i);

		allocated = nova_new_log_blocks(sb, &sih, &blocknr, 1,
			ALLOC_INIT_ZERO, ANY_CPU, ALLOC_FROM_HEAD);
		nova_dbg_verbose("%s: allocate log @ 0x%lx\n", __func__,
							blocknr);
		if (allocated != 1 || blocknr == 0)
			return -ENOSPC;

		block = nova_get_block_off(sb, blocknr, NOVA_BLOCK_TYPE_4K);
		nova_memunlock_range(sb, pair, CACHELINE_SIZE);
		pair->journal_head = pair->journal_tail = block;
		nova_flush_buffer(pair, CACHELINE_SIZE, 0);
		nova_memlock_range(sb, pair, CACHELINE_SIZE);
	}

	PERSISTENT_BARRIER();
	return nova_lite_journal_soft_init(sb);
}

