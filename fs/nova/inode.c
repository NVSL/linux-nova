/*
 * BRIEF DESCRIPTION
 *
 * Inode methods (allocate/free/read/write).
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

#include <linux/fs.h>
#include <linux/aio.h>
#include <linux/highuid.h>
#include <linux/module.h>
#include <linux/mpage.h>
#include <linux/backing-dev.h>
#include <linux/types.h>
#include <linux/ratelimit.h>
#include "nova.h"
#include "inode.h"

unsigned int blk_type_to_shift[NOVA_BLOCK_TYPE_MAX] = {12, 21, 30};
uint32_t blk_type_to_size[NOVA_BLOCK_TYPE_MAX] = {0x1000, 0x200000, 0x40000000};

int nova_init_inode_inuse_list(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_range_node *range_node;
	struct inode_map *inode_map;
	unsigned long range_high;
	int i;
	int ret;

	sbi->s_inodes_used_count = NOVA_NORMAL_INODE_START;

	range_high = NOVA_NORMAL_INODE_START / sbi->cpus;
	if (NOVA_NORMAL_INODE_START % sbi->cpus)
		range_high++;

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		range_node = nova_alloc_inode_node(sb);
		if (range_node == NULL)
			/* FIXME: free allocated memories */
			return -ENOMEM;

		range_node->range_low = 0;
		range_node->range_high = range_high;
		nova_update_range_node_checksum(range_node);
		ret = nova_insert_inodetree(sbi, range_node, i);
		if (ret) {
			nova_err(sb, "%s failed\n", __func__);
			nova_free_inode_node(range_node);
			return ret;
		}
		inode_map->num_range_node_inode = 1;
		inode_map->first_inode_range = range_node;
	}

	return 0;
}

static int nova_alloc_inode_table(struct super_block *sb,
	struct nova_inode_info_header *sih, int version)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct inode_table *inode_table;
	unsigned long blocknr;
	u64 block;
	int allocated;
	int i;
	unsigned long irq_flags = 0;

	for (i = 0; i < sbi->cpus; i++) {
		inode_table = nova_get_inode_table(sb, version, i);
		if (!inode_table)
			return -EINVAL;

		/* Allocate replicate inodes from tail */
		allocated = nova_new_log_blocks(sb, sih, &blocknr, 1,
				ALLOC_INIT_ZERO, i,
				version ? ALLOC_FROM_TAIL : ALLOC_FROM_HEAD);

		nova_dbgv("%s: allocate log @ 0x%lx\n", __func__,
							blocknr);
		if (allocated != 1 || blocknr == 0)
			return -ENOSPC;

		block = nova_get_block_off(sb, blocknr, NOVA_BLOCK_TYPE_2M);
		nova_memunlock_range(sb, inode_table, CACHELINE_SIZE, &irq_flags);
		inode_table->log_head = block;
		nova_memlock_range(sb, inode_table, CACHELINE_SIZE, &irq_flags);
		nova_flush_buffer(inode_table, CACHELINE_SIZE, 0);
	}

	return 0;
}

int nova_init_inode_table(struct super_block *sb)
{
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_INODETABLE_INO);
	struct nova_inode_info_header sih;
	int num_tables;
	int ret = 0;
	int i;
	unsigned long irq_flags = 0;

	nova_memunlock_inode(sb, pi, &irq_flags);
	pi->i_mode = 0;
	pi->i_uid = 0;
	pi->i_gid = 0;
	pi->i_links_count = cpu_to_le16(1);
	pi->i_flags = 0;
	pi->nova_ino = NOVA_INODETABLE_INO;

	pi->i_blk_type = NOVA_BLOCK_TYPE_2M;
	nova_memlock_inode(sb, pi, &irq_flags);

	sih.ino = NOVA_INODETABLE_INO;
	sih.i_blk_type = NOVA_BLOCK_TYPE_2M;

	num_tables = 1;
	if (metadata_csum)
		num_tables = 2;

	for (i = 0; i < num_tables; i++) {
		ret = nova_alloc_inode_table(sb, &sih, i);
		if (ret)
			return ret;
	}

	PERSISTENT_BARRIER();
	return ret;
}

inline int nova_insert_inodetree(struct nova_sb_info *sbi,
	struct nova_range_node *new_node, int cpu)
{
	struct rb_root *tree;
	int ret;

	tree = &sbi->inode_maps[cpu].inode_inuse_tree;
	ret = nova_insert_range_node(tree, new_node, NODE_INODE);
	if (ret)
		nova_dbg("ERROR: %s failed %d\n", __func__, ret);

	return ret;
}

inline int nova_search_inodetree(struct nova_sb_info *sbi,
	unsigned long ino, struct nova_range_node **ret_node)
{
	struct rb_root *tree;
	unsigned long internal_ino;
	int cpu;

	cpu = ino % sbi->cpus;
	tree = &sbi->inode_maps[cpu].inode_inuse_tree;
	internal_ino = ino / sbi->cpus;
	return nova_find_range_node(tree, internal_ino,
			NODE_INODE, ret_node);
}

/* Get the address in PMEM of an inode by inode number.  Allocate additional
 * block to store additional inodes if necessary.
 */
int nova_get_inode_address(struct super_block *sb, u64 ino, int version,
	u64 *pi_addr, int extendable, int extend_alternate)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info_header sih;
	struct inode_table *inode_table;
	unsigned int data_bits;
	unsigned int num_inodes_bits;
	u64 curr;
	unsigned int superpage_count;
	u64 alternate_pi_addr = 0;
	u64 internal_ino;
	int cpuid;
	int extended = 0;
	unsigned int index;
	unsigned int i = 0;
	unsigned long blocknr;
	unsigned long curr_addr;
	int allocated;
	unsigned long irq_flags = 0;

	if (ino < NOVA_NORMAL_INODE_START) {
		*pi_addr = nova_get_reserved_inode_addr(sb, ino);
		return 0;
	}

	sih.ino = NOVA_INODETABLE_INO;
	sih.i_blk_type = NOVA_BLOCK_TYPE_2M;
	data_bits = blk_type_to_shift[sih.i_blk_type];
	num_inodes_bits = data_bits - NOVA_INODE_BITS;

	cpuid = ino % sbi->cpus;
	internal_ino = ino / sbi->cpus;

	inode_table = nova_get_inode_table(sb, version, cpuid);
	superpage_count = internal_ino >> num_inodes_bits;
	index = internal_ino & ((1 << num_inodes_bits) - 1);

	curr = inode_table->log_head;
	if (curr == 0)
		return -EINVAL;

	for (i = 0; i < superpage_count; i++) {
		if (curr == 0)
			return -EINVAL;

		curr_addr = (unsigned long)nova_get_block(sb, curr);
		/* Next page pointer in the last 8 bytes of the superpage */
		curr_addr += nova_inode_blk_size(&sih) - 8;
		curr = *(u64 *)(curr_addr);

		if (curr == 0) {
			if (extendable == 0)
				return -EINVAL;

			extended = 1;

			allocated = nova_new_log_blocks(sb, &sih, &blocknr,
				1, ALLOC_INIT_ZERO, cpuid,
				version ? ALLOC_FROM_TAIL : ALLOC_FROM_HEAD);

			if (allocated != 1)
				return allocated;

			curr = nova_get_block_off(sb, blocknr,
						NOVA_BLOCK_TYPE_2M);
			nova_memunlock_range(sb, (void *)curr_addr,
						CACHELINE_SIZE, &irq_flags);
			*(u64 *)(curr_addr) = curr;
			nova_memlock_range(sb, (void *)curr_addr,
						CACHELINE_SIZE, &irq_flags);
			nova_flush_buffer((void *)curr_addr,
						NOVA_INODE_SIZE, 1);
		}
	}

	/* Extend alternate inode table */
	if (extended && extend_alternate && metadata_csum)
		nova_get_inode_address(sb, ino, version + 1,
					&alternate_pi_addr, extendable, 0);

	*pi_addr = curr + index * NOVA_INODE_SIZE;

	return 0;
}

int nova_get_alter_inode_address(struct super_block *sb, u64 ino,
	u64 *alter_pi_addr)
{
	int ret;

	if (metadata_csum == 0) {
		nova_err(sb, "Access alter inode when replica inode disabled\n");
		return 0;
	}

	if (ino < NOVA_NORMAL_INODE_START) {
		*alter_pi_addr = nova_get_alter_reserved_inode_addr(sb, ino);
	} else {
		ret = nova_get_inode_address(sb, ino, 1, alter_pi_addr, 0, 0);
		if (ret)
			return ret;
	}

	return 0;
}

int nova_delete_file_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long start_blocknr,
	unsigned long last_blocknr, bool delete_nvmm, bool delete_dead,
	u64 epoch_id)
{
	struct nova_file_write_entry *entry;
	struct nova_file_write_entry *entryc, entry_copy;
	struct nova_file_write_entry *old_entry = NULL;
	unsigned long pgoff = start_blocknr;
	unsigned long old_pgoff = 0;
	unsigned int num_free = 0;
	int freed = 0;
	void *ret;
	INIT_TIMING(delete_time);

	NOVA_START_TIMING(delete_file_tree_t, delete_time);

	entryc = (metadata_csum == 0) ? entry : &entry_copy;

	/* Handle EOF blocks */
	do {
		entry = radix_tree_lookup(&sih->tree, pgoff);
		if (entry) {
			ret = radix_tree_delete(&sih->tree, pgoff);
			BUG_ON(!ret || ret != entry);
			if (entry != old_entry) {
				if (old_entry && delete_nvmm) {
					nova_free_old_entry(sb, sih,
							old_entry, old_pgoff,
							num_free, delete_dead,
							epoch_id);
					freed += num_free;
				}

				old_entry = entry;
				old_pgoff = pgoff;
				num_free = 1;
			} else {
				num_free++;
			}
			pgoff++;
		} else {
			/* We are finding a hole. Jump to the next entry. */
			entry = nova_find_next_entry(sb, sih, pgoff);
			if (!entry)
				break;

			if (metadata_csum == 0)
				entryc = entry;
			else if (!nova_verify_entry_csum(sb, entry, entryc))
				break;

			pgoff++;
			pgoff = pgoff > entryc->pgoff ? pgoff : entryc->pgoff;
		}
	} while (1);

	if (old_entry && delete_nvmm) {
		nova_free_old_entry(sb, sih, old_entry, old_pgoff,
					num_free, delete_dead, epoch_id);
		freed += num_free;
	}

	nova_dbgv("Inode %lu: delete file tree from pgoff %lu to %lu, %d blocks freed\n",
			sih->ino, start_blocknr, last_blocknr, freed);

	NOVA_END_TIMING(delete_file_tree_t, delete_time);
	return freed;
}

static int nova_free_dram_resource(struct super_block *sb,
	struct nova_inode_info_header *sih)
{
	unsigned long last_blocknr;
	int freed = 0;

	if (sih->ino == 0)
		return 0;

	if (!(S_ISREG(sih->i_mode)) && !(S_ISDIR(sih->i_mode)))
		return 0;

	if (S_ISREG(sih->i_mode)) {
		last_blocknr = nova_get_last_blocknr(sb, sih);
		freed = nova_delete_file_tree(sb, sih, 0,
					last_blocknr, false, false, 0);
	} else {
		nova_delete_dir_tree(sb, sih);
		freed = 1;
	}

	return freed;
}

static inline void check_eof_blocks(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode,
	struct nova_inode_info_header *sih)
{
	unsigned long irq_flags = 0;
	if ((pi->i_flags & cpu_to_le32(NOVA_EOFBLOCKS_FL)) &&
		(inode->i_size + sb->s_blocksize) > (sih->i_blocks
			<< sb->s_blocksize_bits)) {
		nova_memunlock_inode(sb, pi, &irq_flags);
		pi->i_flags &= cpu_to_le32(~NOVA_EOFBLOCKS_FL);
		nova_update_inode_checksum(pi);
		nova_update_alter_inode(sb, inode, pi);
		nova_memlock_inode(sb, pi, &irq_flags);
	}
}

/*
 * Free data blocks from inode in the range start <=> end
 */
static void nova_truncate_file_blocks(struct inode *inode, loff_t start,
				    loff_t end, u64 epoch_id)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi = nova_get_inode(sb, inode);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	unsigned int data_bits = blk_type_to_shift[sih->i_blk_type];
	unsigned long first_blocknr, last_blocknr;
	int freed = 0;

	inode->i_mtime = inode->i_ctime = current_time(inode);

	nova_dbg_verbose("truncate: pi %p iblocks %lx %llx %llx %llx\n", pi,
			 sih->i_blocks, start, end, pi->i_size);

	first_blocknr = (start + (1UL << data_bits) - 1) >> data_bits;

	if (end == 0)
		return;
	last_blocknr = (end - 1) >> data_bits;

	if (first_blocknr > last_blocknr)
		return;

	freed = nova_delete_file_tree(sb, sih, first_blocknr,
				last_blocknr, true, false, epoch_id);

	inode->i_blocks -= (freed * (1 << (data_bits -
				sb->s_blocksize_bits)));

	sih->i_blocks = inode->i_blocks;
	/* Check for the flag EOFBLOCKS is still valid after the set size */
	check_eof_blocks(sb, pi, inode, sih);

}

/* search the radix tree to find hole or data
 * in the specified range
 * Input:
 * first_blocknr: first block in the specified range
 * last_blocknr: last_blocknr in the specified range
 * @data_found: indicates whether data blocks were found
 * @hole_found: indicates whether a hole was found
 * hole: whether we are looking for a hole or data
 */
static int nova_lookup_hole_in_range(struct super_block *sb,
	struct nova_inode_info_header *sih,
	unsigned long first_blocknr, unsigned long last_blocknr,
	int *data_found, int *hole_found, int hole)
{
	struct nova_file_write_entry *entry;
	struct nova_file_write_entry *entryc, entry_copy;
	unsigned long blocks = 0;
	unsigned long pgoff, old_pgoff;

	entryc = (metadata_csum == 0) ? entry : &entry_copy;

	pgoff = first_blocknr;
	while (pgoff <= last_blocknr) {
		old_pgoff = pgoff;
		entry = radix_tree_lookup(&sih->tree, pgoff);
		if (entry) {
			*data_found = 1;
			if (!hole)
				goto done;
			pgoff++;
		} else {
			*hole_found = 1;
			entry = nova_find_next_entry(sb, sih, pgoff);
			pgoff++;
			if (entry) {
				if (metadata_csum == 0)
					entryc = entry;
				else if (!nova_verify_entry_csum(sb, entry,
								entryc))
					goto done;

				pgoff = pgoff > entryc->pgoff ?
					pgoff : entryc->pgoff;
				if (pgoff > last_blocknr)
					pgoff = last_blocknr + 1;
			}
		}

		if (!*hole_found || !hole)
			blocks += pgoff - old_pgoff;
	}
done:
	return blocks;
}

/* copy persistent state to struct inode */
static int nova_read_inode(struct super_block *sb, struct inode *inode,
	u64 pi_addr)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode *pi, fake_pi;
	struct nova_inode_info_header *sih = &si->header;
	int ret = -EIO;
	unsigned long ino;

	ret = nova_get_reference(sb, pi_addr, &fake_pi,
			(void **)&pi, sizeof(struct nova_inode));
	if (ret) {
		nova_dbg("%s: read pi @ 0x%llx failed\n",
				__func__, pi_addr);
		goto bad_inode;
	}

	inode->i_mode = sih->i_mode;
	i_uid_write(inode, le32_to_cpu(pi->i_uid));
	i_gid_write(inode, le32_to_cpu(pi->i_gid));
//	set_nlink(inode, le16_to_cpu(pi->i_links_count));
	inode->i_generation = le32_to_cpu(pi->i_generation);
	nova_set_inode_flags(inode, pi, le32_to_cpu(pi->i_flags));
	ino = inode->i_ino;

	/* check if the inode is active. */
	if (inode->i_mode == 0 || pi->deleted == 1) {
		/* this inode is deleted */
		ret = -ESTALE;
		goto bad_inode;
	}

	inode->i_blocks = sih->i_blocks;
	inode->i_mapping->a_ops = &nova_aops_dax;

	switch (inode->i_mode & S_IFMT) {
	case S_IFREG:
		inode->i_op = &nova_file_inode_operations;
		if (!test_opt(inode->i_sb, DATA_COW) && wprotect == 0)
			inode->i_fop = &nova_dax_file_operations;
		else
			inode->i_fop = &nova_wrap_file_operations;
		break;
	case S_IFDIR:
		inode->i_op = &nova_dir_inode_operations;
		inode->i_fop = &nova_dir_operations;
		break;
	case S_IFLNK:
		inode->i_op = &nova_symlink_inode_operations;
		break;
	default:
		inode->i_op = &nova_special_inode_operations;
		init_special_inode(inode, inode->i_mode,
				   le32_to_cpu(pi->dev.rdev));
		break;
	}

	/* Update size and time after rebuild the tree */
	inode->i_size = le64_to_cpu(sih->i_size);
	inode->i_atime.tv_sec = (__s32)le32_to_cpu(pi->i_atime);
	inode->i_ctime.tv_sec = (__s32)le32_to_cpu(pi->i_ctime);
	inode->i_mtime.tv_sec = (__s32)le32_to_cpu(pi->i_mtime);
	inode->i_atime.tv_nsec = inode->i_mtime.tv_nsec =
					 inode->i_ctime.tv_nsec = 0;
	set_nlink(inode, le16_to_cpu(pi->i_links_count));
	return 0;

bad_inode:
	make_bad_inode(inode);
	return ret;
}

static void nova_get_inode_flags(struct inode *inode, struct nova_inode *pi)
{
	unsigned int flags = inode->i_flags;
	unsigned int nova_flags = le32_to_cpu(pi->i_flags);

	nova_flags &= ~(FS_SYNC_FL | FS_APPEND_FL | FS_IMMUTABLE_FL |
			 FS_NOATIME_FL | FS_DIRSYNC_FL);
	if (flags & S_SYNC)
		nova_flags |= FS_SYNC_FL;
	if (flags & S_APPEND)
		nova_flags |= FS_APPEND_FL;
	if (flags & S_IMMUTABLE)
		nova_flags |= FS_IMMUTABLE_FL;
	if (flags & S_NOATIME)
		nova_flags |= FS_NOATIME_FL;
	if (flags & S_DIRSYNC)
		nova_flags |= FS_DIRSYNC_FL;

	pi->i_flags = cpu_to_le32(nova_flags);
}

static void nova_init_inode(struct inode *inode, struct nova_inode *pi)
{
	pi->i_mode = cpu_to_le16(inode->i_mode);
	pi->i_uid = cpu_to_le32(i_uid_read(inode));
	pi->i_gid = cpu_to_le32(i_gid_read(inode));
	pi->i_links_count = cpu_to_le16(inode->i_nlink);
	pi->i_size = cpu_to_le64(inode->i_size);
	pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
	pi->i_ctime = cpu_to_le32(inode->i_ctime.tv_sec);
	pi->i_mtime = cpu_to_le32(inode->i_mtime.tv_sec);
	pi->i_generation = cpu_to_le32(inode->i_generation);
	pi->log_head = 0;
	pi->log_tail = 0;
	pi->alter_log_head = 0;
	pi->alter_log_tail = 0;
	pi->deleted = 0;
	pi->delete_epoch_id = 0;
	nova_get_inode_flags(inode, pi);

	if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))
		pi->dev.rdev = cpu_to_le32(inode->i_rdev);
}

static int nova_alloc_unused_inode(struct super_block *sb, int cpuid,
	unsigned long *ino)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct inode_map *inode_map;
	struct nova_range_node *i, *next_i;
	struct rb_node *temp, *next;
	unsigned long next_range_low;
	unsigned long new_ino;
	unsigned long MAX_INODE = 1UL << 31;

	inode_map = &sbi->inode_maps[cpuid];
	i = inode_map->first_inode_range;
	NOVA_ASSERT(i);
	if (!nova_range_node_checksum_ok(i)) {
		nova_dbg("%s: first node failed\n", __func__);
		return -EIO;
	}

	temp = &i->node;
	next = rb_next(temp);

	if (!next) {
		next_i = NULL;
		next_range_low = MAX_INODE;
	} else {
		next_i = container_of(next, struct nova_range_node, node);
		if (!nova_range_node_checksum_ok(next_i)) {
			nova_dbg("%s: second node failed\n", __func__);
			return -EIO;
		}
		next_range_low = next_i->range_low;
	}

	new_ino = i->range_high + 1;

	if (next_i && new_ino == (next_range_low - 1)) {
		/* Fill the gap completely */
		i->range_high = next_i->range_high;
		nova_update_range_node_checksum(i);
		rb_erase(&next_i->node, &inode_map->inode_inuse_tree);
		nova_free_inode_node(next_i);
		inode_map->num_range_node_inode--;
	} else if (new_ino < (next_range_low - 1)) {
		/* Aligns to left */
		i->range_high = new_ino;
		nova_update_range_node_checksum(i);
	} else {
		nova_dbg("%s: ERROR: new ino %lu, next low %lu\n", __func__,
			new_ino, next_range_low);
		return -ENOSPC;
	}

	*ino = new_ino * sbi->cpus + cpuid;
	sbi->s_inodes_used_count++;
	inode_map->allocated++;

	nova_dbg_verbose("Alloc ino %lu\n", *ino);
	return 0;
}

static int nova_free_inuse_inode(struct super_block *sb, unsigned long ino)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct inode_map *inode_map;
	struct nova_range_node *i = NULL;
	struct nova_range_node *curr_node;
	int found = 0;
	int cpuid = ino % sbi->cpus;
	unsigned long internal_ino = ino / sbi->cpus;
	int ret = 0;

	nova_dbg_verbose("Free inuse ino: %lu\n", ino);
	inode_map = &sbi->inode_maps[cpuid];

	mutex_lock(&inode_map->inode_table_mutex);
	found = nova_search_inodetree(sbi, ino, &i);
	if (!found) {
		nova_dbg("%s ERROR: ino %lu not found\n", __func__, ino);
		mutex_unlock(&inode_map->inode_table_mutex);
		return -EINVAL;
	}

	if ((internal_ino == i->range_low) && (internal_ino == i->range_high)) {
		/* fits entire node */
		rb_erase(&i->node, &inode_map->inode_inuse_tree);
		nova_free_inode_node(i);
		inode_map->num_range_node_inode--;
		goto block_found;
	}
	if ((internal_ino == i->range_low) && (internal_ino < i->range_high)) {
		/* Aligns left */
		i->range_low = internal_ino + 1;
		nova_update_range_node_checksum(i);
		goto block_found;
	}
	if ((internal_ino > i->range_low) && (internal_ino == i->range_high)) {
		/* Aligns right */
		i->range_high = internal_ino - 1;
		nova_update_range_node_checksum(i);
		goto block_found;
	}
	if ((internal_ino > i->range_low) && (internal_ino < i->range_high)) {
		/* Aligns somewhere in the middle */
		curr_node = nova_alloc_inode_node(sb);
		NOVA_ASSERT(curr_node);
		if (curr_node == NULL) {
			/* returning without freeing the block */
			goto block_found;
		}
		curr_node->range_low = internal_ino + 1;
		curr_node->range_high = i->range_high;
		nova_update_range_node_checksum(curr_node);

		i->range_high = internal_ino - 1;
		nova_update_range_node_checksum(i);

		ret = nova_insert_inodetree(sbi, curr_node, cpuid);
		if (ret) {
			nova_free_inode_node(curr_node);
			goto err;
		}
		inode_map->num_range_node_inode++;
		goto block_found;
	}

err:
	nova_error_mng(sb, "Unable to free inode %lu\n", ino);
	nova_error_mng(sb, "Found inuse block %lu - %lu\n",
				 i->range_low, i->range_high);
	mutex_unlock(&inode_map->inode_table_mutex);
	return ret;

block_found:
	sbi->s_inodes_used_count--;
	inode_map->freed++;
	mutex_unlock(&inode_map->inode_table_mutex);
	return ret;
}

static int nova_free_inode(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih)
{
	int err = 0;
	INIT_TIMING(free_time);

	NOVA_START_TIMING(free_inode_t, free_time);

	nova_free_inode_log(sb, pi, sih);

	sih->log_pages = 0;
	sih->i_mode = 0;
	sih->pi_addr = 0;
	sih->alter_pi_addr = 0;
	sih->i_size = 0;
	sih->i_blocks = 0;

	err = nova_free_inuse_inode(sb, pi->nova_ino);

	NOVA_END_TIMING(free_inode_t, free_time);
	return err;
}

struct inode *nova_iget(struct super_block *sb, unsigned long ino)
{
	struct nova_inode_info *si;
	struct inode *inode;
	u64 pi_addr;
	int err;

	inode = iget_locked(sb, ino);
	if (unlikely(!inode))
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	si = NOVA_I(inode);

	nova_dbgv("%s: inode %lu\n", __func__, ino);

	err = nova_get_inode_address(sb, ino, 0, &pi_addr, 0, 0);
	if (err) {
		nova_dbg("%s: get inode %lu address failed %d\n",
			 __func__, ino, err);
		goto fail;
	}

	if (pi_addr == 0) {
		nova_dbg("%s: failed to get pi_addr for inode %lu\n",
			 __func__, ino);
		err = -EACCES;
		goto fail;
	}

	err = nova_rebuild_inode(sb, si, ino, pi_addr, 1);
	if (err) {
		nova_dbg("%s: failed to rebuild inode %lu\n", __func__, ino);
		goto fail;
	}

	err = nova_read_inode(sb, inode, pi_addr);
	if (unlikely(err)) {
		nova_dbg("%s: failed to read inode %lu\n", __func__, ino);
		goto fail;

	}

	inode->i_ino = ino;

	unlock_new_inode(inode);
	return inode;
fail:
	iget_failed(inode);
	return ERR_PTR(err);
}

unsigned long nova_get_last_blocknr(struct super_block *sb,
	struct nova_inode_info_header *sih)
{
	struct nova_inode *pi, fake_pi;
	unsigned long last_blocknr;
	unsigned int btype;
	unsigned int data_bits;
	int ret;

	ret = nova_get_reference(sb, sih->pi_addr, &fake_pi,
			(void **)&pi, sizeof(struct nova_inode));
	if (ret) {
		nova_dbg("%s: read pi @ 0x%lx failed\n",
				__func__, sih->pi_addr);
		btype = 0;
	} else {
		btype = sih->i_blk_type;
	}

	data_bits = blk_type_to_shift[btype];

	if (sih->i_size == 0)
		last_blocknr = 0;
	else
		last_blocknr = (sih->i_size - 1) >> data_bits;

	return last_blocknr;
}

static int nova_free_inode_resource(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih)
{
	unsigned long last_blocknr;
	int ret = 0;
	int freed = 0;
	struct nova_inode *alter_pi;
	unsigned long irq_flags = 0;

	nova_memunlock_inode(sb, pi, &irq_flags);
	pi->deleted = 1;

	if (pi->valid) {
		nova_dbg("%s: inode %lu still valid\n",
				__func__, sih->ino);
		pi->valid = 0;
	}
	nova_update_inode_checksum(pi);
	if (metadata_csum && sih->alter_pi_addr) {
		alter_pi = (struct nova_inode *)nova_get_block(sb,
						sih->alter_pi_addr);
		memcpy_to_pmem_nocache(alter_pi, pi, sizeof(struct nova_inode));
	}
	nova_memlock_inode(sb, pi, &irq_flags);

	/* We need the log to free the blocks from the b-tree */
	switch (__le16_to_cpu(pi->i_mode) & S_IFMT) {
	case S_IFREG:
		last_blocknr = nova_get_last_blocknr(sb, sih);
		nova_dbgv("%s: file ino %lu\n", __func__, sih->ino);
		freed = nova_delete_file_tree(sb, sih, 0,
					last_blocknr, true, true, 0);
		break;
	case S_IFDIR:
		nova_dbgv("%s: dir ino %lu\n", __func__, sih->ino);
		nova_delete_dir_tree(sb, sih);
		break;
	case S_IFLNK:
		/* Log will be freed later */
		nova_dbgv("%s: symlink ino %lu\n",
				__func__, sih->ino);
		freed = nova_delete_file_tree(sb, sih, 0, 0,
						true, true, 0);
		break;
	default:
		nova_dbgv("%s: special ino %lu\n",
				__func__, sih->ino);
		break;
	}

	nova_dbg_verbose("%s: Freed %d\n", __func__, freed);
	/* Then we can free the inode */
	ret = nova_free_inode(sb, pi, sih);
	if (ret)
		nova_err(sb, "%s: free inode %lu failed\n",
				__func__, sih->ino);

	return ret;
}

void nova_evict_inode(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi = nova_get_inode(sb, inode);
	struct nova_inode_info_header *sih = NOVA_IH(inode);
	INIT_TIMING(evict_time);
	int destroy = 0;
	int ret;

	NOVA_START_TIMING(evict_inode_t, evict_time);
	if (!sih) {
		nova_err(sb, "%s: ino %lu sih is NULL!\n",
				__func__, inode->i_ino);
		NOVA_ASSERT(0);
		goto out;
	}

	// pi can be NULL if the file has already been deleted, but a handle
	// remains.
	if (pi && pi->nova_ino != inode->i_ino) {
		nova_err(sb, "%s: inode %lu ino does not match: %llu\n",
				__func__, inode->i_ino, pi->nova_ino);
		nova_dbg("inode size %llu, pi addr 0x%lx, pi head 0x%llx, tail 0x%llx, mode %u\n",
				inode->i_size, sih->pi_addr, sih->log_head,
				sih->log_tail, pi->i_mode);
		nova_dbg("sih: ino %lu, inode size %lu, mode %u, inode mode %u\n",
				sih->ino, sih->i_size,
				sih->i_mode, inode->i_mode);
		nova_print_inode_log(sb, inode);
	}

	/* Check if this inode exists in at least one snapshot. */
	if (pi && pi->valid == 0) {
		ret = nova_append_inode_to_snapshot(sb, pi);
		if (ret == 0)
			goto out;
	}

	nova_dbg_verbose("%s: %lu\n", __func__, inode->i_ino);
	if (!inode->i_nlink && !is_bad_inode(inode)) {
		if (IS_APPEND(inode) || IS_IMMUTABLE(inode))
			goto out;

		if (pi) {
			ret = nova_free_inode_resource(sb, pi, sih);
			if (ret)
				goto out;
		}

		destroy = 1;
		pi = NULL; /* we no longer own the nova_inode */

		inode->i_mtime = inode->i_ctime = current_time(inode);
		inode->i_size = 0;
	}
out:
	if (destroy == 0) {
		nova_dbgv("%s: destroying %lu\n", __func__, inode->i_ino);
		nova_free_dram_resource(sb, sih);
	}
	/* TODO: Since we don't use page-cache, do we really need the following
	 * call?
	 */
	truncate_inode_pages(&inode->i_data, 0);

	clear_inode(inode);
	NOVA_END_TIMING(evict_inode_t, evict_time);
}

/* First rebuild the inode tree, then free the blocks */
int nova_delete_dead_inode(struct super_block *sb, u64 ino)
{
	struct nova_inode_info si;
	struct nova_inode_info_header *sih;
	struct nova_inode *pi;
	u64 pi_addr = 0;
	int err;

	if (ino < NOVA_NORMAL_INODE_START) {
		nova_dbg("%s: invalid inode %llu\n", __func__, ino);
		return -EINVAL;
	}

	err = nova_get_inode_address(sb, ino, 0, &pi_addr, 0, 0);
	if (err) {
		nova_dbg("%s: get inode %llu address failed %d\n",
					__func__, ino, err);
		return -EINVAL;
	}

	if (pi_addr == 0)
		return -EACCES;

	memset(&si, 0, sizeof(struct nova_inode_info));
	err = nova_rebuild_inode(sb, &si, ino, pi_addr, 0);
	if (err)
		return err;

	pi = (struct nova_inode *)nova_get_block(sb, pi_addr);
	sih = &si.header;

	nova_dbgv("Delete dead inode %lu, log head 0x%llx, tail 0x%llx\n",
			sih->ino, sih->log_head, sih->log_tail);

	return nova_free_inode_resource(sb, pi, sih);
}

/* Returns 0 on failure */
u64 nova_new_nova_inode(struct super_block *sb, u64 *pi_addr)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct inode_map *inode_map;
	unsigned long free_ino = 0;
	int map_id;
	u64 ino = 0;
	int ret;
	INIT_TIMING(new_inode_time);

	NOVA_START_TIMING(new_nova_inode_t, new_inode_time);
	map_id = sbi->map_id;
	sbi->map_id = (sbi->map_id + 1) % sbi->cpus;

	inode_map = &sbi->inode_maps[map_id];

	mutex_lock(&inode_map->inode_table_mutex);
	ret = nova_alloc_unused_inode(sb, map_id, &free_ino);
	if (ret) {
		nova_dbg("%s: alloc inode number failed %d\n", __func__, ret);
		mutex_unlock(&inode_map->inode_table_mutex);
		return 0;
	}

	ret = nova_get_inode_address(sb, free_ino, 0, pi_addr, 1, 1);
	if (ret) {
		nova_dbg("%s: get inode address failed %d\n", __func__, ret);
		mutex_unlock(&inode_map->inode_table_mutex);
		return 0;
	}

	mutex_unlock(&inode_map->inode_table_mutex);

	ino = free_ino;

	NOVA_END_TIMING(new_nova_inode_t, new_inode_time);
	return ino;
}

struct inode *nova_new_vfs_inode(enum nova_new_inode_type type,
	struct inode *dir, u64 pi_addr, u64 ino, umode_t mode,
	size_t size, dev_t rdev, const struct qstr *qstr, u64 epoch_id)
{
	struct super_block *sb;
	struct nova_sb_info *sbi;
	struct inode *inode;
	struct nova_inode *diri = NULL;
	struct nova_inode_info *si;
	struct nova_inode_info_header *sih = NULL;
	struct nova_inode *pi;
	struct nova_inode *alter_pi;
	int errval;
	u64 alter_pi_addr = 0;
	unsigned long irq_flags = 0;
	INIT_TIMING(new_inode_time);

	NOVA_START_TIMING(new_vfs_inode_t, new_inode_time);
	sb = dir->i_sb;
	sbi = (struct nova_sb_info *)sb->s_fs_info;
	inode = new_inode(sb);
	if (!inode) {
		errval = -ENOMEM;
		goto fail2;
	}

	inode_init_owner(inode, dir, mode);
	inode->i_blocks = inode->i_size = 0;
	inode->i_mtime = inode->i_atime = inode->i_ctime = current_time(inode);

	inode->i_generation = atomic_add_return(1, &sbi->next_generation);
	inode->i_size = size;

	diri = nova_get_inode(sb, dir);
	if (!diri) {
		errval = -EACCES;
		goto fail1;
	}

	if (metadata_csum) {
		/* Get alternate inode address */
		errval = nova_get_alter_inode_address(sb, ino, &alter_pi_addr);
		if (errval)
			goto fail1;
	}

	pi = (struct nova_inode *)nova_get_block(sb, pi_addr);
	nova_dbg_verbose("%s: allocating inode %llu @ 0x%llx\n",
					__func__, ino, pi_addr);

	/* chosen inode is in ino */
	inode->i_ino = ino;

	switch (type) {
	case TYPE_CREATE:
		inode->i_op = &nova_file_inode_operations;
		inode->i_mapping->a_ops = &nova_aops_dax;
		if (!test_opt(inode->i_sb, DATA_COW) && wprotect == 0)
			inode->i_fop = &nova_dax_file_operations;
		else
			inode->i_fop = &nova_wrap_file_operations;
		break;
	case TYPE_MKNOD:
		init_special_inode(inode, mode, rdev);
		inode->i_op = &nova_special_inode_operations;
		break;
	case TYPE_SYMLINK:
		inode->i_op = &nova_symlink_inode_operations;
		inode->i_mapping->a_ops = &nova_aops_dax;
		break;
	case TYPE_MKDIR:
		inode->i_op = &nova_dir_inode_operations;
		inode->i_fop = &nova_dir_operations;
		inode->i_mapping->a_ops = &nova_aops_dax;
		set_nlink(inode, 2);
		break;
	default:
		nova_dbg("Unknown new inode type %d\n", type);
		break;
	}

	/*
	 * Pi is part of the dir log so no transaction is needed,
	 * but we need to flush to NVMM.
	 */
	nova_memunlock_inode(sb, pi, &irq_flags);
	pi->i_blk_type = NOVA_DEFAULT_BLOCK_TYPE;
	pi->i_flags = nova_mask_flags(mode, diri->i_flags);
	pi->nova_ino = ino;
	pi->i_create_time = current_time(inode).tv_sec;
	pi->create_epoch_id = epoch_id;
	nova_init_inode(inode, pi);

	if (metadata_csum) {
		alter_pi = (struct nova_inode *)nova_get_block(sb,
								alter_pi_addr);
		memcpy_to_pmem_nocache(alter_pi, pi, sizeof(struct nova_inode));
	}

	nova_memlock_inode(sb, pi, &irq_flags);

	si = NOVA_I(inode);
	sih = &si->header;
	nova_init_header(sb, sih, inode->i_mode);
	sih->pi_addr = pi_addr;
	sih->alter_pi_addr = alter_pi_addr;
	sih->ino = ino;
	sih->i_blk_type = NOVA_DEFAULT_BLOCK_TYPE;

	nova_set_inode_flags(inode, pi, le32_to_cpu(pi->i_flags));
	sih->i_flags = le32_to_cpu(pi->i_flags);

	if (insert_inode_locked(inode) < 0) {
		nova_err(sb, "nova_new_inode failed ino %lx\n", inode->i_ino);
		errval = -EINVAL;
		goto fail1;
	}

	nova_flush_buffer(pi, NOVA_INODE_SIZE, 0);
	NOVA_END_TIMING(new_vfs_inode_t, new_inode_time);
	return inode;
fail1:
	make_bad_inode(inode);
	iput(inode);
fail2:
	NOVA_END_TIMING(new_vfs_inode_t, new_inode_time);
	return ERR_PTR(errval);
}

int nova_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	/* write_inode should never be called because we always keep our inodes
	 * clean. So let us know if write_inode ever gets called.
	 */
//	BUG();
	return 0;
}

/*
 * dirty_inode() is called from mark_inode_dirty_sync()
 * usually dirty_inode should not be called because NOVA always keeps its inodes
 * clean. Only exception is touch_atime which calls dirty_inode to update the
 * i_atime field.
 */
void nova_dirty_inode(struct inode *inode, int _flags)
{
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *pi, inode_copy;
	unsigned long irq_flags = 0;

	if (sbi->mount_snapshot)
		return;

	pi = nova_get_block(sb, sih->pi_addr);

	/* check the inode before updating to make sure all fields are good */
	if (nova_check_inode_integrity(sb, sih->ino, sih->pi_addr,
					sih->alter_pi_addr, &inode_copy, 0) < 0)
		return;

	/* only i_atime should have changed if at all.
	 * we can do in-place atomic update
	 */
	nova_memunlock_inode(sb, pi, &irq_flags);
	pi->i_atime = cpu_to_le32(inode->i_atime.tv_sec);
	nova_update_inode_checksum(pi);
	nova_update_alter_inode(sb, inode, pi);
	nova_memlock_inode(sb, pi, &irq_flags);
	/* Relax atime persistency */
	nova_flush_buffer(&pi->i_atime, sizeof(pi->i_atime), 0);
}

static void nova_setsize(struct inode *inode, loff_t oldsize, loff_t newsize,
	u64 epoch_id)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info_header *sih = NOVA_IH(inode);
	INIT_TIMING(setsize_time);

	/* We only support truncate regular file */
	if (!(S_ISREG(inode->i_mode))) {
		nova_err(inode->i_sb, "%s:wrong file mode %x\n", inode->i_mode);
		return;
	}

	NOVA_START_TIMING(setsize_t, setsize_time);

	inode_dio_wait(inode);

	nova_dbgv("%s: inode %lu, old size %llu, new size %llu\n",
		__func__, inode->i_ino, oldsize, newsize);

	if (newsize != oldsize) {
		nova_clear_last_page_tail(sb, inode, newsize);
		i_size_write(inode, newsize);
		sih->i_size = newsize;
	}

	/* FIXME: we should make sure that there is nobody reading the inode
	 * before truncating it. Also we need to munmap the truncated range
	 * from application address space, if mmapped.
	 */
	/* synchronize_rcu(); */

	/* FIXME: Do we need to clear truncated DAX pages? */
//	dax_truncate_page(inode, newsize, nova_dax_get_block);

	truncate_pagecache(inode, newsize);
	nova_truncate_file_blocks(inode, newsize, oldsize, epoch_id);
	NOVA_END_TIMING(setsize_t, setsize_time);
}

int nova_getattr(const struct path *path, struct kstat *stat,
		 u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	unsigned int flags = sih->i_flags;

	if (flags & FS_APPEND_FL)
		stat->attributes |= STATX_ATTR_APPEND;
	if (flags & FS_COMPR_FL)
		stat->attributes |= STATX_ATTR_COMPRESSED;
	if (flags & FS_IMMUTABLE_FL)
		stat->attributes |= STATX_ATTR_IMMUTABLE;
	if (flags & FS_NODUMP_FL)
		stat->attributes |= STATX_ATTR_NODUMP;

	generic_fillattr(inode, stat);
	/* stat->blocks should be the number of 512B blocks */
	stat->blocks = (inode->i_blocks << inode->i_sb->s_blocksize_bits) >> 9;
	return 0;
}

int nova_notify_change(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = dentry->d_inode;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi = nova_get_inode(sb, inode);
	int ret;
	unsigned int ia_valid = attr->ia_valid, attr_mask;
	loff_t oldsize = inode->i_size;
	u64 epoch_id;
	INIT_TIMING(setattr_time);

	NOVA_START_TIMING(setattr_t, setattr_time);
	if (!pi) {
		ret = -EACCES;
		goto out;
	}

	ret = setattr_prepare(dentry, attr);
	if (ret)
		goto out;

	/* Update inode with attr except for size */
	setattr_copy(inode, attr);

	epoch_id = nova_get_epoch_id(sb);

	attr_mask = ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_SIZE | ATTR_ATIME
			| ATTR_MTIME | ATTR_CTIME;

	ia_valid = ia_valid & attr_mask;

	if (ia_valid == 0)
		goto out;

	ret = nova_handle_setattr_operation(sb, inode, pi, ia_valid,
					attr, epoch_id);
	if (ret)
		goto out;

	/* Only after log entry is committed, we can truncate size */
	if ((ia_valid & ATTR_SIZE) && (attr->ia_size != oldsize ||
			pi->i_flags & cpu_to_le32(NOVA_EOFBLOCKS_FL))) {
//		nova_set_blocksize_hint(sb, inode, pi, attr->ia_size);

		/* now we can freely truncate the inode */
		nova_setsize(inode, oldsize, attr->ia_size, epoch_id);
	}

	sih->trans_id++;
out:
	NOVA_END_TIMING(setattr_t, setattr_time);
	return ret;
}

void nova_set_inode_flags(struct inode *inode, struct nova_inode *pi,
	unsigned int flags)
{
	inode->i_flags &=
		~(S_SYNC | S_APPEND | S_IMMUTABLE | S_NOATIME | S_DIRSYNC);
	if (flags & FS_SYNC_FL)
		inode->i_flags |= S_SYNC;
	if (flags & FS_APPEND_FL)
		inode->i_flags |= S_APPEND;
	if (flags & FS_IMMUTABLE_FL)
		inode->i_flags |= S_IMMUTABLE;
	if (flags & FS_NOATIME_FL)
		inode->i_flags |= S_NOATIME;
	if (flags & FS_DIRSYNC_FL)
		inode->i_flags |= S_DIRSYNC;
	if (!pi->i_xattr)
		inode_has_no_xattr(inode);
	inode->i_flags |= S_DAX;
}

static ssize_t nova_direct_IO(struct kiocb *iocb, struct iov_iter *iter)
{
	/* DAX does not support direct IO */
	return -EIO;
}

/*
 * find the file offset for SEEK_DATA/SEEK_HOLE
 */
unsigned long nova_find_region(struct inode *inode, loff_t *offset, int hole)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	unsigned int data_bits = blk_type_to_shift[sih->i_blk_type];
	unsigned long first_blocknr, last_blocknr;
	unsigned long blocks = 0, offset_in_block;
	int data_found = 0, hole_found = 0;

	if (*offset >= inode->i_size)
		return -ENXIO;

	if (!inode->i_blocks || !sih->i_size) {
		if (hole)
			return inode->i_size;
		else
			return -ENXIO;
	}

	offset_in_block = *offset & ((1UL << data_bits) - 1);

	first_blocknr = *offset >> data_bits;
	last_blocknr = inode->i_size >> data_bits;

	nova_dbg_verbose("find_region offset %llx, first_blocknr %lx, last_blocknr %lx hole %d\n",
		  *offset, first_blocknr, last_blocknr, hole);

	blocks = nova_lookup_hole_in_range(inode->i_sb, sih,
		first_blocknr, last_blocknr, &data_found, &hole_found, hole);

	/* Searching data but only hole found till the end */
	if (!hole && !data_found && hole_found)
		return -ENXIO;

	if (data_found && !hole_found) {
		/* Searching data but we are already into them */
		if (hole)
			/* Searching hole but only data found, go to the end */
			*offset = inode->i_size;
		return 0;
	}

	/* Searching for hole, hole found and starting inside an hole */
	if (hole && hole_found && !blocks) {
		/* we found data after it */
		if (!data_found)
			/* last hole */
			*offset = inode->i_size;
		return 0;
	}

	if (offset_in_block) {
		blocks--;
		*offset += (blocks << data_bits) +
			   ((1 << data_bits) - offset_in_block);
	} else {
		*offset += blocks << data_bits;
	}

	return 0;
}

static int nova_writepages(struct address_space *mapping,
	struct writeback_control *wbc)
{
	int ret;
	INIT_TIMING(wp_time);

	NOVA_START_TIMING(write_pages_t, wp_time);
	ret = dax_writeback_mapping_range(mapping,
			mapping->host->i_sb->s_bdev, wbc);
	NOVA_END_TIMING(write_pages_t, wp_time);
	return ret;
}

const struct address_space_operations nova_aops_dax = {
	.writepages		= nova_writepages,
	.direct_IO		= nova_direct_IO,
	/*.dax_mem_protect	= nova_dax_mem_protect,*/
};
