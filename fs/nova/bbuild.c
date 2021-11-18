/*
 * NOVA Recovery routines.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
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

#include <linux/fs.h>
#include <linux/bitops.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/delay.h>
#include "nova.h"
#include "journal.h"
#include "super.h"
#include "inode.h"
#include "log.h"

void nova_init_header(struct super_block *sb,
	struct nova_inode_info_header *sih, u16 i_mode)
{
	sih->log_pages = 0;
	sih->i_size = 0;
	sih->ino = 0;
	sih->i_blocks = 0;
	sih->pi_addr = 0;
	sih->alter_pi_addr = 0;
	INIT_RADIX_TREE(&sih->tree, GFP_ATOMIC);
	sih->rb_tree = RB_ROOT;
	sih->vma_tree = RB_ROOT;
	sih->num_vmas = 0;
	INIT_LIST_HEAD(&sih->list);
	sih->i_mode = i_mode;
	sih->i_flags = 0;
	sih->valid_entries = 0;
	sih->num_entries = 0;
	sih->last_setattr = 0;
	sih->last_link_change = 0;
	sih->last_dentry = 0;
	sih->trans_id = 0;
	sih->log_head = 0;
	sih->log_tail = 0;
	sih->alter_log_head = 0;
	sih->alter_log_tail = 0;
	sih->i_blk_type = NOVA_DEFAULT_BLOCK_TYPE;
}

static inline void set_scan_bm(unsigned long bit,
	struct single_scan_bm *scan_bm)
{
	set_bit(bit, scan_bm->bitmap);
}

inline void set_bm(unsigned long bit, struct scan_bitmap *bm,
	enum bm_type type)
{
	switch (type) {
	case BM_4K:
		set_scan_bm(bit, &bm->scan_bm_4K);
		break;
	case BM_2M:
		set_scan_bm(bit, &bm->scan_bm_2M);
		break;
	case BM_1G:
		set_scan_bm(bit, &bm->scan_bm_1G);
		break;
	default:
		break;
	}
}

static inline int get_block_cpuid(struct nova_sb_info *sbi,
	unsigned long blocknr)
{
	return blocknr / sbi->per_list_blocks;
}

static int nova_failure_insert_inodetree(struct super_block *sb,
	unsigned long ino_low, unsigned long ino_high)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct inode_map *inode_map;
	struct nova_range_node *prev = NULL, *next = NULL;
	struct nova_range_node *new_node;
	unsigned long internal_low, internal_high;
	int cpu;
	struct rb_root *tree;
	int ret;

	if (ino_low > ino_high) {
		nova_err(sb, "%s: ino low %lu, ino high %lu\n",
				__func__, ino_low, ino_high);
		BUG();
	}

	cpu = ino_low % sbi->cpus;
	if (ino_high % sbi->cpus != cpu) {
		nova_err(sb, "%s: ino low %lu, ino high %lu\n",
				__func__, ino_low, ino_high);
		BUG();
	}

	internal_low = ino_low / sbi->cpus;
	internal_high = ino_high / sbi->cpus;
	inode_map = &sbi->inode_maps[cpu];
	tree = &inode_map->inode_inuse_tree;
	mutex_lock(&inode_map->inode_table_mutex);

	ret = nova_find_free_slot(tree, internal_low, internal_high,
					&prev, &next);
	if (ret) {
		nova_dbg("%s: ino %lu - %lu already exists!: %d\n",
					__func__, ino_low, ino_high, ret);
		mutex_unlock(&inode_map->inode_table_mutex);
		return ret;
	}

	if (prev && next && (internal_low == prev->range_high + 1) &&
			(internal_high + 1 == next->range_low)) {
		/* fits the hole */
		rb_erase(&next->node, tree);
		inode_map->num_range_node_inode--;
		prev->range_high = next->range_high;
		nova_update_range_node_checksum(prev);
		nova_free_inode_node(next);
		goto finish;
	}
	if (prev && (internal_low == prev->range_high + 1)) {
		/* Aligns left */
		prev->range_high += internal_high - internal_low + 1;
		nova_update_range_node_checksum(prev);
		goto finish;
	}
	if (next && (internal_high + 1 == next->range_low)) {
		/* Aligns right */
		next->range_low -= internal_high - internal_low + 1;
		nova_update_range_node_checksum(next);
		goto finish;
	}

	/* Aligns somewhere in the middle */
	new_node = nova_alloc_inode_node(sb);
	NOVA_ASSERT(new_node);
	new_node->range_low = internal_low;
	new_node->range_high = internal_high;
	nova_update_range_node_checksum(new_node);
	ret = nova_insert_inodetree(sbi, new_node, cpu);
	if (ret) {
		nova_err(sb, "%s failed\n", __func__);
		nova_free_inode_node(new_node);
		goto finish;
	}
	inode_map->num_range_node_inode++;

finish:
	mutex_unlock(&inode_map->inode_table_mutex);
	return ret;
}

static void nova_destroy_blocknode_tree(struct super_block *sb, int cpu)
{
	struct free_list *free_list;

	free_list = nova_get_free_list(sb, cpu);
	nova_destroy_range_node_tree(sb, &free_list->block_free_tree);
}

static void nova_destroy_blocknode_trees(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int i;

	for (i = 0; i < sbi->cpus; i++)
		nova_destroy_blocknode_tree(sb, i);

}

static int nova_init_blockmap_from_inode(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	struct nova_inode_info_header sih;
	struct free_list *free_list;
	struct nova_range_node_lowhigh *entry;
	struct nova_range_node *blknode;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	u64 curr_p;
	u64 cpuid;
	int ret = 0;

	memset(&sih, 0, sizeof(struct nova_info_header));

	/* FIXME: Backup inode for BLOCKNODE */
	ret = nova_get_head_tail(sb, pi, &sih);
	if (ret)
		goto out;

	sih.ino = NOVA_BLOCKNODE_INO;
	curr_p = sih.log_head;
	if (curr_p == 0) {
		nova_dbg("%s: pi head is 0!\n", __func__);
		return -EINVAL;
	}

	while (curr_p != sih.log_tail) {
		if (is_last_entry(curr_p, size))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			nova_dbg("%s: curr_p is NULL!\n", __func__);
			NOVA_ASSERT(0);
			ret = -EINVAL;
			break;
		}

		entry = (struct nova_range_node_lowhigh *)nova_get_block(sb,
							curr_p);
		blknode = nova_alloc_blocknode(sb);
		if (blknode == NULL)
			NOVA_ASSERT(0);
		blknode->range_low = le64_to_cpu(entry->range_low);
		blknode->range_high = le64_to_cpu(entry->range_high);
		nova_update_range_node_checksum(blknode);
		cpuid = get_block_cpuid(sbi, blknode->range_low);

		/* FIXME: Assume NR_CPUS not change */
		free_list = nova_get_free_list(sb, cpuid);
		ret = nova_insert_blocktree(&free_list->block_free_tree,
						blknode);
		if (ret) {
			nova_err(sb, "%s failed\n", __func__);
			nova_free_blocknode(blknode);
			NOVA_ASSERT(0);
			nova_destroy_blocknode_trees(sb);
			goto out;
		}
		free_list->num_blocknode++;
		if (free_list->num_blocknode == 1)
			free_list->first_node = blknode;
		free_list->last_node = blknode;
		free_list->num_free_blocks +=
			blknode->range_high - blknode->range_low + 1;
		curr_p += sizeof(struct nova_range_node_lowhigh);
	}
out:
	nova_free_inode_log(sb, pi, &sih);
	return ret;
}

static void nova_destroy_inode_trees(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct inode_map *inode_map;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		nova_destroy_range_node_tree(sb,
					&inode_map->inode_inuse_tree);
	}
}

#define CPUID_MASK 0xff00000000000000

static int nova_init_inode_list_from_inode(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_INODELIST_INO);
	struct nova_inode_info_header sih;
	struct nova_range_node_lowhigh *entry;
	struct nova_range_node *range_node;
	struct inode_map *inode_map;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	unsigned long num_inode_node = 0;
	u64 curr_p;
	unsigned long cpuid;
	int ret;

	/* FIXME: Backup inode for INODELIST */
	ret = nova_get_head_tail(sb, pi, &sih);
	if (ret)
		goto out;

	sih.ino = NOVA_INODELIST_INO;
	sbi->s_inodes_used_count = 0;
	curr_p = sih.log_head;
	if (curr_p == 0) {
		nova_dbg("%s: pi head is 0!\n", __func__);
		return -EINVAL;
	}

	while (curr_p != sih.log_tail) {
		if (is_last_entry(curr_p, size))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			nova_dbg("%s: curr_p is NULL!\n", __func__);
			NOVA_ASSERT(0);
		}

		entry = (struct nova_range_node_lowhigh *)nova_get_block(sb,
							curr_p);
		range_node = nova_alloc_inode_node(sb);
		if (range_node == NULL)
			NOVA_ASSERT(0);

		cpuid = (entry->range_low & CPUID_MASK) >> 56;
		if (cpuid >= sbi->cpus) {
			nova_err(sb, "Invalid cpuid %lu\n", cpuid);
			nova_free_inode_node(range_node);
			NOVA_ASSERT(0);
			nova_destroy_inode_trees(sb);
			goto out;
		}

		range_node->range_low = entry->range_low & ~CPUID_MASK;
		range_node->range_high = entry->range_high;
		nova_update_range_node_checksum(range_node);
		ret = nova_insert_inodetree(sbi, range_node, cpuid);
		if (ret) {
			nova_err(sb, "%s failed, %d\n", __func__, cpuid);
			nova_free_inode_node(range_node);
			NOVA_ASSERT(0);
			nova_destroy_inode_trees(sb);
			goto out;
		}

		sbi->s_inodes_used_count +=
			range_node->range_high - range_node->range_low + 1;
		num_inode_node++;

		inode_map = &sbi->inode_maps[cpuid];
		inode_map->num_range_node_inode++;
		if (!inode_map->first_inode_range)
			inode_map->first_inode_range = range_node;

		curr_p += sizeof(struct nova_range_node_lowhigh);
	}

	nova_dbg("%s: %lu inode nodes\n", __func__, num_inode_node);
out:
	nova_free_inode_log(sb, pi, &sih);
	return ret;
}

static u64 nova_append_range_node_entry(struct super_block *sb,
	struct nova_range_node *curr, u64 tail, unsigned long cpuid)
{
	u64 curr_p;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	struct nova_range_node_lowhigh *entry;
	unsigned long irq_flags = 0;

	curr_p = tail;

	if (!nova_range_node_checksum_ok(curr)) {
		nova_dbg("%s: range node checksum failure\n", __func__);
		goto out;
	}

	if (curr_p == 0 || (is_last_entry(curr_p, size) &&
				next_log_page(sb, curr_p) == 0)) {
		nova_dbg("%s: inode log reaches end?\n", __func__);
		goto out;
	}

	if (is_last_entry(curr_p, size))
		curr_p = next_log_page(sb, curr_p);

	entry = (struct nova_range_node_lowhigh *)nova_get_block(sb, curr_p);
	nova_memunlock_range(sb, entry, size, &irq_flags);
	entry->range_low = cpu_to_le64(curr->range_low);
	if (cpuid)
		entry->range_low |= cpu_to_le64(cpuid << 56);
	entry->range_high = cpu_to_le64(curr->range_high);
	nova_memlock_range(sb, entry, size, &irq_flags);
	nova_dbgv("append entry block low 0x%lx, high 0x%lx\n",
			curr->range_low, curr->range_high);

	nova_flush_buffer(entry, sizeof(struct nova_range_node_lowhigh), 0);
out:
	return curr_p;
}

static u64 nova_save_range_nodes_to_log(struct super_block *sb,
	struct rb_root *tree, u64 temp_tail, unsigned long cpuid)
{
	struct nova_range_node *curr;
	struct rb_node *temp;
	size_t size = sizeof(struct nova_range_node_lowhigh);
	u64 curr_entry = 0;

	/* Save in increasing order */
	temp = rb_first(tree);
	while (temp) {
		curr = container_of(temp, struct nova_range_node, node);
		curr_entry = nova_append_range_node_entry(sb, curr,
						temp_tail, cpuid);
		temp_tail = curr_entry + size;
		temp = rb_next(temp);
		rb_erase(&curr->node, tree);
		nova_free_range_node(curr);
	}

	return temp_tail;
}

static u64 nova_save_free_list_blocknodes(struct super_block *sb, int cpu,
	u64 temp_tail)
{
	struct free_list *free_list;

	free_list = nova_get_free_list(sb, cpu);
	temp_tail = nova_save_range_nodes_to_log(sb,
				&free_list->block_free_tree, temp_tail, 0);
	return temp_tail;
}

void nova_save_inode_list_to_log(struct super_block *sb)
{
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_INODELIST_INO);
	struct nova_inode_info_header sih;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	unsigned long num_blocks;
	unsigned long num_nodes = 0;
	struct inode_map *inode_map;
	unsigned long i;
	u64 temp_tail;
	u64 new_block;
	int allocated;
	unsigned long irq_flags = 0;

	sih.ino = NOVA_INODELIST_INO;
	sih.i_blk_type = NOVA_DEFAULT_BLOCK_TYPE;
	sih.i_blocks = 0;

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		num_nodes += inode_map->num_range_node_inode;
	}

	num_blocks = num_nodes / RANGENODE_PER_PAGE;
	if (num_nodes % RANGENODE_PER_PAGE)
		num_blocks++;

	allocated = nova_allocate_inode_log_pages(sb, &sih, num_blocks,
						&new_block, ANY_CPU, 0);
	if (allocated != num_blocks) {
		nova_dbg("Error saving inode list: %d\n", allocated);
		return;
	}

	temp_tail = new_block;
	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		temp_tail = nova_save_range_nodes_to_log(sb,
				&inode_map->inode_inuse_tree, temp_tail, i);
	}

	nova_memunlock_inode(sb, pi, &irq_flags);
	pi->alter_log_head = pi->alter_log_tail = 0;
	pi->log_head = new_block;
	nova_update_tail(pi, temp_tail);
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);
	nova_memlock_inode(sb, pi, &irq_flags);

	nova_dbg("%s: %lu inode nodes, pi head 0x%llx, tail 0x%llx\n",
		__func__, num_nodes, pi->log_head, pi->log_tail);
}

void nova_save_blocknode_mappings_to_log(struct super_block *sb)
{
	struct nova_inode *pi = nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	struct nova_inode_info_header sih;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	unsigned long num_blocknode = 0;
	unsigned long num_pages;
	int allocated;
	u64 new_block = 0;
	u64 temp_tail;
	int i;
	unsigned long irq_flags = 0;

	sih.ino = NOVA_BLOCKNODE_INO;
	sih.i_blk_type = NOVA_DEFAULT_BLOCK_TYPE;

	/* Allocate log pages before save blocknode mappings */
	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		num_blocknode += free_list->num_blocknode;
		nova_dbgv("%s: free list %d: %lu nodes\n", __func__,
				i, free_list->num_blocknode);
	}

	num_pages = num_blocknode / RANGENODE_PER_PAGE;
	if (num_blocknode % RANGENODE_PER_PAGE)
		num_pages++;

	allocated = nova_allocate_inode_log_pages(sb, &sih, num_pages,
						&new_block, ANY_CPU, 0);
	if (allocated != num_pages) {
		nova_dbg("Error saving blocknode mappings: %d\n", allocated);
		return;
	}

	temp_tail = new_block;
	for (i = 0; i < sbi->cpus; i++)
		temp_tail = nova_save_free_list_blocknodes(sb, i, temp_tail);

	/* Finally update log head and tail */
	nova_memunlock_inode(sb, pi, &irq_flags);
	pi->alter_log_head = pi->alter_log_tail = 0;
	pi->log_head = new_block;
	nova_update_tail(pi, temp_tail);
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);
	nova_memlock_inode(sb, pi, &irq_flags);

	nova_dbg("%s: %lu blocknodes, %lu log pages, pi head 0x%llx, tail 0x%llx\n",
		  __func__, num_blocknode, num_pages,
		  pi->log_head, pi->log_tail);
}

static int nova_insert_blocknode_map(struct super_block *sb,
	int cpuid, unsigned long low, unsigned long high)
{
	struct free_list *free_list;
	struct rb_root *tree;
	struct nova_range_node *blknode = NULL;
	unsigned long num_blocks = 0;
	int ret;

	num_blocks = high - low + 1;
	nova_dbgv("%s: cpu %d, low %lu, high %lu, num %lu\n",
		__func__, cpuid, low, high, num_blocks);
	free_list = nova_get_free_list(sb, cpuid);
	tree = &(free_list->block_free_tree);

	blknode = nova_alloc_blocknode(sb);
	if (blknode == NULL)
		return -ENOMEM;
	blknode->range_low = low;
	blknode->range_high = high;
	nova_update_range_node_checksum(blknode);
	ret = nova_insert_blocktree(tree, blknode);
	if (ret) {
		nova_err(sb, "%s failed\n", __func__);
		nova_free_blocknode(blknode);
		goto out;
	}
	if (!free_list->first_node)
		free_list->first_node = blknode;
	free_list->last_node = blknode;
	free_list->num_blocknode++;
	free_list->num_free_blocks += num_blocks;
out:
	return ret;
}

static int __nova_build_blocknode_map(struct super_block *sb,
	unsigned long *bitmap, unsigned long bsize, unsigned long scale)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	unsigned long next = 0;
	unsigned long low = 0;
	unsigned long start, end;
	int cpuid = 0;

	free_list = nova_get_free_list(sb, cpuid);
	start = free_list->block_start;
	end = free_list->block_end + 1;
	while (1) {
		next = find_next_zero_bit(bitmap, end, start);
		if (next == bsize)
			break;
		if (next == end) {
			if (cpuid == sbi->cpus - 1)
				break;

			cpuid++;
			free_list = nova_get_free_list(sb, cpuid);
			start = free_list->block_start;
			end = free_list->block_end + 1;
			continue;
		}

		low = next;
		next = find_next_bit(bitmap, end, next);
		if (nova_insert_blocknode_map(sb, cpuid,
				low << scale, (next << scale) - 1)) {
			nova_dbg("Error: could not insert %lu - %lu\n",
				low << scale, ((next << scale) - 1));
		}
		start = next;
		if (next == bsize)
			break;
		if (next == end) {
			if (cpuid == sbi->cpus - 1)
				break;

			cpuid++;
			free_list = nova_get_free_list(sb, cpuid);
			start = free_list->block_start;
			end = free_list->block_end + 1;
		}
	}
	return 0;
}

static void nova_update_4K_map(struct super_block *sb,
	struct scan_bitmap *bm,	unsigned long *bitmap,
	unsigned long bsize, unsigned long scale)
{
	unsigned long next = 0;
	unsigned long low = 0;
	int i;

	while (1) {
		next = find_next_bit(bitmap, bsize, next);
		if (next == bsize)
			break;
		low = next;
		next = find_next_zero_bit(bitmap, bsize, next);
		for (i = (low << scale); i < (next << scale); i++)
			set_bm(i, bm, BM_4K);
		if (next == bsize)
			break;
	}
}

struct scan_bitmap *global_bm[MAX_CPUS];

static int nova_build_blocknode_map(struct super_block *sb,
	unsigned long initsize)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct scan_bitmap *bm;
	struct scan_bitmap *final_bm;
	unsigned long *src, *dst;
	int i, j;
	int num;
	int ret;

	final_bm = kzalloc(sizeof(struct scan_bitmap), GFP_KERNEL);
	if (!final_bm)
		return -ENOMEM;

	final_bm->scan_bm_4K.bitmap_size =
				(initsize >> (PAGE_SHIFT + 0x3));

	/* Alloc memory to hold the block alloc bitmap */
	final_bm->scan_bm_4K.bitmap = kvzalloc(final_bm->scan_bm_4K.bitmap_size,
							GFP_KERNEL);

	if (!final_bm->scan_bm_4K.bitmap) {
		kfree(final_bm);
		return -ENOMEM;
	}

	/*
	 * We are using free lists. Set 2M and 1G blocks in 4K map,
	 * and use 4K map to rebuild block map.
	 */
	for (i = 0; i < sbi->cpus; i++) {
		bm = global_bm[i];
		nova_update_4K_map(sb, bm, bm->scan_bm_2M.bitmap,
			bm->scan_bm_2M.bitmap_size * 8, PAGE_SHIFT_2M - 12);
		nova_update_4K_map(sb, bm, bm->scan_bm_1G.bitmap,
			bm->scan_bm_1G.bitmap_size * 8, PAGE_SHIFT_1G - 12);
	}

	/* Merge per-CPU bms to the final single bm */
	num = final_bm->scan_bm_4K.bitmap_size / sizeof(unsigned long);
	if (final_bm->scan_bm_4K.bitmap_size % sizeof(unsigned long))
		num++;

	for (i = 0; i < sbi->cpus; i++) {
		bm = global_bm[i];
		src = (unsigned long *)bm->scan_bm_4K.bitmap;
		dst = (unsigned long *)final_bm->scan_bm_4K.bitmap;

		for (j = 0; j < num; j++)
			dst[j] |= src[j];
	}

	ret = __nova_build_blocknode_map(sb, final_bm->scan_bm_4K.bitmap,
			final_bm->scan_bm_4K.bitmap_size * 8, PAGE_SHIFT - 12);

	kvfree(final_bm->scan_bm_4K.bitmap);
	kfree(final_bm);

	return ret;
}

static void free_bm(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct scan_bitmap *bm;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		bm = global_bm[i];
		if (bm) {
			kvfree(bm->scan_bm_4K.bitmap);
			kvfree(bm->scan_bm_2M.bitmap);
			kvfree(bm->scan_bm_1G.bitmap);
			kfree(bm);
		}
	}
}

static int alloc_bm(struct super_block *sb, unsigned long initsize)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct scan_bitmap *bm;
	int i;

	for (i = 0; i < sbi->cpus; i++) {
		bm = kzalloc(sizeof(struct scan_bitmap), GFP_KERNEL);
		if (!bm)
			return -ENOMEM;

		global_bm[i] = bm;

		bm->scan_bm_4K.bitmap_size =
				(initsize >> (PAGE_SHIFT + 0x3));
		bm->scan_bm_2M.bitmap_size =
				(initsize >> (PAGE_SHIFT_2M + 0x3));
		bm->scan_bm_1G.bitmap_size =
				(initsize >> (PAGE_SHIFT_1G + 0x3));

		/* Alloc memory to hold the block alloc bitmap */
		bm->scan_bm_4K.bitmap = kvzalloc(bm->scan_bm_4K.bitmap_size,
							GFP_KERNEL);
		bm->scan_bm_2M.bitmap = kvzalloc(bm->scan_bm_2M.bitmap_size,
							GFP_KERNEL);
		bm->scan_bm_1G.bitmap = kvzalloc(bm->scan_bm_1G.bitmap_size,
							GFP_KERNEL);

		if (!bm->scan_bm_4K.bitmap || !bm->scan_bm_2M.bitmap ||
				!bm->scan_bm_1G.bitmap)
			return -ENOMEM;
	}

	return 0;
}

/************************** NOVA recovery ****************************/

#define MAX_PGOFF	262144

struct task_ring {
	u64 addr0[512];
	u64 addr1[512];		/* Second inode address */
	int num;
	int inodes_used_count;
	u64 *entry_array;
	u64 *nvmm_array;
};

static struct task_ring *task_rings;
static struct task_struct **threads;
wait_queue_head_t finish_wq;
int *finished;

static int nova_traverse_inode_log(struct super_block *sb,
	struct nova_inode *pi, struct scan_bitmap *bm, u64 head)
{
	u64 curr_p;
	u64 next;

	curr_p = head;

	if (curr_p == 0)
		return 0;

	BUG_ON(curr_p & (PAGE_SIZE - 1));
	set_bm(curr_p >> PAGE_SHIFT, bm, BM_4K);

	next = next_log_page(sb, curr_p);
	while (next > 0) {
		curr_p = next;
		BUG_ON(curr_p & (PAGE_SIZE - 1));
		set_bm(curr_p >> PAGE_SHIFT, bm, BM_4K);
		next = next_log_page(sb, curr_p);
	}

	return 0;
}

static void nova_traverse_dir_inode_log(struct super_block *sb,
	struct nova_inode *pi, struct scan_bitmap *bm)
{
	nova_traverse_inode_log(sb, pi, bm, pi->log_head);
	if (metadata_csum)
		nova_traverse_inode_log(sb, pi, bm, pi->alter_log_head);
}

static unsigned int nova_check_old_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 entry_addr,
	unsigned long pgoff, unsigned int num_free,
	u64 epoch_id, struct task_ring *ring, unsigned long base,
	struct scan_bitmap *bm)
{
	struct nova_file_write_entry *entry;
	struct nova_file_write_entry *entryc, entry_copy;
	unsigned long old_nvmm, nvmm;
	unsigned long index;
	int i;
	int ret;

	entry = (struct nova_file_write_entry *)entry_addr;

	if (!entry)
		return 0;

	if (metadata_csum == 0)
		entryc = entry;
	else {
		entryc = &entry_copy;
		if (!nova_verify_entry_csum(sb, entry, entryc))
			return 0;
	}

	old_nvmm = get_nvmm(sb, sih, entryc, pgoff);

	ret = nova_append_data_to_snapshot(sb, entryc, old_nvmm,
				num_free, epoch_id);

	if (ret != 0)
		return ret;

	index = pgoff - base;
	for (i = 0; i < num_free; i++) {
		nvmm = ring->nvmm_array[index];
		if (nvmm)
			set_bm(nvmm, bm, BM_4K);
		index++;
	}

	return ret;
}

static int nova_set_ring_array(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	struct nova_file_write_entry *entryc, struct task_ring *ring,
	unsigned long base, struct scan_bitmap *bm)
{
	unsigned long start, end;
	unsigned long pgoff, old_pgoff = 0;
	unsigned long index;
	unsigned int num_free = 0;
	u64 old_entry = 0;
	u64 epoch_id = entryc->epoch_id;

	start = entryc->pgoff;
	if (start < base)
		start = base;

	end = entryc->pgoff + entryc->num_pages;
	if (end > base + MAX_PGOFF)
		end = base + MAX_PGOFF;

	for (pgoff = start; pgoff < end; pgoff++) {
		index = pgoff - base;
		if (ring->nvmm_array[index]) {
			if (ring->entry_array[index] != old_entry) {
				if (old_entry)
					nova_check_old_entry(sb, sih, old_entry,
							old_pgoff, num_free,
							epoch_id, ring, base,
							bm);

				old_entry = ring->entry_array[index];
				old_pgoff = pgoff;
				num_free = 1;
			} else {
				num_free++;
			}
		}
	}

	if (old_entry)
		nova_check_old_entry(sb, sih, old_entry, old_pgoff,
					num_free, epoch_id, ring, base, bm);

	for (pgoff = start; pgoff < end; pgoff++) {
		index = pgoff - base;
		ring->entry_array[index] = (u64)entry;
		ring->nvmm_array[index] = (u64)(entryc->block >> PAGE_SHIFT)
						+ pgoff - entryc->pgoff;
	}

	return 0;
}

static int nova_set_file_bm(struct super_block *sb,
	struct nova_inode_info_header *sih, struct task_ring *ring,
	struct scan_bitmap *bm, unsigned long base, unsigned long last_blocknr)
{
	unsigned long nvmm, pgoff;

	if (last_blocknr >= base + MAX_PGOFF)
		last_blocknr = MAX_PGOFF - 1;
	else
		last_blocknr -= base;

	for (pgoff = 0; pgoff <= last_blocknr; pgoff++) {
		nvmm = ring->nvmm_array[pgoff];
		if (nvmm) {
			set_bm(nvmm, bm, BM_4K);
			ring->nvmm_array[pgoff] = 0;
			ring->entry_array[pgoff] = 0;
		}
	}

	return 0;
}

/* entry given to this function is a copy in dram */
static void nova_ring_setattr_entry(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_setattr_logentry *entry, struct task_ring *ring,
	unsigned long base, unsigned int data_bits, struct scan_bitmap *bm)
{
	unsigned long first_blocknr, last_blocknr;
	unsigned long pgoff, old_pgoff = 0;
	unsigned long index;
	unsigned int num_free = 0;
	u64 old_entry = 0;
	loff_t start, end;
	u64 epoch_id = entry->epoch_id;

	if (sih->i_size <= entry->size)
		goto out;

	start = entry->size;
	end = sih->i_size;

	first_blocknr = (start + (1UL << data_bits) - 1) >> data_bits;

	if (end > 0)
		last_blocknr = (end - 1) >> data_bits;
	else
		last_blocknr = 0;

	if (first_blocknr > last_blocknr)
		goto out;

	if (first_blocknr < base)
		first_blocknr = base;

	if (last_blocknr > base + MAX_PGOFF - 1)
		last_blocknr = base + MAX_PGOFF - 1;

	for (pgoff = first_blocknr; pgoff <= last_blocknr; pgoff++) {
		index = pgoff - base;
		if (ring->nvmm_array[index]) {
			if (ring->entry_array[index] != old_entry) {
				if (old_entry)
					nova_check_old_entry(sb, sih, old_entry,
							old_pgoff, num_free,
							epoch_id, ring, base,
							bm);

				old_entry = ring->entry_array[index];
				old_pgoff = pgoff;
				num_free = 1;
			} else {
				num_free++;
			}
		}
	}

	if (old_entry)
		nova_check_old_entry(sb, sih, old_entry, old_pgoff,
					num_free, epoch_id, ring, base, bm);

	for (pgoff = first_blocknr; pgoff <= last_blocknr; pgoff++) {
		index = pgoff - base;
		ring->nvmm_array[index] = 0;
		ring->entry_array[index] = 0;
	}

out:
	sih->i_size = entry->size;
}

static unsigned long nova_traverse_file_write_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	struct nova_file_write_entry *entryc, struct task_ring *ring,
	unsigned long base, struct scan_bitmap *bm)
{
	unsigned long max_blocknr = 0;
	sih->i_size = entryc->size;

	if (entryc->num_pages != entryc->invalid_pages) {
		max_blocknr = entryc->pgoff + entryc->num_pages - 1;
		if (entryc->pgoff < base + MAX_PGOFF &&
				entryc->pgoff + entryc->num_pages > base)
			nova_set_ring_array(sb, sih, entry, entryc,
						ring, base, bm);
	}

	return max_blocknr;
}

static int nova_traverse_file_inode_log(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	struct task_ring *ring, struct scan_bitmap *bm)
{
	char entry_copy[NOVA_MAX_ENTRY_LEN];
	unsigned long base = 0;
	unsigned long last_blocknr = 0, curr_last;
	u64 ino = pi->nova_ino;
	void *entry, *entryc;
	unsigned int btype;
	unsigned int data_bits;
	u64 curr_p;
	u64 next;
	u8 type;

	btype = pi->i_blk_type;
	data_bits = blk_type_to_shift[btype];

	if (metadata_csum)
		nova_traverse_inode_log(sb, pi, bm, pi->alter_log_head);

	entryc = (metadata_csum == 0) ? NULL : entry_copy;

again:
	curr_p = pi->log_head;
	nova_dbg_verbose("Log head 0x%llx, tail 0x%llx\n",
				curr_p, pi->log_tail);
	if (curr_p == 0 || pi->log_tail == 0) {
		nova_warn("NULL log pointer(s) in file inode %llu\n", ino);
		pi->log_head = 0;
		pi->log_tail = 0;
		nova_flush_buffer(pi, sizeof(struct nova_inode), 1);
		return 0;
	}


	if (base == 0) {
		BUG_ON(curr_p & (PAGE_SIZE - 1));
		set_bm(curr_p >> PAGE_SHIFT, bm, BM_4K);
	}

	while (curr_p != pi->log_tail) {
		if (goto_next_page(sb, curr_p)) {
			curr_p = next_log_page(sb, curr_p);
			if (base == 0) {
				BUG_ON(curr_p & (PAGE_SIZE - 1));
				set_bm(curr_p >> PAGE_SHIFT, bm, BM_4K);
			}
		}

		if (curr_p == 0) {
			nova_err(sb, "File inode %llu log is NULL!\n", ino);
			BUG();
		}

		entry = (void *)nova_get_block(sb, curr_p);

		if (metadata_csum == 0)
			entryc = entry;
		else if (!nova_verify_entry_csum(sb, entry, entryc))
			return 0;

		type = nova_get_entry_type(entryc);
		switch (type) {
		case SET_ATTR:
			nova_ring_setattr_entry(sb, sih, SENTRY(entryc),
						ring, base, data_bits,
						bm);
			curr_p += sizeof(struct nova_setattr_logentry);
			break;
		case LINK_CHANGE:
			curr_p += sizeof(struct nova_link_change_entry);
			break;
		case FILE_WRITE:
			curr_last = nova_traverse_file_write_entry(sb, sih, WENTRY(entry),
						WENTRY(entryc), ring, base, bm);
			curr_p += sizeof(struct nova_file_write_entry);
			if (last_blocknr < curr_last)
				last_blocknr = curr_last;
			break;
		case MMAP_WRITE:
			curr_p += sizeof(struct nova_mmap_entry);
			break;
		default:
			nova_dbg("%s: unknown type %d, 0x%llx\n",
						__func__, type, curr_p);
			NOVA_ASSERT(0);
			BUG();
		}

	}

	if (base == 0) {
		/* Keep traversing until log ends */
		curr_p &= PAGE_MASK;
		next = next_log_page(sb, curr_p);
		while (next > 0) {
			curr_p = next;
			BUG_ON(curr_p & (PAGE_SIZE - 1));
			set_bm(curr_p >> PAGE_SHIFT, bm, BM_4K);
			next = next_log_page(sb, curr_p);
		}
	}

	nova_set_file_bm(sb, sih, ring, bm, base, last_blocknr);
	if (last_blocknr >= base + MAX_PGOFF) {
		base += MAX_PGOFF;
		goto again;
	}

	return 0;
}

/* Pi is DRAM fake version */
static int nova_recover_inode_pages(struct super_block *sb,
	struct nova_inode_info_header *sih, struct task_ring *ring,
	struct nova_inode *pi, struct scan_bitmap *bm)
{
	unsigned long nova_ino;

	if (pi->deleted == 1)
		return 0;

	nova_ino = pi->nova_ino;
	ring->inodes_used_count++;

	sih->i_mode = __le16_to_cpu(pi->i_mode);
	sih->ino = nova_ino;

	nova_dbgv("%s: inode %lu, head 0x%llx, tail 0x%llx\n",
			__func__, nova_ino, pi->log_head, pi->log_tail);

	switch (__le16_to_cpu(pi->i_mode) & S_IFMT) {
	case S_IFDIR:
		nova_traverse_dir_inode_log(sb, pi, bm);
		break;
	case S_IFLNK:
		/* Treat symlink files as normal files */
		/* Fall through */
	case S_IFREG:
		/* Fall through */
	default:
		/* In case of special inode, walk the log */
		nova_traverse_file_inode_log(sb, pi, sih, ring, bm);
		break;
	}

	return 0;
}

static void free_resources(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct task_ring *ring;
	int i;

	if (task_rings) {
		for (i = 0; i < sbi->cpus; i++) {
			ring = &task_rings[i];
			vfree(ring->entry_array);
			vfree(ring->nvmm_array);
			ring->entry_array = NULL;
			ring->nvmm_array = NULL;
		}
	}

	kfree(task_rings);
	kfree(threads);
	kfree(finished);
}

static int failure_thread_func(void *data);

static int allocate_resources(struct super_block *sb, int cpus)
{
	struct task_ring *ring;
	int i;

	task_rings = kcalloc(cpus, sizeof(struct task_ring), GFP_KERNEL);
	if (!task_rings)
		goto fail;

	for (i = 0; i < cpus; i++) {
		ring = &task_rings[i];

		ring->nvmm_array = vzalloc(sizeof(u64) * MAX_PGOFF);
		if (!ring->nvmm_array)
			goto fail;

		ring->entry_array = vmalloc(sizeof(u64) * MAX_PGOFF);
		if (!ring->entry_array)
			goto fail;
	}

	threads = kcalloc(cpus, sizeof(struct task_struct *), GFP_KERNEL);
	if (!threads)
		goto fail;

	finished = kcalloc(cpus, sizeof(int), GFP_KERNEL);
	if (!finished)
		goto fail;

	init_waitqueue_head(&finish_wq);

	for (i = 0; i < cpus; i++) {
		threads[i] = kthread_create(failure_thread_func,
						sb, "recovery thread");
		kthread_bind(threads[i], i);
	}

	return 0;

fail:
	free_resources(sb);
	return -ENOMEM;
}

static void wait_to_finish(int cpus)
{
	int i;

	for (i = 0; i < cpus; i++) {
		while (finished[i] == 0) {
			wait_event_interruptible_timeout(finish_wq, false,
							msecs_to_jiffies(1));
		}
	}
}

/*********************** Failure recovery *************************/

static inline int nova_failure_update_inodetree(struct super_block *sb,
	struct nova_inode *pi, unsigned long *ino_low, unsigned long *ino_high)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (*ino_low == 0) {
		*ino_low = *ino_high = pi->nova_ino;
	} else {
		if (pi->nova_ino == *ino_high + sbi->cpus) {
			*ino_high = pi->nova_ino;
		} else {
			/* A new start */
			nova_failure_insert_inodetree(sb, *ino_low, *ino_high);
			*ino_low = *ino_high = pi->nova_ino;
		}
	}

	return 0;
}

static int failure_thread_func(void *data)
{
	struct super_block *sb = data;
	struct nova_inode_info_header sih;
	struct task_ring *ring;
	struct nova_inode *pi, fake_pi;
	unsigned long num_inodes_per_page;
	unsigned long ino_low, ino_high;
	unsigned long last_blocknr;
	unsigned int data_bits;
	u64 curr, curr1;
	int cpuid = nova_get_cpuid(sb);
	unsigned long i;
	unsigned long max_size = 0;
	u64 pi_addr = 0;
	int ret = 0;
	int count;

	pi = nova_get_inode_by_ino(sb, NOVA_INODETABLE_INO);
	data_bits = blk_type_to_shift[pi->i_blk_type];
	num_inodes_per_page = 1 << (data_bits - NOVA_INODE_BITS);

	ring = &task_rings[cpuid];
	nova_init_header(sb, &sih, 0);

	for (count = 0; count < ring->num; count++) {
		curr = ring->addr0[count];
		curr1 = ring->addr1[count];
		ino_low = ino_high = 0;

		/*
		 * Note: The inode log page is allocated in 2MB
		 * granularity, but not aligned on 2MB boundary.
		 */
		for (i = 0; i < 512; i++)
			set_bm((curr >> PAGE_SHIFT) + i,
					global_bm[cpuid], BM_4K);

		if (metadata_csum) {
			for (i = 0; i < 512; i++)
				set_bm((curr1 >> PAGE_SHIFT) + i,
					global_bm[cpuid], BM_4K);
		}

		for (i = 0; i < num_inodes_per_page; i++) {
			pi_addr = curr + i * NOVA_INODE_SIZE;
			ret = nova_get_reference(sb, pi_addr, &fake_pi,
				(void **)&pi, sizeof(struct nova_inode));
			if (ret) {
				nova_dbg("Recover pi @ 0x%llx failed\n",
						pi_addr);
				continue;
			}
			/* FIXME: Check inode checksum */
			if (fake_pi.i_mode && fake_pi.deleted == 0) {
				if (fake_pi.valid == 0) {
					ret = nova_append_inode_to_snapshot(sb,
									pi);
					if (ret != 0) {
						/* Deleteable */
						pi->deleted = 1;
						fake_pi.deleted = 1;
						continue;
					}
				}

				nova_recover_inode_pages(sb, &sih, ring,
						&fake_pi, global_bm[cpuid]);
				nova_failure_update_inodetree(sb, pi,
						&ino_low, &ino_high);
				if (sih.i_size > max_size)
					max_size = sih.i_size;
			}
		}

		if (ino_low && ino_high)
			nova_failure_insert_inodetree(sb, ino_low, ino_high);
	}

	/* Free radix tree */
	if (max_size) {
		last_blocknr = (max_size - 1) >> PAGE_SHIFT;
		nova_delete_file_tree(sb, &sih, 0, last_blocknr,
						false, false, 0);
	}

	finished[cpuid] = 1;
	wake_up_interruptible(&finish_wq);
	do_exit(ret);
	return ret;
}

static int nova_failure_recovery_crawl(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info_header sih;
	struct inode_table *inode_table;
	struct task_ring *ring;
	struct nova_inode *pi, fake_pi;
	unsigned long curr_addr;
	u64 root_addr;
	u64 curr;
	int num_tables;
	int version;
	int ret = 0;
	int count;
	int cpuid;

	root_addr = nova_get_reserved_inode_addr(sb, NOVA_ROOT_INO);

	num_tables = 1;
	if (metadata_csum)
		num_tables = 2;

	for (cpuid = 0; cpuid < sbi->cpus; cpuid++) {
		ring = &task_rings[cpuid];
		for (version = 0; version < num_tables; version++) {
			inode_table = nova_get_inode_table(sb, version,
								cpuid);
			if (!inode_table)
				return -EINVAL;

			count = 0;
			curr = inode_table->log_head;
			while (curr) {
				if (ring->num >= 512) {
					nova_err(sb, "%s: ring size too small\n",
						 __func__);
					return -EINVAL;
				}

				if (version == 0)
					ring->addr0[count] = curr;
				else
					ring->addr1[count] = curr;

				count++;

				curr_addr = (unsigned long)nova_get_block(sb,
								curr);
				/* Next page resides at the last 8 bytes */
				curr_addr += 2097152 - 8;
				curr = *(u64 *)(curr_addr);
			}

			if (count > ring->num)
				ring->num = count;
		}
	}

	for (cpuid = 0; cpuid < sbi->cpus; cpuid++)
		wake_up_process(threads[cpuid]);

	nova_init_header(sb, &sih, 0);
	/* Recover the root iode */
	ret = nova_get_reference(sb, root_addr, &fake_pi,
			(void **)&pi, sizeof(struct nova_inode));
	if (ret) {
		nova_dbg("Recover root pi failed\n");
		return ret;
	}

	nova_recover_inode_pages(sb, &sih, &task_rings[0],
					&fake_pi, global_bm[0]);

	return ret;
}

int nova_failure_recovery(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct task_ring *ring;
	struct nova_inode *pi;
	struct journal_ptr_pair *pair;
	int ret;
	int i;

	sbi->s_inodes_used_count = 0;

	/* Initialize inuse inode list */
	if (nova_init_inode_inuse_list(sb) < 0)
		return -EINVAL;

	/* Handle special inodes */
	pi = nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	pi->log_head = pi->log_tail = 0;
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 0);

	for (i = 0; i < sbi->cpus; i++) {
		pair = nova_get_journal_pointers(sb, i);

		set_bm(pair->journal_head >> PAGE_SHIFT, global_bm[i], BM_4K);
	}

	i = NOVA_SNAPSHOT_INO % sbi->cpus;
	pi = nova_get_inode_by_ino(sb, NOVA_SNAPSHOT_INO);
	/* Set snapshot info log pages */
	nova_traverse_dir_inode_log(sb, pi, global_bm[i]);

	PERSISTENT_BARRIER();

	ret = allocate_resources(sb, sbi->cpus);
	if (ret)
		return ret;

	ret = nova_failure_recovery_crawl(sb);

	wait_to_finish(sbi->cpus);

	for (i = 0; i < sbi->cpus; i++) {
		ring = &task_rings[i];
		sbi->s_inodes_used_count += ring->inodes_used_count;
	}

	free_resources(sb);

	nova_dbg("Failure recovery total recovered %lu\n",
			sbi->s_inodes_used_count - NOVA_NORMAL_INODE_START);
	return ret;
}

/*********************** Recovery entrance *************************/

/* Return TRUE if we can do a normal unmount recovery */
static bool nova_try_normal_recovery(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi =  nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	int ret;

	if (pi->log_head == 0 || pi->log_tail == 0)
		return false;

	ret = nova_init_blockmap_from_inode(sb);
	if (ret) {
		nova_err(sb, "init blockmap failed, fall back to failure recovery\n");
		return false;
	}

	ret = nova_init_inode_list_from_inode(sb);
	if (ret) {
		nova_err(sb, "init inode list failed, fall back to failure recovery\n");
		nova_destroy_blocknode_trees(sb);
		return false;
	}

	if (sbi->mount_snapshot == 0) {
		ret = nova_restore_snapshot_table(sb, 0);
		if (ret) {
			nova_err(sb, "Restore snapshot table failed, fall back to failure recovery\n");
			nova_destroy_snapshot_infos(sb);
			return false;
		}
	}

	return true;
}

/*
 * Recovery routine has three tasks:
 * 1. Restore snapshot table;
 * 2. Restore inuse inode list;
 * 3. Restore the NVMM allocator.
 */
int nova_recovery(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *super = sbi->nova_sb;
	unsigned long initsize = le64_to_cpu(super->s_size);
	bool value = false;
	int ret = 0;
	INIT_TIMING(start);
	INIT_TIMING(end);

	nova_dbgv("%s\n", __func__);

	/* Always check recovery time */
	if (measure_timing == 0)
		getrawmonotonic(&start);

	NOVA_START_TIMING(recovery_t, start);
	sbi->num_blocks = ((unsigned long)(initsize) >> PAGE_SHIFT);

	/* initialize free list info */
	nova_init_blockmap(sb, 1);

	value = nova_try_normal_recovery(sb);
	if (value) {
		nova_dbg("NOVA: Normal shutdown\n");
	} else {
		nova_dbg("NOVA: Failure recovery\n");
		ret = alloc_bm(sb, initsize);
		if (ret)
			goto out;

		if (sbi->mount_snapshot == 0) {
			/* Initialize the snapshot infos */
			ret = nova_restore_snapshot_table(sb, 1);
			if (ret) {
				nova_dbg("Initialize snapshot infos failed\n");
				nova_destroy_snapshot_infos(sb);
				goto out;
			}
		}

		sbi->s_inodes_used_count = 0;
		ret = nova_failure_recovery(sb);
		if (ret)
			goto out;

		ret = nova_build_blocknode_map(sb, initsize);
	}

out:
	NOVA_END_TIMING(recovery_t, start);
	if (measure_timing == 0) {
		getrawmonotonic(&end);
		Timingstats[recovery_t] +=
			(end.tv_sec - start.tv_sec) * 1000000000 +
			(end.tv_nsec - start.tv_nsec);
	}

	if (!value)
		free_bm(sb);

	sbi->s_epoch_id = le64_to_cpu(super->s_epoch_id);
	return ret;
}
