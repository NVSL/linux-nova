/*
 * BRIEF DESCRIPTION
 *
 * Memory protection for the filesystem pages.
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
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/io.h>
#include "nova.h"
#include "inode.h"

static inline void wprotect_disable(void)
{
	unsigned long cr0_val;

	cr0_val = read_cr0();
	cr0_val &= (~X86_CR0_WP);
	write_cr0(cr0_val);
}

static inline void wprotect_enable(void)
{
	unsigned long cr0_val;

	cr0_val = read_cr0();
	cr0_val |= X86_CR0_WP;
	write_cr0(cr0_val);
}

/* FIXME: Assumes that we are always called in the right order.
 * nova_writeable(vaddr, size, 1);
 * nova_writeable(vaddr, size, 0);
 */
int nova_writeable(void *vaddr, unsigned long size, int rw)
{
	static unsigned long flags;
	INIT_TIMING(wprotect_time);

	NOVA_START_TIMING(wprotect_t, wprotect_time);
	if (rw) {
		local_irq_save(flags);
		wprotect_disable();
	} else {
		wprotect_enable();
		local_irq_restore(flags);
	}
	NOVA_END_TIMING(wprotect_t, wprotect_time);
	return 0;
}

int nova_dax_mem_protect(struct super_block *sb, void *vaddr,
			  unsigned long size, int rw)
{
	if (!nova_is_wprotected(sb))
		return 0;
	return nova_writeable(vaddr, size, rw);
}

int nova_get_vma_overlap_range(struct super_block *sb,
	struct nova_inode_info_header *sih, struct vm_area_struct *vma,
	unsigned long entry_pgoff, unsigned long entry_pages,
	unsigned long *start_pgoff, unsigned long *num_pages)
{
	unsigned long vma_pgoff;
	unsigned long vma_pages;
	unsigned long end_pgoff;

	vma_pgoff = vma->vm_pgoff;
	vma_pages = (vma->vm_end - vma->vm_start) >> sb->s_blocksize_bits;

	if (vma_pgoff + vma_pages <= entry_pgoff ||
				entry_pgoff + entry_pages <= vma_pgoff)
		return 0;

	*start_pgoff = vma_pgoff > entry_pgoff ? vma_pgoff : entry_pgoff;
	end_pgoff = (vma_pgoff + vma_pages) > (entry_pgoff + entry_pages) ?
			entry_pgoff + entry_pages : vma_pgoff + vma_pages;
	*num_pages = end_pgoff - *start_pgoff;
	return 1;
}

static int nova_update_dax_mapping(struct super_block *sb,
	struct nova_inode_info_header *sih, struct vm_area_struct *vma,
	struct nova_file_write_entry *entry, unsigned long start_pgoff,
	unsigned long num_pages)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	void **pentry;
	unsigned long curr_pgoff;
	unsigned long blocknr, start_blocknr;
	unsigned long value, new_value;
	int i;
	int ret = 0;
	INIT_TIMING(update_time);

	NOVA_START_TIMING(update_mapping_t, update_time);

	start_blocknr = nova_get_blocknr(sb, entry->block, sih->i_blk_type);
	xa_lock_irq(&mapping->i_pages);
	for (i = 0; i < num_pages; i++) {
		curr_pgoff = start_pgoff + i;
		blocknr = start_blocknr + i;

		pentry = radix_tree_lookup_slot(&mapping->i_pages,
						curr_pgoff);
		if (pentry) {
			value = (unsigned long)radix_tree_deref_slot(pentry);
			/* 9 = sector shift (3) + RADIX_DAX_SHIFT (6) */
			new_value = (blocknr << 9) | (value & 0xff);
			nova_dbgv("%s: pgoff %lu, entry 0x%lx, new 0x%lx\n",
						__func__, curr_pgoff,
						value, new_value);
			radix_tree_replace_slot(&sih->tree, pentry,
						(void *)new_value);
			radix_tree_tag_set(&mapping->i_pages, curr_pgoff,
						PAGECACHE_TAG_DIRTY);
		}
	}

	xa_unlock_irq(&mapping->i_pages);

	NOVA_END_TIMING(update_mapping_t, update_time);
	return ret;
}

static int nova_update_entry_pfn(struct super_block *sb,
	struct nova_inode_info_header *sih, struct vm_area_struct *vma,
	struct nova_file_write_entry *entry, unsigned long start_pgoff,
	unsigned long num_pages)
{
	unsigned long newflags;
	unsigned long addr;
	unsigned long size;
	unsigned long pfn;
	pgprot_t new_prot;
	int ret;
	INIT_TIMING(update_time);

	NOVA_START_TIMING(update_pfn_t, update_time);

	addr = vma->vm_start + ((start_pgoff - vma->vm_pgoff) << PAGE_SHIFT);
	pfn = nova_get_pfn(sb, entry->block) + start_pgoff - entry->pgoff;
	size = num_pages << PAGE_SHIFT;

	nova_dbgv("%s: addr 0x%lx, size 0x%lx\n", __func__,
			addr, size);

	newflags = vma->vm_flags | VM_WRITE;
	new_prot = vm_get_page_prot(newflags);

	ret = remap_pfn_range(vma, addr, pfn, size, new_prot);

	NOVA_END_TIMING(update_pfn_t, update_time);
	return ret;
}

static int nova_dax_mmap_update_mapping(struct super_block *sb,
	struct nova_inode_info_header *sih, struct vm_area_struct *vma,
	struct nova_file_write_entry *entry_data)
{
	unsigned long start_pgoff, num_pages = 0;
	int ret;

	ret = nova_get_vma_overlap_range(sb, sih, vma, entry_data->pgoff,
						entry_data->num_pages,
						&start_pgoff, &num_pages);
	if (ret == 0)
		return ret;


	NOVA_STATS_ADD(mapping_updated_pages, num_pages);

	ret = nova_update_dax_mapping(sb, sih, vma, entry_data,
						start_pgoff, num_pages);
	if (ret) {
		nova_err(sb, "update DAX mapping return %d\n", ret);
		return ret;
	}

	ret = nova_update_entry_pfn(sb, sih, vma, entry_data,
						start_pgoff, num_pages);
	if (ret)
		nova_err(sb, "update_pfn return %d\n", ret);


	return ret;
}

static int nova_dax_cow_mmap_handler(struct super_block *sb,
	struct vm_area_struct *vma, struct nova_inode_info_header *sih,
	u64 begin_tail)
{
	struct nova_file_write_entry *entry;
	struct nova_file_write_entry *entryc, entry_copy;
	u64 curr_p = begin_tail;
	size_t entry_size = sizeof(struct nova_file_write_entry);
	int ret = 0;
	INIT_TIMING(update_time);

	NOVA_START_TIMING(mmap_handler_t, update_time);
	entryc = (metadata_csum == 0) ? entry : &entry_copy;
	while (curr_p && curr_p != sih->log_tail) {
		if (is_last_entry(curr_p, entry_size))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) {
			nova_err(sb, "%s: File inode %lu log is NULL!\n",
				__func__, sih->ino);
			ret = -EINVAL;
			break;
		}

		entry = (struct nova_file_write_entry *)
					nova_get_block(sb, curr_p);

		if (metadata_csum == 0)
			entryc = entry;
		else if (!nova_verify_entry_csum(sb, entry, entryc)) {
			ret = -EIO;
			curr_p += entry_size;
			continue;
		}

		if (nova_get_entry_type(entryc) != FILE_WRITE) {
			/* for debug information, still use nvmm entry */
			nova_dbg("%s: entry type is not write? %d\n",
				__func__, nova_get_entry_type(entry));
			curr_p += entry_size;
			continue;
		}

		ret = nova_dax_mmap_update_mapping(sb, sih, vma, entryc);
		if (ret)
			break;

		curr_p += entry_size;
	}

	NOVA_END_TIMING(mmap_handler_t, update_time);
	return ret;
}

static int nova_get_dax_cow_range(struct super_block *sb,
	struct vm_area_struct *vma, unsigned long address,
	unsigned long *start_blk, int *num_blocks)
{
	int base = 1;
	unsigned long vma_blocks;
	unsigned long pgoff;
	unsigned long start_pgoff;

	vma_blocks = (vma->vm_end - vma->vm_start) >> sb->s_blocksize_bits;

	/* Read ahead, avoid sequential page faults */
	if (vma_blocks >= 4096)
		base = 4096;

	pgoff = (address - vma->vm_start) >> sb->s_blocksize_bits;
	start_pgoff = pgoff & ~(base - 1);
	*start_blk = vma->vm_pgoff + start_pgoff;
	*num_blocks = (base > vma_blocks - start_pgoff) ?
			vma_blocks - start_pgoff : base;
	nova_dbgv("%s: start block %lu, %d blocks\n",
			__func__, *start_blk, *num_blocks);
	return 0;
}

int nova_mmap_to_new_blocks(struct vm_area_struct *vma,
	unsigned long address)
{
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct inode *inode = mapping->host;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi;
	struct nova_file_write_entry *entry;
	struct nova_file_write_entry *entryc, entry_copy;
	struct nova_file_write_entry entry_data;
	struct nova_inode_update update;
	unsigned long start_blk, end_blk;
	unsigned long entry_pgoff;
	unsigned long from_blocknr = 0;
	unsigned long blocknr = 0;
	unsigned long avail_blocks;
	unsigned long copy_blocks;
	int num_blocks = 0;
	u64 from_blockoff, to_blockoff;
	size_t copied;
	int allocated = 0;
	void *from_kmem;
	void *to_kmem;
	size_t bytes;
	INIT_TIMING(memcpy_time);
	u64 begin_tail = 0;
	u64 epoch_id;
	u64 entry_size;
	u32 time;
	INIT_TIMING(mmap_cow_time);
	int ret = 0;

	NOVA_START_TIMING(mmap_cow_t, mmap_cow_time);

	nova_get_dax_cow_range(sb, vma, address, &start_blk, &num_blocks);

	end_blk = start_blk + num_blocks;
	if (start_blk >= end_blk) {
		NOVA_END_TIMING(mmap_cow_t, mmap_cow_time);
		return 0;
	}

	if (sbi->snapshot_taking) {
		/* Block CoW mmap until snapshot taken completes */
		NOVA_STATS_ADD(dax_cow_during_snapshot, 1);
		wait_event_interruptible(sbi->snapshot_mmap_wait,
					sbi->snapshot_taking == 0);
	}

	inode_lock(inode);

	pi = nova_get_inode(sb, inode);

	nova_dbgv("%s: inode %lu, start pgoff %lu, end pgoff %lu\n",
			__func__, inode->i_ino, start_blk, end_blk);

	time = current_time(inode).tv_sec;

	epoch_id = nova_get_epoch_id(sb);
	update.tail = pi->log_tail;
	update.alter_tail = pi->alter_log_tail;

	entryc = (metadata_csum == 0) ? entry : &entry_copy;

	while (start_blk < end_blk) {
		entry = nova_get_write_entry_lockfree(sb, sih, start_blk);
		if (!entry) {
			nova_dbgv("%s: Found hole: pgoff %lu\n",
					__func__, start_blk);

			/* Jump the hole */
			entry = nova_find_next_entry_lockfree(sb, sih, start_blk);
			if (!entry)
				break;

			if (metadata_csum == 0)
				entryc = entry;
			else if (!nova_verify_entry_csum(sb, entry, entryc))
				break;

			start_blk = entryc->pgoff;
			if (start_blk >= end_blk)
				break;
		} else {
			if (metadata_csum == 0)
				entryc = entry;
			else if (!nova_verify_entry_csum(sb, entry, entryc))
				break;
		}

		if (entryc->epoch_id == epoch_id) {
			/* Someone has done it for us. */
			break;
		}

		from_blocknr = get_nvmm(sb, sih, entryc, start_blk);
		from_blockoff = nova_get_block_off(sb, from_blocknr,
						pi->i_blk_type);
		from_kmem = nova_get_block(sb, from_blockoff);

		if (entryc->reassigned == 0)
			avail_blocks = entryc->num_pages -
					(start_blk - entryc->pgoff);
		else
			avail_blocks = 1;

		if (avail_blocks > end_blk - start_blk)
			avail_blocks = end_blk - start_blk;

		allocated = nova_new_data_blocks(sb, sih, &blocknr, start_blk,
					 avail_blocks, ALLOC_NO_INIT, ANY_CPU,
					 ALLOC_FROM_HEAD);

		nova_dbgv("%s: alloc %d blocks @ %lu\n", __func__,
						allocated, blocknr);

		if (allocated <= 0) {
			nova_dbg("%s alloc blocks failed!, %d\n",
						__func__, allocated);
			ret = allocated;
			goto out;
		}

		to_blockoff = nova_get_block_off(sb, blocknr,
						pi->i_blk_type);
		to_kmem = nova_get_block(sb, to_blockoff);
		entry_pgoff = start_blk;

		copy_blocks = allocated;

		bytes = sb->s_blocksize * copy_blocks;

		/* Now copy from user buf */
		NOVA_START_TIMING(memcpy_w_wb_t, memcpy_time);
		nova_memunlock_range(sb, to_kmem, bytes);
		copied = bytes - memcpy_to_pmem_nocache(to_kmem, from_kmem,
							bytes);
		nova_memlock_range(sb, to_kmem, bytes);
		NOVA_END_TIMING(memcpy_w_wb_t, memcpy_time);

		// reclaim_get_nvmm(sb, from_blocknr, entryc, start_blk);

		if (copied == bytes) {
			start_blk += copy_blocks;
		} else {
			nova_dbg("%s ERROR!: bytes %lu, copied %lu\n",
				__func__, bytes, copied);
			ret = -EFAULT;
			goto out;
		}

		entry_size = cpu_to_le64(inode->i_size);

		nova_init_file_write_entry(sb, sih, &entry_data,
					epoch_id, entry_pgoff, copy_blocks,
					blocknr, time, entry_size);

		ret = nova_append_file_write_entry(sb, pi, inode,
					&entry_data, &update);
		if (ret) {
			nova_dbg("%s: append inode entry failed\n",
					__func__);
			ret = -ENOSPC;
			goto out;
		}

		if (begin_tail == 0)
			begin_tail = update.curr_entry;
	}

	if (begin_tail == 0)
		goto out;

	nova_memunlock_inode(sb, pi);
	nova_update_inode(sb, inode, pi, &update, 1);
	nova_memlock_inode(sb, pi);

	/* Update file tree */
	ret = nova_reassign_file_tree(sb, sih, begin_tail, true);
	if (ret)
		goto out;


	/* Update pfn and prot */
	ret = nova_dax_cow_mmap_handler(sb, vma, sih, begin_tail);
	if (ret)
		goto out;


	sih->trans_id++;

out:
	if (ret < 0)
		nova_cleanup_incomplete_write(sb, sih, blocknr, allocated,
						begin_tail, update.tail);

	inode_unlock(inode);
	NOVA_END_TIMING(mmap_cow_t, mmap_cow_time);
	return ret;
}

static int nova_set_vma_read(struct vm_area_struct *vma)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long oldflags = vma->vm_flags;
	unsigned long newflags;
	pgprot_t new_page_prot;

	down_write(&mm->mmap_sem);

	newflags = oldflags & (~VM_WRITE);
	if (oldflags == newflags)
		goto out;

	nova_dbgv("Set vma %p read, start 0x%lx, end 0x%lx\n",
				vma, vma->vm_start,
				vma->vm_end);

	new_page_prot = vm_get_page_prot(newflags);
	change_protection(vma, vma->vm_start, vma->vm_end,
				new_page_prot, 0, 0);
	vma->original_write = 1;

out:
	up_write(&mm->mmap_sem);

	return 0;
}

static inline bool pgoff_in_vma(struct vm_area_struct *vma,
	unsigned long pgoff)
{
	unsigned long num_pages;

	num_pages = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;

	if (pgoff >= vma->vm_pgoff && pgoff < vma->vm_pgoff + num_pages)
		return true;

	return false;
}

bool nova_find_pgoff_in_vma(struct inode *inode, unsigned long pgoff)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct vma_item *item;
	struct rb_node *temp;
	bool ret = false;

	if (sih->num_vmas == 0)
		return ret;

	temp = rb_first(&sih->vma_tree);
	while (temp) {
		item = container_of(temp, struct vma_item, node);
		temp = rb_next(temp);
		if (pgoff_in_vma(item->vma, pgoff)) {
			ret = true;
			break;
		}
	}

	return ret;
}

static int nova_set_sih_vmas_readonly(struct nova_inode_info_header *sih)
{
	struct vma_item *item;
	struct rb_node *temp;
	INIT_TIMING(set_read_time);

	NOVA_START_TIMING(set_vma_read_t, set_read_time);

	temp = rb_first(&sih->vma_tree);
	while (temp) {
		item = container_of(temp, struct vma_item, node);
		temp = rb_next(temp);
		nova_set_vma_read(item->vma);
	}

	NOVA_END_TIMING(set_vma_read_t, set_read_time);
	return 0;
}

int nova_set_vmas_readonly(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info_header *sih;

	nova_dbgv("%s\n", __func__);
	mutex_lock(&sbi->vma_mutex);
	list_for_each_entry(sih, &sbi->mmap_sih_list, list)
		nova_set_sih_vmas_readonly(sih);
	mutex_unlock(&sbi->vma_mutex);

	return 0;
}

#if 0
int nova_destroy_vma_tree(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct vma_item *item;
	struct rb_node *temp;

	nova_dbgv("%s\n", __func__);
	mutex_lock(&sbi->vma_mutex);
	temp = rb_first(&sbi->vma_tree);
	while (temp) {
		item = container_of(temp, struct vma_item, node);
		temp = rb_next(temp);
		rb_erase(&item->node, &sbi->vma_tree);
		kfree(item);
	}
	mutex_unlock(&sbi->vma_mutex);

	return 0;
}
#endif
