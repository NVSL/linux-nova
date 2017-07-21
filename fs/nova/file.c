/*
 * BRIEF DESCRIPTION
 *
 * File operations for files.
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

#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/falloc.h>
#include <asm/mman.h>
#include "nova.h"
#include "inode.h"


static inline int nova_can_set_blocksize_hint(struct inode *inode,
	struct nova_inode *pi, loff_t new_size)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;

	/* Currently, we don't deallocate data blocks till the file is deleted.
	 * So no changing blocksize hints once allocation is done.
	 */
	if (sih->i_size > 0)
		return 0;
	return 1;
}

int nova_set_blocksize_hint(struct super_block *sb, struct inode *inode,
	struct nova_inode *pi, loff_t new_size)
{
	unsigned short block_type;

	if (!nova_can_set_blocksize_hint(inode, pi, new_size))
		return 0;

	if (new_size >= 0x40000000) {   /* 1G */
		block_type = NOVA_BLOCK_TYPE_1G;
		goto hint_set;
	}

	if (new_size >= 0x200000) {     /* 2M */
		block_type = NOVA_BLOCK_TYPE_2M;
		goto hint_set;
	}

	/* defaulting to 4K */
	block_type = NOVA_BLOCK_TYPE_4K;

hint_set:
	nova_dbg_verbose(
		"Hint: new_size 0x%llx, i_size 0x%llx\n",
		new_size, pi->i_size);
	nova_dbg_verbose("Setting the hint to 0x%x\n", block_type);
	nova_memunlock_inode(sb, pi);
	pi->i_blk_type = block_type;
	nova_memlock_inode(sb, pi);
	return 0;
}

static loff_t nova_llseek(struct file *file, loff_t offset, int origin)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	int retval;

	if (origin != SEEK_DATA && origin != SEEK_HOLE)
		return generic_file_llseek(file, offset, origin);

	inode_lock(inode);
	switch (origin) {
	case SEEK_DATA:
		retval = nova_find_region(inode, &offset, 0);
		if (retval) {
			inode_unlock(inode);
			return retval;
		}
		break;
	case SEEK_HOLE:
		retval = nova_find_region(inode, &offset, 1);
		if (retval) {
			inode_unlock(inode);
			return retval;
		}
		break;
	}

	if ((offset < 0 && !(file->f_mode & FMODE_UNSIGNED_OFFSET)) ||
	    offset > inode->i_sb->s_maxbytes) {
		inode_unlock(inode);
		return -EINVAL;
	}

	if (offset != file->f_pos) {
		file->f_pos = offset;
		file->f_version = 0;
	}

	inode_unlock(inode);
	return offset;
}

/* This function is called by both msync() and fsync().
 * TODO: Check if we can avoid calling nova_flush_buffer() for fsync. We use
 * movnti to write data to files, so we may want to avoid doing unnecessary
 * nova_flush_buffer() on fsync()
 */
int nova_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = file->f_path.dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	unsigned long start_pgoff, end_pgoff;
	int ret = 0;
	timing_t fsync_time;

	NOVA_START_TIMING(fsync_t, fsync_time);

	if (datasync)
		NOVA_STATS_ADD(fdatasync, 1);

	/* No need to flush if the file is not mmaped */
	if (!mapping_mapped(mapping))
		goto persist;

	start_pgoff = start >> PAGE_SHIFT;
	end_pgoff = (end + 1) >> PAGE_SHIFT;
	nova_dbgv("%s: msync pgoff range %lu to %lu\n",
			__func__, start_pgoff, end_pgoff);

	/*
	 * Set csum and parity.
	 * We do not protect data integrity during mmap, but we have to
	 * update csum here since msync clears dirty bit.
	 */
	nova_reset_mapping_csum_parity(sb, inode, mapping,
					start_pgoff, end_pgoff);

	ret = generic_file_fsync(file, start, end, datasync);

persist:
	PERSISTENT_BARRIER();
	NOVA_END_TIMING(fsync_t, fsync_time);

	return ret;
}

/* This callback is called when a file is closed */
static int nova_flush(struct file *file, fl_owner_t id)
{
	PERSISTENT_BARRIER();
	return 0;
}

static int nova_open(struct inode *inode, struct file *filp)
{
	return generic_file_open(inode, filp);
}

static long nova_fallocate(struct file *file, int mode, loff_t offset,
	loff_t len)
{
	struct inode *inode = file->f_path.dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *pi;
	struct nova_file_write_entry *entry;
	struct nova_file_write_entry *entryc, entry_copy;
	struct nova_file_write_entry entry_data;
	struct nova_inode_update update;
	unsigned long start_blk, num_blocks, ent_blks = 0;
	unsigned long total_blocks = 0;
	unsigned long blocknr = 0;
	unsigned long blockoff;
	unsigned int data_bits;
	loff_t new_size;
	long ret = 0;
	int inplace = 0;
	int blocksize_mask;
	int allocated = 0;
	bool update_log = false;
	timing_t fallocate_time;
	u64 begin_tail = 0;
	u64 epoch_id;
	u32 time;

	/*
	 * Fallocate does not make much sence for CoW,
	 * but we still support it for DAX-mmap purpose.
	 */

	/* We only support the FALLOC_FL_KEEP_SIZE mode */
	if (mode & ~FALLOC_FL_KEEP_SIZE)
		return -EOPNOTSUPP;

	if (S_ISDIR(inode->i_mode))
		return -ENODEV;

	new_size = len + offset;
	if (!(mode & FALLOC_FL_KEEP_SIZE) && new_size > inode->i_size) {
		ret = inode_newsize_ok(inode, new_size);
		if (ret)
			return ret;
	} else {
		new_size = inode->i_size;
	}

	nova_dbgv("%s: inode %lu, offset %lld, count %lld, mode 0x%x\n",
			__func__, inode->i_ino,	offset, len, mode);

	NOVA_START_TIMING(fallocate_t, fallocate_time);
	inode_lock(inode);

	pi = nova_get_inode(sb, inode);
	if (!pi) {
		ret = -EACCES;
		goto out;
	}

	inode->i_mtime = inode->i_ctime = CURRENT_TIME_SEC;
	time = CURRENT_TIME_SEC.tv_sec;

	blocksize_mask = sb->s_blocksize - 1;
	start_blk = offset >> sb->s_blocksize_bits;
	blockoff = offset & blocksize_mask;
	num_blocks = (blockoff + len + blocksize_mask) >> sb->s_blocksize_bits;

	epoch_id = nova_get_epoch_id(sb);
	update.tail = sih->log_tail;
	update.alter_tail = sih->alter_log_tail;
	while (num_blocks > 0) {
		ent_blks = nova_check_existing_entry(sb, inode, num_blocks,
						start_blk, &entry, &entry_copy,
						1, epoch_id, &inplace, 1);

		entryc = (metadata_csum == 0) ? entry : &entry_copy;

		if (entry && inplace) {
			if (entryc->size < new_size) {
				/* Update existing entry */
				nova_memunlock_range(sb, entry, CACHELINE_SIZE);
				entry->size = new_size;
				nova_update_entry_csum(entry);
				nova_update_alter_entry(sb, entry);
				nova_memlock_range(sb, entry, CACHELINE_SIZE);
			}
			allocated = ent_blks;
			goto next;
		}

		/* Allocate zeroed blocks to fill hole */
		allocated = nova_new_data_blocks(sb, sih, &blocknr, start_blk,
						ent_blks, 1, ANY_CPU, 0);
		nova_dbgv("%s: alloc %d blocks @ %lu\n", __func__,
						allocated, blocknr);

		if (allocated <= 0) {
			nova_dbg("%s alloc %lu blocks failed!, %d\n",
						__func__, ent_blks, allocated);
			ret = allocated;
			goto out;
		}

		/* Handle hole fill write */
		nova_init_file_write_entry(sb, sih, &entry_data, epoch_id,
					start_blk, allocated, blocknr,
					time, new_size);

		ret = nova_append_file_write_entry(sb, pi, inode,
					&entry_data, &update);
		if (ret) {
			nova_dbg("%s: append inode entry failed\n", __func__);
			ret = -ENOSPC;
			goto out;
		}

		entry = nova_get_block(sb, update.curr_entry);
		nova_reset_csum_parity_range(sb, sih, entry, start_blk,
					start_blk + allocated, 1, 0);

		update_log = true;
		if (begin_tail == 0)
			begin_tail = update.curr_entry;

		total_blocks += allocated;
next:
		num_blocks -= allocated;
		start_blk += allocated;
	}

	data_bits = blk_type_to_shift[sih->i_blk_type];
	sih->i_blocks += (total_blocks << (data_bits - sb->s_blocksize_bits));

	inode->i_blocks = sih->i_blocks;

	if (update_log) {
		sih->log_tail = update.tail;
		sih->alter_log_tail = update.alter_tail;

		nova_memunlock_inode(sb, pi);
		nova_update_tail(pi, update.tail);
		if (metadata_csum)
			nova_update_alter_tail(pi, update.alter_tail);
		nova_memlock_inode(sb, pi);

		/* Update file tree */
		ret = nova_reassign_file_tree(sb, sih, begin_tail);
		if (ret)
			goto out;

	}

	nova_dbgv("blocks: %lu, %lu\n", inode->i_blocks, sih->i_blocks);

	if (ret || (mode & FALLOC_FL_KEEP_SIZE)) {
		nova_memunlock_inode(sb, pi);
		pi->i_flags |= cpu_to_le32(NOVA_EOFBLOCKS_FL);
		nova_memlock_inode(sb, pi);
	}

	if (!(mode & FALLOC_FL_KEEP_SIZE) && new_size > inode->i_size) {
		inode->i_size = new_size;
		sih->i_size = new_size;
	}

	nova_memunlock_inode(sb, pi);
	nova_update_inode_checksum(pi);
	nova_update_alter_inode(sb, inode, pi);
	nova_memlock_inode(sb, pi);

	sih->trans_id++;
out:
	if (ret < 0)
		nova_cleanup_incomplete_write(sb, sih, blocknr, allocated,
						begin_tail, update.tail);

	inode_unlock(inode);
	NOVA_END_TIMING(fallocate_t, fallocate_time);
	return ret;
}

static int nova_iomap_begin_nolock(struct inode *inode, loff_t offset,
	loff_t length, unsigned int flags, struct iomap *iomap)
{
	return nova_iomap_begin(inode, offset, length, flags, iomap, false);
}

static struct iomap_ops nova_iomap_ops_nolock = {
	.iomap_begin	= nova_iomap_begin_nolock,
	.iomap_end	= nova_iomap_end,
};

static ssize_t nova_dax_read_iter(struct kiocb *iocb, struct iov_iter *to)
{
	struct inode *inode = iocb->ki_filp->f_mapping->host;
	ssize_t ret;
	timing_t read_iter_time;

	if (!iov_iter_count(to))
		return 0;

	NOVA_START_TIMING(read_iter_t, read_iter_time);
	inode_lock_shared(inode);
	ret = dax_iomap_rw(iocb, to, &nova_iomap_ops_nolock);
	inode_unlock_shared(inode);

	file_accessed(iocb->ki_filp);
	NOVA_END_TIMING(read_iter_t, read_iter_time);
	return ret;
}

static int nova_update_iter_csum_parity(struct super_block *sb,
	struct inode *inode, loff_t offset, size_t count)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	unsigned long start_pgoff, end_pgoff;
	loff_t end;

	if (data_csum == 0 && data_parity == 0)
		return 0;

	end = offset + count;

	start_pgoff = offset >> sb->s_blocksize_bits;
	end_pgoff = end >> sb->s_blocksize_bits;
	if (end & (nova_inode_blk_size(sih) - 1))
		end_pgoff++;

	nova_reset_csum_parity_range(sb, sih, NULL, start_pgoff,
			end_pgoff, 0, 0);

	return 0;
}

static ssize_t nova_dax_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file->f_mapping->host;
	struct super_block *sb = inode->i_sb;
	loff_t offset;
	size_t count;
	ssize_t ret;
	timing_t write_iter_time;

	NOVA_START_TIMING(write_iter_t, write_iter_time);
	inode_lock(inode);
	ret = generic_write_checks(iocb, from);
	if (ret <= 0)
		goto out_unlock;

	ret = file_remove_privs(file);
	if (ret)
		goto out_unlock;

	ret = file_update_time(file);
	if (ret)
		goto out_unlock;

	count = iov_iter_count(from);
	offset = iocb->ki_pos;

	ret = dax_iomap_rw(iocb, from, &nova_iomap_ops_nolock);
	if (ret > 0 && iocb->ki_pos > i_size_read(inode)) {
		i_size_write(inode, iocb->ki_pos);
		mark_inode_dirty(inode);
	}

	nova_update_iter_csum_parity(sb, inode, offset, count);

out_unlock:
	inode_unlock(inode);
	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	NOVA_END_TIMING(write_iter_t, write_iter_time);
	return ret;
}

const struct file_operations nova_dax_file_operations = {
	.llseek			= nova_llseek,
	.read			= nova_dax_file_read,
	.write			= nova_dax_file_write,
	.read_iter		= nova_dax_read_iter,
	.write_iter		= nova_dax_write_iter,
	.mmap			= nova_dax_file_mmap,
	.open			= nova_open,
	.fsync			= nova_fsync,
	.flush			= nova_flush,
	.unlocked_ioctl		= nova_ioctl,
	.fallocate		= nova_fallocate,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= nova_compat_ioctl,
#endif
};


static ssize_t nova_wrap_rw_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *filp = iocb->ki_filp;
	ssize_t ret = -EIO;
	ssize_t written = 0;
	unsigned long seg;
	unsigned long nr_segs = iter->nr_segs;
	const struct iovec *iv = iter->iov;

	nova_dbgv("%s %s: %lu segs\n", __func__,
			iov_iter_rw(iter) == READ ? "read" : "write",
			nr_segs);
	iv = iter->iov;
	for (seg = 0; seg < nr_segs; seg++) {
		if (iov_iter_rw(iter) == READ) {
			ret = nova_dax_file_read(filp, iv->iov_base,
					iv->iov_len, &iocb->ki_pos);
		} else if (iov_iter_rw(iter) == WRITE) {
			ret = nova_dax_file_write(filp, iv->iov_base,
					iv->iov_len, &iocb->ki_pos);
		}
		if (ret < 0)
			goto err;

		if (iter->count > iv->iov_len)
			iter->count -= iv->iov_len;
		else
			iter->count = 0;

		written += ret;
		iter->nr_segs--;
		iv++;
	}
	ret = written;
err:
	return ret;
}


/* Wrap read/write_iter for DP, CoW and WP */
const struct file_operations nova_wrap_file_operations = {
	.llseek			= nova_llseek,
	.read			= nova_dax_file_read,
	.write			= nova_dax_file_write,
	.read_iter		= nova_wrap_rw_iter,
	.write_iter		= nova_wrap_rw_iter,
	.mmap			= nova_dax_file_mmap,
	.open			= nova_open,
	.fsync			= nova_fsync,
	.flush			= nova_flush,
	.unlocked_ioctl		= nova_ioctl,
	.fallocate		= nova_fallocate,
#ifdef CONFIG_COMPAT
	.compat_ioctl		= nova_compat_ioctl,
#endif
};

const struct inode_operations nova_file_inode_operations = {
	.setattr	= nova_notify_change,
	.getattr	= nova_getattr,
	.get_acl	= NULL,
};
