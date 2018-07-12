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
#include "bdev.h"
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
		return -ENXIO;
	}

	if (offset != file->f_pos) {
		file->f_pos = offset;
		file->f_version = 0;
	}

	inode_unlock(inode);
	return offset;
}

inline int nova_sync_entry_blocks(struct nova_file_write_entry *entry) {
	return vpmem_flush_pages_sync(blockoff_to_virt(entry->block >> PAGE_SHIFT), entry->num_pages);
}

int nova_fsync_range(struct inode *inode, unsigned long start_pgoff, unsigned long end_pgoff) {
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
    unsigned long index = start_pgoff;
	int ret = 0;
    unsigned int num_pages;
    unsigned long pgoff, isize;
	struct nova_file_write_entry *entry, *last_entry = NULL;
	
	isize = i_size_read(inode);
	if (end_pgoff > (isize) >> PAGE_SHIFT) end_pgoff = (isize) >> PAGE_SHIFT;
	
    do {
        entry = nova_find_next_entry(sb, sih, index);
		// nova_info("index %lu %lu %lu\n", index, start_pgoff, end_pgoff);
        if (entry) {            
            if (entry == last_entry) {
                index++;
				put_write_entry(entry);
                continue;
            }
            if (entry->reassigned) {
                pgoff = index;
                num_pages = valid_index_range(sb, sih, index);
            }
            else {
                pgoff = le64_to_cpu(entry->pgoff);
                num_pages = le32_to_cpu(entry->num_pages);
            }      
			if (entry->block >> PAGE_SHIFT >= sbi->num_blocks)     
				ret += nova_sync_entry_blocks(entry);
			
            index = (pgoff + num_pages) > index+1 ? pgoff + num_pages : index+1;
			put_write_entry(entry);
        }
        else {
            index++;
        }
        last_entry = entry;
    } while (index <= end_pgoff);
	// nova_info("fsync %d pages\n", ret);
	return ret;
}

/* This function is called by both msync() and fsync().
 * TODO: Check if we can avoid calling nova_flush_buffer() for fsync. We use
 * movnti to write data to files, so we may want to avoid doing unnecessary
 * nova_flush_buffer() on fsync()
 */
static int nova_fsync(struct file *file, loff_t start, loff_t end, int datasync)
{
	struct address_space *mapping = file->f_mapping;
	struct inode *inode = file->f_path.dentry->d_inode;
	struct super_block *sb = inode->i_sb;
	unsigned long start_pgoff, end_pgoff;
	int ret = 0;
	timing_t fsync_time;

	NOVA_START_TIMING(fsync_t, fsync_time);
	if (DEBUG_FORE_FILE) nova_info("nova_fsync is called\n");
	if (MODE_FORE_ALLOC) nova_prof_judge_sync(file);
	if (datasync)
		NOVA_STATS_ADD(fdatasync, 1);

	start_pgoff = start >> PAGE_SHIFT;
	end_pgoff = (end + 1) >> PAGE_SHIFT;
	nova_dbgv("%s: msync pgoff range %lu to %lu\n",
			__func__, start_pgoff, end_pgoff);

	nova_fsync_range(file_inode(file), start_pgoff, end_pgoff);
	
	/* No need to flush if the file is not mmaped */
	if (!mapping_mapped(mapping))
		goto persist;

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

static int nova_migration(struct inode *inode, struct file *file) {
	struct super_block *sb = inode->i_sb;
	
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;

	if (DEBUG_DO_MIGRATION) {
		if(rwsem_is_locked(&inode->i_rwsem)) nova_info("nova_flush is locked\n");
		else nova_info("nova_flush is not locked\n");
	}

	if (DEBUG_DO_MIGRATION)
	nova_info("Release i_count:%d,i_dio_count:%d,i_writecount:%d,i_readcount:%d\n",
		inode->i_count.counter,inode->i_dio_count.counter,inode->i_writecount.counter,inode->i_readcount.counter);

	switch (file->f_flags & O_ACCMODE) {
		case O_RDONLY:
			if (inode->i_writecount.counter!=0 || inode->i_readcount.counter!=1) {
				nova_info("Flag: O_RDONLY.\n");
				goto out;
			}
			break;
		case O_WRONLY:
			if (inode->i_writecount.counter!=1 || inode->i_readcount.counter!=0) {
				nova_info("Flag: O_WRONLY.\n");
				goto out;
			}
			break;
		case O_RDWR:
			if (inode->i_writecount.counter!=1 || inode->i_readcount.counter!=0) {
				nova_info("Flag: O_RDWR.\n");
				goto out;
			}
			break;
		default:
			nova_info("Unidentified file access mode.\n");
			goto out;
	}

	if (file->f_flags & O_SYNC) {
		migrate_a_file_to_pmem(inode);
		goto end;
	}

	if (DEBUG_DO_MIGRATION) nova_info("Do migration.\n");

	// Tiering migration
	if (DEBUG_BFL_INFO) {
		nova_info("[Start migration]\n");
		print_all_bfl(sb);
	}	

	if (DEBUG_WRITE_ENTRY) print_file_write_entries(sb, sih);
		
	if ( MIGRATION_POLICY == MIGRATION_ROTATE ) {
		sb_start_write(inode->i_sb);
		inode_lock(inode);
		do_migrate_a_file_rotate(inode);
		inode_unlock(inode);
		sb_end_write(inode->i_sb);
	}
	
	// if ( MIGRATION_POLICY == MIGRATION_DOWNWARD ) do_migrate_a_file_downward(sb);

	if (DEBUG_WRITE_ENTRY) print_file_write_entries(sb, sih);
	if (DEBUG_BFL_INFO) {
		print_all_bfl(sb);
		nova_info("[End migration]\n");
	}

	goto end;
	
out:
	if (DEBUG_DO_MIGRATION) nova_info("No migration.\n");

end:
	return 0;
}

/* This callback is called when a file is closed */
static int nova_flush(struct file *file, fl_owner_t id)
{
	// nova_info("nova_flush is called\n");
	PERSISTENT_BARRIER();
	return 0;
}

static int nova_release(struct inode *inode, struct file *file)
{
	// struct nova_inode_info *si = NOVA_I(inode);
	// struct nova_inode_info_header *sih = &si->header;
	if (DEBUG_FORE_FILE) nova_info("nova_release (inode %lu) is called\n", inode->i_ino);
	// if (DEBUG_MIGRATION_SEM) nova_info("Mig_sem (inode %lu) up_read (nova_release)\n", sih->ino);
    // up_read(&sih->mig_sem);
	if (0) return nova_migration(inode, file);
	return 0;
}

static int nova_open(struct inode *inode, struct file *filp)
{
	// struct nova_inode_info *si = NOVA_I(inode);
	// struct nova_inode_info_header *sih = &si->header;
	if (DEBUG_FORE_FILE) nova_info("nova_open (inode %lu) is called\n", inode->i_ino);
	// if (DEBUG_MIGRATION_SEM) nova_info("Mig_sem (inode %lu) down_read (nova_open)\n", sih->ino);
    // down_read(&sih->mig_sem);
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

	inode->i_mtime = inode->i_ctime = current_time(inode);
	time = current_time(inode).tv_sec;

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
			put_write_entry(entry);
			goto next;
		} else if (entry) {
			put_write_entry(entry);
		}

		/* Allocate zeroed blocks to fill hole */
		allocated = nova_new_data_blocks(sb, sih, &blocknr, start_blk,
				 ent_blks, ALLOC_INIT_ZERO, ANY_CPU,
				 ALLOC_FROM_HEAD);
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
		ret = nova_reassign_file_tree(sb, sih, begin_tail, true);
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

static ssize_t
do_dax_mapping_read(struct file *filp, char __user *buf,
	size_t len, loff_t *ppos)
{
	struct inode *inode = filp->f_mapping->host;
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_entry *entry = NULL;
	struct nova_file_write_entry *entryc, entry_copy;
	pgoff_t index, end_index;
	unsigned long offset;
	loff_t isize, pos;
	size_t copied = 0, error = 0;
	timing_t memcpy_time;

	pos = *ppos;
	index = pos >> PAGE_SHIFT;
	offset = pos & ~PAGE_MASK;

	// nova_info("read 1 len %lu pos %llu\n", len, pos);

	if (!access_ok(VERIFY_WRITE, buf, len)) {
		error = -EFAULT;
		goto out;
	}

	isize = i_size_read(inode);
	if (!isize)
		goto out;

	nova_dbgv("%s: inode %lu, offset %lld, count %lu, size %lld\n",
		__func__, inode->i_ino,	pos, len, isize);

	if (len > isize - pos)
		len = isize - pos;

	if (len <= 0)
		goto out;

	if (MODE_KEEP_STAT) sbi->stat->read += len;
	if (MODE_USE_DYN_THRES) nova_update_stat(sbi, len, true);
	
	entryc = (metadata_csum == 0) ? entry : &entry_copy;

	end_index = (isize - 1) >> PAGE_SHIFT;
	do {
		unsigned long nr, left;
		unsigned long nvmm = 0;
		void *dax_mem = NULL;
		int zero = 0;
		
		/* nr is the maximum number of bytes to copy from this page */
		if (index >= end_index) {
			if (index > end_index)
				goto out;
			nr = ((isize - 1) & ~PAGE_MASK) + 1;
			if (nr <= offset)
				goto out;
		}

		entry = nova_get_write_entry(sb, sih, index);
		
		if (unlikely(entry == NULL)) {
			nova_dbgv("Required extent not found: pgoff %lu, inode size %lld\n",
				index, isize);
			nr = PAGE_SIZE;
			zero = 1;
			goto memcpy;
		}

		if (metadata_csum == 0)
			entryc = entry;
		else if (!nova_verify_entry_csum(sb, entry, entryc))
			return -EIO;

		/* Find contiguous blocks */
		if (index < entryc->pgoff ||
			index - entryc->pgoff >= entryc->num_pages) {
			print_a_write_entry(sb, entry, -2);
			nova_err(sb, "%s ERROR: Inode %lu %lu, entry pgoff %llu, num %u, blocknr %llu tier %d\n",
				__func__, sih->ino, index, entry->pgoff,
				entry->num_pages, entry->block >> PAGE_SHIFT, get_entry_tier(entry));
			return -EINVAL;
		}
		if (entryc->reassigned == 0) {
			nr = (entryc->num_pages - (index - entryc->pgoff))
				* PAGE_SIZE;
		} else {
			nr = PAGE_SIZE;
		}

		nvmm = get_nvmm(sb, sih, entryc, index);
		dax_mem = nova_get_block(sb, (nvmm << PAGE_SHIFT));

		if (DEBUG_GET_NVMM) nova_info("nvmm: %lu, dax_mem: %p\n", nvmm, dax_mem);
		// print_a_page(dax_mem);

memcpy:
		nr = nr - offset;
		if (nr > len - copied)
			nr = len - copied;

		if ((!zero) && (data_csum > 0)) {
			if (nova_find_pgoff_in_vma(inode, index))
				goto skip_verify;

			/*
			if (!nova_verify_data_csum(sb, sih, nvmm, offset, nr)) {
				nova_err(sb, "%s: nova data checksum and recovery fail! inode %lu, offset %lu, entry pgoff %lu, %u pages, pgoff %lu\n",
					 __func__, inode->i_ino, offset,
					 entry->pgoff, entry->num_pages, index);
				error = -EIO;
				goto out;
			}
			*/
		}

		if (vpmem_valid_address((unsigned long)dax_mem)) {
        // nova_info("dax %lx %lx %lu %lu %lu\n", (unsigned long)dax_mem, (unsigned long)dax_mem + offset + nr - 1,
		// 	(unsigned long)entryc->num_pages, index, (unsigned long)entryc->pgoff);
			vpmem_do_page_fault_range((unsigned long)dax_mem, 
				(unsigned long)dax_mem + offset + nr - 1, entryc->num_pages - (index - entryc->pgoff));
		}

skip_verify:
		NOVA_START_TIMING(memcpy_r_nvmm_t, memcpy_time);

		if (!zero) {
			// nova_info("read 2 buf %p, copied %lu dax_mem %p offset %lu nr %lu\n", 
			// 	buf, copied, dax_mem, offset, nr);
			left = __copy_to_user(buf + copied,
						dax_mem + offset, nr);
		}
		else
			left = __clear_user(buf + copied, nr);

		/*
		nova_info("read 3 ino %lu len %lu pos %llu block [%llu,%llu] virt [%lx,%lx] pgoff [%llu,%llu] nr %lu left %lu\n", sih->ino, len, pos, 
			entry->block>>PAGE_SHIFT, (entry->block>>PAGE_SHIFT)+((unsigned long)entry->num_pages)-1, 
			blockoff_to_virt(entry->block>>PAGE_SHIFT), blockoff_to_virt((entry->block>>PAGE_SHIFT)+(unsigned long)entry->num_pages-1),
			entry->pgoff, entry->pgoff+(unsigned long)entry->num_pages-1, 
			(unsigned long)entry->num_pages, left);
		*/

		NOVA_END_TIMING(memcpy_r_nvmm_t, memcpy_time);

		if (entry)
			put_write_entry(entry);
		// reclaim_get_nvmm(sb, nvmm, entry, index);
		
		// if (is_dram_buffer_addr(dax_mem)) {
		// 	if (DEBUG_BUFFERING) nova_info("put off %lu, nr %lu", mb_offset - index + (unsigned long)entry->pgoff, (unsigned long)entry->num_pages);
		// 	put_dram_buffer_range(mb_offset - index + entry->pgoff, entry->num_pages);
		// }

		if (left) {
			nova_dbg("%s ERROR!: bytes %lu, left %lu\n",
				__func__, nr, left);
			error = -EFAULT;
			goto out;
		}

		copied += (nr - left);
		offset += (nr - left);
		index += offset >> PAGE_SHIFT;
		offset &= ~PAGE_MASK;
	} while (copied < len);

out:
	*ppos = pos + copied;
	if (filp)
		file_accessed(filp);
		
	// TODOzsa: Read-frequent entry -> Pinned page cache
	// if (entry) nova_update_sih_tier(sb, sih, get_entry_tier(entry), false, true);
	
	if (entry) nova_update_sih_tier(sb, sih, get_entry_tier(entry), 3);

	NOVA_STATS_ADD(read_bytes, copied);

	nova_dbgv("%s returned %zu\n", __func__, copied);
	return copied ? copied : error;
}

/*
 * Wrappers. We need to use the rcu read lock to avoid
 * concurrent truncate operation. No problem for write because we held
 * lock.
 */
static ssize_t nova_dax_file_read(struct file *filp, char __user *buf,
			    size_t len, loff_t *ppos)
{
	// struct inode *inode = filp->f_mapping->host;
	ssize_t res;
	timing_t dax_read_time;

	NOVA_START_TIMING(dax_read_t, dax_read_time);
	// inode_lock_shared(inode);
	res = do_dax_mapping_read(filp, buf, len, ppos);
	// inode_unlock_shared(inode);
	NOVA_END_TIMING(dax_read_t, dax_read_time);
	return res;
}

/*
 * Perform a COW write.   Must hold the inode lock before calling.
 */
static ssize_t do_nova_cow_file_write(struct file *filp,
	const char __user *buf,	size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode	*inode = mapping->host;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *pi;
	struct nova_file_write_entry entry_data;
	struct nova_inode_update update;
	ssize_t	written = 0;
	loff_t pos;
	size_t count, offset, copied;
	unsigned long start_blk, num_blocks;
	unsigned long total_blocks;
	unsigned long blocknr = 0;
	unsigned int data_bits;
	unsigned int seq_count = 0;
	int allocated = 0;
	void *kmem;
	u64 file_size;
	size_t bytes;
	long status = 0;
	timing_t cow_write_time, memcpy_time;
	unsigned long step = 0;
	ssize_t ret;
	u64 begin_tail = 0;
	int try_inplace = 0;
	u64 epoch_id;
	u32 time;
	int write_tier = TIER_PMEM;

	if (len == 0)
		return 0;

	NOVA_START_TIMING(cow_write_t, cow_write_time);

		if (!access_ok(VERIFY_READ, buf, len)) {
		ret = -EFAULT;
		goto out;
	}
	pos = *ppos;

	if (filp->f_flags & O_APPEND)
		pos = i_size_read(inode);

	count = len;
	
	pi = nova_get_block(sb, sih->pi_addr);

	/* nova_inode tail pointer will be updated and we make sure all other
	 * inode fields are good before checksumming the whole structure
	 */
	/*
	if (nova_check_inode_integrity(sb, sih->ino, sih->pi_addr,
			sih->alter_pi_addr, &inode_copy, 0) < 0) {
		ret = -EIO;
		goto out;
	}
	*/

	offset = pos & (sb->s_blocksize - 1);
	num_blocks = ((count + offset - 1) >> sb->s_blocksize_bits) + 1;
	total_blocks = num_blocks;
	start_blk = pos >> sb->s_blocksize_bits;

	/*
	if (nova_check_overlap_vmas(sb, sih, start_blk, num_blocks)) {
		nova_dbgv("COW write overlaps with vma: inode %lu, pgoff %lu, %lu blocks\n",
				inode->i_ino, start_blk, num_blocks);
		NOVA_STATS_ADD(cow_overlap_mmap, 1);
		try_inplace = 1;
		ret = -EACCES;
		goto out;
	}
	*/

	/* offset in the actual block size block */

	ret = file_remove_privs(filp);
	if (ret)
		goto out;

	inode->i_ctime = inode->i_mtime = current_time(inode);
	time = current_time(inode).tv_sec;

	nova_dbgv("%s: inode %lu, offset %lld, count %lu\n",
			__func__, inode->i_ino,	pos, count);

	epoch_id = nova_get_epoch_id(sb);

	if (MODE_FORE_PMEM) write_tier = TIER_PMEM;
	else write_tier = TIER_BDEV_LOW;

	if (MODE_FORE_BAL) {
		write_tier = get_lowest_tier(sb);
	}	

	if (MODE_FORE_ALLOC) {	
		write_tier = TIER_PMEM;
		
		/* Profiler #1 */
		nova_sih_increase_wcount(sb, sih, len);
		if (nova_sih_is_sync(sih)) {
			write_tier = TIER_PMEM;
			goto prof;
		}
		
		/* Profiler #2 */
		seq_count = nova_get_prev_seq_count(sb, sih, start_blk, num_blocks);
		if (!nova_prof_judge_seq(seq_count)) {
			write_tier = TIER_PMEM;
			goto prof;
		}

		// nova_info("p %d b %d\n",pgc_tier_free_order(0),pgc_tier_free_order(1));
		write_tier = get_suitable_tier(sb, num_blocks);

prof:
		write_tier = get_available_tier(sb, write_tier);
	}
	
	if (MODE_KEEP_STAT) sbi->stat->write += len;
	if (MODE_USE_DYN_THRES) nova_update_stat(sbi, len, false);
	if (MODE_KEEP_STAT && write_tier!=TIER_PMEM) sbi->stat->write_dram += len;

	// nova_info("[Write] %lu blocks in [tier #%d] -> [seq %u tier #%d].\n", 
	// 	num_blocks, old_write_tier, seq_count, write_tier);

	nova_update_sih_tier(sb, sih, write_tier, 3);

	update.tail = sih->log_tail;
	update.alter_tail = sih->alter_log_tail;
	while (num_blocks > 0) {
		offset = pos & (nova_inode_blk_size(sih) - 1);
		start_blk = pos >> sb->s_blocksize_bits;

		if (write_tier == TIER_PMEM) {
			/* don't zero-out the allocated blocks */
			allocated = nova_new_data_blocks(sb, sih, &blocknr, start_blk,
					num_blocks, ALLOC_NO_INIT, ANY_CPU,
					ALLOC_FROM_HEAD);
		}
		else {
			allocated = nova_alloc_block_tier(NOVA_SB(sb), write_tier, ANY_CPU, 
				&blocknr, num_blocks, ALLOC_FROM_HEAD, true);
		}

		if (MODE_FORE_ALLOC && allocated <= 0) {
			nova_update_usage(sb);
			allocated = nova_alloc_block_tier(NOVA_SB(sb), TIER_BDEV_LOW, ANY_CPU, 
				&blocknr, num_blocks, ALLOC_FROM_HEAD, true);
		}

		nova_dbg_verbose("%s: alloc %d blocks @ %lu\n", __func__,
						allocated, blocknr);
        
		if (allocated <= 0) {
			nova_info("Error: tier: %d allocated: %d\n", write_tier, allocated);
			nova_dbg("%s alloc blocks failed %d\n", __func__,
								allocated);
			ret = allocated;
			goto out;
		}

		step++;
		bytes = sb->s_blocksize * allocated - offset;
		if (bytes > count)
			bytes = count;

		kmem = nova_get_block(inode->i_sb,
			     nova_get_block_off(sb, blocknr, sih->i_blk_type));

		if (offset || ((offset + bytes) & (PAGE_SIZE - 1)) != 0)  {
			ret = nova_handle_head_tail_blocks(sb, inode, pos,
							   bytes, kmem);
			if (ret)
				goto out;
		}
		/* Now copy from user buf */
		//		nova_dbg("Write: %p\n", kmem);
		NOVA_START_TIMING(memcpy_w_nvmm_t, memcpy_time);
		// nova_memunlock_range(sb, kmem + offset, bytes);
		copied = bytes - memcpy_to_pmem_nocache(kmem + offset,
						buf, bytes);
		// nova_memlock_range(sb, kmem + offset, bytes);
		NOVA_END_TIMING(memcpy_w_nvmm_t, memcpy_time);

		/*
		if (data_csum > 0 || data_parity > 0) {
			ret = nova_protect_file_data(sb, inode, pos, bytes,
							buf, blocknr, false);
			if (ret)
				goto out;
		}
		*/

		if (pos + copied > inode->i_size)
			file_size = cpu_to_le64(pos + copied);
		else
			file_size = cpu_to_le64(inode->i_size);

		/*
		if (write_tier!=TIER_PMEM) {
		nova_info("Write: kmem %p block [%lu,%lu] [%lu,%lu]offset %lu buf %p bytes %lu size %llu\n", kmem, 
			virt_to_blockoff((unsigned long)kmem), virt_to_blockoff((unsigned long)kmem+offset+bytes),
			start_blk, ((start_blk<<PAGE_SHIFT)+offset+bytes)>>PAGE_SHIFT,
			offset, buf, bytes, file_size>>PAGE_SHIFT);
		}
		*/

		nova_init_file_write_entry(sb, sih, &entry_data, epoch_id,
					start_blk, allocated, blocknr, time,
					file_size);

		entry_data.seq_count = seq_count;

		ret = nova_append_file_write_entry(sb, pi, inode,
					&entry_data, &update);
		if (ret) {
			nova_dbg("%s: append inode entry failed\n", __func__);
			ret = -ENOSPC;
			goto out;
		}

		nova_dbgv("Write: %p, %lu\n", kmem, copied);
		if (copied > 0) {
			status = copied;
			written += copied;
			pos += copied;
			buf += copied;
			count -= copied;
			num_blocks -= allocated;
		}
		if (unlikely(copied != bytes)) {
			nova_dbg("%s ERROR!: %p, bytes %lu, copied %lu\n",
				__func__, kmem, bytes, copied);
			if (status >= 0)
				status = -EFAULT;
		}
		if (status < 0)
			break;

		if (begin_tail == 0)
			begin_tail = update.curr_entry;
	}

	data_bits = blk_type_to_shift[sih->i_blk_type];
	sih->i_blocks += (total_blocks << (data_bits - sb->s_blocksize_bits));

	// nova_memunlock_inode(sb, pi);
	nova_update_inode(sb, inode, pi, &update, 1);
	// nova_memlock_inode(sb, pi);

	/* Free the overlap blocks after the write is committed */
	ret = nova_reassign_file_tree(sb, sih, begin_tail, true);
	if (ret)
		goto out;

	inode->i_blocks = sih->i_blocks;

	ret = written;
	NOVA_STATS_ADD(cow_write_breaks, step);
	nova_dbgv("blocks: %lu, %lu\n", inode->i_blocks, sih->i_blocks);

	*ppos = pos;
	if (pos > inode->i_size) {
		i_size_write(inode, pos);
		sih->i_size = pos;
	}

	sih->trans_id++;
out:
	if (DEBUG_WRITE_ENTRY) print_file_write_entries(sb, sih);
	
	if (ret < 0)
		nova_cleanup_incomplete_write(sb, sih, blocknr, allocated,
						begin_tail, update.tail);

	NOVA_END_TIMING(cow_write_t, cow_write_time);
	NOVA_STATS_ADD(cow_write_bytes, written);

	if (try_inplace)
		return do_nova_inplace_file_write(filp, buf, len, ppos);

	return ret;
}

/*
 * Acquire locks and perform COW write.
 */
ssize_t nova_cow_file_write(struct file *filp,
	const char __user *buf,	size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	int ret;

	if (len == 0)
		return 0;
	
	sb_start_write(inode->i_sb);
	inode_lock(inode);

	ret = do_nova_cow_file_write(filp, buf, len, ppos);

	inode_unlock(inode);
	sb_end_write(inode->i_sb);

	return ret;
}

static ssize_t nova_dax_file_write(struct file *filp, const char __user *buf,
				   size_t len, loff_t *ppos)
{
	if (inplace_data_updates)
		return nova_inplace_file_write(filp, buf, len, ppos);
	else
		return nova_cow_file_write(filp, buf, len, ppos);
}

static ssize_t do_nova_dax_file_write(struct file *filp, const char __user *buf,
				   size_t len, loff_t *ppos)
{
	if (inplace_data_updates)
		return do_nova_inplace_file_write(filp, buf, len, ppos);
	else
		return do_nova_cow_file_write(filp, buf, len, ppos);
}


static int nova_dax_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file->f_mapping->host;

	file_accessed(file);

	vma->vm_flags |= VM_MIXEDMAP | VM_HUGEPAGE;

	vma->vm_ops = &nova_dax_vm_ops;

	nova_insert_write_vma(vma);

	nova_dbg_mmap4k("[%s:%d] inode %lu, MMAP 4KPAGE vm_start(0x%lx), vm_end(0x%lx), vm pgoff %lu, %lu blocks, vm_flags(0x%lx), vm_page_prot(0x%lx)\n",
			__func__, __LINE__,
			inode->i_ino, vma->vm_start, vma->vm_end,
			vma->vm_pgoff,
			(vma->vm_end - vma->vm_start) >> PAGE_SHIFT,
			vma->vm_flags,
			pgprot_val(vma->vm_page_prot));

	return 0;
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
	struct inode *inode = filp->f_mapping->host;
	ssize_t ret = -EIO;
	ssize_t written = 0;
	unsigned long seg;
	unsigned long nr_segs = iter->nr_segs;
	const struct iovec *iv = iter->iov;

	nova_dbgv("%s %s: %lu segs\n", __func__,
			iov_iter_rw(iter) == READ ? "read" : "write",
			nr_segs);

	if (iov_iter_rw(iter) == WRITE)  {
		sb_start_write(inode->i_sb);
		inode_lock(inode);
	} else {
		inode_lock_shared(inode);
	}
		
	iv = iter->iov;
	for (seg = 0; seg < nr_segs; seg++) {
		if (iov_iter_rw(iter) == READ) {
			ret = do_dax_mapping_read(filp, iv->iov_base,
						  iv->iov_len, &iocb->ki_pos);
		} else if (iov_iter_rw(iter) == WRITE) {
			ret = do_nova_dax_file_write(filp, iv->iov_base,
						     iv->iov_len, &iocb->ki_pos);
		} else {
			BUG();
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
	if (iov_iter_rw(iter) == WRITE)  {
		inode_unlock(inode);
		sb_end_write(inode->i_sb);
	} else {
		inode_unlock_shared(inode);
	}

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
	.release		= nova_release,
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
