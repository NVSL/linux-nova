/*
 * BRIEF DESCRIPTION
 *
 * File operations for directories.
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
#include <linux/pagemap.h>
#include "nova.h"
#include "inode.h"

#define DT2IF(dt) (((dt) << 12) & S_IFMT)
#define IF2DT(sif) (((sif) & S_IFMT) >> 12)

struct nova_dentry *nova_find_dentry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode, const char *name,
	unsigned long name_len)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_dentry *direntry = NULL;
	struct nova_range_node *ret_node = NULL;
	unsigned long hash;
	int found = 0;

	hash = BKDRHash(name, name_len);

	found = nova_find_range_node(&sih->rb_tree, hash,
				NODE_DIR, &ret_node);
	if (found == 1 && hash == ret_node->hash)
		direntry = ret_node->direntry;

	return direntry;
}

int nova_insert_dir_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, const char *name,
	int namelen, struct nova_dentry *direntry)
{
	struct nova_range_node *node = NULL;
	unsigned long hash;
	int ret;

	hash = BKDRHash(name, namelen);
	nova_dbgv("%s: insert %s hash %lu\n", __func__, name, hash);

	/* FIXME: hash collision ignored here */
	node = nova_alloc_dir_node(sb);
	if (!node)
		return -ENOMEM;

	node->hash = hash;
	node->direntry = direntry;
	ret = nova_insert_range_node(&sih->rb_tree, node, NODE_DIR);
	if (ret) {
		nova_free_dir_node(node);
		nova_dbg("%s ERROR %d: %s\n", __func__, ret, name);
	}

	return ret;
}

static int nova_check_dentry_match(struct super_block *sb,
	struct nova_dentry *dentry, const char *name, int namelen)
{
	if (dentry->name_len != namelen)
		return -EINVAL;

	return strncmp(dentry->name, name, namelen);
}

int nova_remove_dir_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, const char *name, int namelen,
	int replay, struct nova_dentry **create_dentry)
{
	struct nova_dentry *entry;
	struct nova_dentry *entryc, entry_copy;
	struct nova_range_node *ret_node = NULL;
	unsigned long hash;
	int found = 0;

	hash = BKDRHash(name, namelen);
	found = nova_find_range_node(&sih->rb_tree, hash,
				NODE_DIR, &ret_node);
	if (found == 0) {
		nova_dbg("%s target not found: %s, length %d, "
				"hash %lu\n", __func__, name, namelen, hash);
		return -EINVAL;
	}

	entry = ret_node->direntry;
	rb_erase(&ret_node->node, &sih->rb_tree);
	nova_free_dir_node(ret_node);

	if (replay == 0) {
		if (!entry) {
			nova_dbg("%s ERROR: %s, length %d, hash %lu\n",
					__func__, name, namelen, hash);
			return -EINVAL;
		}

		if (metadata_csum == 0)
			entryc = entry;
		else {
			entryc = &entry_copy;
			if (!nova_verify_entry_csum(sb, entry, entryc))
				return -EINVAL;
		}

		if (entryc->ino == 0 || entryc->invalid ||
		    nova_check_dentry_match(sb, entryc, name, namelen)) {
			nova_dbg("%s dentry not match: %s, length %d, hash %lu\n",
				 __func__, name, namelen, hash);
			/* for debug information, still allow access to nvmm */
			nova_dbg("dentry: type %d, inode %llu, name %s, namelen %u, rec len %u\n",
				 entry->entry_type, le64_to_cpu(entry->ino),
				 entry->name, entry->name_len,
				 le16_to_cpu(entry->de_len));
			return -EINVAL;
		}

		if (create_dentry)
			*create_dentry = entry;
	}

	return 0;
}

void nova_delete_dir_tree(struct super_block *sb,
	struct nova_inode_info_header *sih)
{
	INIT_TIMING(delete_time);

	NOVA_START_TIMING(delete_dir_tree_t, delete_time);

	nova_dbgv("%s: delete dir %lu\n", __func__, sih->ino);
	nova_destroy_range_node_tree(sb, &sih->rb_tree);
	NOVA_END_TIMING(delete_dir_tree_t, delete_time);
}

/* ========================= Entry operations ============================= */

static unsigned int nova_init_dentry(struct super_block *sb,
	struct nova_dentry *de_entry, u64 self_ino, u64 parent_ino,
	u64 epoch_id)
{
	void *start = de_entry;
	struct nova_inode_log_page *curr_page = start;
	unsigned int length;
	unsigned short de_len;
	struct timespec64 now;


	de_len = NOVA_DIR_LOG_REC_LEN(1);
	memset(de_entry, 0, de_len);
	de_entry->entry_type = DIR_LOG;
	de_entry->epoch_id = epoch_id;
	de_entry->trans_id = 0;
	de_entry->ino = cpu_to_le64(self_ino);
	de_entry->name_len = 1;
	de_entry->de_len = cpu_to_le16(de_len);
	ktime_get_coarse_real_ts64(&now);
	de_entry->mtime = timespec64_trunc(now,
					 sb->s_time_gran).tv_sec;

	de_entry->links_count = 1;
	strncpy(de_entry->name, ".\0", 2);
	nova_update_entry_csum(de_entry);

	length = de_len;

	de_entry = (struct nova_dentry *)((char *)de_entry + length);
	de_len = NOVA_DIR_LOG_REC_LEN(2);
	memset(de_entry, 0, de_len);
	de_entry->entry_type = DIR_LOG;
	de_entry->epoch_id = epoch_id;
	de_entry->trans_id = 0;
	de_entry->ino = cpu_to_le64(parent_ino);
	de_entry->name_len = 2;
	de_entry->de_len = cpu_to_le16(de_len);
	ktime_get_coarse_real_ts64(&now);
	de_entry->mtime = timespec64_trunc(now,
					 sb->s_time_gran).tv_sec;

	de_entry->links_count = 2;
	strncpy(de_entry->name, "..\0", 3);
	nova_update_entry_csum(de_entry);
	length += de_len;

	nova_set_page_num_entries(sb, curr_page, 2, 1);

	nova_flush_buffer(start, length, 0);
	return length;
}

/* Append . and .. entries
 *
 * TODO: why is epoch_id a parameter when we pass in the sb?
 */
int nova_append_dir_init_entries(struct super_block *sb,
	struct nova_inode *pi, u64 self_ino, u64 parent_ino, u64 epoch_id)
{
	struct nova_inode_info_header sih;
	struct nova_inode *alter_pi;
	u64 alter_pi_addr = 0;
	int allocated;
	int ret;
	u64 new_block;
	unsigned int length;
	struct nova_dentry *de_entry;

	sih.ino = self_ino;
	sih.i_blk_type = NOVA_DEFAULT_BLOCK_TYPE;

	allocated = nova_allocate_inode_log_pages(sb, &sih, 1, &new_block,
							ANY_CPU, 0);
	if (allocated != 1) {
		nova_err(sb, "ERROR: no inode log page available\n");
		return -ENOMEM;
	}

	nova_memunlock_inode(sb, pi);

	pi->log_tail = pi->log_head = new_block;

	de_entry = (struct nova_dentry *)nova_get_block(sb, new_block);

	length = nova_init_dentry(sb, de_entry, self_ino, parent_ino, epoch_id);

	nova_update_tail(pi, new_block + length);

	nova_memlock_inode(sb, pi);

	if (metadata_csum == 0)
		return 0;

	allocated = nova_allocate_inode_log_pages(sb, &sih, 1, &new_block,
							ANY_CPU, 1);
	if (allocated != 1) {
		nova_err(sb, "ERROR: no inode log page available\n");
		return -ENOMEM;
	}
	nova_memunlock_inode(sb, pi);
	pi->alter_log_tail = pi->alter_log_head = new_block;

	de_entry = (struct nova_dentry *)nova_get_block(sb, new_block);

	length = nova_init_dentry(sb, de_entry, self_ino, parent_ino, epoch_id);

	nova_update_alter_tail(pi, new_block + length);
	nova_update_alter_pages(sb, pi, pi->log_head,
						pi->alter_log_head);
	nova_update_inode_checksum(pi);
	nova_flush_buffer(pi, sizeof(struct nova_inode), 0);
	nova_memlock_inode(sb, pi);

	/* Get alternate inode address */
	ret = nova_get_alter_inode_address(sb, self_ino, &alter_pi_addr);
	if (ret)
		return ret;

	alter_pi = (struct nova_inode *)nova_get_block(sb, alter_pi_addr);
	if (!alter_pi)
		return -EINVAL;

	nova_memunlock_inode(sb, alter_pi);
	memcpy_to_pmem_nocache(alter_pi, pi, sizeof(struct nova_inode));
	nova_memlock_inode(sb, alter_pi);

	return 0;
}

/* adds a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 */
int nova_add_dentry(struct dentry *dentry, u64 ino, int inc_link,
	struct nova_inode_update *update, u64 epoch_id)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct nova_inode_info *si = NOVA_I(dir);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *pidir;
	const char *name = dentry->d_name.name;
	int namelen = dentry->d_name.len;
	struct nova_dentry *direntry;
	unsigned short loglen;
	int ret;
	u64 curr_entry;
	INIT_TIMING(add_dentry_time);

	nova_dbg_verbose("%s: dir %lu new inode %llu\n",
				__func__, dir->i_ino, ino);
	nova_dbg_verbose("%s: %s %d\n", __func__, name, namelen);
	NOVA_START_TIMING(add_dentry_t, add_dentry_time);
	if (namelen == 0)
		return -EINVAL;

	pidir = nova_get_inode(sb, dir);

	/*
	 * XXX shouldn't update any times until successful
	 * completion of syscall, but too many callers depend
	 * on this.
	 */
	dir->i_mtime = dir->i_ctime = current_time(dir);

	loglen = NOVA_DIR_LOG_REC_LEN(namelen);
	ret = nova_append_dentry(sb, pidir, dir, dentry,
				ino, loglen, update,
				inc_link, epoch_id);

	if (ret) {
		nova_dbg("%s: append dir entry failure\n", __func__);
		return ret;
	}

	curr_entry = update->curr_entry;
	direntry = (struct nova_dentry *)nova_get_block(sb, curr_entry);
	sih->last_dentry = curr_entry;
	ret = nova_insert_dir_tree(sb, sih, name, namelen, direntry);

	sih->trans_id++;
	NOVA_END_TIMING(add_dentry_t, add_dentry_time);
	return ret;
}

static int nova_can_inplace_update_dentry(struct super_block *sb,
	struct nova_dentry *dentry, u64 epoch_id)
{
	struct nova_dentry *dentryc, entry_copy;

	if (metadata_csum == 0)
		dentryc = dentry;
	else {
		dentryc = &entry_copy;
		if (!nova_verify_entry_csum(sb, dentry, dentryc))
			return 0;
	}

	if (dentry && dentryc->epoch_id == epoch_id)
		return 1;

	return 0;
}

static int nova_inplace_update_dentry(struct super_block *sb,
	struct inode *dir, struct nova_dentry *dentry, int link_change,
	u64 epoch_id)
{
	struct nova_inode_info *si = NOVA_I(dir);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_log_entry_info entry_info;

	entry_info.type = DIR_LOG;
	entry_info.link_change = link_change;
	entry_info.epoch_id = epoch_id;
	entry_info.trans_id = sih->trans_id;
	entry_info.inplace = 1;

	return nova_inplace_update_log_entry(sb, dir, dentry,
					&entry_info);
}

/* removes a directory entry pointing to the inode. assumes the inode has
 * already been logged for consistency
 */
int nova_remove_dentry(struct dentry *dentry, int dec_link,
	struct nova_inode_update *update, u64 epoch_id)
{
	struct inode *dir = dentry->d_parent->d_inode;
	struct super_block *sb = dir->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info *si = NOVA_I(dir);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *pidir;
	struct qstr *entry = &dentry->d_name;
	struct nova_dentry *old_dentry = NULL;
	unsigned short loglen;
	int ret;
	u64 curr_entry;
	INIT_TIMING(remove_dentry_time);

	NOVA_START_TIMING(remove_dentry_t, remove_dentry_time);

	update->create_dentry = NULL;
	update->delete_dentry = NULL;

	if (!dentry->d_name.len) {
		ret = -EINVAL;
		goto out;
	}

	ret = nova_remove_dir_tree(sb, sih, entry->name, entry->len, 0,
					&old_dentry);

	if (ret)
		goto out;

	pidir = nova_get_inode(sb, dir);

	dir->i_mtime = dir->i_ctime = current_time(dir);

	if (nova_can_inplace_update_dentry(sb, old_dentry, epoch_id)) {
		nova_inplace_update_dentry(sb, dir, old_dentry,
						dec_link, epoch_id);
		curr_entry = nova_get_addr_off(sbi, old_dentry);

		sih->last_dentry = curr_entry;
		/* Leave create/delete_dentry to NULL
		 * Do not change tail/alter_tail if used as input
		 */
		if (update->tail == 0) {
			update->tail = sih->log_tail;
			update->alter_tail = sih->alter_log_tail;
		}
		sih->trans_id++;
		goto out;
	}

	loglen = NOVA_DIR_LOG_REC_LEN(entry->len);
	ret = nova_append_dentry(sb, pidir, dir, dentry,
				0, loglen, update,
				dec_link, epoch_id);

	if (ret) {
		nova_dbg("%s: append dir entry failure\n", __func__);
		goto out;
	}

	update->create_dentry = old_dentry;
	curr_entry = update->curr_entry;
	update->delete_dentry = (struct nova_dentry *)nova_get_block(sb,
						curr_entry);
	sih->last_dentry = curr_entry;
	sih->trans_id++;
out:
	NOVA_END_TIMING(remove_dentry_t, remove_dentry_time);
	return ret;
}

/* Create dentry and delete dentry must be invalidated together */
int nova_invalidate_dentries(struct super_block *sb,
	struct nova_inode_update *update)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_dentry *create_dentry;
	struct nova_dentry *create_dentryc, entry_copy;
	struct nova_dentry *delete_dentry;
	u64 create_curr, delete_curr;
	int ret;

	create_dentry = update->create_dentry;
	delete_dentry = update->delete_dentry;

	if (!create_dentry)
		return 0;

	nova_reassign_logentry(sb, create_dentry, DIR_LOG);

	if (metadata_csum == 0)
		create_dentryc = create_dentry;
	else {
		create_dentryc = &entry_copy;
		if (!nova_verify_entry_csum(sb, create_dentry, create_dentryc))
			return 0;
	}

	if (!old_entry_freeable(sb, create_dentryc->epoch_id))
		return 0;

	create_curr = nova_get_addr_off(sbi, create_dentry);
	delete_curr = nova_get_addr_off(sbi, delete_dentry);

	nova_invalidate_logentry(sb, create_dentry, DIR_LOG, 0);

	ret = nova_invalidate_logentry(sb, delete_dentry, DIR_LOG, 0);

	return ret;
}

static int nova_readdir_slow_rbtree(struct file *file,
	struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct super_block *sb = inode->i_sb;
	struct nova_range_node *curr;
	struct nova_inode *child_pi;
	struct nova_dentry *entry;
	struct nova_dentry *entryc, entry_copy;
	unsigned long pos = ctx->pos;
	struct rb_node *temp = NULL;
	int found = 0;
	u64 pi_addr;
	ino_t ino;
	int ret;

	if (pos == 0)
		temp = rb_first(&sih->rb_tree);
	else if (pos == READDIR_END)
		return 0;
	else {
		found = nova_find_range_node(&sih->rb_tree, pos,
				NODE_DIR, &curr);
		if (found == 1 && pos == curr->hash)
			temp = &curr->node;
	}

	entryc = (metadata_csum == 0) ? entry : &entry_copy;

	while (temp) {
		curr = container_of(temp, struct nova_range_node, node);
		entry = curr->direntry;

		if (metadata_csum == 0)
			entryc = entry;
		else if (!nova_verify_entry_csum(sb, entry, entryc))
			return -EIO;

		pos = BKDRHash(entryc->name, entryc->name_len);
		ctx->pos = pos;
		ino = __le64_to_cpu(entryc->ino);
		if (ino == 0)
			continue;

		ret = nova_get_inode_address(sb, ino, 0, &pi_addr,
						     0, 0);

		if (ret) {
			nova_dbg("%s: get child inode %lu address failed %d\n",
				 __func__, ino, ret);
			ctx->pos = READDIR_END;
			return ret;
		}

		child_pi = nova_get_block(sb, pi_addr);
		nova_dbgv("ctx: ino %llu, name %s, name_len %u, de_len %u, csum 0x%x\n",
			(u64)ino, entry->name, entry->name_len,
			entry->de_len, entry->csum);
		if (!dir_emit(ctx, entryc->name, entryc->name_len,
			ino, IF2DT(le16_to_cpu(child_pi->i_mode)))) {
			nova_dbgv("Here: pos %llu\n", ctx->pos);
			return 0;
		}
		temp = rb_next(temp);
	}

	ctx->pos = READDIR_END;
	return 0;
}

static int nova_readdir_slow(struct file *file, struct dir_context *ctx)
{
	int ret;
	INIT_TIMING(readdir_time);

	NOVA_START_TIMING(readdir_t, readdir_time);

	ret = nova_readdir_slow_rbtree(file, ctx);

	NOVA_END_TIMING(readdir_t, readdir_time);
	return ret;
}

static u64 nova_find_next_dentry_addr(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 pos)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_dentry *entry = NULL;
	struct nova_range_node *ret_node = NULL;
	int found = 0;
	u64 addr = 0;

	found = nova_find_range_node(&sih->rb_tree, pos,
					NODE_DIR, &ret_node);
	if (found == 1 && pos == ret_node->hash) {
		entry = ret_node->direntry;
		addr = nova_get_addr_off(sbi, entry);
	}

	return addr;
}

static int nova_readdir_fast(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pidir;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode *child_pi;
	struct nova_inode *prev_child_pi = NULL;
	struct nova_dentry *entry = NULL;
	struct nova_dentry *entryc, entry_copy;
	struct nova_dentry *prev_entry = NULL;
	struct nova_dentry *prev_entryc, prev_entry_copy;
	unsigned short de_len;
	u64 pi_addr;
	unsigned long pos = 0;
	ino_t ino;
	void *addr;
	u64 curr_p;
	u8 type;
	int ret;
	INIT_TIMING(readdir_time);

	NOVA_START_TIMING(readdir_t, readdir_time);
	pidir = nova_get_inode(sb, inode);
	nova_dbgv("%s: ino %llu, size %llu, pos 0x%llx\n",
			__func__, (u64)inode->i_ino,
			pidir->i_size, ctx->pos);

	if (sih->log_head == 0) {
		nova_err(sb, "Dir %lu log is NULL!\n", inode->i_ino);
		return -ENOSPC;
	}

	pos = ctx->pos;

	if (pos == 0)
		curr_p = sih->log_head;
	else if (pos == READDIR_END)
		goto out;
	else {
		curr_p = nova_find_next_dentry_addr(sb, sih, pos);
		if (curr_p == 0)
			goto out;
	}

	entryc = (metadata_csum == 0) ? entry : &entry_copy;
	prev_entryc = (metadata_csum == 0) ? prev_entry : &prev_entry_copy;

	while (curr_p != sih->log_tail) {
		if (goto_next_page(sb, curr_p))
			curr_p = next_log_page(sb, curr_p);


		if (curr_p == 0) {
			nova_err(sb, "Dir %lu log is NULL!\n", inode->i_ino);
			BUG();
			return -EINVAL;
		}

		addr = (void *)nova_get_block(sb, curr_p);
		type = nova_get_entry_type(addr);
		switch (type) {
		case SET_ATTR:
			curr_p += sizeof(struct nova_setattr_logentry);
			continue;
		case LINK_CHANGE:
			curr_p += sizeof(struct nova_link_change_entry);
			continue;
		case DIR_LOG:
			break;
		default:
			nova_dbg("%s: unknown type %d, 0x%llx\n",
				 __func__, type, curr_p);
			BUG();
			return -EINVAL;
		}

		entry = (struct nova_dentry *)nova_get_block(sb, curr_p);
		nova_dbgv("curr_p: 0x%llx, type %d, ino %llu, name %s, namelen %u, rec len %u\n",
			  curr_p, entry->entry_type, le64_to_cpu(entry->ino),
			  entry->name, entry->name_len,
			  le16_to_cpu(entry->de_len));

		if (metadata_csum == 0)
			entryc = entry;
		else if (!nova_verify_entry_csum(sb, entry, entryc))
			return -EIO;

		de_len = le16_to_cpu(entryc->de_len);
		if (entryc->ino > 0 && entryc->invalid == 0
					&& entryc->reassigned == 0) {
			ino = __le64_to_cpu(entryc->ino);
			pos = BKDRHash(entryc->name, entryc->name_len);

			ret = nova_get_inode_address(sb, ino, 0,
						     &pi_addr, 0, 0);
			if (ret) {
				nova_dbg("%s: get child inode %lu address failed %d\n",
					 __func__, ino, ret);
				ctx->pos = READDIR_END;
				return ret;
			}

			child_pi = nova_get_block(sb, pi_addr);
			nova_dbgv("ctx: ino %llu, name %s, name_len %u, de_len %u\n",
				(u64)ino, entry->name, entry->name_len,
				entry->de_len);
			if (prev_entry && !dir_emit(ctx, prev_entryc->name,
				prev_entryc->name_len, ino,
				IF2DT(le16_to_cpu(prev_child_pi->i_mode)))) {
				nova_dbgv("Here: pos %llu\n", ctx->pos);
				return 0;
			}
			prev_entry = entry;

			if (metadata_csum == 0)
				prev_entryc = prev_entry;
			else
				memcpy(prev_entryc, entryc,
						sizeof(struct nova_dentry));

			prev_child_pi = child_pi;
		}
		ctx->pos = pos;
		curr_p += de_len;
	}

	if (prev_entry && !dir_emit(ctx, prev_entryc->name,
			prev_entryc->name_len, ino,
			IF2DT(le16_to_cpu(prev_child_pi->i_mode))))
		return 0;

	ctx->pos = READDIR_END;
out:
	NOVA_END_TIMING(readdir_t, readdir_time);
	nova_dbgv("%s return\n", __func__);
	return 0;
}

static int nova_readdir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (sbi->mount_snapshot == 0)
		return nova_readdir_fast(file, ctx);
	else
		return nova_readdir_slow(file, ctx);
}

const struct file_operations nova_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.iterate	= nova_readdir,
	.fsync		= noop_fsync,
	.unlocked_ioctl = nova_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= nova_compat_ioctl,
#endif
};
