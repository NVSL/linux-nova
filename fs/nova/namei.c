/*
 * BRIEF DESCRIPTION
 *
 * Inode operations for directories.
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
#include "journal.h"
#include "inode.h"

static ino_t nova_inode_by_name(struct inode *dir, struct qstr *entry,
				 struct nova_dentry **res_entry)
{
	struct super_block *sb = dir->i_sb;
	struct nova_dentry *direntry;
	struct nova_dentry *direntryc, entry_copy;

	direntry = nova_find_dentry(sb, NULL, dir,
					entry->name, entry->len);
	if (direntry == NULL)
		return 0;

	if (metadata_csum == 0)
		direntryc = direntry;
	else {
		direntryc = &entry_copy;
		if (!nova_verify_entry_csum(sb, direntry, direntryc))
			return 0;
	}

	*res_entry = direntry;
	return direntryc->ino;
}

static struct dentry *nova_lookup(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	struct inode *inode = NULL;
	struct nova_dentry *de;
	ino_t ino;
	INIT_TIMING(lookup_time);

	NOVA_START_TIMING(lookup_t, lookup_time);
	if (dentry->d_name.len > NOVA_NAME_LEN) {
		nova_dbg("%s: namelen %u exceeds limit\n",
			__func__, dentry->d_name.len);
		return ERR_PTR(-ENAMETOOLONG);
	}

	nova_dbg_verbose("%s: %s\n", __func__, dentry->d_name.name);
	ino = nova_inode_by_name(dir, &dentry->d_name, &de);
	nova_dbg_verbose("%s: ino %lu\n", __func__, ino);
	if (ino) {
		inode = nova_iget(dir->i_sb, ino);
		if (inode == ERR_PTR(-ESTALE) || inode == ERR_PTR(-ENOMEM)
				|| inode == ERR_PTR(-EACCES)) {
			nova_err(dir->i_sb,
				  "%s: get inode failed: %lu\n",
				  __func__, (unsigned long)ino);
			return ERR_PTR(-EIO);
		}
	}

	NOVA_END_TIMING(lookup_t, lookup_time);
	return d_splice_alias(inode, dentry);
}

static void nova_lite_transaction_for_new_inode(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode *pidir, struct inode *inode,
	struct inode *dir, struct nova_inode_update *update)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int cpu;
	u64 journal_tail;
	unsigned long irq_flags = 0;
	INIT_TIMING(trans_time);

	NOVA_START_TIMING(create_trans_t, trans_time);

	cpu = nova_get_cpuid(sb);
	spin_lock(&sbi->journal_locks[cpu]);
	nova_memunlock_journal(sb, &irq_flags);

	// If you change what's required to create a new inode, you need to
	// update this functions so the changes will be roll back on failure.
	journal_tail = nova_create_inode_transaction(sb, inode, dir, cpu, 1, 0);

	nova_update_inode(sb, dir, pidir, update, 0);

	pi->valid = 1;
	nova_update_inode_checksum(pi);
	PERSISTENT_BARRIER();

	nova_commit_lite_transaction(sb, journal_tail, cpu);
	nova_memlock_journal(sb, &irq_flags);
	spin_unlock(&sbi->journal_locks[cpu]);

	if (metadata_csum) {
		nova_memunlock_inode(sb, pi, &irq_flags);
		nova_update_alter_inode(sb, inode, pi);
		nova_update_alter_inode(sb, dir, pidir);
		nova_memlock_inode(sb, pi, &irq_flags);
	}
	NOVA_END_TIMING(create_trans_t, trans_time);
}

/* Returns new tail after append */
/*
 * By the time this is called, we already have created
 * the directory cache entry for the new file, but it
 * is so far negative - it has no inode.
 *
 * If the create succeeds, we fill in the inode information
 * with d_instantiate().
 */
static int nova_create(struct inode *dir, struct dentry *dentry, umode_t mode,
			bool excl)
{
	struct inode *inode = NULL;
	int err = PTR_ERR(inode);
	struct super_block *sb = dir->i_sb;
	struct nova_inode *pidir, *pi;
	struct nova_inode_update update;
	u64 pi_addr = 0;
	u64 ino, epoch_id;
	INIT_TIMING(create_time);

	NOVA_START_TIMING(create_t, create_time);

	pidir = nova_get_inode(sb, dir);
	if (!pidir)
		goto out_err;

	epoch_id = nova_get_epoch_id(sb);
	ino = nova_new_nova_inode(sb, &pi_addr);
	if (ino == 0)
		goto out_err;

	update.tail = 0;
	update.alter_tail = 0;
	err = nova_add_dentry(dentry, ino, 0, &update, epoch_id);
	if (err)
		goto out_err;

	nova_dbgv("%s: %s\n", __func__, dentry->d_name.name);
	nova_dbgv("%s: inode %llu, dir %lu\n", __func__, ino, dir->i_ino);
	inode = nova_new_vfs_inode(TYPE_CREATE, dir, pi_addr, ino, mode,
					0, 0, &dentry->d_name, epoch_id);
	if (IS_ERR(inode))
		goto out_err;

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	pi = nova_get_block(sb, pi_addr);
	nova_lite_transaction_for_new_inode(sb, pi, pidir, inode, dir,
						&update);
	NOVA_END_TIMING(create_t, create_time);
	return err;
out_err:
	nova_err(sb, "%s return %d\n", __func__, err);
	NOVA_END_TIMING(create_t, create_time);
	return err;
}

static int nova_mknod(struct inode *dir, struct dentry *dentry, umode_t mode,
		       dev_t rdev)
{
	struct inode *inode = NULL;
	int err = PTR_ERR(inode);
	struct super_block *sb = dir->i_sb;
	u64 pi_addr = 0;
	struct nova_inode *pidir, *pi;
	struct nova_inode_update update;
	u64 ino;
	u64 epoch_id;
	INIT_TIMING(mknod_time);

	NOVA_START_TIMING(mknod_t, mknod_time);

	pidir = nova_get_inode(sb, dir);
	if (!pidir)
		goto out_err;

	epoch_id = nova_get_epoch_id(sb);
	ino = nova_new_nova_inode(sb, &pi_addr);
	if (ino == 0)
		goto out_err;

	nova_dbgv("%s: %s\n", __func__, dentry->d_name.name);
	nova_dbgv("%s: inode %llu, dir %lu\n", __func__, ino, dir->i_ino);

	update.tail = 0;
	update.alter_tail = 0;
	err = nova_add_dentry(dentry, ino, 0, &update, epoch_id);
	if (err)
		goto out_err;

	inode = nova_new_vfs_inode(TYPE_MKNOD, dir, pi_addr, ino, mode,
					0, rdev, &dentry->d_name, epoch_id);
	if (IS_ERR(inode))
		goto out_err;

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	pi = nova_get_block(sb, pi_addr);
	nova_lite_transaction_for_new_inode(sb, pi, pidir, inode, dir,
						&update);
	NOVA_END_TIMING(mknod_t, mknod_time);
	return err;
out_err:
	nova_err(sb, "%s return %d\n", __func__, err);
	NOVA_END_TIMING(mknod_t, mknod_time);
	return err;
}

static int nova_symlink(struct inode *dir, struct dentry *dentry,
			 const char *symname)
{
	struct super_block *sb = dir->i_sb;
	int err = -ENAMETOOLONG;
	unsigned int len = strlen(symname);
	struct inode *inode;
	struct nova_inode_info *si;
	struct nova_inode_info_header *sih;
	u64 pi_addr = 0;
	struct nova_inode *pidir, *pi;
	struct nova_inode_update update;
	u64 ino;
	u64 epoch_id;
	INIT_TIMING(symlink_time);

	NOVA_START_TIMING(symlink_t, symlink_time);
	if (len + 1 > sb->s_blocksize)
		goto out;

	pidir = nova_get_inode(sb, dir);
	if (!pidir)
		goto out_fail;

	epoch_id = nova_get_epoch_id(sb);
	ino = nova_new_nova_inode(sb, &pi_addr);
	if (ino == 0)
		goto out_fail;

	nova_dbgv("%s: name %s, symname %s\n", __func__,
				dentry->d_name.name, symname);
	nova_dbgv("%s: inode %llu, dir %lu\n", __func__, ino, dir->i_ino);

	update.tail = 0;
	update.alter_tail = 0;
	err = nova_add_dentry(dentry, ino, 0, &update, epoch_id);
	if (err)
		goto out_fail;

	inode = nova_new_vfs_inode(TYPE_SYMLINK, dir, pi_addr, ino,
					S_IFLNK|0777, len, 0,
					&dentry->d_name, epoch_id);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_fail;
	}

	pi = nova_get_inode(sb, inode);

	si = NOVA_I(inode);
	sih = &si->header;

	err = nova_block_symlink(sb, pi, inode, symname, len, epoch_id);
	if (err)
		goto out_fail;

	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	nova_lite_transaction_for_new_inode(sb, pi, pidir, inode, dir,
					&update);
out:
	NOVA_END_TIMING(symlink_t, symlink_time);
	return err;

out_fail:
	nova_err(sb, "%s return %d\n", __func__, err);
	goto out;
}

static void nova_lite_transaction_for_time_and_link(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode *pidir, struct inode *inode,
	struct inode *dir, struct nova_inode_update *update,
	struct nova_inode_update *update_dir, int invalidate, u64 epoch_id)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u64 journal_tail;
	int cpu;
	unsigned long irq_flags = 0;
	INIT_TIMING(trans_time);

	NOVA_START_TIMING(link_trans_t, trans_time);

	cpu = nova_get_cpuid(sb);
	spin_lock(&sbi->journal_locks[cpu]);
	nova_memunlock_journal(sb, &irq_flags);

	// If you change what's required to create a new inode, you need to
	// update this functions so the changes will be roll back on failure.
	journal_tail = nova_create_inode_transaction(sb, inode, dir, cpu,
						0, invalidate);

	if (invalidate) {
		pi->valid = 0;
		pi->delete_epoch_id = epoch_id;
	}
	nova_update_inode(sb, inode, pi, update, 0);

	nova_update_inode(sb, dir, pidir, update_dir, 0);

	PERSISTENT_BARRIER();

	nova_commit_lite_transaction(sb, journal_tail, cpu);
	nova_memlock_journal(sb, &irq_flags);
	spin_unlock(&sbi->journal_locks[cpu]);

	if (metadata_csum) {
		nova_memunlock_inode(sb, pi, &irq_flags);
		nova_update_alter_inode(sb, inode, pi);
		nova_update_alter_inode(sb, dir, pidir);
		nova_memlock_inode(sb, pi, &irq_flags);
	}

	NOVA_END_TIMING(link_trans_t, trans_time);
}

static int nova_link(struct dentry *dest_dentry, struct inode *dir,
		      struct dentry *dentry)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode = dest_dentry->d_inode;
	struct nova_inode *pi = nova_get_inode(sb, inode);
	struct nova_inode *pidir;
	struct nova_inode_update update_dir;
	struct nova_inode_update update;
	u64 old_linkc = 0;
	u64 epoch_id;
	int err = -ENOMEM;
	INIT_TIMING(link_time);

	NOVA_START_TIMING(link_t, link_time);
	if (inode->i_nlink >= NOVA_LINK_MAX) {
		err = -EMLINK;
		goto out;
	}

	pidir = nova_get_inode(sb, dir);
	if (!pidir) {
		err = -EINVAL;
		goto out;
	}

	ihold(inode);
	epoch_id = nova_get_epoch_id(sb);

	nova_dbgv("%s: name %s, dest %s\n", __func__,
			dentry->d_name.name, dest_dentry->d_name.name);
	nova_dbgv("%s: inode %lu, dir %lu\n", __func__,
			inode->i_ino, dir->i_ino);

	update_dir.tail = 0;
	update_dir.alter_tail = 0;
	err = nova_add_dentry(dentry, inode->i_ino, 0, &update_dir, epoch_id);
	if (err) {
		iput(inode);
		goto out;
	}

	inode->i_ctime = current_time(inode);
	inc_nlink(inode);

	update.tail = 0;
	update.alter_tail = 0;
	err = nova_append_link_change_entry(sb, pi, inode, &update,
						&old_linkc, epoch_id);
	if (err) {
		iput(inode);
		goto out;
	}

	d_instantiate(dentry, inode);
	nova_lite_transaction_for_time_and_link(sb, pi, pidir, inode, dir,
					&update, &update_dir, 0, epoch_id);

	nova_invalidate_link_change_entry(sb, old_linkc);

out:
	NOVA_END_TIMING(link_t, link_time);
	return err;
}

static int nova_unlink(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct super_block *sb = dir->i_sb;
	int retval = -ENOMEM;
	struct nova_inode *pi = nova_get_inode(sb, inode);
	struct nova_inode *pidir;
	struct nova_inode_update update_dir;
	struct nova_inode_update update;
	u64 old_linkc = 0;
	u64 epoch_id;
	int invalidate = 0;
	INIT_TIMING(unlink_time);

	NOVA_START_TIMING(unlink_t, unlink_time);

	pidir = nova_get_inode(sb, dir);
	if (!pidir)
		goto out;

	epoch_id = nova_get_epoch_id(sb);
	nova_dbgv("%s: %s\n", __func__, dentry->d_name.name);
	nova_dbgv("%s: inode %lu, dir %lu\n", __func__,
				inode->i_ino, dir->i_ino);

	update_dir.tail = 0;
	update_dir.alter_tail = 0;
	retval = nova_remove_dentry(dentry, 0, &update_dir, epoch_id);
	if (retval)
		goto out;

	inode->i_ctime = dir->i_ctime;

	if (inode->i_nlink == 1)
		invalidate = 1;

	if (inode->i_nlink)
		drop_nlink(inode);

	update.tail = 0;
	update.alter_tail = 0;
	retval = nova_append_link_change_entry(sb, pi, inode, &update,
						&old_linkc, epoch_id);
	if (retval)
		goto out;

	nova_lite_transaction_for_time_and_link(sb, pi, pidir, inode, dir,
				&update, &update_dir, invalidate, epoch_id);

	nova_invalidate_link_change_entry(sb, old_linkc);
	nova_invalidate_dentries(sb, &update_dir);

	NOVA_END_TIMING(unlink_t, unlink_time);
	return 0;
out:
	nova_err(sb, "%s return %d\n", __func__, retval);
	NOVA_END_TIMING(unlink_t, unlink_time);
	return retval;
}

static int nova_mkdir(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	struct super_block *sb = dir->i_sb;
	struct inode *inode;
	struct nova_inode *pidir, *pi;
	struct nova_inode_info *si, *sidir;
	struct nova_inode_info_header *sih = NULL;
	struct nova_inode_update update;
	u64 pi_addr = 0;
	u64 ino;
	u64 epoch_id;
	int err = -EMLINK;
	INIT_TIMING(mkdir_time);

	NOVA_START_TIMING(mkdir_t, mkdir_time);
	if (dir->i_nlink >= NOVA_LINK_MAX)
		goto out;

	ino = nova_new_nova_inode(sb, &pi_addr);
	if (ino == 0)
		goto out_err;

	epoch_id = nova_get_epoch_id(sb);
	nova_dbgv("%s: name %s\n", __func__, dentry->d_name.name);
	nova_dbgv("%s: inode %llu, dir %lu, link %d\n", __func__,
				ino, dir->i_ino, dir->i_nlink);

	update.tail = 0;
	update.alter_tail = 0;
	err = nova_add_dentry(dentry, ino, 1, &update, epoch_id);
	if (err) {
		nova_dbg("failed to add dir entry\n");
		goto out_err;
	}

	inode = nova_new_vfs_inode(TYPE_MKDIR, dir, pi_addr, ino,
					S_IFDIR | mode, sb->s_blocksize,
					0, &dentry->d_name, epoch_id);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_err;
	}

	pi = nova_get_inode(sb, inode);
	err = nova_append_dir_init_entries(sb, pi, inode->i_ino, dir->i_ino,
					epoch_id);
	if (err < 0)
		goto out_err;

	/* Build the dir tree */
	si = NOVA_I(inode);
	sih = &si->header;
	nova_rebuild_dir_inode_tree(sb, pi, pi_addr, sih);

	pidir = nova_get_inode(sb, dir);
	sidir = NOVA_I(dir);
	sih = &si->header;
	dir->i_blocks = sih->i_blocks;
	inc_nlink(dir);
	d_instantiate(dentry, inode);
	unlock_new_inode(inode);

	nova_lite_transaction_for_new_inode(sb, pi, pidir, inode, dir,
					&update);
out:
	NOVA_END_TIMING(mkdir_t, mkdir_time);
	return err;

out_err:
//	clear_nlink(inode);
	nova_err(sb, "%s return %d\n", __func__, err);
	goto out;
}

/*
 * routine to check that the specified directory is empty (for rmdir)
 */
static int nova_empty_dir(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_range_node *curr;
	struct nova_dentry *entry;
	struct nova_dentry *entryc, entry_copy;
	struct rb_node *temp;

	entryc = (metadata_csum == 0) ? entry : &entry_copy;

	temp = rb_first(&sih->rb_tree);
	while (temp) {
		curr = container_of(temp, struct nova_range_node, node);
		entry = curr->direntry;

		if (metadata_csum == 0)
			entryc = entry;
		else if (!nova_verify_entry_csum(sb, entry, entryc))
			return 0;

		if (!is_dir_init_entry(sb, entryc))
			return 0;

		temp = rb_next(temp);
	}

	return 1;
}

static int nova_rmdir(struct inode *dir, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct nova_dentry *de;
	struct super_block *sb = inode->i_sb;
	struct nova_inode *pi = nova_get_inode(sb, inode), *pidir;
	struct nova_inode_update update_dir;
	struct nova_inode_update update;
	u64 old_linkc = 0;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	int err = -ENOTEMPTY;
	u64 epoch_id;
	INIT_TIMING(rmdir_time);

	NOVA_START_TIMING(rmdir_t, rmdir_time);
	if (!inode)
		return -ENOENT;

	nova_dbgv("%s: name %s\n", __func__, dentry->d_name.name);
	pidir = nova_get_inode(sb, dir);
	if (!pidir)
		return -EINVAL;

	if (nova_inode_by_name(dir, &dentry->d_name, &de) == 0)
		return -ENOENT;

	if (!nova_empty_dir(inode))
		return err;

	nova_dbgv("%s: inode %lu, dir %lu, link %d\n", __func__,
				inode->i_ino, dir->i_ino, dir->i_nlink);

	if (inode->i_nlink != 2)
		nova_dbg("empty directory %lu has nlink!=2 (%d), dir %lu",
				inode->i_ino, inode->i_nlink, dir->i_ino);

	epoch_id = nova_get_epoch_id(sb);

	update_dir.tail = 0;
	update_dir.alter_tail = 0;
	err = nova_remove_dentry(dentry, -1, &update_dir, epoch_id);
	if (err)
		goto end_rmdir;

	/*inode->i_version++; */
	clear_nlink(inode);
	inode->i_ctime = dir->i_ctime;

	if (dir->i_nlink)
		drop_nlink(dir);

	nova_delete_dir_tree(sb, sih);

	update.tail = 0;
	update.alter_tail = 0;
	err = nova_append_link_change_entry(sb, pi, inode, &update,
						&old_linkc, epoch_id);
	if (err)
		goto end_rmdir;

	nova_lite_transaction_for_time_and_link(sb, pi, pidir, inode, dir,
					&update, &update_dir, 1, epoch_id);

	nova_invalidate_link_change_entry(sb, old_linkc);
	nova_invalidate_dentries(sb, &update_dir);

	NOVA_END_TIMING(rmdir_t, rmdir_time);
	return err;

end_rmdir:
	nova_err(sb, "%s return %d\n", __func__, err);
	NOVA_END_TIMING(rmdir_t, rmdir_time);
	return err;
}

static int nova_rename(struct inode *old_dir,
			struct dentry *old_dentry,
			struct inode *new_dir, struct dentry *new_dentry,
			unsigned int flags)
{
	struct inode *old_inode = old_dentry->d_inode;
	struct inode *new_inode = new_dentry->d_inode;
	struct super_block *sb = old_inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode *old_pi = NULL, *new_pi = NULL;
	struct nova_inode *new_pidir = NULL, *old_pidir = NULL;
	struct nova_dentry *father_entry = NULL;
	struct nova_dentry *father_entryc, entry_copy;
	char *head_addr = NULL;
	int invalidate_new_inode = 0;
	struct nova_inode_update update_dir_new;
	struct nova_inode_update update_dir_old;
	struct nova_inode_update update_new;
	struct nova_inode_update update_old;
	u64 old_linkc1 = 0, old_linkc2 = 0;
	int err = -ENOENT;
	int inc_link = 0, dec_link = 0;
	int cpu;
	int change_parent = 0;
	u64 journal_tail;
	u64 epoch_id;
	unsigned long irq_flags = 0;
	INIT_TIMING(rename_time);

	nova_dbgv("%s: rename %s to %s,\n", __func__,
			old_dentry->d_name.name, new_dentry->d_name.name);
	nova_dbgv("%s: %s inode %lu, old dir %lu, new dir %lu, new inode %lu\n",
			__func__, S_ISDIR(old_inode->i_mode) ? "dir" : "normal",
			old_inode->i_ino, old_dir->i_ino, new_dir->i_ino,
			new_inode ? new_inode->i_ino : 0);

	if (flags & ~RENAME_NOREPLACE)
		return -EINVAL;

	NOVA_START_TIMING(rename_t, rename_time);

	if (new_inode) {
		err = -ENOTEMPTY;
		if (S_ISDIR(old_inode->i_mode) && !nova_empty_dir(new_inode))
			goto out;
	} else {
		if (S_ISDIR(old_inode->i_mode)) {
			err = -EMLINK;
			if (new_dir->i_nlink >= NOVA_LINK_MAX)
				goto out;
		}
	}

	if (S_ISDIR(old_inode->i_mode)) {
		dec_link = -1;
		if (!new_inode)
			inc_link = 1;
		/*
		 * Tricky for in-place update:
		 * New dentry is always after renamed dentry, so we have to
		 * make sure new dentry has the correct links count
		 * to workaround the rebuild nlink issue.
		 */
		if (old_dir == new_dir) {
			inc_link--;
			if (inc_link == 0)
				dec_link = 0;
		}
	}

	epoch_id = nova_get_epoch_id(sb);
	new_pidir = nova_get_inode(sb, new_dir);
	old_pidir = nova_get_inode(sb, old_dir);

	old_pi = nova_get_inode(sb, old_inode);
	old_inode->i_ctime = current_time(old_inode);
	update_old.tail = 0;
	update_old.alter_tail = 0;
	err = nova_append_link_change_entry(sb, old_pi, old_inode,
					&update_old, &old_linkc1, epoch_id);
	if (err)
		goto out;

	if (S_ISDIR(old_inode->i_mode) && old_dir != new_dir) {
		/* My father is changed. Update .. entry */
		/* For simplicity, we use in-place update and journal it */
		change_parent = 1;
		head_addr = (char *)nova_get_block(sb, old_pi->log_head);
		father_entry = (struct nova_dentry *)(head_addr +
					NOVA_DIR_LOG_REC_LEN(1));

		if (metadata_csum == 0)
			father_entryc = father_entry;
		else {
			father_entryc = &entry_copy;
			if (!nova_verify_entry_csum(sb, father_entry,
							father_entryc)) {
				err = -EIO;
				goto out;
			}
		}

		if (le64_to_cpu(father_entryc->ino) != old_dir->i_ino)
			nova_err(sb, "%s: dir %lu parent should be %lu, but actually %lu\n",
				__func__,
				old_inode->i_ino, old_dir->i_ino,
				le64_to_cpu(father_entry->ino));
	}

	update_dir_new.tail = 0;
	update_dir_new.alter_tail = 0;
	if (new_inode) {
		/* First remove the old entry in the new directory */
		err = nova_remove_dentry(new_dentry, 0, &update_dir_new,
					epoch_id);
		if (err)
			goto out;
	}

	/* link into the new directory. */
	err = nova_add_dentry(new_dentry, old_inode->i_ino,
				inc_link, &update_dir_new, epoch_id);
	if (err)
		goto out;

	if (inc_link > 0)
		inc_nlink(new_dir);

	update_dir_old.tail = 0;
	update_dir_old.alter_tail = 0;
	if (old_dir == new_dir) {
		update_dir_old.tail = update_dir_new.tail;
		update_dir_old.alter_tail = update_dir_new.alter_tail;
	}

	err = nova_remove_dentry(old_dentry, dec_link, &update_dir_old,
					epoch_id);
	if (err)
		goto out;

	if (dec_link < 0)
		drop_nlink(old_dir);

	if (new_inode) {
		new_pi = nova_get_inode(sb, new_inode);
		new_inode->i_ctime = current_time(new_inode);

		if (S_ISDIR(old_inode->i_mode)) {
			if (new_inode->i_nlink)
				drop_nlink(new_inode);
		}
		if (new_inode->i_nlink)
			drop_nlink(new_inode);

		update_new.tail = 0;
		update_new.alter_tail = 0;
		err = nova_append_link_change_entry(sb, new_pi, new_inode,
						&update_new, &old_linkc2,
						epoch_id);
		if (err)
			goto out;
	}

	cpu = nova_get_cpuid(sb);
	spin_lock(&sbi->journal_locks[cpu]);
	nova_memunlock_journal(sb, &irq_flags);
	if (new_inode && new_inode->i_nlink == 0)
		invalidate_new_inode = 1;
	journal_tail = nova_create_rename_transaction(sb, old_inode, old_dir,
				new_inode,
				old_dir != new_dir ? new_dir : NULL,
				father_entry,
				invalidate_new_inode,
				cpu);

	nova_update_inode(sb, old_inode, old_pi, &update_old, 0);
	nova_update_inode(sb, old_dir, old_pidir, &update_dir_old, 0);

	if (old_pidir != new_pidir)
		nova_update_inode(sb, new_dir, new_pidir, &update_dir_new, 0);

	if (change_parent && father_entry) {
		father_entry->ino = cpu_to_le64(new_dir->i_ino);
		nova_update_entry_csum(father_entry);
		nova_update_alter_entry(sb, father_entry);
	}

	if (new_inode) {
		if (invalidate_new_inode) {
			new_pi->valid = 0;
			new_pi->delete_epoch_id = epoch_id;
		}
		nova_update_inode(sb, new_inode, new_pi, &update_new, 0);
	}

	PERSISTENT_BARRIER();

	nova_commit_lite_transaction(sb, journal_tail, cpu);
	nova_memlock_journal(sb, &irq_flags);
	spin_unlock(&sbi->journal_locks[cpu]);

	nova_memunlock_inode(sb, old_pi, &irq_flags);
	nova_update_alter_inode(sb, old_inode, old_pi);
	nova_update_alter_inode(sb, old_dir, old_pidir);
	if (old_dir != new_dir)
		nova_update_alter_inode(sb, new_dir, new_pidir);
	if (new_inode)
		nova_update_alter_inode(sb, new_inode, new_pi);
	nova_memlock_inode(sb, old_pi, &irq_flags);

	nova_invalidate_link_change_entry(sb, old_linkc1);
	nova_invalidate_link_change_entry(sb, old_linkc2);
	if (new_inode)
		nova_invalidate_dentries(sb, &update_dir_new);
	nova_invalidate_dentries(sb, &update_dir_old);

	NOVA_END_TIMING(rename_t, rename_time);
	return 0;
out:
	nova_err(sb, "%s return %d\n", __func__, err);
	NOVA_END_TIMING(rename_t, rename_time);
	return err;
}

struct dentry *nova_get_parent(struct dentry *child)
{
	struct inode *inode;
	struct qstr dotdot = QSTR_INIT("..", 2);
	struct nova_dentry *de = NULL;
	ino_t ino;

	nova_inode_by_name(child->d_inode, &dotdot, &de);
	if (!de)
		return ERR_PTR(-ENOENT);

	/* FIXME: can de->ino be avoided by using the return value of
	 * nova_inode_by_name()?
	 */
	ino = le64_to_cpu(de->ino);

	if (ino)
		inode = nova_iget(child->d_inode->i_sb, ino);
	else
		return ERR_PTR(-ENOENT);

	return d_obtain_alias(inode);
}

const struct inode_operations nova_dir_inode_operations = {
	.create		= nova_create,
	.lookup		= nova_lookup,
	.link		= nova_link,
	.unlink		= nova_unlink,
	.symlink	= nova_symlink,
	.mkdir		= nova_mkdir,
	.rmdir		= nova_rmdir,
	.mknod		= nova_mknod,
	.rename		= nova_rename,
	.setattr	= nova_notify_change,
	.get_acl	= NULL,
};

const struct inode_operations nova_special_inode_operations = {
	.setattr	= nova_notify_change,
	.get_acl	= NULL,
};
