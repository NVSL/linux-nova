/*
 * BRIEF DESCRIPTION
 *
 * Log methods
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

#include "nova.h"
#include "journal.h"
#include "inode.h"
#include "log.h"

static int nova_execute_invalidate_reassign_logentry(struct super_block *sb,
	void *entry, enum nova_entry_type type, int reassign,
	unsigned int num_free)
{
	struct nova_file_write_entry *fw_entry;
	int invalid = 0;

	switch (type) {
	case FILE_WRITE:
		fw_entry = (struct nova_file_write_entry *)entry;
		if (reassign)
			fw_entry->reassigned = 1;
		if (num_free)
			fw_entry->invalid_pages += num_free;
		if (fw_entry->invalid_pages == fw_entry->num_pages)
			invalid = 1;
		break;
	case DIR_LOG:
		if (reassign) {
			((struct nova_dentry *)entry)->reassigned = 1;
		} else {
			((struct nova_dentry *)entry)->invalid = 1;
			invalid = 1;
		}
		break;
	case SET_ATTR:
		((struct nova_setattr_logentry *)entry)->invalid = 1;
		invalid = 1;
		break;
	case LINK_CHANGE:
		((struct nova_link_change_entry *)entry)->invalid = 1;
		invalid = 1;
		break;
	case MMAP_WRITE:
		((struct nova_mmap_entry *)entry)->invalid = 1;
		invalid = 1;
		break;
	case SNAPSHOT_INFO:
		((struct nova_snapshot_info_entry *)entry)->deleted = 1;
		invalid = 1;
		break;
	default:
		break;
	}

	if (invalid) {
		u64 addr = nova_get_addr_off(NOVA_SB(sb), entry);

		nova_inc_page_invalid_entries(sb, addr);
	}

	nova_update_entry_csum(entry);
	return 0;
}

static int nova_invalidate_reassign_logentry(struct super_block *sb,
	void *entry, enum nova_entry_type type, int reassign,
	unsigned int num_free)
{
	nova_memunlock_range(sb, entry, CACHELINE_SIZE);

	nova_execute_invalidate_reassign_logentry(sb, entry, type,
						reassign, num_free);
	nova_update_alter_entry(sb, entry);
	nova_memlock_range(sb, entry, CACHELINE_SIZE);

	return 0;
}

int nova_invalidate_logentry(struct super_block *sb, void *entry,
	enum nova_entry_type type, unsigned int num_free)
{
	return nova_invalidate_reassign_logentry(sb, entry, type, 0, num_free);
}

int nova_reassign_logentry(struct super_block *sb, void *entry,
	enum nova_entry_type type)
{
	return nova_invalidate_reassign_logentry(sb, entry, type, 1, 0);
}

static inline int nova_invalidate_write_entry(struct super_block *sb,
	struct nova_file_write_entry *entry, int reassign,
	unsigned int num_free)
{
	struct nova_file_write_entry *entryc, entry_copy;

	if (!entry)
		return 0;

	if (metadata_csum == 0)
		entryc = entry;
	else {
		entryc = &entry_copy;
		if (!nova_verify_entry_csum(sb, entry, entryc))
			return -EIO;
	}

	if (num_free == 0 && entryc->reassigned == 1)
		return 0;

	return nova_invalidate_reassign_logentry(sb, entry, FILE_WRITE,
							reassign, num_free);
}

unsigned int nova_free_old_entry(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry,
	unsigned long pgoff, unsigned int num_free,
	bool delete_dead, u64 epoch_id)
{
	struct nova_file_write_entry *entryc, entry_copy;
	unsigned long old_nvmm;
	int ret;
	INIT_TIMING(free_time);

	if (!entry)
		return 0;

	NOVA_START_TIMING(free_old_t, free_time);

	if (metadata_csum == 0)
		entryc = entry;
	else {
		entryc = &entry_copy;
		if (!nova_verify_entry_csum(sb, entry, entryc))
			return -EIO;
	}

	old_nvmm = get_nvmm(sb, sih, entryc, pgoff);

	if (!delete_dead) {
		ret = nova_append_data_to_snapshot(sb, entryc, old_nvmm,
				num_free, epoch_id);
		if (ret == 0) {
			nova_invalidate_write_entry(sb, entry, 1, 0);
			goto out;
		}

		nova_invalidate_write_entry(sb, entry, 1, num_free);
	}

	nova_dbgv("%s: pgoff %lu, free %u blocks\n",
				__func__, pgoff, num_free);
	nova_free_data_blocks(sb, sih, old_nvmm, num_free);

out:
	sih->i_blocks -= num_free;

	NOVA_END_TIMING(free_old_t, free_time);
	return num_free;
}

struct nova_file_write_entry *nova_find_next_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, pgoff_t pgoff)
{
	struct nova_file_write_entry *entry = NULL;
	struct nova_file_write_entry *entries[1];
	int nr_entries;

	nr_entries = radix_tree_gang_lookup(&sih->tree,
					(void **)entries, pgoff, 1);
	if (nr_entries == 1)
		entry = entries[0];

	return entry;
}

/*
 * Zero the tail page. Used in resize request
 * to avoid to keep data in case the file grows again.
 */
void nova_clear_last_page_tail(struct super_block *sb,
	struct inode *inode, loff_t newsize)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	unsigned long offset = newsize & (sb->s_blocksize - 1);
	unsigned long pgoff, length;
	u64 nvmm;
	char *nvmm_addr;

	if (offset == 0 || newsize > inode->i_size)
		return;

	length = sb->s_blocksize - offset;
	pgoff = newsize >> sb->s_blocksize_bits;

	nvmm = nova_find_nvmm_block(sb, sih, NULL, pgoff);
	if (nvmm == 0)
		return;

	nvmm_addr = (char *)nova_get_block(sb, nvmm);
	nova_memunlock_range(sb, nvmm_addr + offset, length);
	memcpy_to_pmem_nocache(nvmm_addr + offset, sbi->zeroed_page, length);
	nova_memlock_range(sb, nvmm_addr + offset, length);

	if (data_csum > 0)
		nova_update_truncated_block_csum(sb, inode, newsize);
	if (data_parity > 0)
		nova_update_truncated_block_parity(sb, inode, newsize);
}

static void nova_update_setattr_entry(struct inode *inode,
	struct nova_setattr_logentry *entry,
	struct nova_log_entry_info *entry_info)
{
	struct iattr *attr = entry_info->attr;
	unsigned int ia_valid = attr->ia_valid, attr_mask;

	/* These files are in the lowest byte */
	attr_mask = ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_SIZE |
			ATTR_ATIME | ATTR_MTIME | ATTR_CTIME;

	entry->entry_type	= SET_ATTR;
	entry->attr	= ia_valid & attr_mask;
	entry->mode	= cpu_to_le16(inode->i_mode);
	entry->uid	= cpu_to_le32(i_uid_read(inode));
	entry->gid	= cpu_to_le32(i_gid_read(inode));
	entry->atime	= cpu_to_le32(inode->i_atime.tv_sec);
	entry->ctime	= cpu_to_le32(inode->i_ctime.tv_sec);
	entry->mtime	= cpu_to_le32(inode->i_mtime.tv_sec);
	entry->epoch_id = cpu_to_le64(entry_info->epoch_id);
	entry->trans_id	= cpu_to_le64(entry_info->trans_id);
	entry->invalid	= 0;

	if (ia_valid & ATTR_SIZE)
		entry->size = cpu_to_le64(attr->ia_size);
	else
		entry->size = cpu_to_le64(inode->i_size);

	nova_update_entry_csum(entry);
}

static void nova_update_link_change_entry(struct inode *inode,
	struct nova_link_change_entry *entry,
	struct nova_log_entry_info *entry_info)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;

	entry->entry_type	= LINK_CHANGE;
	entry->epoch_id		= cpu_to_le64(entry_info->epoch_id);
	entry->trans_id		= cpu_to_le64(entry_info->trans_id);
	entry->invalid		= 0;
	entry->links		= cpu_to_le16(inode->i_nlink);
	entry->ctime		= cpu_to_le32(inode->i_ctime.tv_sec);
	entry->flags		= cpu_to_le32(sih->i_flags);
	entry->generation	= cpu_to_le32(inode->i_generation);

	nova_update_entry_csum(entry);
}

static int nova_update_write_entry(struct super_block *sb,
	struct nova_file_write_entry *entry,
	struct nova_log_entry_info *entry_info)
{
	entry->epoch_id = cpu_to_le64(entry_info->epoch_id);
	entry->trans_id = cpu_to_le64(entry_info->trans_id);
	entry->mtime = cpu_to_le32(entry_info->time);
	entry->size = cpu_to_le64(entry_info->file_size);
	entry->updating = 0;
	nova_update_entry_csum(entry);
	return 0;
}

static int nova_update_old_dentry(struct super_block *sb,
	struct inode *dir, struct nova_dentry *dentry,
	struct nova_log_entry_info *entry_info)
{
	unsigned short links_count;
	int link_change = entry_info->link_change;
	u64 addr;

	dentry->epoch_id = entry_info->epoch_id;
	dentry->trans_id = entry_info->trans_id;
	/* Remove_dentry */
	dentry->ino = cpu_to_le64(0);
	dentry->invalid = 1;
	dentry->mtime = cpu_to_le32(dir->i_mtime.tv_sec);

	links_count = cpu_to_le16(dir->i_nlink);
	if (links_count == 0 && link_change == -1)
		links_count = 0;
	else
		links_count += link_change;
	dentry->links_count = cpu_to_le16(links_count);

	addr = nova_get_addr_off(NOVA_SB(sb), dentry);
	nova_inc_page_invalid_entries(sb, addr);

	/* Update checksum */
	nova_update_entry_csum(dentry);

	return 0;
}

static int nova_update_new_dentry(struct super_block *sb,
	struct inode *dir, struct nova_dentry *entry,
	struct nova_log_entry_info *entry_info)
{
	struct dentry *dentry = entry_info->data;
	unsigned short links_count;
	int link_change = entry_info->link_change;

	entry->entry_type = DIR_LOG;
	entry->epoch_id = entry_info->epoch_id;
	entry->trans_id = entry_info->trans_id;
	entry->ino = entry_info->ino;
	entry->name_len = dentry->d_name.len;
	memcpy_to_pmem_nocache(entry->name, dentry->d_name.name,
				dentry->d_name.len);
	entry->name[dentry->d_name.len] = '\0';
	entry->mtime = cpu_to_le32(dir->i_mtime.tv_sec);
	//entry->size = cpu_to_le64(dir->i_size);

	links_count = cpu_to_le16(dir->i_nlink);
	if (links_count == 0 && link_change == -1)
		links_count = 0;
	else
		links_count += link_change;
	entry->links_count = cpu_to_le16(links_count);

	/* Update actual de_len */
	entry->de_len = cpu_to_le16(entry_info->file_size);

	/* Update checksum */
	nova_update_entry_csum(entry);

	return 0;
}

static int nova_update_log_entry(struct super_block *sb, struct inode *inode,
	void *entry, struct nova_log_entry_info *entry_info)
{
	enum nova_entry_type type = entry_info->type;

	switch (type) {
	case FILE_WRITE:
		if (entry_info->inplace)
			nova_update_write_entry(sb, entry, entry_info);
		else
			memcpy_to_pmem_nocache(entry, entry_info->data,
				sizeof(struct nova_file_write_entry));
		break;
	case DIR_LOG:
		if (entry_info->inplace)
			nova_update_old_dentry(sb, inode, entry, entry_info);
		else
			nova_update_new_dentry(sb, inode, entry, entry_info);
		break;
	case SET_ATTR:
		nova_update_setattr_entry(inode, entry, entry_info);
		break;
	case LINK_CHANGE:
		nova_update_link_change_entry(inode, entry, entry_info);
		break;
	case MMAP_WRITE:
		memcpy_to_pmem_nocache(entry, entry_info->data,
				sizeof(struct nova_mmap_entry));
		break;
	case SNAPSHOT_INFO:
		memcpy_to_pmem_nocache(entry, entry_info->data,
				sizeof(struct nova_snapshot_info_entry));
		break;
	default:
		break;
	}

	return 0;
}

static int nova_append_log_entry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode,
	struct nova_inode_info_header *sih,
	struct nova_log_entry_info *entry_info)
{
	void *entry, *alter_entry;
	enum nova_entry_type type = entry_info->type;
	struct nova_inode_update *update = entry_info->update;
	u64 tail, alter_tail;
	u64 curr_p, alter_curr_p;
	size_t size;
	int extended = 0;

	if (type == DIR_LOG)
		size = entry_info->file_size;
	else
		size = nova_get_log_entry_size(sb, type);

	tail = update->tail;
	alter_tail = update->alter_tail;

	curr_p = nova_get_append_head(sb, pi, sih, tail, size,
						MAIN_LOG, 0, &extended);
	if (curr_p == 0)
		return -ENOSPC;

	nova_dbg_verbose("%s: inode %lu attr change entry @ 0x%llx\n",
				__func__, sih->ino, curr_p);

	entry = nova_get_block(sb, curr_p);
	/* inode is already updated with attr */
	nova_memunlock_range(sb, entry, size);
	memset(entry, 0, size);
	nova_update_log_entry(sb, inode, entry, entry_info);
	nova_inc_page_num_entries(sb, curr_p);
	nova_memlock_range(sb, entry, size);
	update->curr_entry = curr_p;
	update->tail = curr_p + size;

	if (metadata_csum) {
		alter_curr_p = nova_get_append_head(sb, pi, sih, alter_tail,
						size, ALTER_LOG, 0, &extended);
		if (alter_curr_p == 0)
			return -ENOSPC;

		alter_entry = nova_get_block(sb, alter_curr_p);
		nova_memunlock_range(sb, alter_entry, size);
		memset(alter_entry, 0, size);
		nova_update_log_entry(sb, inode, alter_entry, entry_info);
		nova_memlock_range(sb, alter_entry, size);

		update->alter_entry = alter_curr_p;
		update->alter_tail = alter_curr_p + size;
	}

	entry_info->curr_p = curr_p;
	return 0;
}

int nova_inplace_update_log_entry(struct super_block *sb,
	struct inode *inode, void *entry,
	struct nova_log_entry_info *entry_info)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	enum nova_entry_type type = entry_info->type;
	u64 journal_tail;
	size_t size;
	int cpu;
	INIT_TIMING(update_time);

	NOVA_START_TIMING(update_entry_t, update_time);
	size = nova_get_log_entry_size(sb, type);

	if (metadata_csum) {
		nova_memunlock_range(sb, entry, size);
		nova_update_log_entry(sb, inode, entry, entry_info);
		// Also update the alter inode log entry.
		nova_update_alter_entry(sb, entry);
		nova_memlock_range(sb, entry, size);
		goto out;
	}

	cpu = nova_get_cpuid(sb);
	spin_lock(&sbi->journal_locks[cpu]);
	nova_memunlock_journal(sb);
	journal_tail = nova_create_logentry_transaction(sb, entry, type, cpu);
	nova_update_log_entry(sb, inode, entry, entry_info);

	PERSISTENT_BARRIER();

	nova_commit_lite_transaction(sb, journal_tail, cpu);
	nova_memlock_journal(sb);
	spin_unlock(&sbi->journal_locks[cpu]);
out:
	NOVA_END_TIMING(update_entry_t, update_time);
	return 0;
}

/* Returns new tail after append */
static int nova_append_setattr_entry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode, struct iattr *attr,
	struct nova_inode_update *update, u64 *last_setattr, u64 epoch_id)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode inode_copy;
	struct nova_log_entry_info entry_info;
	INIT_TIMING(append_time);
	int ret;

	NOVA_START_TIMING(append_setattr_t, append_time);
	entry_info.type = SET_ATTR;
	entry_info.attr = attr;
	entry_info.update = update;
	entry_info.epoch_id = epoch_id;
	entry_info.trans_id = sih->trans_id;

	if (nova_check_inode_integrity(sb, sih->ino, sih->pi_addr,
			sih->alter_pi_addr, &inode_copy, 0) < 0) {
		ret = -EIO;
		goto out;
	}

	ret = nova_append_log_entry(sb, pi, inode, sih, &entry_info);
	if (ret) {
		nova_err(sb, "%s failed\n", __func__);
		goto out;
	}

	*last_setattr = sih->last_setattr;
	sih->last_setattr = entry_info.curr_p;

out:
	NOVA_END_TIMING(append_setattr_t, append_time);
	return ret;
}

/* Invalidate old link change entry */
static int nova_invalidate_setattr_entry(struct super_block *sb,
	u64 last_setattr)
{
	struct nova_setattr_logentry *old_entry;
	struct nova_setattr_logentry *old_entryc, old_entry_copy;
	void *addr;
	int ret;

	addr = (void *)nova_get_block(sb, last_setattr);
	old_entry = (struct nova_setattr_logentry *)addr;

	if (metadata_csum == 0)
		old_entryc = old_entry;
	else {
		old_entryc = &old_entry_copy;
		if (!nova_verify_entry_csum(sb, old_entry, old_entryc))
			return -EIO;
	}

	/* Do not invalidate setsize entries */
	if (!old_entry_freeable(sb, old_entryc->epoch_id) ||
			(old_entryc->attr & ATTR_SIZE))
		return 0;

	ret = nova_invalidate_logentry(sb, old_entry, SET_ATTR, 0);

	return ret;
}

#if 0
static void setattr_copy_to_nova_inode(struct super_block *sb,
	struct inode *inode, struct nova_inode *pi, u64 epoch_id)
{
	pi->i_mode  = cpu_to_le16(inode->i_mode);
	pi->i_uid	= cpu_to_le32(i_uid_read(inode));
	pi->i_gid	= cpu_to_le32(i_gid_read(inode));
	pi->i_atime	= cpu_to_le32(inode->i_atime.tv_sec);
	pi->i_ctime	= cpu_to_le32(inode->i_ctime.tv_sec);
	pi->i_mtime	= cpu_to_le32(inode->i_mtime.tv_sec);
	pi->create_epoch_id = epoch_id;

	nova_update_alter_inode(sb, inode, pi);
}
#endif

static int nova_can_inplace_update_setattr(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 epoch_id)
{
	u64 last_log = 0;
	struct nova_setattr_logentry *entry = NULL;

	last_log = sih->last_setattr;
	if (last_log) {
		entry = (struct nova_setattr_logentry *)nova_get_block(sb,
								last_log);
		/* Do not overwrite setsize entry */
		if (entry->attr & ATTR_SIZE)
			return 0;
		if (entry->epoch_id == epoch_id)
			return 1;
	}

	return 0;
}

static int nova_inplace_update_setattr_entry(struct super_block *sb,
	struct inode *inode, struct nova_inode_info_header *sih,
	struct iattr *attr, u64 epoch_id)
{
	struct nova_setattr_logentry *entry = NULL;
	struct nova_log_entry_info entry_info;
	u64 last_log = 0;

	nova_dbgv("%s : Modifying last log entry for inode %lu\n",
				__func__, inode->i_ino);
	last_log = sih->last_setattr;
	entry = (struct nova_setattr_logentry *)nova_get_block(sb,
							last_log);

	entry_info.type = SET_ATTR;
	entry_info.attr = attr;
	entry_info.epoch_id = epoch_id;
	entry_info.trans_id = sih->trans_id;

	return nova_inplace_update_log_entry(sb, inode, entry,
					&entry_info);
}

int nova_handle_setattr_operation(struct super_block *sb, struct inode *inode,
	struct nova_inode *pi, unsigned int ia_valid, struct iattr *attr,
	u64 epoch_id)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode_update update;
	u64 last_setattr = 0;
	int ret;

	if (ia_valid & ATTR_MODE)
		sih->i_mode = inode->i_mode;

	/*
	 * Let's try to do inplace update.
	 * If there are currently no snapshots holding this inode,
	 * we can update the inode in place. If a snapshot creation
	 * is in progress, we will use the create_snapshot_epoch_id
	 * as the latest snapshot id.
	 */
	if (!(ia_valid & ATTR_SIZE) &&
			nova_can_inplace_update_setattr(sb, sih, epoch_id)) {
		nova_inplace_update_setattr_entry(sb, inode, sih,
						attr, epoch_id);
	} else {
		/* We are holding inode lock so OK to append the log */
		nova_dbgv("%s : Appending last log entry for inode ino = %lu\n",
				__func__, inode->i_ino);
		update.tail = update.alter_tail = 0;
		ret = nova_append_setattr_entry(sb, pi, inode, attr, &update,
						&last_setattr, epoch_id);
		if (ret) {
			nova_dbg("%s: append setattr entry failure\n",
								__func__);
			return ret;
		}

		nova_memunlock_inode(sb, pi);
		nova_update_inode(sb, inode, pi, &update, 1);
		nova_memlock_inode(sb, pi);
	}

	/* Invalidate old setattr entry */
	if (last_setattr)
		nova_invalidate_setattr_entry(sb, last_setattr);

	return 0;
}

/* Invalidate old link change entry */
int nova_invalidate_link_change_entry(struct super_block *sb,
	u64 old_link_change)
{
	struct nova_link_change_entry *old_entry;
	struct nova_link_change_entry *old_entryc, old_entry_copy;
	void *addr;
	int ret;

	if (old_link_change == 0)
		return 0;

	addr = (void *)nova_get_block(sb, old_link_change);
	old_entry = (struct nova_link_change_entry *)addr;

	if (metadata_csum == 0)
		old_entryc = old_entry;
	else {
		old_entryc = &old_entry_copy;
		if (!nova_verify_entry_csum(sb, old_entry, old_entryc))
			return -EIO;
	}

	if (!old_entry_freeable(sb, old_entryc->epoch_id))
		return 0;

	ret = nova_invalidate_logentry(sb, old_entry, LINK_CHANGE, 0);

	return ret;
}

static int nova_can_inplace_update_lcentry(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 epoch_id)
{
	u64 last_log = 0;
	struct nova_link_change_entry *entry = NULL;

	last_log = sih->last_link_change;
	if (last_log) {
		entry = (struct nova_link_change_entry *)nova_get_block(sb,
								last_log);
		if (entry->epoch_id == epoch_id)
			return 1;
	}

	return 0;
}

static int nova_inplace_update_lcentry(struct super_block *sb,
	struct inode *inode, struct nova_inode_info_header *sih,
	u64 epoch_id)
{
	struct nova_link_change_entry *entry = NULL;
	struct nova_log_entry_info entry_info;
	u64 last_log = 0;

	last_log = sih->last_link_change;
	entry = (struct nova_link_change_entry *)nova_get_block(sb,
							last_log);

	entry_info.type = LINK_CHANGE;
	entry_info.epoch_id = epoch_id;
	entry_info.trans_id = sih->trans_id;

	return nova_inplace_update_log_entry(sb, inode, entry,
					&entry_info);
}

/* Returns new tail after append */
int nova_append_link_change_entry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode,
	struct nova_inode_update *update, u64 *old_linkc, u64 epoch_id)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode inode_copy;
	struct nova_log_entry_info entry_info;
	int ret = 0;
	INIT_TIMING(append_time);

	NOVA_START_TIMING(append_link_change_t, append_time);

	if (nova_check_inode_integrity(sb, sih->ino, sih->pi_addr,
			sih->alter_pi_addr, &inode_copy, 0) < 0) {
		ret = -EIO;
		goto out;
	}

	if (nova_can_inplace_update_lcentry(sb, sih, epoch_id)) {
		nova_inplace_update_lcentry(sb, inode, sih, epoch_id);
		update->tail = sih->log_tail;
		update->alter_tail = sih->alter_log_tail;

		*old_linkc = 0;
		sih->trans_id++;
		goto out;
	}

	entry_info.type = LINK_CHANGE;
	entry_info.update = update;
	entry_info.epoch_id = epoch_id;
	entry_info.trans_id = sih->trans_id;

	ret = nova_append_log_entry(sb, pi, inode, sih, &entry_info);
	if (ret) {
		nova_err(sb, "%s failed\n", __func__);
		goto out;
	}

	*old_linkc = sih->last_link_change;
	sih->last_link_change = entry_info.curr_p;
	sih->trans_id++;
out:
	NOVA_END_TIMING(append_link_change_t, append_time);
	return ret;
}

int nova_assign_write_entry(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry,
	struct nova_file_write_entry *entryc,
	bool free)
{
	struct nova_file_write_entry *old_entry;
	struct nova_file_write_entry *start_old_entry = NULL;
	void **pentry;
	unsigned long start_pgoff = entryc->pgoff;
	unsigned long start_old_pgoff = 0;
	unsigned int num = entryc->num_pages;
	unsigned int num_free = 0;
	unsigned long curr_pgoff;
	int i;
	int ret = 0;
	INIT_TIMING(assign_time);

	NOVA_START_TIMING(assign_t, assign_time);
	for (i = 0; i < num; i++) {
		curr_pgoff = start_pgoff + i;

		pentry = radix_tree_lookup_slot(&sih->tree, curr_pgoff);
		if (pentry) {
			old_entry = radix_tree_deref_slot(pentry);
			if (old_entry != start_old_entry) {
				if (start_old_entry && free)
					nova_free_old_entry(sb, sih,
							start_old_entry,
							start_old_pgoff,
							num_free, false,
							entryc->epoch_id);
				nova_invalidate_write_entry(sb,
						start_old_entry, 1, 0);

				start_old_entry = old_entry;
				start_old_pgoff = curr_pgoff;
				num_free = 1;
			} else {
				num_free++;
			}

			radix_tree_replace_slot(&sih->tree, pentry, entry);
		} else {
			ret = radix_tree_insert(&sih->tree, curr_pgoff, entry);
			if (ret) {
				nova_dbg("%s: ERROR %d\n", __func__, ret);
				goto out;
			}
		}
	}

	if (start_old_entry && free)
		nova_free_old_entry(sb, sih, start_old_entry,
					start_old_pgoff, num_free, false,
					entryc->epoch_id);

	nova_invalidate_write_entry(sb, start_old_entry, 1, 0);

out:
	NOVA_END_TIMING(assign_t, assign_time);

	return ret;
}

int nova_inplace_update_write_entry(struct super_block *sb,
	struct inode *inode, struct nova_file_write_entry *entry,
	struct nova_log_entry_info *entry_info)
{
	return nova_inplace_update_log_entry(sb, inode, entry,
					entry_info);
}

int nova_set_write_entry_updating(struct super_block *sb,
	struct nova_file_write_entry *entry, int set)
{
	nova_memunlock_range(sb, entry, sizeof(*entry));
	entry->updating = set ? 1 : 0;
	nova_update_entry_csum(entry);
	nova_update_alter_entry(sb, entry);
	nova_memlock_range(sb, entry, sizeof(*entry));

	return 0;
}

/*
 * Append a nova_file_write_entry to the current nova_inode_log_page.
 * blocknr and start_blk are pgoff.
 * We cannot update pi->log_tail here because a transaction may contain
 * multiple entries.
 */
int nova_append_file_write_entry(struct super_block *sb, struct nova_inode *pi,
	struct inode *inode, struct nova_file_write_entry *data,
	struct nova_inode_update *update)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_log_entry_info entry_info;
	INIT_TIMING(append_time);
	int ret;

	NOVA_START_TIMING(append_file_entry_t, append_time);

	nova_update_entry_csum(data);

	entry_info.type = FILE_WRITE;
	entry_info.update = update;
	entry_info.data = data;
	entry_info.epoch_id = data->epoch_id;
	entry_info.trans_id = data->trans_id;
	entry_info.inplace = 0;

	ret = nova_append_log_entry(sb, pi, inode, sih, &entry_info);
	if (ret)
		nova_err(sb, "%s failed\n", __func__);

	NOVA_END_TIMING(append_file_entry_t, append_time);
	return ret;
}

int nova_append_mmap_entry(struct super_block *sb, struct nova_inode *pi,
	struct inode *inode, struct nova_mmap_entry *data,
	struct nova_inode_update *update, struct vma_item *item)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode inode_copy;
	struct nova_log_entry_info entry_info;
	INIT_TIMING(append_time);
	int ret;

	NOVA_START_TIMING(append_mmap_entry_t, append_time);

	nova_update_entry_csum(data);

	entry_info.type = MMAP_WRITE;
	entry_info.update = update;
	entry_info.data = data;
	entry_info.epoch_id = data->epoch_id;

	if (nova_check_inode_integrity(sb, sih->ino, sih->pi_addr,
			sih->alter_pi_addr, &inode_copy, 0) < 0) {
		ret = -EIO;
		goto out;
	}

	ret = nova_append_log_entry(sb, pi, inode, sih, &entry_info);
	if (ret)
		nova_err(sb, "%s failed\n", __func__);

	item->mmap_entry = entry_info.curr_p;
out:
	NOVA_END_TIMING(append_mmap_entry_t, append_time);
	return ret;
}

int nova_append_snapshot_info_entry(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info *si,
	struct snapshot_info *info, struct nova_snapshot_info_entry *data,
	struct nova_inode_update *update)
{
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode inode_copy;
	struct nova_log_entry_info entry_info;
	INIT_TIMING(append_time);
	int ret;

	NOVA_START_TIMING(append_snapshot_info_t, append_time);

	nova_update_entry_csum(data);

	entry_info.type = SNAPSHOT_INFO;
	entry_info.update = update;
	entry_info.data = data;
	entry_info.epoch_id = data->epoch_id;
	entry_info.inplace = 0;

	if (nova_check_inode_integrity(sb, sih->ino, sih->pi_addr,
			sih->alter_pi_addr, &inode_copy, 0) < 0) {
		ret = -EIO;
		goto out;
	}

	ret = nova_append_log_entry(sb, pi, NULL, sih, &entry_info);
	if (ret)
		nova_err(sb, "%s failed\n", __func__);

	info->snapshot_entry = entry_info.curr_p;
out:
	NOVA_END_TIMING(append_snapshot_info_t, append_time);
	return ret;
}

int nova_append_dentry(struct super_block *sb, struct nova_inode *pi,
	struct inode *dir, struct dentry *dentry, u64 ino,
	unsigned short de_len, struct nova_inode_update *update,
	int link_change, u64 epoch_id)
{
	struct nova_inode_info *si = NOVA_I(dir);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode inode_copy;
	struct nova_log_entry_info entry_info;
	INIT_TIMING(append_time);
	int ret;

	NOVA_START_TIMING(append_dir_entry_t, append_time);

	entry_info.type = DIR_LOG;
	entry_info.update = update;
	entry_info.data = dentry;
	entry_info.ino = ino;
	entry_info.link_change = link_change;
	entry_info.file_size = de_len;
	entry_info.epoch_id = epoch_id;
	entry_info.trans_id = sih->trans_id;
	entry_info.inplace = 0;

	/* nova_inode tail pointer will be updated and we make sure all other
	 * inode fields are good before checksumming the whole structure
	 */
	if (nova_check_inode_integrity(sb, sih->ino, sih->pi_addr,
			sih->alter_pi_addr, &inode_copy, 0) < 0) {
		ret = -EIO;
		goto out;
	}

	ret = nova_append_log_entry(sb, pi, dir, sih, &entry_info);
	if (ret)
		nova_err(sb, "%s failed\n", __func__);

	dir->i_blocks = sih->i_blocks;
out:
	NOVA_END_TIMING(append_dir_entry_t, append_time);
	return ret;
}

int nova_update_alter_pages(struct super_block *sb, struct nova_inode *pi,
	u64 curr, u64 alter_curr)
{
	if (curr == 0 || alter_curr == 0 || metadata_csum == 0)
		return 0;

	while (curr && alter_curr) {
		nova_set_alter_page_address(sb, curr, alter_curr);
		curr = next_log_page(sb, curr);
		alter_curr = next_log_page(sb, alter_curr);
	}

	if (curr || alter_curr)
		nova_dbg("%s: curr 0x%llx, alter_curr 0x%llx\n",
					__func__, curr, alter_curr);

	return 0;
}

static int nova_coalesce_log_pages(struct super_block *sb,
	unsigned long prev_blocknr, unsigned long first_blocknr,
	unsigned long num_pages)
{
	unsigned long next_blocknr;
	u64 curr_block, next_page;
	struct nova_inode_log_page *curr_page;
	int i;

	if (prev_blocknr) {
		/* Link prev block and newly allocated head block */
		curr_block = nova_get_block_off(sb, prev_blocknr,
						NOVA_BLOCK_TYPE_4K);
		curr_page = (struct nova_inode_log_page *)
				nova_get_block(sb, curr_block);
		next_page = nova_get_block_off(sb, first_blocknr,
				NOVA_BLOCK_TYPE_4K);
		nova_memunlock_block(sb, curr_page);
		nova_set_next_page_address(sb, curr_page, next_page, 0);
		nova_memlock_block(sb, curr_page);
	}

	next_blocknr = first_blocknr + 1;
	curr_block = nova_get_block_off(sb, first_blocknr,
						NOVA_BLOCK_TYPE_4K);
	curr_page = (struct nova_inode_log_page *)
				nova_get_block(sb, curr_block);
	for (i = 0; i < num_pages - 1; i++) {
		next_page = nova_get_block_off(sb, next_blocknr,
				NOVA_BLOCK_TYPE_4K);
		nova_memunlock_block(sb, curr_page);
		nova_set_page_num_entries(sb, curr_page, 0, 0);
		nova_set_page_invalid_entries(sb, curr_page, 0, 0);
		nova_set_next_page_address(sb, curr_page, next_page, 0);
		nova_memlock_block(sb, curr_page);
		curr_page++;
		next_blocknr++;
	}

	/* Last page */
	nova_memunlock_block(sb, curr_page);
	nova_set_page_num_entries(sb, curr_page, 0, 0);
	nova_set_page_invalid_entries(sb, curr_page, 0, 0);
	nova_set_next_page_address(sb, curr_page, 0, 1);
	nova_memlock_block(sb, curr_page);
	return 0;
}

/* Log block resides in NVMM */
int nova_allocate_inode_log_pages(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long num_pages,
	u64 *new_block, int cpuid, enum nova_alloc_direction from_tail)
{
	unsigned long new_inode_blocknr;
	unsigned long first_blocknr;
	unsigned long prev_blocknr;
	int allocated;
	int ret_pages = 0;

	allocated = nova_new_log_blocks(sb, sih, &new_inode_blocknr,
			num_pages, ALLOC_NO_INIT, cpuid, from_tail);

	if (allocated <= 0) {
		nova_err(sb, "ERROR: no inode log page available: %d %d\n",
			num_pages, allocated);
		return allocated;
	}
	ret_pages += allocated;
	num_pages -= allocated;
	nova_dbg_verbose("Pi %lu: Alloc %d log blocks @ 0x%lx\n",
			sih->ino, allocated, new_inode_blocknr);

	/* Coalesce the pages */
	nova_coalesce_log_pages(sb, 0, new_inode_blocknr, allocated);
	first_blocknr = new_inode_blocknr;
	prev_blocknr = new_inode_blocknr + allocated - 1;

	/* Allocate remaining pages */
	while (num_pages) {
		allocated = nova_new_log_blocks(sb, sih,
					&new_inode_blocknr, num_pages,
					ALLOC_NO_INIT, cpuid, from_tail);

		nova_dbg_verbose("Alloc %d log blocks @ 0x%lx\n",
					allocated, new_inode_blocknr);
		if (allocated <= 0) {
			nova_dbg("%s: no inode log page available: %lu %d\n",
				__func__, num_pages, allocated);
			/* Return whatever we have */
			break;
		}
		ret_pages += allocated;
		num_pages -= allocated;
		nova_coalesce_log_pages(sb, prev_blocknr, new_inode_blocknr,
						allocated);
		prev_blocknr = new_inode_blocknr + allocated - 1;
	}

	*new_block = nova_get_block_off(sb, first_blocknr,
						NOVA_BLOCK_TYPE_4K);

	return ret_pages;
}

static int nova_initialize_inode_log(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	int log_id)
{
	u64 new_block;
	int allocated;

	allocated = nova_allocate_inode_log_pages(sb, sih,
					1, &new_block, ANY_CPU,
					log_id == MAIN_LOG ? 0 : 1);
	if (allocated != 1) {
		nova_err(sb, "%s ERROR: no inode log page available\n",
					__func__);
		return -ENOSPC;
	}

	nova_memunlock_inode(sb, pi);
	if (log_id == MAIN_LOG) {
		pi->log_tail = new_block;
		nova_flush_buffer(&pi->log_tail, CACHELINE_SIZE, 0);
		pi->log_head = new_block;
		sih->log_head = sih->log_tail = new_block;
		sih->log_pages = 1;
		nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);
	} else {
		pi->alter_log_tail = new_block;
		nova_flush_buffer(&pi->alter_log_tail, CACHELINE_SIZE, 0);
		pi->alter_log_head = new_block;
		sih->alter_log_head = sih->alter_log_tail = new_block;
		sih->log_pages++;
		nova_flush_buffer(&pi->alter_log_head, CACHELINE_SIZE, 1);
	}
	nova_update_inode_checksum(pi);
	nova_memlock_inode(sb, pi);

	return 0;
}

/*
 * Extend the log.  If the log is less than EXTEND_THRESHOLD pages, double its
 * allocated size.  Otherwise, increase by EXTEND_THRESHOLD. Then, do GC.
 */
static u64 nova_extend_inode_log(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih, u64 curr_p)
{
	u64 new_block, alter_new_block = 0;
	int allocated;
	unsigned long num_pages;
	int ret;

	nova_dbgv("%s: inode %lu, curr 0x%llx\n", __func__, sih->ino, curr_p);

	if (curr_p == 0) {
		ret = nova_initialize_inode_log(sb, pi, sih, MAIN_LOG);
		if (ret)
			return 0;

		if (metadata_csum) {
			ret = nova_initialize_inode_log(sb, pi, sih, ALTER_LOG);
			if (ret)
				return 0;

			nova_memunlock_inode(sb, pi);
			nova_update_alter_pages(sb, pi, sih->log_head,
							sih->alter_log_head);
			nova_memlock_inode(sb, pi);
		}

		return sih->log_head;
	}

	num_pages = sih->log_pages >= EXTEND_THRESHOLD ?
				EXTEND_THRESHOLD : sih->log_pages;
//	nova_dbg("Before append log pages:\n");
//	nova_print_inode_log_page(sb, inode);
	allocated = nova_allocate_inode_log_pages(sb, sih,
					num_pages, &new_block, ANY_CPU, 0);
	nova_dbg_verbose("Link block %llu to block %llu\n",
					curr_p >> PAGE_SHIFT,
					new_block >> PAGE_SHIFT);
	if (allocated <= 0) {
		nova_err(sb, "%s ERROR: no inode log page available\n",
					__func__);
		nova_dbg("curr_p 0x%llx, %lu pages\n", curr_p,
					sih->log_pages);
		return 0;
	}

	if (metadata_csum) {
		allocated = nova_allocate_inode_log_pages(sb, sih,
				num_pages, &alter_new_block, ANY_CPU, 1);
		if (allocated <= 0) {
			nova_err(sb, "%s ERROR: no inode log page available\n",
					__func__);
			nova_dbg("curr_p 0x%llx, %lu pages\n", curr_p,
					sih->log_pages);
			return 0;
		}

		nova_memunlock_inode(sb, pi);
		nova_update_alter_pages(sb, pi, new_block, alter_new_block);
		nova_memlock_inode(sb, pi);
	}


	nova_inode_log_fast_gc(sb, pi, sih, curr_p,
			       new_block, alter_new_block, allocated, 0);

//	nova_dbg("After append log pages:\n");
//	nova_print_inode_log_page(sb, inode);
	/* Atomic switch to new log */
//	nova_switch_to_new_log(sb, pi, new_block, num_pages);

	return new_block;
}

/* For thorough GC, simply append one more page */
static u64 nova_append_one_log_page(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 curr_p)
{
	struct nova_inode_log_page *curr_page;
	u64 new_block;
	u64 curr_block;
	int allocated;

	allocated = nova_allocate_inode_log_pages(sb, sih, 1, &new_block,
							ANY_CPU, 0);
	if (allocated != 1) {
		nova_err(sb, "%s: ERROR: no inode log page available\n",
				__func__);
		return 0;
	}

	if (curr_p == 0) {
		curr_p = new_block;
	} else {
		/* Link prev block and newly allocated head block */
		curr_block = BLOCK_OFF(curr_p);
		curr_page = (struct nova_inode_log_page *)
				nova_get_block(sb, curr_block);
		nova_memunlock_block(sb, curr_page);
		nova_set_next_page_address(sb, curr_page, new_block, 1);
		nova_memlock_block(sb, curr_page);
	}

	return curr_p;
}

u64 nova_get_append_head(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih, u64 tail, size_t size, int log_id,
	int thorough_gc, int *extended)
{
	u64 curr_p;

	if (tail)
		curr_p = tail;
	else if (log_id == MAIN_LOG)
		curr_p = sih->log_tail;
	else
		curr_p = sih->alter_log_tail;

	if (curr_p == 0 || (is_last_entry(curr_p, size) &&
				next_log_page(sb, curr_p) == 0)) {
		if (is_last_entry(curr_p, size)) {
			nova_memunlock_block(sb, nova_get_block(sb, curr_p));
			nova_set_next_page_flag(sb, curr_p);
			nova_memlock_block(sb, nova_get_block(sb, curr_p));
		}

		/* Alternate log should not go here */
		if (log_id != MAIN_LOG)
			return 0;

		if (thorough_gc == 0) {
			curr_p = nova_extend_inode_log(sb, pi, sih, curr_p);
		} else {
			curr_p = nova_append_one_log_page(sb, sih, curr_p);
			/* For thorough GC */
			*extended = 1;
		}

		if (curr_p == 0)
			return 0;
	}

	if (is_last_entry(curr_p, size)) {
		nova_memunlock_block(sb, nova_get_block(sb, curr_p));
		nova_set_next_page_flag(sb, curr_p);
		nova_memlock_block(sb, nova_get_block(sb, curr_p));
		curr_p = next_log_page(sb, curr_p);
	}

	return curr_p;
}

int nova_free_contiguous_log_blocks(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 head)
{
	unsigned long blocknr, start_blocknr = 0;
	u64 curr_block = head;
	u8 btype = sih->i_blk_type;
	int num_free = 0;
	int freed = 0;

	while (curr_block > 0) {
		if (ENTRY_LOC(curr_block)) {
			nova_dbg("%s: ERROR: invalid block %llu\n",
					__func__, curr_block);
			break;
		}

		blocknr = nova_get_blocknr(sb, le64_to_cpu(curr_block),
				    btype);
		nova_dbg_verbose("%s: free page %llu\n", __func__, curr_block);
		curr_block = next_log_page(sb, curr_block);

		if (start_blocknr == 0) {
			start_blocknr = blocknr;
			num_free = 1;
		} else {
			if (blocknr == start_blocknr + num_free) {
				num_free++;
			} else {
				/* A new start */
				nova_free_log_blocks(sb, sih, start_blocknr,
							num_free);
				freed += num_free;
				start_blocknr = blocknr;
				num_free = 1;
			}
		}
	}
	if (start_blocknr) {
		nova_free_log_blocks(sb, sih, start_blocknr, num_free);
		freed += num_free;
	}

	return freed;
}

int nova_free_inode_log(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih)
{
	struct nova_inode *alter_pi;
	int freed = 0;
	INIT_TIMING(free_time);

	if (sih->log_head == 0 || sih->log_tail == 0)
		return 0;

	NOVA_START_TIMING(free_inode_log_t, free_time);

	/* The inode is invalid now, no need to fence */
	if (pi) {
		nova_memunlock_inode(sb, pi);
		pi->log_head = pi->log_tail = 0;
		pi->alter_log_head = pi->alter_log_tail = 0;
		nova_update_inode_checksum(pi);
		if (metadata_csum) {
			alter_pi = (struct nova_inode *)nova_get_block(sb,
						sih->alter_pi_addr);
			if (alter_pi) {
				memcpy_to_pmem_nocache(alter_pi, pi,
						sizeof(struct nova_inode));
			}
		}
		nova_flush_buffer(pi, sizeof(struct nova_inode), 0); 
		nova_memlock_inode(sb, pi);
	}

	freed = nova_free_contiguous_log_blocks(sb, sih, sih->log_head);
	if (metadata_csum)
		freed += nova_free_contiguous_log_blocks(sb, sih,
					sih->alter_log_head);

	NOVA_END_TIMING(free_inode_log_t, free_time);
	return 0;
}
