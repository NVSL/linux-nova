/*
 * BRIEF DESCRIPTION
 *
 * Garbage collection methods
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
#include "inode.h"

static bool curr_log_entry_invalid(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	u64 curr_p, size_t *length)
{
	struct nova_file_write_entry *entry;
	struct nova_dentry *dentry;
	struct nova_setattr_logentry *setattr_entry;
	struct nova_link_change_entry *linkc_entry;
	struct nova_mmap_entry *mmap_entry;
	struct nova_snapshot_info_entry *sn_entry;
	char entry_copy[NOVA_MAX_ENTRY_LEN];
	void *addr, *entryc;
	u8 type;
	bool ret = true;

	addr = (void *)nova_get_block(sb, curr_p);

	/* FIXME: this check might hurt performance for workloads that
	 * frequently invokes gc
	 */
	if (metadata_csum == 0)
		entryc = addr;
	else {
		entryc = entry_copy;
		if (!nova_verify_entry_csum(sb, addr, entryc))
			return true;
	}

	type = nova_get_entry_type(entryc);
	switch (type) {
	case SET_ATTR:
		setattr_entry = (struct nova_setattr_logentry *) entryc;
		if (setattr_entry->invalid == 0)
			ret = false;
		*length = sizeof(struct nova_setattr_logentry);
		break;
	case LINK_CHANGE:
		linkc_entry = (struct nova_link_change_entry *) entryc;
		if (linkc_entry->invalid == 0)
			ret = false;
		*length = sizeof(struct nova_link_change_entry);
		break;
	case FILE_WRITE:
		entry = (struct nova_file_write_entry *) entryc;
		if (entry->num_pages != entry->invalid_pages)
			ret = false;
		*length = sizeof(struct nova_file_write_entry);
		break;
	case DIR_LOG:
		dentry = (struct nova_dentry *) entryc;
		if (dentry->invalid == 0)
			ret = false;
		if (sih->last_dentry == curr_p)
			ret = false;
		*length = le16_to_cpu(dentry->de_len);
		break;
	case MMAP_WRITE:
		mmap_entry = (struct nova_mmap_entry *) entryc;
		if (mmap_entry->invalid == 0)
			ret = false;
		*length = sizeof(struct nova_mmap_entry);
		break;
	case SNAPSHOT_INFO:
		sn_entry = (struct nova_snapshot_info_entry *) entryc;
		if (sn_entry->deleted == 0)
			ret = false;
		*length = sizeof(struct nova_snapshot_info_entry);
		break;
	case NEXT_PAGE:
		/* No more entries in this page */
		*length = PAGE_SIZE - ENTRY_LOC(curr_p);
		break;
	default:
		nova_dbg("%s: unknown type %d, 0x%llx\n",
					__func__, type, curr_p);
		NOVA_ASSERT(0);
		*length = PAGE_SIZE - ENTRY_LOC(curr_p);
		break;
	}

	return ret;
}

static bool curr_page_invalid(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	u64 page_head)
{
	struct nova_inode_log_page *curr_page;
	struct nova_inode_page_tail page_tail;
	unsigned int num_entries;
	unsigned int invalid_entries;
	bool ret;
	INIT_TIMING(check_time);
	int rc;

	NOVA_START_TIMING(check_invalid_t, check_time);

	curr_page = (struct nova_inode_log_page *)
					nova_get_block(sb, page_head);
	rc = memcpy_mcsafe(&page_tail, &curr_page->page_tail,
					sizeof(struct nova_inode_page_tail));
	if (rc) {
		/* FIXME: Recover use replica log */
		nova_err(sb, "check page failed\n");
		return false;
	}

	num_entries = le32_to_cpu(page_tail.num_entries);
	invalid_entries = le32_to_cpu(page_tail.invalid_entries);

	ret = (invalid_entries == num_entries);
	if (!ret) {
		sih->num_entries += num_entries;
		sih->valid_entries += num_entries - invalid_entries;
	}

	NOVA_END_TIMING(check_invalid_t, check_time);
	return ret;
}

static void free_curr_page(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_inode_log_page *curr_page,
	struct nova_inode_log_page *last_page, u64 curr_head)
{
	u8 btype = sih->i_blk_type;
	unsigned long irq_flags = 0;

	nova_memunlock_block(sb, last_page, &irq_flags);
	nova_set_next_page_address(sb, last_page,
			curr_page->page_tail.next_page, 1);
	nova_memlock_block(sb, last_page, &irq_flags);
	nova_free_log_blocks(sb, sih,
			nova_get_blocknr(sb, curr_head, btype), 1);
}

static int nova_gc_assign_file_entry(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *old_entry,
	struct nova_file_write_entry *new_entry)
{
	struct nova_file_write_entry *temp;
	void **pentry;
	unsigned long start_pgoff = old_entry->pgoff;
	unsigned int num = old_entry->num_pages;
	unsigned long curr_pgoff;
	int i;
	int ret = 0;

	for (i = 0; i < num; i++) {
		curr_pgoff = start_pgoff + i;

		pentry = radix_tree_lookup_slot(&sih->tree, curr_pgoff);
		if (pentry) {
			temp = radix_tree_deref_slot(pentry);
			if (temp == old_entry)
				radix_tree_replace_slot(&sih->tree, pentry,
							new_entry);
		}
	}

	return ret;
}

static int nova_gc_assign_dentry(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_dentry *old_dentry,
	struct nova_dentry *new_dentry)
{
	struct nova_range_node *ret_node = NULL;
	unsigned long hash;
	int found = 0;
	int ret = 0;

	hash = BKDRHash(old_dentry->name, old_dentry->name_len);
	nova_dbgv("%s: assign %s hash %lu\n", __func__,
			old_dentry->name, hash);

	/* FIXME: hash collision ignored here */
	found = nova_find_range_node(&sih->rb_tree, hash,
				NODE_DIR, &ret_node);
	if (found == 1 && hash == ret_node->hash) {
		if (ret_node->direntry == old_dentry)
			ret_node->direntry = new_dentry;
	}

	return ret;
}

static int nova_gc_assign_mmap_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 curr_p, u64 new_curr)
{
	struct vma_item *item;
	struct rb_node *temp;
	int ret = 0;

	if (sih->num_vmas == 0)
		return ret;

	temp = rb_first(&sih->vma_tree);
	while (temp) {
		item = container_of(temp, struct vma_item, node);
		temp = rb_next(temp);
		if (item->mmap_entry == curr_p) {
			item->mmap_entry = new_curr;
			break;
		}
	}

	return ret;
}

static int nova_gc_assign_snapshot_entry(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_snapshot_info_entry *old_entry, u64 curr_p, u64 new_curr)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct snapshot_info *info;
	int ret = 0;

	info = radix_tree_lookup(&sbi->snapshot_info_tree,
				old_entry->epoch_id);

	if (info && info->snapshot_entry == curr_p)
		info->snapshot_entry = new_curr;

	return ret;
}

static int nova_gc_assign_new_entry(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	u64 curr_p, u64 new_curr)
{
	struct nova_file_write_entry *old_entry, *new_entry;
	struct nova_dentry *old_dentry, *new_dentry;
	void *addr, *new_addr;
	u8 type;
	int ret = 0;

	addr = (void *)nova_get_block(sb, curr_p);
	type = nova_get_entry_type(addr);
	switch (type) {
	case SET_ATTR:
		sih->last_setattr = new_curr;
		break;
	case LINK_CHANGE:
		sih->last_link_change = new_curr;
		break;
	case MMAP_WRITE:
		ret = nova_gc_assign_mmap_entry(sb, sih, curr_p, new_curr);
		break;
	case SNAPSHOT_INFO:
		ret = nova_gc_assign_snapshot_entry(sb, sih, addr,
						curr_p, new_curr);
		break;
	case FILE_WRITE:
		new_addr = (void *)nova_get_block(sb, new_curr);
		old_entry = (struct nova_file_write_entry *)addr;
		new_entry = (struct nova_file_write_entry *)new_addr;
		ret = nova_gc_assign_file_entry(sb, sih, old_entry, new_entry);
		break;
	case DIR_LOG:
		new_addr = (void *)nova_get_block(sb, new_curr);
		old_dentry = (struct nova_dentry *)addr;
		new_dentry = (struct nova_dentry *)new_addr;
		if (sih->last_dentry == curr_p)
			sih->last_dentry = new_curr;
		ret = nova_gc_assign_dentry(sb, sih, old_dentry, new_dentry);
		break;
	default:
		nova_dbg("%s: unknown type %d, 0x%llx\n",
					__func__, type, curr_p);
		NOVA_ASSERT(0);
		break;
	}

	return ret;
}

/* Copy live log entries to the new log and atomically replace the old log */
static unsigned long nova_inode_log_thorough_gc(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	unsigned long blocks, unsigned long checked_pages)
{
	struct nova_inode_log_page *curr_page = NULL;
	size_t length;
	struct nova_inode *alter_pi;
	u64 ino = pi->nova_ino;
	u64 curr_p, new_curr;
	u64 old_curr_p;
	u64 tail_block;
	u64 old_head;
	u64 new_head = 0;
	u64 next;
	int allocated;
	int extended = 0;
	int ret;
	unsigned long irq_flags = 0;
	INIT_TIMING(gc_time);

	NOVA_START_TIMING(thorough_gc_t, gc_time);

	curr_p = sih->log_head;
	old_curr_p = curr_p;
	old_head = sih->log_head;
	nova_dbg_verbose("Log head 0x%llx, tail 0x%llx\n",
				curr_p, sih->log_tail);
	if (curr_p == 0 && sih->log_tail == 0)
		goto out;

	if (curr_p >> PAGE_SHIFT == sih->log_tail >> PAGE_SHIFT)
		goto out;

	allocated = nova_allocate_inode_log_pages(sb, sih, blocks,
					&new_head, ANY_CPU, 0);
	if (allocated != blocks) {
		nova_err(sb, "%s: ERROR: no inode log page available\n",
					__func__);
		goto out;
	}

	new_curr = new_head;
	while (curr_p != sih->log_tail) {
		old_curr_p = curr_p;
		if (goto_next_page(sb, curr_p))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p >> PAGE_SHIFT == sih->log_tail >> PAGE_SHIFT) {
			/* Don't recycle tail page */
			break;
		}

		if (curr_p == 0) {
			nova_err(sb, "File inode %llu log is NULL!\n", ino);
			BUG();
		}

		length = 0;
		ret = curr_log_entry_invalid(sb, pi, sih, curr_p, &length);
		if (!ret) {
			extended = 0;
			new_curr = nova_get_append_head(sb, pi, sih,
						new_curr, length, MAIN_LOG,
						1, &extended);
			if (extended)
				blocks++;
			/* Copy entry to the new log */
			nova_memunlock_block(sb, nova_get_block(sb, new_curr), &irq_flags);
			memcpy_to_pmem_nocache(nova_get_block(sb, new_curr),
				nova_get_block(sb, curr_p), length);
			nova_inc_page_num_entries(sb, new_curr);
			nova_memlock_block(sb, nova_get_block(sb, new_curr), &irq_flags);
			nova_gc_assign_new_entry(sb, pi, sih, curr_p, new_curr);
			new_curr += length;
		}

		curr_p += length;
	}

	/* Step 1: Link new log to the tail block */
	tail_block = BLOCK_OFF(sih->log_tail);
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb,
							BLOCK_OFF(new_curr));
	next = next_log_page(sb, new_curr);
	if (next > 0)
		nova_free_contiguous_log_blocks(sb, sih, next);

	nova_memunlock_block(sb, curr_page, &irq_flags);
	nova_set_next_page_flag(sb, new_curr);
	nova_set_next_page_address(sb, curr_page, tail_block, 0);
	nova_memlock_block(sb, curr_page, &irq_flags);

	/* Step 2: Atomically switch to the new log */
	nova_memunlock_inode(sb, pi, &irq_flags);
	pi->log_head = new_head;
	nova_update_inode_checksum(pi);
	if (metadata_csum && sih->alter_pi_addr) {
		alter_pi = (struct nova_inode *)nova_get_block(sb,
						sih->alter_pi_addr);
		memcpy_to_pmem_nocache(alter_pi, pi, sizeof(struct nova_inode));
	}
	nova_memlock_inode(sb, pi, &irq_flags);
	sih->log_head = new_head;

	/* Step 3: Unlink the old log */
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb,
							BLOCK_OFF(old_curr_p));
	next = next_log_page(sb, old_curr_p);
	if (next != tail_block) {
		nova_err(sb, "Old log error: old curr_p 0x%lx, next 0x%lx ",
			"curr_p 0x%lx, tail block 0x%lx\n", old_curr_p,
			next, curr_p, tail_block);
		BUG();
	}
	nova_memunlock_block(sb, curr_page, &irq_flags);
	nova_set_next_page_address(sb, curr_page, 0, 1);
	nova_memlock_block(sb, curr_page, &irq_flags);

	/* Step 4: Free the old log */
	nova_free_contiguous_log_blocks(sb, sih, old_head);

	sih->log_pages = sih->log_pages + blocks - checked_pages;
	NOVA_STATS_ADD(thorough_gc_pages, checked_pages - blocks);
	NOVA_STATS_ADD(thorough_checked_pages, checked_pages);
out:
	NOVA_END_TIMING(thorough_gc_t, gc_time);
	return blocks;
}

/* Copy original log to alternate log */
static unsigned long nova_inode_alter_log_thorough_gc(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	unsigned long blocks, unsigned long checked_pages)
{
	struct nova_inode_log_page *alter_curr_page = NULL;
	struct nova_inode *alter_pi;
	u64 ino = pi->nova_ino;
	u64 curr_p, new_curr;
	u64 alter_curr_p;
	u64 old_alter_curr_p;
	u64 alter_tail_block;
	u64 alter_old_head;
	u64 new_head = 0;
	u64 alter_next;
	int allocated;
	unsigned long irq_flags = 0;
	INIT_TIMING(gc_time);

	NOVA_START_TIMING(thorough_gc_t, gc_time);

	curr_p = sih->log_head;
	alter_old_head = sih->alter_log_head;
	nova_dbg_verbose("Log head 0x%llx, tail 0x%llx\n",
				curr_p, sih->log_tail);
	if (curr_p == 0 && sih->log_tail == 0)
		goto out;

	if (curr_p >> PAGE_SHIFT == sih->log_tail >> PAGE_SHIFT)
		goto out;

	if (alter_old_head >> PAGE_SHIFT == sih->alter_log_tail >> PAGE_SHIFT)
		goto out;

	allocated = nova_allocate_inode_log_pages(sb, sih, blocks,
					&new_head, ANY_CPU, 1);
	if (allocated != blocks) {
		nova_err(sb, "%s: ERROR: no inode log page available\n",
					__func__);
		goto out;
	}

	new_curr = new_head;
	while (1) {
		nova_memunlock_block(sb, nova_get_block(sb, new_curr), &irq_flags);
		memcpy_to_pmem_nocache(nova_get_block(sb, new_curr),
				nova_get_block(sb, curr_p), LOG_BLOCK_TAIL);

		nova_set_alter_page_address(sb, curr_p, new_curr);
		nova_memlock_block(sb, nova_get_block(sb, new_curr), &irq_flags);

		curr_p = next_log_page(sb, curr_p);

		if (curr_p >> PAGE_SHIFT == sih->log_tail >> PAGE_SHIFT) {
			/* Don't recycle tail page */
			break;
		}

		new_curr = next_log_page(sb, new_curr);

		if (curr_p == 0) {
			nova_err(sb, "File inode %llu log is NULL!\n", ino);
			BUG();
		}
	}

	/* Step 1: Link new log to the tail block */
	alter_tail_block = BLOCK_OFF(sih->alter_log_tail);
	alter_curr_page = (struct nova_inode_log_page *)nova_get_block(sb,
							BLOCK_OFF(new_curr));
	alter_next = next_log_page(sb, new_curr);
	if (alter_next > 0)
		nova_free_contiguous_log_blocks(sb, sih, alter_next);
	nova_memunlock_block(sb, alter_curr_page, &irq_flags);
	nova_set_next_page_address(sb, alter_curr_page, alter_tail_block, 0);
	nova_memlock_block(sb, alter_curr_page, &irq_flags);

	/* Step 2: Find the old log block before the tail block */
	alter_curr_p = sih->alter_log_head;
	while (1) {
		old_alter_curr_p = alter_curr_p;
		alter_curr_p = next_log_page(sb, alter_curr_p);

		if (alter_curr_p >> PAGE_SHIFT ==
				sih->alter_log_tail >> PAGE_SHIFT)
			break;

		if (alter_curr_p == 0) {
			nova_err(sb, "File inode %llu log is NULL!\n", ino);
			BUG();
		}
	}

	/* Step 3: Atomically switch to the new log */
	nova_memunlock_inode(sb, pi, &irq_flags);
	pi->alter_log_head = new_head;
	nova_update_inode_checksum(pi);
	if (metadata_csum && sih->alter_pi_addr) {
		alter_pi = (struct nova_inode *)nova_get_block(sb,
						sih->alter_pi_addr);
		memcpy_to_pmem_nocache(alter_pi, pi, sizeof(struct nova_inode));
	}
	nova_memlock_inode(sb, pi, &irq_flags);
	sih->alter_log_head = new_head;

	/* Step 4: Unlink the old log */
	alter_curr_page = (struct nova_inode_log_page *)nova_get_block(sb,
						BLOCK_OFF(old_alter_curr_p));
	alter_next = next_log_page(sb, old_alter_curr_p);
	if (alter_next != alter_tail_block) {
		nova_err(sb, "Old log error: old curr_p 0x%lx, next 0x%lx ",
			"curr_p 0x%lx, tail block 0x%lx\n", old_alter_curr_p,
			alter_next, alter_curr_p, alter_tail_block);
		BUG();
	}
	nova_memunlock_block(sb, alter_curr_page, &irq_flags);
	nova_set_next_page_address(sb, alter_curr_page, 0, 1);
	nova_memlock_block(sb, alter_curr_page, &irq_flags);

	/* Step 5: Free the old log */
	nova_free_contiguous_log_blocks(sb, sih, alter_old_head);

	sih->log_pages = sih->log_pages + blocks - checked_pages;
	NOVA_STATS_ADD(thorough_gc_pages, checked_pages - blocks);
	NOVA_STATS_ADD(thorough_checked_pages, checked_pages);
out:
	NOVA_END_TIMING(thorough_gc_t, gc_time);
	return blocks;
}

/*
 * Scan pages in the log and remove those with no valid log entries.
 */
int nova_inode_log_fast_gc(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info_header *sih,
	u64 curr_tail, u64 new_block, u64 alter_new_block,
	int num_pages, int force_thorough)
{
	struct nova_inode *alter_pi;
	u64 curr, next, possible_head = 0;
	u64 alter_curr, alter_next = 0, alter_possible_head = 0;
	int found_head = 0;
	struct nova_inode_log_page *last_page = NULL;
	struct nova_inode_log_page *curr_page = NULL;
	struct nova_inode_log_page *alter_last_page = NULL;
	struct nova_inode_log_page *alter_curr_page = NULL;
	int first_need_free = 0;
	int num_logs;
	u8 btype = sih->i_blk_type;
	unsigned long blocks;
	unsigned long checked_pages = 0;
	int freed_pages = 0;
	unsigned long irq_flags = 0;
	INIT_TIMING(gc_time);

	NOVA_START_TIMING(fast_gc_t, gc_time);
	curr = sih->log_head;
	alter_curr = sih->alter_log_head;
	sih->valid_entries = 0;
	sih->num_entries = 0;

	num_logs = 1;
	if (metadata_csum)
		num_logs = 2;

	nova_dbgv("%s: log head 0x%llx, tail 0x%llx\n",
				__func__, curr, curr_tail);
	while (1) {
		if (curr >> PAGE_SHIFT == sih->log_tail >> PAGE_SHIFT) {
			/* Don't recycle tail page */
			if (found_head == 0) {
				possible_head = cpu_to_le64(curr);
				alter_possible_head = cpu_to_le64(alter_curr);
			}
			break;
		}

		curr_page = (struct nova_inode_log_page *)
					nova_get_block(sb, curr);
		next = next_log_page(sb, curr);
		if (next < 0)
			break;

		if (metadata_csum) {
			alter_curr_page = (struct nova_inode_log_page *)
						nova_get_block(sb, alter_curr);
			alter_next = next_log_page(sb, alter_curr);
			if (alter_next < 0)
				break;
		}
		nova_dbg_verbose("curr 0x%llx, next 0x%llx\n", curr, next);
		if (curr_page_invalid(sb, pi, sih, curr)) {
			nova_dbg_verbose("curr page %p invalid\n", curr_page);
			if (curr == sih->log_head) {
				/* Free first page later */
				first_need_free = 1;
				last_page = curr_page;
				alter_last_page = alter_curr_page;
			} else {
				nova_dbg_verbose("Free log block 0x%llx\n",
						curr >> PAGE_SHIFT);
				free_curr_page(sb, sih, curr_page, last_page,
						curr);
				if (metadata_csum)
					free_curr_page(sb, sih, alter_curr_page,
						alter_last_page, alter_curr);
			}
			NOVA_STATS_ADD(fast_gc_pages, 1);
			freed_pages++;
		} else {
			if (found_head == 0) {
				possible_head = cpu_to_le64(curr);
				alter_possible_head = cpu_to_le64(alter_curr);
				found_head = 1;
			}
			last_page = curr_page;
			alter_last_page = alter_curr_page;
		}

		curr = next;
		alter_curr = alter_next;
		checked_pages++;
		if (curr == 0 || (metadata_csum && alter_curr == 0))
			break;
	}

	NOVA_STATS_ADD(fast_checked_pages, checked_pages);
	nova_dbgv("checked pages %lu, freed %d\n", checked_pages, freed_pages);
	checked_pages -= freed_pages;

	// TODO:  I think this belongs in nova_extend_inode_log.
	if (num_pages > 0) {
		curr = BLOCK_OFF(curr_tail);
		curr_page = (struct nova_inode_log_page *)
						  nova_get_block(sb, curr);

		nova_memunlock_block(sb, curr_page, &irq_flags);
		nova_set_next_page_address(sb, curr_page, new_block, 1);
		nova_memlock_block(sb, curr_page, &irq_flags);

		if (metadata_csum) {
			alter_curr = BLOCK_OFF(sih->alter_log_tail);

			while (next_log_page(sb, alter_curr) > 0)
				alter_curr = next_log_page(sb, alter_curr);

			alter_curr_page = (struct nova_inode_log_page *)
				nova_get_block(sb, alter_curr);
			nova_memunlock_block(sb, curr_page, &irq_flags);
			nova_set_next_page_address(sb, alter_curr_page,
						   alter_new_block, 1);
			nova_memlock_block(sb, curr_page, &irq_flags);
		}
	}

	curr = sih->log_head;
	alter_curr = sih->alter_log_head;

	nova_memunlock_inode(sb, pi, &irq_flags);
	pi->log_head = possible_head;
	pi->alter_log_head = alter_possible_head;
	nova_update_inode_checksum(pi);
	if (metadata_csum && sih->alter_pi_addr) {
		alter_pi = (struct nova_inode *)nova_get_block(sb,
						sih->alter_pi_addr);
		memcpy_to_pmem_nocache(alter_pi, pi, sizeof(struct nova_inode));
	}
	nova_memlock_inode(sb, pi, &irq_flags);
	sih->log_head = possible_head;
	sih->alter_log_head = alter_possible_head;
	nova_dbgv("%s: %d new head 0x%llx\n", __func__,
					found_head, possible_head);
	sih->log_pages += (num_pages - freed_pages) * num_logs;
	/* Don't update log tail pointer here */
	nova_flush_buffer(&pi->log_head, CACHELINE_SIZE, 1);

	if (first_need_free) {
		nova_dbg_verbose("Free log head block 0x%llx\n",
					curr >> PAGE_SHIFT);
		nova_free_log_blocks(sb, sih,
				nova_get_blocknr(sb, curr, btype), 1);
		if (metadata_csum)
			nova_free_log_blocks(sb, sih,
				nova_get_blocknr(sb, alter_curr, btype), 1);
	}

	NOVA_END_TIMING(fast_gc_t, gc_time);

	if (sih->num_entries == 0)
		return 0;

	/* Estimate how many pages worth of valid entries the log contains.
	 *
	 * If it is less than half the number pages that remain in the log,
	 * compress them with thorough gc.
	 */
	blocks = (sih->valid_entries * checked_pages) / sih->num_entries;
	if ((sih->valid_entries * checked_pages) % sih->num_entries)
		blocks++;

	if (force_thorough || (blocks && blocks * 2 < checked_pages)) {
		nova_dbgv("Thorough GC for inode %lu: checked pages %lu, valid pages %lu\n",
				sih->ino,
				checked_pages, blocks);
		blocks = nova_inode_log_thorough_gc(sb, pi, sih,
							blocks, checked_pages);
		if (metadata_csum)
			nova_inode_alter_log_thorough_gc(sb, pi, sih,
							blocks, checked_pages);
	}

	return 0;
}
