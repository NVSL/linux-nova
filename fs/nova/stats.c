/*
 * NOVA File System statistics
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
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

#include "nova.h"

const char *Timingstring[TIMING_NUM] = {
	/* Init */
	"================ Initialization ================",
	"init",
	"mount",
	"ioremap",
	"new_init",
	"recovery",

	/* Namei operations */
	"============= Directory operations =============",
	"create",
	"lookup",
	"link",
	"unlink",
	"symlink",
	"mkdir",
	"rmdir",
	"mknod",
	"rename",
	"readdir",
	"add_dentry",
	"remove_dentry",
	"setattr",
	"setsize",

	/* I/O operations */
	"================ I/O operations ================",
	"dax_read",
	"do_cow_write",
	"cow_write",
	"inplace_write",
	"copy_to_nvmm",
	"dax_get_block",
	"read_iter",
	"write_iter",
	"wrap_iter",

	/* Memory operations */
	"============== Memory operations ===============",
	"memcpy_read_nvmm",
	"memcpy_write_nvmm",
	"memcpy_write_back_to_nvmm",
	"handle_partial_block",

	/* Memory management */
	"============== Memory management ===============",
	"alloc_blocks",
	"new_data_blocks",
	"new_log_blocks",
	"free_blocks",
	"free_data_blocks",
	"free_log_blocks",

	/* Transaction */
	"================= Transaction ==================",
	"transaction_new_inode",
	"transaction_link_change",
	"update_tail",

	/* Logging */
	"============= Logging operations ===============",
	"append_dir_entry",
	"append_file_entry",
	"append_mmap_entry",
	"append_link_change",
	"append_setattr",
	"append_snapshot_info",
	"inplace_update_entry",

	/* Tree */
	"=============== Tree operations ================",
	"checking_entry",
	"assign_blocks",

	/* GC */
	"============= Garbage collection ===============",
	"log_fast_gc",
	"log_thorough_gc",
	"check_invalid_log",

	/* Integrity */
	"============ Integrity operations ==============",
	"block_csum",
	"block_parity",
	"block_csum_parity",
	"protect_memcpy",
	"protect_file_data",
	"verify_entry_csum",
	"verify_data_csum",
	"calc_entry_csum",
	"restore_file_data",
	"reset_mapping",
	"reset_vma",

	/* Others */
	"================ Miscellaneous =================",
	"find_cache_page",
	"fsync",
	"write_pages",
	"fallocate",
	"direct_IO",
	"free_old_entry",
	"delete_file_tree",
	"delete_dir_tree",
	"new_vfs_inode",
	"new_nova_inode",
	"free_inode",
	"free_inode_log",
	"evict_inode",
	"test_perf",
	"wprotect",

	/* Mmap */
	"=============== MMap operations ================",
	"mmap_page_fault",
	"mmap_pmd_fault",
	"mmap_pfn_mkwrite",
	"insert_vma",
	"remove_vma",
	"set_vma_readonly",
	"mmap_cow",
	"udpate_mapping",
	"udpate_pfn",
	"mmap_handler",

	/* Rebuild */
	"=================== Rebuild ====================",
	"rebuild_dir",
	"rebuild_file",
	"rebuild_snapshot_table",

	/* Snapshot */
	"=================== Snapshot ===================",
	"create_snapshot",
	"init_snapshot_info",
	"delete_snapshot",
	"append_snapshot_filedata",
	"append_snapshot_inode",

	/* Tiering */
	"=================== Tiering ====================",
	"migrate_a_file",
	"update_sih_tier",
	"unlink_inode_lru_list",
	"pop_a_file",

	/* VPMEM */
	"==================== VPMEM =====================",
	"pgcache_insert",
	"pgcache_lookup",
	"pgcache_evict",
	"pgcache_range",

	/* BDEV */
	"===================== BDEV =====================",
	"bdev_read",
	"bdev_read_range",
	"bdev_write_range",
};

u64 Timingstats[TIMING_NUM];
DEFINE_PER_CPU(u64[TIMING_NUM], Timingstats_percpu);
u64 Countstats[TIMING_NUM];
DEFINE_PER_CPU(u64[TIMING_NUM], Countstats_percpu);
u64 IOstats[STATS_NUM];
DEFINE_PER_CPU(u64[STATS_NUM], IOstats_percpu);

static void nova_print_alloc_stats(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	unsigned long alloc_log_count = 0;
	unsigned long alloc_log_pages = 0;
	unsigned long alloc_data_count = 0;
	unsigned long alloc_data_pages = 0;
	unsigned long free_log_count = 0;
	unsigned long freed_log_pages = 0;
	unsigned long free_data_count = 0;
	unsigned long freed_data_pages = 0;
	int i;

	nova_info("=========== NOVA allocation stats ===========\n");
	nova_info("Alloc %llu, alloc steps %llu, average %llu\n",
		Countstats[new_data_blocks_t], IOstats[alloc_steps],
		Countstats[new_data_blocks_t] ?
			IOstats[alloc_steps] / Countstats[new_data_blocks_t]
			: 0);
	nova_info("Free %llu\n", Countstats[free_data_t]);
	nova_info("Fast GC %llu, check pages %llu, free pages %llu, average %llu\n",
		Countstats[fast_gc_t], IOstats[fast_checked_pages],
		IOstats[fast_gc_pages], Countstats[fast_gc_t] ?
			IOstats[fast_gc_pages] / Countstats[fast_gc_t] : 0);
	nova_info("Thorough GC %llu, checked pages %llu, free pages %llu, average %llu\n",
		Countstats[thorough_gc_t],
		IOstats[thorough_checked_pages], IOstats[thorough_gc_pages],
		Countstats[thorough_gc_t] ?
			IOstats[thorough_gc_pages] / Countstats[thorough_gc_t]
			: 0);

	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);

		alloc_log_count += free_list->alloc_log_count;
		alloc_log_pages += free_list->alloc_log_pages;
		alloc_data_count += free_list->alloc_data_count;
		alloc_data_pages += free_list->alloc_data_pages;
		free_log_count += free_list->free_log_count;
		freed_log_pages += free_list->freed_log_pages;
		free_data_count += free_list->free_data_count;
		freed_data_pages += free_list->freed_data_pages;
	}

	nova_info("alloc log count %lu, allocated log pages %lu, alloc data count %lu, allocated data pages %lu, free log count %lu, freed log pages %lu, free data count %lu, freed data pages %lu\n",
		alloc_log_count, alloc_log_pages,
		alloc_data_count, alloc_data_pages,
		free_log_count, freed_log_pages,
		free_data_count, freed_data_pages);
}

static void nova_print_IO_stats(struct super_block *sb)
{
	nova_info("=========== NOVA I/O stats ===========\n");
	nova_info("Read %llu, bytes %llu, average %llu\n",
		Countstats[dax_read_t], IOstats[read_bytes],
		Countstats[dax_read_t] ?
			IOstats[read_bytes] / Countstats[dax_read_t] : 0);
	nova_info("COW write %llu, bytes %llu, average %llu, write breaks %llu, average %llu\n",
		Countstats[do_cow_write_t], IOstats[cow_write_bytes],
		Countstats[do_cow_write_t] ?
			IOstats[cow_write_bytes] / Countstats[do_cow_write_t] : 0,
		IOstats[cow_write_breaks], Countstats[do_cow_write_t] ?
			IOstats[cow_write_breaks] / Countstats[do_cow_write_t]
			: 0);
	nova_info("Inplace write %llu, bytes %llu, average %llu, write breaks %llu, average %llu\n",
		Countstats[inplace_write_t], IOstats[inplace_write_bytes],
		Countstats[inplace_write_t] ?
			IOstats[inplace_write_bytes] /
			Countstats[inplace_write_t] : 0,
		IOstats[inplace_write_breaks], Countstats[inplace_write_t] ?
			IOstats[inplace_write_breaks] /
			Countstats[inplace_write_t] : 0);
}

void nova_get_timing_stats(void)
{
	int i;
	int cpu;

	for (i = 0; i < TIMING_NUM; i++) {
		Timingstats[i] = 0;
		Countstats[i] = 0;
		for_each_possible_cpu(cpu) {
			Timingstats[i] += per_cpu(Timingstats_percpu[i], cpu);
			Countstats[i] += per_cpu(Countstats_percpu[i], cpu);
		}
	}
}

void nova_get_IO_stats(void)
{
	int i;
	int cpu;

	for (i = 0; i < STATS_NUM; i++) {
		IOstats[i] = 0;
		for_each_possible_cpu(cpu)
			IOstats[i] += per_cpu(IOstats_percpu[i], cpu);
	}
}

void nova_print_timing_stats(struct super_block *sb)
{
	int i;

	nova_get_timing_stats();
	nova_get_IO_stats();

	nova_info("=========== NOVA kernel timing stats ============\n");
	for (i = 0; i < TIMING_NUM; i++) {
		/* Title */
		if (Timingstring[i][0] == '=') {
			nova_info("\n%s\n\n", Timingstring[i]);
			continue;
		}

		if (measure_timing || Timingstats[i]) {
			nova_info("%s: count %llu, timing %llu, average %llu\n",
				Timingstring[i],
				Countstats[i],
				Timingstats[i],
				Countstats[i] ?
				Timingstats[i] / Countstats[i] : 0);
		} else {
			nova_info("%s: count %llu\n",
				Timingstring[i],
				Countstats[i]);
		}
	}

	nova_info("\n");
	nova_print_alloc_stats(sb);
	nova_print_IO_stats(sb);
}

static void nova_clear_timing_stats(void)
{
	int i;
	int cpu;

	for (i = 0; i < TIMING_NUM; i++) {
		Countstats[i] = 0;
		Timingstats[i] = 0;
		for_each_possible_cpu(cpu) {
			per_cpu(Timingstats_percpu[i], cpu) = 0;
			per_cpu(Countstats_percpu[i], cpu) = 0;
		}
	}
}

static void nova_clear_IO_stats(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	int i;
	int cpu;

	for (i = 0; i < STATS_NUM; i++) {
		IOstats[i] = 0;
		for_each_possible_cpu(cpu)
			per_cpu(IOstats_percpu[i], cpu) = 0;
	}

	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);

		free_list->alloc_log_count = 0;
		free_list->alloc_log_pages = 0;
		free_list->alloc_data_count = 0;
		free_list->alloc_data_pages = 0;
		free_list->free_log_count = 0;
		free_list->freed_log_pages = 0;
		free_list->free_data_count = 0;
		free_list->freed_data_pages = 0;
	}
}

void nova_clear_stats(struct super_block *sb)
{
	nova_clear_timing_stats();
	nova_clear_IO_stats(sb);
}

void nova_print_inode(struct nova_inode *pi)
{
	nova_dbg("%s: NOVA inode %llu\n", __func__, pi->nova_ino);
	nova_dbg("valid %u, deleted %u, blk type %u, flags %u\n",
		pi->valid, pi->deleted, pi->i_blk_type, pi->i_flags);
	nova_dbg("size %llu, ctime %u, mtime %u, atime %u\n",
		pi->i_size, pi->i_ctime, pi->i_mtime, pi->i_atime);
	nova_dbg("mode %u, links %u, xattr 0x%llx, csum %u\n",
		pi->i_mode, pi->i_links_count, pi->i_xattr, pi->csum);
	nova_dbg("uid %u, gid %u, gen %u, create time %u\n",
		pi->i_uid, pi->i_gid, pi->i_generation, pi->i_create_time);
	nova_dbg("head 0x%llx, tail 0x%llx, alter head 0x%llx, tail 0x%llx\n",
		pi->log_head, pi->log_tail, pi->alter_log_head,
		pi->alter_log_tail);
	nova_dbg("create epoch id %llu, delete epoch id %llu\n",
		pi->create_epoch_id, pi->delete_epoch_id);
}

static inline void nova_print_file_write_entry(struct super_block *sb,
	u64 curr, struct nova_file_write_entry *entry)
{
	nova_dbg("file write entry @ 0x%llx: epoch %llu, trans %llu, pgoff %llu, pages %u, blocknr %llu, reassigned %u, updating %u, invalid count %u, size %llu, mtime %u\n",
			curr, entry->epoch_id, entry->trans_id,
			entry->pgoff, entry->num_pages,
			entry->block >> PAGE_SHIFT,
			entry->reassigned, entry->updating,
			entry->invalid_pages, entry->size, entry->mtime);
}

static inline void nova_print_set_attr_entry(struct super_block *sb,
	u64 curr, struct nova_setattr_logentry *entry)
{
	nova_dbg("set attr entry @ 0x%llx: epoch %llu, trans %llu, invalid %u, mode %u, size %llu, atime %u, mtime %u, ctime %u\n",
			curr, entry->epoch_id, entry->trans_id,
			entry->invalid, entry->mode,
			entry->size, entry->atime, entry->mtime, entry->ctime);
}

static inline void nova_print_link_change_entry(struct super_block *sb,
	u64 curr, struct nova_link_change_entry *entry)
{
	nova_dbg("link change entry @ 0x%llx: epoch %llu, trans %llu, invalid %u, links %u, flags %u, ctime %u\n",
			curr, entry->epoch_id, entry->trans_id,
			entry->invalid, entry->links,
			entry->flags, entry->ctime);
}

static inline void nova_print_mmap_entry(struct super_block *sb,
	u64 curr, struct nova_mmap_entry *entry)
{
	nova_dbg("mmap write entry @ 0x%llx: epoch %llu, invalid %u, pgoff %llu, pages %llu\n",
			curr, entry->epoch_id, entry->invalid,
			entry->pgoff, entry->num_pages);
}

static inline void nova_print_snapshot_info_entry(struct super_block *sb,
	u64 curr, struct nova_snapshot_info_entry *entry)
{
	nova_dbg("snapshot info entry @ 0x%llx: epoch %llu, deleted %u, timestamp %llu\n",
			curr, entry->epoch_id, entry->deleted,
			entry->timestamp);
}

static inline size_t nova_print_dentry(struct super_block *sb,
	u64 curr, struct nova_dentry *entry)
{
	nova_dbg("dir logentry @ 0x%llx: epoch %llu, trans %llu, reassigned %u, invalid %u, inode %llu, links %u, namelen %u, rec len %u, name %s, mtime %u\n",
			curr, entry->epoch_id, entry->trans_id,
			entry->reassigned, entry->invalid,
			le64_to_cpu(entry->ino),
			entry->links_count, entry->name_len,
			le16_to_cpu(entry->de_len), entry->name,
			entry->mtime);

	return le16_to_cpu(entry->de_len);
}

u64 nova_print_log_entry(struct super_block *sb, u64 curr)
{
	void *addr;
	size_t size;
	u8 type;

	addr = (void *)nova_get_block(sb, curr);
	type = nova_get_entry_type(addr);
	switch (type) {
	case SET_ATTR:
		nova_print_set_attr_entry(sb, curr, addr);
		curr += sizeof(struct nova_setattr_logentry);
		break;
	case LINK_CHANGE:
		nova_print_link_change_entry(sb, curr, addr);
		curr += sizeof(struct nova_link_change_entry);
		break;
	case MMAP_WRITE:
		nova_print_mmap_entry(sb, curr, addr);
		curr += sizeof(struct nova_mmap_entry);
		break;
	case SNAPSHOT_INFO:
		nova_print_snapshot_info_entry(sb, curr, addr);
		curr += sizeof(struct nova_snapshot_info_entry);
		break;
	case FILE_WRITE:
		nova_print_file_write_entry(sb, curr, addr);
		curr += sizeof(struct nova_file_write_entry);
		break;
	case DIR_LOG:
		size = nova_print_dentry(sb, curr, addr);
		curr += size;
		if (size == 0) {
			nova_dbg("%s: dentry with size 0 @ 0x%llx\n",
					__func__, curr);
			curr += sizeof(struct nova_file_write_entry);
			NOVA_ASSERT(0);
		}
		break;
	case NEXT_PAGE:
		nova_dbg("%s: next page sign @ 0x%llx\n", __func__, curr);
		curr = PAGE_TAIL(curr);
		break;
	default:
		nova_dbg("%s: unknown type %d, 0x%llx\n", __func__, type, curr);
		curr = 0;
		NOVA_ASSERT(0);
		break;
	}

	return curr;
}

void nova_print_curr_log_page(struct super_block *sb, u64 curr)
{
	struct nova_inode_page_tail *tail;
	u64 start, end;

	start = BLOCK_OFF(curr);
	end = PAGE_TAIL(curr);

	while (start < end && start != 0)
		start = nova_print_log_entry(sb, start);

	tail = nova_get_block(sb, end);
	nova_dbg("Page tail. curr 0x%llx, next page 0x%llx, %u entries, %u invalid\n",
			start, tail->next_page,
			tail->num_entries, tail->invalid_entries);
}

void nova_print_nova_log(struct super_block *sb,
	struct nova_inode_info_header *sih)
{
	u64 curr;

	if (sih->log_tail == 0 || sih->log_head == 0)
		return;

	curr = sih->log_head;
	nova_dbg("Pi %lu: log head 0x%llx, tail 0x%llx\n",
			sih->ino, curr, sih->log_tail);

	if (sih->ino != NOVA_ROOT_INO && sih->ino < NOVA_NORMAL_INODE_START) {
		nova_dbg("Special inode, return\n");
		return;
	}

	while (curr != sih->log_tail) {
		if ((curr & (PAGE_SIZE - 1)) == LOG_BLOCK_TAIL) {
			struct nova_inode_page_tail *tail =
					nova_get_block(sb, curr);
			nova_dbg("Log tail, curr 0x%llx, next page 0x%llx, %u entries, %u invalid\n",
					curr, tail->next_page,
					tail->num_entries,
					tail->invalid_entries);
			curr = tail->next_page;
		} else {
			curr = nova_print_log_entry(sb, curr);
		}
		if (curr == 0)
			break;
	}
}

void nova_print_inode_log(struct super_block *sb, struct inode *inode)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;

	nova_print_nova_log(sb, sih);
}

int nova_get_nova_log_pages(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_inode *pi)
{
	struct nova_inode_log_page *curr_page;
	u64 curr, next;
	int count = 1;

	if (pi->log_head == 0 || pi->log_tail == 0) {
		nova_dbg("Pi %lu has no log\n", sih->ino);
		return 0;
	}

	curr = pi->log_head;
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr);
	while ((next = curr_page->page_tail.next_page) != 0) {
		curr = next;
		curr_page = (struct nova_inode_log_page *)
			nova_get_block(sb, curr);
		count++;
	}

	return count;
}

void nova_print_nova_log_pages(struct super_block *sb,
	struct nova_inode_info_header *sih)
{
	struct nova_inode_log_page *curr_page;
	u64 curr, next;
	int count = 1;
	int used = count;

	if (sih->log_head == 0 || sih->log_tail == 0) {
		nova_dbg("Pi %lu has no log\n", sih->ino);
		return;
	}

	curr = sih->log_head;
	nova_dbg("Pi %lu: log head @ 0x%llx, tail @ 0x%llx\n",
			sih->ino, curr, sih->log_tail);
	curr_page = (struct nova_inode_log_page *)nova_get_block(sb, curr);
	while ((next = curr_page->page_tail.next_page) != 0) {
		nova_dbg("Current page 0x%llx, next page 0x%llx, %u entries, %u invalid\n",
			curr >> PAGE_SHIFT, next >> PAGE_SHIFT,
			curr_page->page_tail.num_entries,
			curr_page->page_tail.invalid_entries);
		if (sih->log_tail >> PAGE_SHIFT == curr >> PAGE_SHIFT)
			used = count;
		curr = next;
		curr_page = (struct nova_inode_log_page *)
			nova_get_block(sb, curr);
		count++;
	}
	if (sih->log_tail >> PAGE_SHIFT == curr >> PAGE_SHIFT)
		used = count;
	nova_dbg("Pi %lu: log used %d pages, has %d pages, si reports %lu pages\n",
		sih->ino, used, count,
		sih->log_pages);
}

void nova_print_inode_log_pages(struct super_block *sb, struct inode *inode)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;

	nova_print_nova_log_pages(sb, sih);
}

int nova_check_inode_logs(struct super_block *sb, struct nova_inode *pi)
{
	int count1 = 0;
	int count2 = 0;
	int tail1_at = 0;
	int tail2_at = 0;
	u64 curr, alter_curr;

	curr = pi->log_head;
	alter_curr = pi->alter_log_head;

	while (curr && alter_curr) {
		if (alter_log_page(sb, curr) != alter_curr ||
				alter_log_page(sb, alter_curr) != curr)
			nova_dbg("Inode %llu page %d: curr 0x%llx, alter 0x%llx, alter_curr 0x%llx, alter 0x%llx\n",
					pi->nova_ino, count1,
					curr, alter_log_page(sb, curr),
					alter_curr,
					alter_log_page(sb, alter_curr));

		count1++;
		count2++;
		if ((curr >> PAGE_SHIFT) == (pi->log_tail >> PAGE_SHIFT))
			tail1_at = count1;
		if ((alter_curr >> PAGE_SHIFT) ==
				(pi->alter_log_tail >> PAGE_SHIFT))
			tail2_at = count2;
		curr = next_log_page(sb, curr);
		alter_curr = next_log_page(sb, alter_curr);
	}

	while (curr) {
		count1++;
		if ((curr >> PAGE_SHIFT) == (pi->log_tail >> PAGE_SHIFT))
			tail1_at = count1;
		curr = next_log_page(sb, curr);
	}

	while (alter_curr) {
		count2++;
		if ((alter_curr >> PAGE_SHIFT) ==
				(pi->alter_log_tail >> PAGE_SHIFT))
			tail2_at = count2;
		alter_curr = next_log_page(sb, alter_curr);
	}

	nova_dbg("Log1 %d pages, tail @ page %d\n", count1, tail1_at);
	nova_dbg("Log2 %d pages, tail @ page %d\n", count2, tail2_at);

	return 0;
}

void nova_print_free_lists(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	int i;

	nova_dbg("======== NOVA per-CPU free list allocation stats ========\n");
	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		nova_dbg("Free list %d: block start %lu, block end %lu, num_blocks %lu, num_free_blocks %lu, blocknode %lu\n",
			i, free_list->block_start, free_list->block_end,
			free_list->block_end - free_list->block_start + 1,
			free_list->num_free_blocks, free_list->num_blocknode);

		nova_dbg("Free list %d: csum start %lu, replica csum start %lu, csum blocks %lu, parity start %lu, parity blocks %lu\n",
			i, free_list->csum_start, free_list->replica_csum_start,
			free_list->num_csum_blocks,
			free_list->parity_start, free_list->num_parity_blocks);

		nova_dbg("Free list %d: alloc log count %lu, allocated log pages %lu, alloc data count %lu, allocated data pages %lu, free log count %lu, freed log pages %lu, free data count %lu, freed data pages %lu\n",
			 i,
			 free_list->alloc_log_count,
			 free_list->alloc_log_pages,
			 free_list->alloc_data_count,
			 free_list->alloc_data_pages,
			 free_list->free_log_count,
			 free_list->freed_log_pages,
			 free_list->free_data_count,
			 free_list->freed_data_pages);
	}
}
