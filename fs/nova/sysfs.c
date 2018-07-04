/*
 * BRIEF DESCRIPTION
 *
 * Proc fs operations
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

#include "nova.h"
#include "bdev.h"
#include "inode.h"

extern atomic_t faults;
extern atomic_t writes;
extern atomic_t evicts;
extern atomic_t bdev_read;
extern atomic_t bdev_write;

extern unsigned long already_cached;
extern unsigned long renew;
extern unsigned long lite;
extern unsigned long range;
extern unsigned long invalidate;

extern struct kmem_cache *nova_vpmem_pgnp;

const char *proc_dirname = "fs/NOVA";
struct proc_dir_entry *nova_proc_root;

/* ====================== Statistics ======================== */
static int nova_seq_timing_show(struct seq_file *seq, void *v)
{
	int i;

	nova_get_timing_stats();

	seq_puts(seq, "=========== NOVA kernel timing stats ===========\n");
	for (i = 0; i < TIMING_NUM; i++) {
		/* Title */
		if (Timingstring[i][0] == '=') {
			seq_printf(seq, "\n%s\n\n", Timingstring[i]);
			continue;
		}

		if (measure_timing || Timingstats[i]) {
			seq_printf(seq, "%s: count %llu, timing %llu, average %llu\n",
				Timingstring[i],
				Countstats[i],
				Timingstats[i],
				Countstats[i] ?
				Timingstats[i] / Countstats[i] : 0);
		} else {
			seq_printf(seq, "%s: count %llu\n",
				Timingstring[i],
				Countstats[i]);
		}
	}

	seq_puts(seq, "\n");
	return 0;
}

static int nova_seq_timing_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_timing_show, PDE_DATA(inode));
}

ssize_t nova_seq_clear_stats(struct file *filp, const char __user *buf,
	size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct super_block *sb = PDE_DATA(inode);

	nova_clear_stats(sb);
	return len;
}

static const struct file_operations nova_seq_timing_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_timing_open,
	.read		= seq_read,
	.write		= nova_seq_clear_stats,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int nova_seq_IO_show(struct seq_file *seq, void *v)
{
	struct super_block *sb = seq->private;
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

	nova_get_timing_stats();
	nova_get_IO_stats();

	seq_puts(seq, "============ NOVA allocation stats ============\n\n");

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

	seq_printf(seq, "alloc log count %lu, allocated log pages %lu\n"
		"alloc data count %lu, allocated data pages %lu\n"
		"free log count %lu, freed log pages %lu\n"
		"free data count %lu, freed data pages %lu\n",
		alloc_log_count, alloc_log_pages,
		alloc_data_count, alloc_data_pages,
		free_log_count, freed_log_pages,
		free_data_count, freed_data_pages);

	seq_printf(seq, "Fast GC %llu, check pages %llu, free pages %llu, average %llu\n",
		Countstats[fast_gc_t], IOstats[fast_checked_pages],
		IOstats[fast_gc_pages], Countstats[fast_gc_t] ?
			IOstats[fast_gc_pages] / Countstats[fast_gc_t] : 0);
	seq_printf(seq, "Thorough GC %llu, checked pages %llu, free pages %llu, average %llu\n",
		Countstats[thorough_gc_t],
		IOstats[thorough_checked_pages], IOstats[thorough_gc_pages],
		Countstats[thorough_gc_t] ?
			IOstats[thorough_gc_pages] / Countstats[thorough_gc_t]
			: 0);

	seq_puts(seq, "\n");

	seq_puts(seq, "================ NOVA I/O stats ================\n\n");
	seq_printf(seq, "Read %llu, bytes %llu, average %llu\n",
		Countstats[dax_read_t], IOstats[read_bytes],
		Countstats[dax_read_t] ?
			IOstats[read_bytes] / Countstats[dax_read_t] : 0);
	seq_printf(seq, "COW write %llu, bytes %llu, average %llu, write breaks %llu, average %llu\n",
		Countstats[cow_write_t], IOstats[cow_write_bytes],
		Countstats[cow_write_t] ?
			IOstats[cow_write_bytes] / Countstats[cow_write_t] : 0,
		IOstats[cow_write_breaks], Countstats[cow_write_t] ?
			IOstats[cow_write_breaks] / Countstats[cow_write_t]
			: 0);
	seq_printf(seq, "Inplace write %llu, bytes %llu, average %llu, write breaks %llu, average %llu\n",
		Countstats[inplace_write_t], IOstats[inplace_write_bytes],
		Countstats[inplace_write_t] ?
			IOstats[inplace_write_bytes] /
			Countstats[inplace_write_t] : 0,
		IOstats[inplace_write_breaks], Countstats[inplace_write_t] ?
			IOstats[inplace_write_breaks] /
			Countstats[inplace_write_t] : 0);
	seq_printf(seq, "Inplace write %llu, allocate new blocks %llu\n",
			Countstats[inplace_write_t],
			IOstats[inplace_new_blocks]);
	seq_printf(seq, "DAX get blocks %llu, allocate new blocks %llu\n",
			Countstats[dax_get_block_t], IOstats[dax_new_blocks]);
	seq_printf(seq, "Dirty pages %llu\n", IOstats[dirty_pages]);
	seq_printf(seq, "Protect head %llu, tail %llu\n",
			IOstats[protect_head], IOstats[protect_tail]);
	seq_printf(seq, "Block csum parity %llu\n", IOstats[block_csum_parity]);
	seq_printf(seq, "Page fault %llu, dax cow fault %llu, dax cow fault during snapshot creation %llu\n"
			"CoW write overlap mmap range %llu, mapping/pfn updated pages %llu\n",
			Countstats[mmap_fault_t], Countstats[mmap_cow_t],
			IOstats[dax_cow_during_snapshot],
			IOstats[cow_overlap_mmap],
			IOstats[mapping_updated_pages]);
	seq_printf(seq, "fsync %llu, fdatasync %llu\n",
			Countstats[fsync_t], IOstats[fdatasync]);

	seq_puts(seq, "\n");

	nova_print_snapshot_lists(sb, seq);
	seq_puts(seq, "\n");

	return 0;
}

static int nova_seq_IO_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_IO_show, PDE_DATA(inode));
}

static const struct file_operations nova_seq_IO_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_IO_open,
	.read		= seq_read,
	.write		= nova_seq_clear_stats,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int nova_seq_ts_show(struct seq_file *seq, void *v)
{
	struct super_block *sb = seq->private;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *fl = NULL;
	struct bdev_free_list *bfl = NULL;
	int i;
	int lru = 0;
	int wb = 0;
	int evict = 0;
	int rb = 0;
    unsigned long used = 0;
    unsigned long total = 0;
    unsigned long sumu = 0;
	unsigned long sumt = 0;
	int pgc_size = pgc_total_size();

	nova_get_timing_stats();
	nova_get_IO_stats();

	for (i=TIER_BDEV_LOW;i<=TIER_BDEV_HIGH;++i) {
    	used += nova_bdev_used(sbi, i);
	}
	seq_printf(seq, "[TNOVA] FT %d BR %d WR %d BW %d UP %lu UB %lu UD %d\n",
	atomic_read(&faults), atomic_read(&bdev_read), atomic_read(&writes), atomic_read(&bdev_write),
	nova_pmem_used(sbi), used, pgc_size);

	seq_printf(seq, "----------------------------------------------------------------------\n");
	seq_printf(seq, "                          [PMEM free lists]\n");
	seq_printf(seq, "|Tier|CPU|  Start  |   End   |  Used  | Cached |  Free  | Total |Node|\n");
	for (i=0;i<sbi->cpus;++i) {
		fl = nova_get_free_list(sb, i);
		seq_printf(seq, "|%4d|%3d|%9lu|%9lu|%8lu|%8d|%8lu|%7lu|%4lu|\n",
		0, fl->index, fl->block_start, fl->block_end, fl->block_end - fl->block_start + 1 - fl->num_free_blocks,
		0, fl->num_free_blocks, fl->block_end - fl->block_start + 1, fl->num_blocknode);
	}
	if (DEBUG_PROC_LOCK) {
	seq_printf(seq, "------------------------------------------------------------------------------\n");
	}
	else {
	seq_printf(seq, "----------------------------------------------------------------------\n");
	}
	seq_printf(seq, "                          [BDEV free lists]\n");
	if (DEBUG_PROC_LOCK) {
	seq_printf(seq, "|Tier|CPU|  Start  |   End   |  Used  | Cached |  Free  | Total |Node| Locks |\n");
	}
	else {
	seq_printf(seq, "|Tier|CPU|  Start  |   End   |  Used  | Cached |  Free  | Total |Node|\n");
	}
	for (i=0;i<TIER_BDEV_HIGH*sbi->cpus;++i) {
		if (DEBUG_PROC_LOCK) {
			if (mutex_trylock(&sbi->vpmem_lru_mutex[i])) {
				lru = 0;
				mutex_unlock(&sbi->vpmem_lru_mutex[i]);
			}
			else lru = 1;
			if (mutex_trylock(&sbi->vpmem_wb_mutex[i])) {
				wb = 0;
				mutex_unlock(&sbi->vpmem_wb_mutex[i]);
			}
			else wb = 1;
			if (mutex_trylock(&sbi->vpmem_evict_mutex[i])) {
				evict = 0;
				mutex_unlock(&sbi->vpmem_evict_mutex[i]);
			}
			else evict = 1;
			if (mutex_trylock(&sbi->vpmem_rb_mutex[i])) {
				rb = 0;
				mutex_unlock(&sbi->vpmem_rb_mutex[i]);
			}
			else rb = 1;
		}
		bfl = nova_get_bdev_free_list_flat(sbi,i);
		if (DEBUG_PROC_LOCK) {
			seq_printf(seq, "|%4d|%3d|%9lu|%9lu|%8lu|%8d|%8lu|%7lu|%4lu|%1d|%1d|%1d|%1d|\n",
			bfl->tier, bfl->cpu, bfl->block_start, bfl->block_end, bfl->num_total_blocks - bfl->num_free_blocks,
			atomic_read(&sbi->pgcache_size[i]), bfl->num_free_blocks, bfl->num_total_blocks, bfl->num_blocknode,
			lru, wb, evict, rb );
		}
		else {
			seq_printf(seq, "|%4d|%3d|%9lu|%9lu|%8lu|%8d|%8lu|%7lu|%4lu|\n",
			bfl->tier, bfl->cpu, bfl->block_start, bfl->block_end, bfl->num_total_blocks - bfl->num_free_blocks,
			atomic_read(&sbi->pgcache_size[i]), bfl->num_free_blocks, bfl->num_total_blocks, bfl->num_blocknode);
		}
	}
	if (DEBUG_PROC_LOCK) {
	seq_printf(seq, "------------------------------------------------------------------------------\n");
	}
	else {
	seq_printf(seq, "----------------------------------------------------------------------\n");
	}

	seq_printf(seq, "|[Migration]|  Writes  | Writes-C |  Reads   |Group Migs|Interrupts|\n");
    seq_printf(seq, "|           |%10lu|%10lu|%10lu|%10lu|%10lu|\n",
		sbi->stat->write >> 12, sbi->stat->write_dram  >> 12, sbi->stat->read >> 12,sbi->stat->mig_group, 
            sbi->stat->mig_interrupt);
	seq_printf(seq, "--------------------------------------------------------------------\n");
	seq_printf(seq, "|  [VPMEM]  |  Cached  |  Range   |  Renew   |   Lite   |Invalidate|\n");
    seq_printf(seq, "|           |%10lu|%10lu|%10lu|%10lu|%10lu|\n",
		already_cached, range, renew, lite, invalidate);
	
	seq_printf(seq, "--------------------------------------------------------------------\n");
	seq_printf(seq, "|  [VPMEM]  |  Faults  | BDV_Read |  Writes  | BDV_Writ |  Evicts  |\n");
    seq_printf(seq, "|           |%10d|%10d|%10d|%10d|%10d|\n",
		atomic_read(&faults), atomic_read(&bdev_read), atomic_read(&writes), atomic_read(&bdev_write), atomic_read(&evicts));
	seq_printf(seq, "--------------------------------------------------------------------\n");
	used = nova_pmem_used(sbi);
	sumu += used;
	total = nova_pmem_total(sbi);
	sumt += total;
	seq_printf(seq, "|Tier|  Used  | (Block) |Curr%%|Targ%%|  Total  | (Block) |\n");
	seq_printf(seq, "---------------------------------------------------------\n");
    seq_printf(seq, "|%4d|%6luMB|%9lu|%4lu%%|%4u%%|%7luMB|%9lu|\n",
        0, used>>8, used, used * 100 / total, MIGRATION_DOWN_PMEM_PERC, total>>8, total);
            
    for (i=TIER_BDEV_LOW;i<=TIER_BDEV_HIGH;++i) {
    	used = nova_bdev_used(sbi, i);
		sumu += used;
    	total = nova_bdev_total(sbi, i);
		sumt += total;
		if (i!=TIER_BDEV_HIGH)
    	seq_printf(seq, "|%4d|%6luMB|%9lu|%4lu%%|%4u%%|%7luMB|%9lu|\n",
        	i, used>>8, used, used * 100 / total, MIGRATION_DOWN_BDEV_PERC, total>>8, total);
		else
    	seq_printf(seq, "|%4d|%6luMB|%9lu|%4lu%%|  N/A|%7luMB|%9lu|\n",
        	i, used>>8, used, used * 100 / total, total>>8, total);
    }
	seq_printf(seq, "---------------------------------------------------------\n");
	seq_printf(seq, "|DRAM|%6dMB|%9d|%4d%%|%4u%%|%7uMB|%9u|\n", 
		pgc_size/256, pgc_size, pgc_size * 100 / (VPMEM_MAX_PAGES_QTR*4*TIER_BDEV_HIGH*sbi->cpus), MIGRATION_IDEAL_PERC,
		(VPMEM_MAX_PAGES_QTR*4*TIER_BDEV_HIGH*sbi->cpus)>>8, VPMEM_MAX_PAGES_QTR*4*TIER_BDEV_HIGH*sbi->cpus);
	seq_printf(seq, "|NOVA|%6luMB|%9lu|%4lu%%|  N/A|%7luMB|%9lu|\n", sumu>>8, sumu, sumu * 100 / sumt, sumt>>8, sumt);
	
	seq_printf(seq, "---------------------------------------------------------\n");
	return 0;
}

static int nova_seq_ts_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_ts_show, PDE_DATA(inode));
}

static const struct file_operations nova_seq_ts_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_ts_open,
	.read		= seq_read,
	.write		= nova_seq_clear_stats,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int nova_seq_show_allocator(struct seq_file *seq, void *v)
{
	struct super_block *sb = seq->private;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct free_list *free_list;
	int i;
	unsigned long log_pages = 0;
	unsigned long data_pages = 0;

	seq_puts(seq, "======== NOVA per-CPU allocator stats ========\n");
	for (i = 0; i < sbi->cpus; i++) {
		free_list = nova_get_free_list(sb, i);
		seq_printf(seq, "Free list %d: block start %lu, block end %lu, num_blocks %lu, num_free_blocks %lu, blocknode %lu\n",
			i, free_list->block_start, free_list->block_end,
			free_list->block_end - free_list->block_start + 1,
			free_list->num_free_blocks, free_list->num_blocknode);

		if (free_list->first_node) {
			seq_printf(seq, "First node %lu - %lu\n",
					free_list->first_node->range_low,
					free_list->first_node->range_high);
		}

		if (free_list->last_node) {
			seq_printf(seq, "Last node %lu - %lu\n",
					free_list->last_node->range_low,
					free_list->last_node->range_high);
		}

		seq_printf(seq, "Free list %d: csum start %lu, replica csum start %lu, csum blocks %lu, parity start %lu, parity blocks %lu\n",
			i, free_list->csum_start, free_list->replica_csum_start,
			free_list->num_csum_blocks,
			free_list->parity_start, free_list->num_parity_blocks);

		seq_printf(seq, "Free list %d: alloc log count %lu, allocated log pages %lu, alloc data count %lu, allocated data pages %lu, free log count %lu, freed log pages %lu, free data count %lu, freed data pages %lu\n",
			   i,
			   free_list->alloc_log_count,
			   free_list->alloc_log_pages,
			   free_list->alloc_data_count,
			   free_list->alloc_data_pages,
			   free_list->free_log_count,
			   free_list->freed_log_pages,
			   free_list->free_data_count,
			   free_list->freed_data_pages);

		log_pages += free_list->alloc_log_pages;
		log_pages -= free_list->freed_log_pages;

		data_pages += free_list->alloc_data_pages;
		data_pages -= free_list->freed_data_pages;
	}

	seq_printf(seq, "\nCurrently used pmem pages: log %lu, data %lu\n",
			log_pages, data_pages);

	return 0;
}

static int nova_seq_allocator_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_show_allocator,
				PDE_DATA(inode));
}

static const struct file_operations nova_seq_allocator_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_allocator_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* ====================== Snapshot ======================== */
static int nova_seq_create_snapshot_show(struct seq_file *seq, void *v)
{
	seq_puts(seq, "Write to create a snapshot\n");
	return 0;
}

static int nova_seq_create_snapshot_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_create_snapshot_show,
				PDE_DATA(inode));
}

ssize_t nova_seq_create_snapshot(struct file *filp, const char __user *buf,
	size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct super_block *sb = PDE_DATA(inode);

	nova_create_snapshot(sb);
	return len;
}

static const struct file_operations nova_seq_create_snapshot_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_create_snapshot_open,
	.read		= seq_read,
	.write		= nova_seq_create_snapshot,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int nova_seq_delete_snapshot_show(struct seq_file *seq, void *v)
{
	seq_puts(seq, "Echo index to delete a snapshot\n");
	return 0;
}

static int nova_seq_delete_snapshot_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_delete_snapshot_show,
				PDE_DATA(inode));
}

ssize_t nova_seq_delete_snapshot(struct file *filp, const char __user *buf,
	size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct super_block *sb = PDE_DATA(inode);
	u64 epoch_id;
	int ret;

	ret = kstrtoull(buf, 10, &epoch_id);
	if (ret < 0)
		nova_warn("Couldn't parse snapshot id %s", buf);
	else
		nova_delete_snapshot(sb, epoch_id);

	return len;
}

static const struct file_operations nova_seq_delete_snapshot_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_delete_snapshot_open,
	.read		= seq_read,
	.write		= nova_seq_delete_snapshot,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int nova_seq_show_snapshots(struct seq_file *seq, void *v)
{
	struct super_block *sb = seq->private;

	nova_print_snapshots(sb, seq);
	return 0;
}

static int nova_seq_show_snapshots_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_show_snapshots,
				PDE_DATA(inode));
}

static const struct file_operations nova_seq_show_snapshots_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_show_snapshots_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* ====================== Performance ======================== */
static int nova_seq_test_perf_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "Echo function:poolmb:size:disks to test function performance working on size of data.\n"
			"    example: echo 1:128:4096:8 > /proc/fs/NOVA/pmem0/test_perf\n"
			"The disks value only matters for raid functions.\n"
			"Set function to 0 to test all functions.\n");
	return 0;
}

static int nova_seq_test_perf_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_test_perf_show, PDE_DATA(inode));
}

ssize_t nova_seq_test_perf(struct file *filp, const char __user *buf,
	size_t len, loff_t *ppos)
{
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct super_block *sb = PDE_DATA(inode);
	size_t size;
	unsigned int func_id, poolmb, disks;

	if (sscanf(buf, "%u:%u:%zu:%u", &func_id, &poolmb, &size, &disks) == 4)
		nova_test_perf(sb, func_id, poolmb, size, disks);
	else
		nova_warn("Couldn't parse test_perf request: %s", buf);

	return len;
}

static const struct file_operations nova_seq_test_perf_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_test_perf_open,
	.read		= seq_read,
	.write		= nova_seq_test_perf,
	.llseek		= seq_lseek,
	.release	= single_release,
};


/* ====================== GC ======================== */


static int nova_seq_gc_show(struct seq_file *seq, void *v)
{
	seq_printf(seq, "Echo inode number to trigger garbage collection\n"
		   "    example: echo 34 > /proc/fs/NOVA/pmem0/gc\n");
	return 0;
}

static int nova_seq_gc_open(struct inode *inode, struct file *file)
{
	return single_open(file, nova_seq_gc_show, PDE_DATA(inode));
}

ssize_t nova_seq_gc(struct file *filp, const char __user *buf,
	size_t len, loff_t *ppos)
{
	u64 target_inode_number;
	struct address_space *mapping = filp->f_mapping;
	struct inode *inode = mapping->host;
	struct super_block *sb = PDE_DATA(inode);
	struct inode *target_inode;
	struct nova_inode *target_pi;
	struct nova_inode_info *target_sih;

	int ret;
	char *_buf;
	int retval = len;

	_buf = kmalloc(len, GFP_KERNEL);
	if (_buf == NULL)  {
		retval = -ENOMEM;
		nova_dbg("%s: kmalloc failed\n", __func__);
		goto out;
	}

	if (copy_from_user(_buf, buf, len)) {
		retval = -EFAULT;
		goto out;
	}

	_buf[len] = 0;
	ret = kstrtoull(_buf, 0, &target_inode_number);
	if (ret) {
		nova_info("%s: Could not parse ino '%s'\n", __func__, _buf);
		return ret;
	}
	nova_info("%s: target_inode_number=%llu.", __func__,
		  target_inode_number);

	target_inode = nova_iget(sb, target_inode_number);
	if (target_inode == NULL) {
		nova_info("%s: inode %llu does not exist.", __func__,
			  target_inode_number);
		retval = -ENOENT;
		goto out;
	}

	target_pi = nova_get_inode(sb, target_inode);
	if (target_pi == NULL) {
		nova_info("%s: couldn't get nova inode %llu.", __func__,
			  target_inode_number);
		retval = -ENOENT;
		goto out;
	}

	target_sih = NOVA_I(target_inode);

	nova_info("%s: got inode %llu @ 0x%p; pi=0x%p\n", __func__,
		  target_inode_number, target_inode, target_pi);

	nova_inode_log_fast_gc(sb, target_pi, &target_sih->header,
			       0, 0, 0, 0, 1);
	iput(target_inode);

out:
	kfree(_buf);
	return retval;
}

static const struct file_operations nova_seq_gc_fops = {
	.owner		= THIS_MODULE,
	.open		= nova_seq_gc_open,
	.read		= seq_read,
	.write		= nova_seq_gc,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* ====================== Setup/teardown======================== */
void nova_sysfs_init(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (nova_proc_root)
		sbi->s_proc = proc_mkdir(sbi->s_bdev->bd_disk->disk_name,
					 nova_proc_root);

	if (sbi->s_proc) {
		proc_create_data("timing_stats", 0444, sbi->s_proc,
				 &nova_seq_timing_fops, sb);
		proc_create_data("IO_stats", 0444, sbi->s_proc,
				 &nova_seq_IO_fops, sb);
		proc_create_data("tiering_stats", 0444, sbi->s_proc,
				 &nova_seq_ts_fops, sb);
		proc_create_data("allocator", 0444, sbi->s_proc,
				 &nova_seq_allocator_fops, sb);
		proc_create_data("create_snapshot", 0444, sbi->s_proc,
				 &nova_seq_create_snapshot_fops, sb);
		proc_create_data("delete_snapshot", 0444, sbi->s_proc,
				 &nova_seq_delete_snapshot_fops, sb);
		proc_create_data("snapshots", 0444, sbi->s_proc,
				 &nova_seq_show_snapshots_fops, sb);
		proc_create_data("test_perf", 0444, sbi->s_proc,
				 &nova_seq_test_perf_fops, sb);
		proc_create_data("gc", 0444, sbi->s_proc,
				 &nova_seq_gc_fops, sb);
	}
}

void nova_sysfs_exit(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (sbi->s_proc) {
		remove_proc_entry("timing_stats", sbi->s_proc);
		remove_proc_entry("IO_stats", sbi->s_proc);
		remove_proc_entry("tiering_stats", sbi->s_proc);
		remove_proc_entry("allocator", sbi->s_proc);
		remove_proc_entry("create_snapshot", sbi->s_proc);
		remove_proc_entry("delete_snapshot", sbi->s_proc);
		remove_proc_entry("snapshots", sbi->s_proc);
		remove_proc_entry("test_perf", sbi->s_proc);
		remove_proc_entry("gc", sbi->s_proc);
		remove_proc_entry(sbi->s_bdev->bd_disk->disk_name,
					nova_proc_root);
	}
}
