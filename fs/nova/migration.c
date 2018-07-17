#include "nova.h"
#include "bdev.h"

/*
 * [About Migration Policy]
 * Rotate policy - used for debugging
 *   The file rotates from tier 0 -> tier 1 -> tier 2 -> ... -> tier 0.
 * Downward policy - used for run-time
 *   Downward migration: Migrate all write entries lower than the input tier
 *                       to the input tier, ignore higher ones.
 *   Upward migration: Migrate all write entries to TIER_PMEM.
 * Force: true - do migration regardless of original tiers of entries
 *        false - only migrate tiers which are lower than input tier
 */

/* 
 * [About Mini Buffer]
 * It is a temporary buffer solution for tiering file system.
 * Includes: (for each buffer page)
 *          down_read: mini-buffer in use
 *          down_write: under-migration
 *      tier: tier number
 *      blocknr: blocknr in this tier
 */

// Allocate a DRAM buffer in sbi
int init_dram_buffer(struct nova_sb_info *sbi) {
    unsigned int i = 0;

	sbi->bdev_buffer = kcalloc(BDEV_BUFFER_PAGES, IO_BLOCK_SIZE, GFP_KERNEL);
	if (!sbi->bdev_buffer) return -ENOMEM;

    sbi->bb_pages = kcalloc(BDEV_BUFFER_PAGES, sizeof(struct page *), GFP_KERNEL);
	if (!sbi->bb_pages) return -ENOMEM;
   
	mutex_init(&sbi->bb_mutex);

    spin_lock_init(&sbi->bal_lock);

	for (i = 0; i < BDEV_BUFFER_PAGES; i++) {
        sbi->bb_pages[i] = virt_to_page(sbi->bdev_buffer+i*IO_BLOCK_SIZE);
    }

    sbi->bal_head = kzalloc(sizeof(struct bio_async_list), GFP_KERNEL);
    
	INIT_LIST_HEAD(&sbi->bal_head->list);

    return 0;
}

// n: input sequence number or force print indicator (-2)
void print_a_write_entry(struct super_block *sb, struct nova_file_write_entry *entry, int n) {
    char *ii;
    char stmp[100] = {0};
    char *addr;
	char *ctmp = kzalloc(300, GFP_KERNEL);
    int count = 0;
    int i;

    nova_info("\e[0;32m#%3d\e[0m [P]%p [B]%lu\n", n, entry, virt_to_block((unsigned long)entry));
    
    if (entry->entry_type == FILE_WRITE || n == -2) {
        nova_info("     ||Type|Tier| num_pg |invalidp| block  | pgoff  |counter ||");
        nova_info("     ||%4u|%4u|%8u|%8u|%8llu|%8llu|%8d||", entry->entry_type, get_entry_tier(entry),
            entry->num_pages, entry->invalid_pages, entry->block  >> PAGE_SHIFT, entry->pgoff, entry->counter);
        addr = nova_get_block(sb, entry->block);
        for (ii=(char *)addr; ii<(char *)(addr+((entry->num_pages)<<PAGE_SHIFT)); ii+=1024) {
            ctmp[count++] = *ii;
            ctmp[count]='\0';
        }
        for(i=0;i<count;i+=64) {
            strncat(stmp, &ctmp[i], 64);
            printk("%s\n",stmp);
            stmp[0] = '\0';
        }
    }
    kfree(ctmp);
}

void print_a_write_entry_data(struct super_block *sb, void* addr, int n) {
    char *ii;
    char stmp[100] = {0};
	char *ctmp = kzalloc(300, GFP_KERNEL);
    int count = 0;
    int i;
    addr = (void *)((unsigned long)addr & PAGE_MASK);

    for (ii=(char *)addr; ii<(char *)addr+PAGE_SIZE; ii+=64) {
        ctmp[count++] = *ii;
        ctmp[count]='\0';
    }
    for(i=0;i<count;i+=16) {
        strncat(stmp, &ctmp[i], 16);
        printk("%p %lu %d %s \n",addr,virt_to_blockoff((unsigned long)addr),n,stmp);
        stmp[0] = '\0';
    }

    kfree(ctmp);
}

int print_file_write_entries(struct super_block *sb, struct nova_inode_info_header *sih) {
	void *addr;
    struct nova_inode_log_page *addrp;
    struct nova_inode *pi = nova_get_block(sb, sih->pi_addr);
	struct nova_file_write_entry *entry;
    unsigned int inv, num;
    unsigned long epoch_id;
    int i = 0;
    int j = 0;
	unsigned long curr_p = le64_to_cpu(pi->log_head);
	size_t entry_size = sizeof(struct nova_file_write_entry);

    nova_info("Print Inode %lu [start]\n", sih->ino);
    nova_info("valid %u deleted %u link %u\n", pi->valid, pi->deleted, pi->i_links_count);
    addrp = nova_get_block(sb, curr_p);
    if (!addrp) return -1;
    inv = addrp->page_tail.invalid_entries;
    num = addrp->page_tail.num_entries;
    epoch_id = addrp->page_tail.epoch_id;
    nova_info("\e[0;34m Log page: %p num:%u invalid: %u epoch: %lu \e[0m",
        addrp, num, inv, epoch_id);
    
	while (curr_p && curr_p != sih->log_tail) {
        if (is_last_entry(curr_p, entry_size)) {
			curr_p = next_log_page(sb, curr_p);
		    addrp = nova_get_block(sb, curr_p);
            if (!addrp) return -1;
            inv = addrp->page_tail.invalid_entries;
            num = addrp->page_tail.num_entries;
            epoch_id = addrp->page_tail.epoch_id;
            nova_info("\e[0;34m Log page: %p num:%u invalid: %u epoch: %lu \e[0m", 
                addrp, num, inv, epoch_id);
            j = 0;
        }
        if (num == 0) break;

		if (curr_p == 0) {
			nova_err(sb, "%s: File inode %lu log is NULL!\n",
				__func__, sih->ino);
			return -EINVAL;
		}

		// nova_info("curr_p %llu\n",curr_p);
		// nova_info("[entry] %llu,%llu,%u\n", 
        // entry->block >> PAGE_SHIFT, entry->pgoff, entry->num_pages);
        if (j<num){
            addr = (void *) nova_get_block(sb, curr_p);
            entry = (struct nova_file_write_entry *) addr;
            print_a_write_entry(sb, entry, i++);
        }
        ++j;

		curr_p += entry_size;		
	}
    nova_info("Print Inode %lu [end]\n", sih->ino);

	return 0;
}

/*
 * clear_dram_buffer(): Clear the metadata (and data) of the buffer
 *      Used for file data deletion
 *      The buffer is invalid after clear()
 * put_dram_buffer(): Flush the page to block device
 *      Used for fsync
 *      The buffer is still valid after put()
 */ 
inline int clear_dram_buffer_range(unsigned long blockoff, unsigned long length) {
    return vpmem_invalidate_pages(blockoff_to_virt(blockoff), length);
}

inline int put_dram_buffer_range(unsigned long blockoff, unsigned long length) {
    return vpmem_flush_pages(blockoff_to_virt(blockoff), length);
}

inline int renew_dram_buffer_range(void *addr, unsigned long blockoff, unsigned long length) {
    return vpmem_renew_pages(addr, blockoff_to_virt(blockoff), length);
}

bool is_dram_buffer_addr(void *addr) {
    return (vpmem_start <= (unsigned long)addr) && ((unsigned long)addr <= vpmem_end);
}

// Return the tier of the first write entry
int current_tier(struct inode *inode) {
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_entry *entry;
    loff_t isize = i_size_read(inode);
    pgoff_t index = 0;
    pgoff_t end_index = (isize) >> PAGE_SHIFT;
    if ( si == NULL || sih == NULL || end_index == 0 ) return -1;
    do {
        entry = nova_find_next_entry_lockfree(sb, sih, index);
        if (entry) {
            return get_entry_tier(entry);
        }
        else return -1;
    } while (index <= end_index);

    return -1;
}

inline int get_ltier(struct inode *inode) {
	struct nova_inode_info *si = NOVA_I(inode);
    return si->header.ltier;
}

inline int get_htier(struct inode *inode) {
	struct nova_inode_info *si = NOVA_I(inode);
    return si->header.htier;
}

// Return 0 if all write entries are in the same tier
// Else the block number of the first write entry with a different tier
int is_not_same_tier(struct inode *inode) {
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_entry *entry;
    unsigned int num_pages;
    unsigned long pgoff;
    int t;
    loff_t isize = i_size_read(inode);
    pgoff_t index = 0;
    pgoff_t end_index = (isize) >> PAGE_SHIFT;
    bool exist = false;
    if ( si == NULL || sih == NULL || end_index == 0 ) return 1;
    do {
        // nova_info("%lu index %lu end_index %lu\n",inode->i_ino,index,end_index);
        entry = nova_find_next_entry_lockfree(sb, sih, index);
        if (entry) {
            if (!exist) {
                exist = true;
                t = get_entry_tier(entry);
                continue;
            }
            if (get_entry_tier(entry) == t) {
                num_pages = le32_to_cpu(entry->num_pages);
                pgoff = le64_to_cpu(entry->pgoff);
                index = pgoff + (unsigned long)num_pages;
                continue;
            }
            else {
                return 1;
            }
        }
        else return 0;
    } while (index <= end_index);

    return 0;
}

inline bool should_migrate_entry(struct inode *inode, struct nova_inode_info_header *sih,
    struct nova_file_write_entry *entry, int to, bool force) {
    struct super_block *sb = inode->i_sb;
    struct nova_sb_info *sbi = NOVA_SB(sb);
    /* If file is already to big, then migrate in entry granularity. */
    if (!is_tier_usage_quite_high(sbi, get_entry_tier(entry)) && i_size_read(inode) >= 1<<30 ) return false;
    if (entry->mtime > sih->avg_atime && sih->avg_atime > current_time(inode).tv_sec - 1)
        return false;
    if (force) return (get_entry_tier(entry)) != to;
    else return (get_entry_tier(entry)) < to;
}

/* 
 * Migrate continuous blocks from pmem to block device, with block number
 */
inline int migrate_blocks_pmem_to_bdev(struct nova_sb_info *sbi, 
    void *dax_mem, unsigned long nr, int tier, unsigned long blockoff) {
    return nova_bdev_write_block(sbi, get_bdev_raw(sbi, tier), blockoff, nr,
        address_to_page(dax_mem), BIO_SYNC);
}

/*
 * Migrate continuous blocks from block device to pmem, with block number
 */
inline int migrate_blocks_bdev_to_pmem(struct nova_sb_info *sbi, 
    void *dax_mem, unsigned long nr, int tier, unsigned long blockoff) {
    return nova_bdev_read_block(sbi, get_bdev_raw(sbi, tier), blockoff, nr, 
        address_to_page(dax_mem), BIO_SYNC);
}

/*
 * Migrate continuous blocks from block device to block device, with block number
 * Since DRAM buffer is currently limited, this migration is always in SYNC.
 */
int migrate_blocks_bdev_to_bdev(struct nova_sb_info *sbi, 
    unsigned long blockfrom, int from, unsigned long nr,  unsigned long blockto, int to) {
    int ret = 0;
    struct page *pg = sbi->bb_pages[0];
    struct block_device *bdev_raw_from = get_bdev_raw(sbi, from);
    struct block_device *bdev_raw_to = get_bdev_raw(sbi, to);

	mutex_lock(&sbi->bb_mutex);
    ret = nova_bdev_read_block(sbi, bdev_raw_from, blockfrom, nr, pg, BIO_SYNC);
    ret = nova_bdev_write_block(sbi, bdev_raw_to, blockto, nr, pg, BIO_SYNC);
	mutex_unlock(&sbi->bb_mutex);

    return ret;
}

// Migrate continuous blocks from pmem to block device
int migrate_blocks(struct nova_sb_info *sbi, unsigned long blockfrom, 
    unsigned long nr, int from, int to, unsigned long blocknr) {
    unsigned long raw_blockfrom = get_raw_from_blocknr(sbi, blockfrom);
    unsigned long raw_blockto = get_raw_from_blocknr(sbi, blocknr);

    if (is_tier_pmem(from) && is_tier_bdev(to))
        return migrate_blocks_pmem_to_bdev(sbi, (void *) sbi->virt_addr + 
            (raw_blockfrom << PAGE_SHIFT), nr, to, raw_blockto);
    if (is_tier_bdev(from) && is_tier_pmem(to)) 
        return migrate_blocks_bdev_to_pmem(sbi, (void *) sbi->virt_addr + 
            (raw_blockto << PAGE_SHIFT), nr, from, raw_blockfrom);
    if (is_tier_bdev(from) && is_tier_bdev(to)) 
        return migrate_blocks_bdev_to_bdev(sbi, raw_blockfrom, from, nr, 
            raw_blockto, to);

    return -2;
}

/*
 * Only check the corresponding mb-page, not the other pages.
 * Because in the ultimate design, each block will only have one buffer page.
 */ 
int is_entry_busy(struct nova_sb_info *sbi, struct nova_file_write_entry *entry) {
    if (entry->updating == 1) return 1; 
    if (entry->updating == 3) return 3; 
    if (!is_tier_bdev(get_entry_tier(entry))) return 0;
    // if (vpmem_is_range_rwsem_locked(blockoff_to_virt(entry->block >> PAGE_SHIFT), 
    //     le32_to_cpu(entry->num_pages))) return 2;
    return 0;
}

unsigned int valid_index_range(struct super_block *sb, 
    struct nova_inode_info_header *sih, pgoff_t index) {
	struct nova_file_write_entry *entry;
    unsigned long ret = 1;

    entry = nova_find_next_entry_lockfree(sb, sih, index);
    if (!entry) {
        nova_info("valid entry not found\n");
        return 0;
    }
    while (entry == nova_find_next_entry_lockfree(sb, sih, index+ret)) ret++;
    return ret;
}

/*
 * Clone and assign a write entry
 * block: New global block number
 * num_pages: 0 - Normal clone (single migration)
 *            else - Set num_pages manually (group migration)
 */ 
int nova_clone_write_entry(struct nova_sb_info *sbi, struct nova_inode_info *si, 
    struct nova_file_write_entry *entry, int tier, unsigned long block, 
    unsigned int num_pages, struct nova_inode_update *update) {
	struct super_block *sb = sbi->sb;
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_entry entry_data;
	struct nova_file_write_entry *entryc;
    struct inode *inode = &si->vfs_inode;
    struct nova_inode *pi = nova_get_block(sb, sih->pi_addr);
	unsigned int data_bits;
	void *addr;
    int ret = 0;

    memcpy_mcsafe(&entry_data, entry, sizeof(struct nova_file_write_entry));

    if (DEBUG_MIGRATION_CLONE) print_a_write_entry(sb, entry, 0);

	entry_data.entry_type = FILE_WRITE;
    entry_data.block = cpu_to_le64(nova_get_block_off(sb, block, sih->i_blk_type));
    entry_data.updating = 0;
    entry_data.invalid_pages = 0;
    entry_data.size = sih->i_size;
    entry_data.counter = 0;

    if (num_pages!=0) entry_data.num_pages = num_pages;
	nova_update_entry_csum(&entry_data);

    if (DEBUG_MIGRATION_CLONE) print_a_write_entry(sb, &entry_data, 0);

    ret = nova_append_file_write_entry(sb, pi, inode, &entry_data, update);
    if (ret) {
        nova_dbg("%s: append inode entry failed\n", __func__);
        ret = -ENOSPC;
        return ret;
    }
    
    addr = (void *) nova_get_block(sb, update->curr_entry);
    entryc = (struct nova_file_write_entry *)addr;

    if (DEBUG_MIGRATION_CLONE) print_a_write_entry(sb, entryc, 0);

	nova_flush_buffer(entryc, sizeof(struct nova_file_write_entry), 0);

	data_bits = blk_type_to_shift[sih->i_blk_type];
	sih->i_blocks += (le32_to_cpu(entry->num_pages) << (data_bits - sb->s_blocksize_bits));
	inode->i_blocks = sih->i_blocks;
    
	ret = nova_assign_write_entry(sb, sih, entryc, entryc, true);

    return ret;
}

// Always force
int migrate_entry_blocks(struct nova_sb_info *sbi, int to, struct nova_inode_info *si, 
    struct nova_file_write_entry *entry, unsigned long blocknr_hint, 
    struct nova_inode_update *update, unsigned long new_pgoff, unsigned int new_num_pages) {
	struct super_block *sb = sbi->sb;
    unsigned long blocknr = 0;
    struct nova_file_write_entry nentry;
    int from, ret = 0;
    unsigned long i;

    nova_set_stage(6);
    /* Step 1. Check */
    if (!entry) return ret;
    if (DEBUG_MIGRATION_ALLOC) 
        nova_info("[Migration] #1 entry->block %lu, entry->num_pages %u new %u\n", 
        (unsigned long)entry->block >> PAGE_SHIFT, entry->num_pages, new_num_pages);
    from = get_entry_tier(entry);

    ret = is_entry_busy(sbi, entry);
    if (ret) {
        nova_info("Error: entry->block %lu is busy, code %d\n", 
            (unsigned long)entry->block >> PAGE_SHIFT, ret);
        return -1;
    }
    
    memcpy_mcsafe(&nentry, entry, sizeof(struct nova_file_write_entry));

    entry->updating = 3;
	nova_update_entry_csum(entry);
    nova_flush_buffer(&entry, CACHELINE_SIZE, 0);

    nentry.num_pages = new_num_pages;
    nentry.invalid_pages = 0;
    nentry.block += (new_pgoff - nentry.pgoff) << PAGE_SHIFT;
    nentry.pgoff = new_pgoff;

    /* Step 2. Allocate */

    if (DEBUG_MIGRATION_ALLOC) 
        nova_info("[Migration] #2 entry->block %lu, entry->num_pages %u\n", 
        (unsigned long)nentry.block >> PAGE_SHIFT, nentry.num_pages);
    // print_a_page((void *) sbi->virt_addr + entry->block);

    if (blocknr_hint) {
        blocknr = blocknr_hint;
        if (DEBUG_MIGRATION_ALLOC) nova_info("[Migration] Hint blocknr:%lu number:%d.\n",
            blocknr, le32_to_cpu(nentry.num_pages));
    }
    else {
        // The &blocknr is global block number
        ret = nova_alloc_block_tier(sbi, to, ANY_CPU, &blocknr, le32_to_cpu(nentry.num_pages), ALLOC_FROM_HEAD, false);

        if (ret<0) {
            nova_info("[Migration] Block allocation error T%d %d.\n", to, ret);
            // Note that PMEM may not have large contingous blocks
            goto end;
        }
        if (DEBUG_MIGRATION_ALLOC) nova_info("[Migration] Allocate blocknr:%lu number:%d.\n",
            blocknr, le32_to_cpu(nentry.num_pages));
    }

    /* Step 3. Copy */

    // Invalidate the page
    if (is_tier_bdev(from)) clear_dram_buffer_range(nentry.block >> PAGE_SHIFT, le32_to_cpu(nentry.num_pages));
    if (is_tier_bdev(to)) renew_dram_buffer_range(nova_get_block(sb, nentry.block), blocknr, le32_to_cpu(nentry.num_pages));
    // if (is_tier_bdev(to)) clear_dram_buffer_range(blocknr, le32_to_cpu(nentry.num_pages));

    ret = migrate_blocks(sbi, nentry.block >> PAGE_SHIFT, le32_to_cpu(nentry.num_pages), from, to, blocknr);
    if (ret<0) {
        nova_info("[Migration] Block copy error.\n");
        if (ret == -2) nova_info("[Migration] Unsupported migration attempt.\n");
        return ret;
    }

    ret = flush_bal_entry(sbi);
    if (ret<0) {
        nova_info("[Migration] Flush bal error.\n");
        return ret;
    }

    // nova_info("en %llu blocknr %lu p %lx", entryt.block >> PAGE_SHIFT, blocknr, blockoff_to_virt(blocknr));

    // if (is_tier_bdev(to)) clear_dram_buffer_range(blocknr, le32_to_cpu(nentry.num_pages));
    
    // Temp solution: memcpy to invalidate the page cache + pre-allocate empty page
    if (MODE_USE_MEMCPY && is_tier_pmem(from) && is_tier_bdev(to)) {
        // nova_info("[Migration] memcpy %lu <- %llu num: %u\n", 
        // blocknr, nentry.block>>PAGE_SHIFT, nentry.num_pages);
        for (i=0;i<nentry.num_pages;++i)
            memcpy_mcsafe(nova_get_block(sb, blocknr << PAGE_SHIFT) + (i << PAGE_SHIFT),
                nova_get_block(sb, nentry.block) + (i << PAGE_SHIFT), PAGE_SIZE);
    }

    if (MODE_USE_COOKIE && is_tier_pmem(from) && is_tier_bdev(to)) {
        if (is_pgcache_ideal()) {
            for (i=0;i<nentry.num_pages;++i)
                vpmem_do_page_fault_lite(nova_get_block(sb, nentry.block) + (i << PAGE_SHIFT),
                    nova_get_block(sb, blocknr << PAGE_SHIFT) + (i << PAGE_SHIFT));
        }
        else {
            if (!is_pgcache_large()) {
                vpmem_do_page_fault_lite(nova_get_block(sb, nentry.block),
                    nova_get_block(sb, blocknr << PAGE_SHIFT));
                if (nentry.num_pages>1) {
                    vpmem_do_page_fault_lite(nova_get_block(sb, nentry.block) + ((nentry.num_pages-1) << PAGE_SHIFT),
                        nova_get_block(sb, blocknr << PAGE_SHIFT) + ((nentry.num_pages-1) << PAGE_SHIFT));
                }
            }
        }
    }

    // nova_bdev_read_blockoff(sbi, blocknr, le32_to_cpu(entry->num_pages), 
    //     virt_to_page(nova_get_block(sb, entryt.block)), BIO_SYNC);
    // if (is_tier_bdev(to)) vpmem_invalidate_pages(blockoff_to_virt(blocknr), le32_to_cpu(entry->num_pages));
    // if (is_tier_bdev(to)) vpmem_cache_pages_safe(blockoff_to_virt(blocknr), le32_to_cpu(entry->num_pages));

    /* Step 4. Free */
    /* The free step is now included in the clone write entry function */
    // ret = nova_free_blocks_tier(sbi, entry->block >> PAGE_SHIFT, entry->num_pages);
    
    nova_set_stage(7);
    /* Step 5. Clone */
    if (!blocknr_hint) ret = nova_clone_write_entry(sbi, si, &nentry, to, blocknr, 0, update);

end:
    // Update tiering info
    entry->updating = 0;
	nova_update_entry_csum(entry);
    nova_flush_buffer(&entry, sizeof(struct nova_file_write_entry), 0);
    
    return ret;
}

/* 
 * Group migration
 * Range: [start_index, end_index - 1]
 * Makes sure that the file entries fit the boundary of optsize 
 * Always force
 */
int migrate_group_entry_blocks(struct nova_sb_info *sbi, struct inode *inode, int to,
    pgoff_t start_index, pgoff_t end_index, struct nova_inode_update *update) {
	struct super_block *sb = sbi->sb;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
    int ret = 0;
    unsigned long blocknr = 0;
    unsigned int opt_size = 1 << sbi->bdev_list[to - TIER_BDEV_LOW].opt_size_bit;
	struct nova_file_write_entry *entry;
	struct nova_file_write_entry *entry_first = NULL;
	// struct nova_file_write_entry entry_data;
    pgoff_t index = start_index;
    unsigned int num_pages;
    unsigned long pgoff;

    nova_set_stage(4);
	if (MODE_KEEP_STAT) sbi->stat->mig_group += end_index - start_index + 1;

    ret = nova_alloc_block_tier(sbi, to, ANY_CPU, &blocknr, opt_size, ALLOC_FROM_TAIL, false);
    if (ret<0) {
        nova_info("[Migration] Block group allocation error.\n");
        return ret;
    }
    
    do {
        entry = nova_find_next_entry_lockfree(sb, sih, index);
        if (entry) {            
            if (DEBUG_MIGRATION_ENTRY) 
                nova_info("[Migration] Migrating (group) write entry with index:%lu (inode %lu)\n", index, sih->ino);
            if (entry->reassigned) {
                pgoff = index;
                num_pages = valid_index_range(sb, sih, index);
            }
            else {
                pgoff = le64_to_cpu(entry->pgoff);
                num_pages = le32_to_cpu(entry->num_pages);
            }
            ret = migrate_entry_blocks(sbi, to, si, entry, 
                    blocknr + (pgoff & (opt_size - 1)), update, pgoff, num_pages);
            index = (pgoff + num_pages) > index+1 ? pgoff + num_pages : index+1;
        }
        else index++;
    } while (index < end_index);

    entry_first = nova_find_next_entry_lockfree(sb, sih, start_index);

    if (DEBUG_MIGRATION_MERGE) nova_info("Merge entry: [Before] [entry] %llu,%llu,%u\n", 
        entry_first->block >> PAGE_SHIFT, entry_first->pgoff, entry_first->num_pages);


    ret = nova_clone_write_entry(sbi, si, entry_first, to, blocknr, end_index - start_index, update);

    // if (DEBUG_MIGRATION_MERGE) nova_info("Merge entry: [After ] [entry] %llu,%llu,%u\n", 
        // entry_data.block >> PAGE_SHIFT, entry_data.pgoff, entry_data.num_pages);
    
    return ret;
}

bool is_entry_cross_boundary(struct nova_sb_info *sbi, int tier,
    unsigned long new_pgoff, unsigned int new_num_pages) {
    unsigned int osb = 0;
    // There is no boundary in PMEM
    if (tier==TIER_PMEM) return false;

    osb = sbi->bdev_list[tier - TIER_BDEV_LOW].opt_size_bit;
    if ( (new_pgoff >> osb) !=  
        ( (new_pgoff + new_num_pages - 1) >> osb ) ) {
        if (DEBUG_MIGRATION_SPLIT) 
            nova_info("cross entry: entry->pgoff:%lu entry->num_pages:%u\n", new_pgoff, new_num_pages);
        return true;
    }
    else return false;
}

/*
 * Split a write entry into two halves
 * If the entry is like:  |||| xx** **** *xxx ||||
 *   Then the first half:        **
 *   The second half:               **** *
 *   |: Irrelevant data pages
 *   *: Data pages at [new_pgoff, new_pgoff + new_num_pages - 1]
 *   x: Other data pages in this write entry
 * Normally, the entry only crosses the boundary once.
 */
unsigned int nova_split_write_entry(struct nova_sb_info *sbi, struct nova_inode_info *si, 
    struct nova_file_write_entry *entry, int tier, struct nova_inode_update *update,
    unsigned long new_pgoff, unsigned int new_num_pages) {
	struct super_block *sb = sbi->sb;
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_entry entry_data1, entry_data2;
	struct nova_file_write_entry *entryc;
    struct inode *inode = &si->vfs_inode;
    struct nova_inode *pi = nova_get_block(sb, sih->pi_addr);
	unsigned int data_bits;
    unsigned int osb = sbi->bdev_list[tier - TIER_BDEV_LOW].opt_size_bit;
    unsigned int num_pages1 = (((new_pgoff >> osb) +1) << osb) - new_pgoff;
	unsigned int num_pages2 = new_num_pages - num_pages1;
	void *addr;
    int ret = 0;

    if (DEBUG_MIGRATION_SPLIT) {
        nova_info("entry->pgoff:%llu block:%llu num_pages:%u osb:%u\n", 
            entry->pgoff, entry->block >> PAGE_SHIFT, entry->num_pages, ((1<<osb) - 1));
        nova_info("num_pages1:%u num_pages2:%u\n", num_pages1, num_pages2);
    }
    
    memcpy_mcsafe(&entry_data1, entry, sizeof(struct nova_file_write_entry));
    memcpy_mcsafe(&entry_data2, entry, sizeof(struct nova_file_write_entry));

    if (DEBUG_MIGRATION_CLONE) print_a_write_entry(sb, entry, 0);

	entry_data1.entry_type = FILE_WRITE;
	entry_data2.entry_type = FILE_WRITE;
	entry_data1.num_pages = num_pages1;
	entry_data2.num_pages = num_pages2;
    entry_data1.block = entry->block + ((new_pgoff - entry->pgoff) << PAGE_SHIFT);
    entry_data2.block = entry->block + ((new_pgoff - entry->pgoff + num_pages1) << PAGE_SHIFT);
    entry_data1.pgoff = new_pgoff;
    entry_data2.pgoff = new_pgoff + num_pages1;
    entry_data1.invalid_pages = 0;
    entry_data2.invalid_pages = 0;
    entry_data1.updating = 0;
    entry_data2.updating = 0;
    entry_data1.size = sih->i_size;
    entry_data2.size = sih->i_size;
    entry_data1.counter = 0;
    entry_data2.counter = 0;

	nova_update_entry_csum(&entry_data1);
	nova_update_entry_csum(&entry_data2);

    if (DEBUG_MIGRATION_SPLIT) {
        nova_info("entry1-> pgoff:%llu block:%llu num_pages:%u\n",
            entry_data1.pgoff, entry_data1.block >> PAGE_SHIFT, entry_data1.num_pages);
        nova_info("entry2-> pgoff:%llu block:%llu num_pages:%u\n",
            entry_data2.pgoff, entry_data2.block >> PAGE_SHIFT, entry_data2.num_pages);
    }

    if (DEBUG_MIGRATION_CLONE) print_a_write_entry(sb, &entry_data1, 0);
    if (DEBUG_MIGRATION_CLONE) print_a_write_entry(sb, &entry_data2, 0);

    /* Assign entry #1 */
    ret = nova_append_file_write_entry(sb, pi, inode, &entry_data1, update);
    if (ret) {
        nova_dbg("%s: append inode entry failed\n", __func__);
        ret = -ENOSPC;
        return 0;
    }
    addr = (void *) nova_get_block(sb, update->curr_entry);
    entryc = (struct nova_file_write_entry *)addr;
    if (DEBUG_MIGRATION_CLONE) print_a_write_entry(sb, entryc, 0);
	nova_flush_buffer(entryc, sizeof(struct nova_file_write_entry), 0);
    data_bits = blk_type_to_shift[sih->i_blk_type];
	sih->i_blocks += (le32_to_cpu(entry->num_pages) << (data_bits - sb->s_blocksize_bits));
	inode->i_blocks = sih->i_blocks;    
	ret = nova_assign_write_entry(sb, sih, entryc, entryc, false);

    /* Assign entry #2 */
    ret = nova_append_file_write_entry(sb, pi, inode, &entry_data2, update);
    if (ret) {
        nova_dbg("%s: append inode entry failed\n", __func__);
        ret = -ENOSPC;
        return 0;
    }    
    addr = (void *) nova_get_block(sb, update->curr_entry);
    entryc = (struct nova_file_write_entry *)addr;
    if (DEBUG_MIGRATION_CLONE) print_a_write_entry(sb, entryc, 0);
	nova_flush_buffer(entryc, sizeof(struct nova_file_write_entry), 0);
	data_bits = blk_type_to_shift[sih->i_blk_type];
	sih->i_blocks += (le32_to_cpu(entry->num_pages) << (data_bits - sb->s_blocksize_bits));
	inode->i_blocks = sih->i_blocks;    
	ret = nova_assign_write_entry(sb, sih, entryc, entryc, false);
	// ret = nova_invalidate_write_entry(sb, entry, 1, entry->num_pages);

    return num_pages1;
}

inline bool is_inode_wait_list_empty(struct inode *inode) {
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
    return list_empty(&sih->mig_sem.wait_list) && list_empty(&inode->i_rwsem.wait_list);
}

/*
 * Migrate a file from one tier to another
 * How migration works: Check -> Allocate -> Copy -> Free
 */ 
int migrate_a_file_by_entries(struct inode *inode, int to, bool force, pgoff_t index, pgoff_t end_index, bool sync)
{
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
    struct nova_inode *pi = nova_get_block(sb, sih->pi_addr);
	struct nova_file_write_entry *entry, *last_entry = NULL;
    // struct nova_file_write_entry *entryd;
    struct nova_inode_update update;
	u64 begin_tail = 0;
    unsigned int num_pages;
    unsigned long pgoff;
    int ret = 0;
	loff_t isize = i_size_read(inode);
    
    bool interrupted = false;
    bool full = ((end_index - index) == isize>>PAGE_SHIFT);
    unsigned int nentry = 0;
    
    if (DEBUG_MIGRATION) 
        nova_info("[Migration] Start migrating (by entries) inode %lu to:T%d force:%d (cpu:%d)\n",
        inode->i_ino, to, force, smp_processor_id());

	update.tail = sih->log_tail;
	update.alter_tail = sih->alter_log_tail;

    begin_tail = update.tail;
    
    do {
        if (is_tier_usage_quite_high(sbi, to) || !is_inode_wait_list_empty(inode) || (!sync && kthread_should_stop())) {
            interrupted = true;
            if (MODE_KEEP_STAT) sbi->stat->mig_interrupt++;
            goto end;
        }

        entry = nova_find_next_entry_lockfree(sb, sih, index);
        // nova_info("entry %p\n", entry);
        // nova_info("index:%lu ret:%d\n", index, ret);

        if (entry) {            
            if (entry == last_entry) {
                index++;
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

            // nova_info("Inode %lu Index:%lu entry->pgoff:%lu entry->num_pages:%u \n", 
            //     sih->ino, index, pgoff, num_pages);
            
            if (should_migrate_entry(inode, sih, entry, to, force)) {
                if (DEBUG_MIGRATION_ENTRY) 
                    nova_info("[Migration] Migrating ( one ) write entry with index:%lu (inode %lu)\n", 
                        index, sih->ino);
                ret = migrate_entry_blocks(sbi, to, si, entry, 0, &update, pgoff, num_pages);
            }
            // entryd = nova_find_next_entry_lockfree(sb, sih, index);
            // if (DEBUG_MIGRATION_ENTRY) {
            //     if (entryd) print_a_write_entry(sb, entryd, 0);
            //     else nova_info("entryd: %p\n", entryd);
            // }
            index = (pgoff + num_pages) > index+1 ? pgoff + num_pages : index+1;
            if (DEBUG_MIGRATION) nentry++;
        }
        else {
            if (DEBUG_MIGRATION_ENTRY) nova_info("Entry not found. Inode %lu index:%lu\n",
                inode->i_ino, index);
            index++;
        }
        last_entry = entry;
    } while (index <= end_index);

end:
    if (interrupted) nova_update_sih_tier(sb, sih, to, 5);
    else {
        if (full) nova_update_sih_tier(sb, sih, to, 1);
        else nova_update_sih_tier(sb, sih, to, 4);
    }

    nova_memunlock_inode(sb, pi);
	nova_update_inode(sb, inode, pi, &update, 1);
	nova_memlock_inode(sb, pi);

	nova_inode_log_fast_gc(sb, pi, sih, 0, 0, 0, 0, 0);
    // nova_info("sih->log_pages: %lu\n",sih->log_pages);
    
	if (DEBUG_MIGRATION_SEM) nova_info("Mig_sem (inode %lu) up_write (migrate_a_file_by_entries)\n", sih->ino);
    up_write(&sih->mig_sem);

    inode_unlock(inode);

    if (interrupted) schedule();
    
    if (DEBUG_MIGRATION) 
        nova_info("[Migration] End migrating (by entries) inode %lu to:T%d force:%d (%d entries)\n",
        inode->i_ino, to, force, nentry);

    return ret;
}

// inode->i_rwsem and sih->mig_sem are (write) locked before calling this function
int migrate_file_logs(struct inode *inode, int to, bool force)
{
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
    struct nova_inode *pi = nova_get_block(sb, sih->pi_addr);
    int ret = nova_inode_log_fast_gc_to_bdev(sb, pi, sih, 0, 0, 0, 0, 1);

    nova_update_sih_tier(sb, sih, to, 5);

    up_write(&sih->mig_sem);
    inode_unlock(inode);
    return ret;
}

// inode->i_rwsem and sih->mig_sem are (write) locked before calling this function
int migrate_a_file(struct inode *inode, int to, bool force)
{
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
    struct nova_inode *pi = nova_get_block(sb, sih->pi_addr);
	struct nova_file_write_entry *entry;
    pgoff_t index = 0;
    pgoff_t end_index = 0;
    struct nova_inode_update update;
	u64 begin_tail = 0;
    unsigned int num_pages;
    unsigned long pgoff;

    int ret = 0;
    bool interrupted = false;
    unsigned int i = 0;
    unsigned int oentry = 0;
    unsigned int nentry = 0;
    unsigned int n1 = 0;
    unsigned int n2 = 0;
    loff_t isize = 0;
    bool full = end_index - index == isize>>PAGE_SHIFT;
    // int progress = 0;
    
	timing_t mig_time;

    unsigned int osb = sbi->bdev_list[to - TIER_BDEV_LOW].opt_size_bit;
    
	NOVA_START_TIMING(mig_t, mig_time);

    if (!MODE_USE_GROUP || to == TIER_PMEM) 
        return migrate_a_file_to_tier(inode, to, force);

    if (DEBUG_MIGRATION) nova_info("[Migration] Start migrating inode %lu to:T%d force:%d (cpu:%d)\n",
        inode->i_ino, to, force, smp_processor_id());

	update.tail = sih->log_tail;
	update.alter_tail = sih->alter_log_tail;

    begin_tail = update.tail;

	isize = i_size_read(inode);
	end_index = (isize) >> PAGE_SHIFT;
    
    for (i=0;i<=end_index>>osb;++i) {
next:
        if (is_tier_usage_really_high(sbi, to) || !is_inode_wait_list_empty(inode) || kthread_should_stop()) {
            interrupted = true;
            if (MODE_KEEP_STAT) sbi->stat->mig_interrupt++;
            goto end;
        }

        n1 = 0;
        n2 = 0;
        index = i<<osb;
        // if (i*10 > progress*(end_index>>osb)) {
        //     if (DEBUG_MIGRATION) 
        //         nova_info("[Migration] Progress:%3d%% Index:%lu\n", 10*(progress++), index);
        // }
        do {
            nova_set_stage(3);
            entry = nova_find_next_entry(sb, sih, index);
            if (entry) {
                put_write_entry(entry);
                if (get_entry_tier(entry) == to) {
                        goto mig;
                }
                if ( (entry->pgoff)>>osb > i ) {
                    if (n1==0) {
                        i = (entry->pgoff)>>osb;
                        goto next;
                    }
                    else goto mig;
                }
                if (!should_migrate_entry(inode, sih, entry, to, force)) goto mig;

                if (entry->reassigned) {
                    pgoff = index;
                    num_pages = valid_index_range(sb, sih, index);
                }
                else {
                    pgoff = le64_to_cpu(entry->pgoff);
                    num_pages = le32_to_cpu(entry->num_pages);
                }
                
                if (is_entry_cross_boundary(sbi, to, pgoff, num_pages)) {
                    if (n1 == 0) {
                        goto mig;
                    }
                    num_pages = nova_split_write_entry(sbi, si, entry, to, &update, pgoff, num_pages);
                }
                index = (pgoff + num_pages) > index+1 ? pgoff + num_pages : index+1;
                n1++;
            }
            else goto mig;
        } while (index < (i+1)<<osb);

        if (index == (i+1)<<osb) {
            if (n1!=1) {
                migrate_group_entry_blocks(sbi, inode, to, i<<osb, (i+1)<<osb, &update);
                if (DEBUG_MIGRATION) {
                    oentry += n1;
                    nentry += 1;
                }
                continue;
            }
            else {
                if (entry->reassigned) {
                    pgoff = index;
                    num_pages = valid_index_range(sb, sih, index);
                }
                else {
                    pgoff = le64_to_cpu(entry->pgoff);
                    num_pages = le32_to_cpu(entry->num_pages);
                }
                if (entry->num_pages == 0) nova_info("Error: num_pages 0 here\n");
                ret = migrate_entry_blocks(sbi, to, si, entry, 0, &update, pgoff, num_pages);
                if (DEBUG_MIGRATION) {
                    oentry += 1;
                    nentry += 1;
                }
                continue;
            }
        }
    // This osb section can only be migrated individually
mig: 
        index = i<<osb;
        do {
            nova_set_stage(5);
            entry = nova_find_next_entry_lockfree(sb, sih, index);
            // nova_info("entry %p\n", entry);
            // nova_info("index:%lu ret:%d\n", index, ret);

            if (entry) {
                // if (is_entry_cross_boundary(sbi, entry, to)) {
                //     nova_split_write_entry(sbi, si, entry, to, &update);
                // }
                if (entry->num_pages == 0) break;
                if (entry->reassigned) {
                    pgoff = index;
                    num_pages = valid_index_range(sb, sih, index);
                }
                else {
                    pgoff = le64_to_cpu(entry->pgoff);
                    num_pages = le32_to_cpu(entry->num_pages);
                }
                if ((entry->pgoff)>>osb != i) {
                    // nova_info("Error pgoff %llu i %d\n", entry->pgoff, i);
                    index = (pgoff + num_pages) > index+1 ? pgoff + num_pages : index+1;
                    continue;
                }
                if (should_migrate_entry(inode, sih, entry, to, force)) {
                    if (DEBUG_MIGRATION_ENTRY) 
                        nova_info("[Migration] Migrating ( one ) write entry with index:%lu (inode %lu)\n", 
                            index, sih->ino);
                    ret = migrate_entry_blocks(sbi, to, si, entry, 0, &update, pgoff, num_pages);
                }
                index = (pgoff + num_pages) > index+1 ? pgoff + num_pages : index+1;
                n2++;
            }
            else index++;
        } while (index < (i+1)<<osb);
        if (DEBUG_MIGRATION) {
            oentry += n2;
            nentry += n2;
        }
    }

end:
    nova_set_stage(8);
    if (interrupted) nova_update_sih_tier(sb, sih, to, 5);
    else {
        if (full) nova_update_sih_tier(sb, sih, to, 1);
        else nova_update_sih_tier(sb, sih, to, 4);
    }

    nova_memunlock_inode(sb, pi);
	nova_update_inode(sb, inode, pi, &update, 1);
	nova_memlock_inode(sb, pi);

	nova_inode_log_fast_gc(sb, pi, sih, 0, 0, 0, 0, 1);

    if (DEBUG_MIGRATION) 
        nova_info("[Migration] End migrating inode %lu to:T%d force:%d (E %u->%u) I:%d F:%d\n",
        inode->i_ino, to, force, oentry, nentry, interrupted?1:0, full?1:0);

	if (DEBUG_MIGRATION_SEM) nova_info("Mig_sem (inode %lu) up_write (migrate_a_file)\n", sih->ino);
    up_write(&sih->mig_sem);

    inode_unlock(inode);

	NOVA_END_TIMING(mig_t, mig_time);

    if (interrupted) schedule();
    
    return ret;
}

unsigned long nova_pmem_used(struct nova_sb_info *sbi) {
	struct super_block *sb = sbi->sb;
    unsigned long used = 0;
    int i;
	struct free_list *fl = NULL;
	for (i=0;i<sbi->cpus;++i) {
		fl = nova_get_free_list(sb, i);
        used += fl->block_end - fl->block_start + 1 - fl->num_free_blocks;
	}
    return used;
}

unsigned long nova_pmem_total(struct nova_sb_info *sbi) {
	struct super_block *sb = sbi->sb;
    unsigned long total = 0;
    int i;
	struct free_list *fl = NULL;
	for (i=0;i<sbi->cpus;++i) {
		fl = nova_get_free_list(sb, i);
        total += fl->block_end - fl->block_start + 1;
	}
    return total;
}

// Used for reverse migration
inline bool is_pmem_usage_quite_high(struct nova_sb_info *sbi) {
    return sbi->stat->tier_usage_quite_high[TIER_PMEM];
}

// Used for migration
inline bool is_pmem_usage_high(struct nova_sb_info *sbi) {
    return sbi->stat->tier_usage_high[TIER_PMEM];
}

// Used for foreground allocation
inline bool is_pmem_usage_really_high(struct nova_sb_info *sbi) {
    return sbi->stat->tier_usage_really_high[TIER_PMEM];
}

// Used for log allocation
inline bool is_pmem_usage_too_high(struct nova_sb_info *sbi) {
    return sbi->stat->tier_usage_too_high[TIER_PMEM];
}

unsigned long nova_bdev_used(struct nova_sb_info *sbi, int tier) {
    unsigned long used = 0;
    int i;
	struct bdev_free_list *bfl = NULL;
	for (i=0;i<sbi->cpus;++i) {
		bfl = nova_get_bdev_free_list(sbi,tier,i);
        used += bfl->num_total_blocks - bfl->num_free_blocks;
	}
    return used;
}

unsigned long nova_bdev_total(struct nova_sb_info *sbi, int tier) {
    unsigned long total = 0;
    int i;
	struct bdev_free_list *bfl = NULL;
	for (i=0;i<sbi->cpus;++i) {
		bfl = nova_get_bdev_free_list(sbi, tier, i);
        total += bfl->num_total_blocks;
	}
    return total;
}

// Used for reverse migration
inline bool is_bdev_usage_quite_high(struct nova_sb_info *sbi, int tier) {
    return sbi->stat->tier_usage_quite_high[tier];
}

// Used for migration
inline bool is_bdev_usage_high(struct nova_sb_info *sbi, int tier) {
    return sbi->stat->tier_usage_high[tier];
}

// Used for foreground allocation
inline bool is_bdev_usage_really_high(struct nova_sb_info *sbi, int tier) {
    return sbi->stat->tier_usage_really_high[tier];
}

inline bool is_tier_usage_really_high(struct nova_sb_info *sbi, int tier) {
    if (tier == TIER_PMEM) return is_pmem_usage_really_high(sbi);
    else return is_bdev_usage_really_high(sbi, tier);
}

inline bool is_tier_usage_quite_high(struct nova_sb_info *sbi, int tier) {
    if (tier == TIER_PMEM) return is_pmem_usage_quite_high(sbi);
    else return is_bdev_usage_quite_high(sbi, tier);
}

int get_lowest_tier(struct super_block *sb) {
	struct nova_sb_info *sbi = NOVA_SB(sb);
    unsigned long used = nova_pmem_used(sbi);
    unsigned long total = nova_pmem_total(sbi);
    unsigned long low = (used << 7) / total;
    unsigned long this;
    int i, tier = TIER_PMEM;
    for (i=TIER_BDEV_LOW;i<=TIER_BDEV_HIGH;++i) {
        used = nova_bdev_used(sbi, i);
        total = nova_bdev_total(sbi, i);
        this = (used << 7) / total;
        if (this<low) {
            tier = i;
            low = this;
        }
    }
    return tier;
}

int get_available_tier(struct super_block *sb, int tier) {
	struct nova_sb_info *sbi = NOVA_SB(sb);
    int i;
    for (i=tier;i<=TIER_BDEV_HIGH;++i) {
        if (!is_tier_usage_really_high(sbi, i)) return i;
    }
    for (i=TIER_PMEM;i<tier;++i) {
        if (!is_tier_usage_really_high(sbi, i)) return i;
    }
    return TIER_PMEM;
}

// Get an inode with tier, starting from the smallest inode number
struct inode *pop_an_inode_to_migrate_by_ino(struct nova_sb_info *sbi, int tier) {
	struct super_block *sb = sbi->sb;
	struct inode_map *inode_map;
	struct nova_range_node *i, *next_i;
	struct rb_node *next;
    int j, jj;
    unsigned long k;
    unsigned long ino = 0;
    int cpu = smp_processor_id();

    struct inode *ret;
	struct nova_inode_info *si;
	struct nova_file_write_entry *entry;

    for (jj=cpu;jj<cpu+sbi->cpus;++jj) {
        if (MODE_MIG_SELF && jj!=cpu) break;
        j = jj%(sbi->cpus);
        inode_map = &sbi->inode_maps[j];
        i = inode_map->first_inode_range;
        next = &i->node;

        more:
        if (!next) {
            next_i = NULL;
            continue;
        } else {
            next_i = container_of(next, struct nova_range_node, node);
            for (k=next_i->range_low;k<=next_i->range_high;++k) {
                if (k<=8) continue;
                // nova_info("Inode found: [%d] %lu\n",j,k*sbi->cpus+j);

                ino = k*sbi->cpus+j;
                ret = nova_iget(sb, ino);
                if (!ret) goto next;
                si = NOVA_I(ret);
                if (!si) goto next;
                entry = nova_find_next_entry_lockfree(sb, &si->header, 0);
                if (!entry) goto next;
                if (get_entry_tier(entry) == tier) {
                    if(DEBUG_MIGRATION) nova_info("Inode %lu is poped.\n",ino);
                    return ret;
                }
            }
        }
        next:
        next = rb_next(next);
        goto more;
    }
    return NULL;
}

/*
 * Get a lru inode with tier
 * Order: [1] The lru inode of [tier, this cpu]
 *        [2] The lru inode of [tier, other cpu]
 *        [3] NULL
 * Return an inode with mig_sem and i_rwsem locked
 */
struct inode *pop_an_inode_to_migrate(struct nova_sb_info *sbi, int tier, struct inode *last) {
	struct super_block *sb = sbi->sb;
    struct nova_inode_info *si;
	struct nova_inode_info_header *sih, *tmpsih;
    struct nova_inode *pi;
	struct list_head *list;
    struct mutex *mutex;
    struct inode *ret;
    int cpu = smp_processor_id();
    int j, jj;
	timing_t pop_time;

	NOVA_START_TIMING(pop_t, pop_time);

    nova_set_stage(2);
    for (jj=cpu;jj<cpu+sbi->cpus;++jj) {
        if (MODE_MIG_SELF && jj!=cpu) break;
        j = jj%(sbi->cpus);
        mutex = nova_get_inode_lru_mutex(sbi, tier, j);
        mutex_lock(mutex);
        list = nova_get_inode_lru_lists(sbi, tier, j);
        list_for_each_entry_safe(sih, tmpsih, list, lru_list[tier]) {
            if (DEBUG_MIGRATION) nova_info("[C%2d] Inode %lu is selected.\n", cpu, sih->ino);
            if (sih->lru_list[tier].next == &sih->lru_list[tier]) {
                nova_info("Error: sih->lru_list[%d].next is self.\n", tier);
                break;
            }
            if (sih->ino<36) {
                nova_info("Error: sih->ino is %lu.\n", sih->ino);
                continue;
            }
            pi = nova_get_block(sb, sih->pi_addr);
            if (!pi) {
                nova_info("Error: pi is NULL, sih->pi_addr %lu.\n", sih->pi_addr);
                continue;
            }
            si = container_of(sih, struct nova_inode_info, header);
            if (!si) {
                nova_info("Error: si is NULL.\n");
                continue;
            }
            ret = &si->vfs_inode;
            if (!ret) {
                nova_info("Error: ret is NULL.\n");
                continue;
            }
            if (ret == last) {
                if (DEBUG_MIGRATION) nova_info("Warning: ret is last\n");
                continue;
            }
            if (!i_size_read(ret)) {
                if (DEBUG_MIGRATION) nova_info("Warning: Inode %lu ret->i_size is 0.\n", sih->ino);
                continue;
            }
            if (!inode_trylock(ret)) {
                if (DEBUG_MIGRATION) nova_info("Warning: Inode %lu rw_sem is locked.\n", sih->ino);
                continue;
            }
            if (!down_write_trylock(&sih->mig_sem)) {
                inode_unlock(ret);
                if (DEBUG_MIGRATION) nova_info("Warning: Inode %lu is locked.\n", sih->ino);
                continue;
            }
            if (DEBUG_MIGRATION) nova_info("[C%2d] Inode %lu is poped.\n", cpu, sih->ino);
            mutex_unlock(mutex);
	        NOVA_END_TIMING(pop_t, pop_time);
            return ret;
        }
        mutex_unlock(mutex);
    }
        
	NOVA_END_TIMING(pop_t, pop_time);
    return NULL;
}

struct inode *pop_an_inode_to_migrate_reverse(struct nova_sb_info *sbi, int tier) {
	struct super_block *sb = sbi->sb;
    struct nova_inode_info *si;
	struct nova_inode_info_header *sih, *tmpsih;
    struct nova_inode *pi;
	struct list_head *list;
    struct mutex *mutex;
    struct inode *ret;
    int cpu = smp_processor_id();
    int j, jj;
    bool first = false;
	timing_t pop_time;

	NOVA_START_TIMING(pop_t, pop_time);

    for (jj=cpu;jj<cpu+sbi->cpus;++jj) {
        if (MODE_MIG_SELF && jj!=cpu) break;
        j = jj%(sbi->cpus);
        mutex = nova_get_inode_lru_mutex(sbi, tier, j);
        mutex_lock(mutex);
        list = nova_get_inode_lru_lists(sbi, tier, j);
        list_for_each_entry_safe_reverse(sih, tmpsih, list, lru_list[tier]) {
            if (first) {
                first = false;
                continue;
            }
            if (DEBUG_MIGRATION) nova_info("Inode %lu is selected.\n", sih->ino);
            if (sih->lru_list[tier].next == &sih->lru_list[tier]) {
                nova_info("Error: sih->lru_list[%d].next is self.\n", tier);
                break;
            }
            if (sih->ino<36) {
                nova_info("Error: sih->ino is %lu.\n", sih->ino);
                continue;
            }
            pi = nova_get_block(sb, sih->pi_addr);
            if (!pi) {
                nova_info("Error: pi is NULL, sih->pi_addr %lu.\n", sih->pi_addr);
                continue;
            }
            si = container_of(sih, struct nova_inode_info, header);
            if (!si) {
                nova_info("Error: si is NULL.\n");
                continue;
            }
            ret = &si->vfs_inode;
            if (!ret) {
                nova_info("Error: ret is NULL.\n");
                continue;
            }
            if (!i_size_read(ret)) {
                if (DEBUG_MIGRATION) nova_info("Warning: Inode %lu ret->i_size is 0.\n", sih->ino);
                continue;
            }
            if (!inode_trylock(ret)) {
                if (DEBUG_MIGRATION) nova_info("Warning: Inode %lu rw_sem is locked.\n", sih->ino);
                continue;
            }
            if (!down_write_trylock(&sih->mig_sem)) {
                inode_unlock(ret);
                if (DEBUG_MIGRATION) nova_info("Warning: Inode %lu mig_sem is locked.\n", sih->ino);
                continue;
            }
            if (DEBUG_MIGRATION) nova_info("Inode %lu is poped.\n", sih->ino);
            mutex_unlock(mutex);
	        NOVA_END_TIMING(pop_t, pop_time);
            return ret;
        }
        mutex_unlock(mutex);
    }
        
	NOVA_END_TIMING(pop_t, pop_time);
    return NULL;
}

// Used only during migration (previously locked)
int migrate_a_file_to_tier(struct inode *inode, int to, bool force) {
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	loff_t isize = i_size_read(inode);
    if (get_htier(inode) == to && get_ltier(inode) == to) {
	    if (DEBUG_MIGRATION_SEM) nova_info("Mig_sem (inode %lu) up_write (migrate_a_file_to_tier)\n", sih->ino);
        up_write(&sih->mig_sem);
        inode_unlock(inode);
        return 0;
    }
    else {
        return migrate_a_file_by_entries(inode, to, force, 0, (isize) >> PAGE_SHIFT, false);
    }
}

// Used during foreground operations (not previously locked)
inline int migrate_a_file_to_pmem(struct inode *inode) {
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
    inode_lock(inode);
	if (DEBUG_MIGRATION_SEM) nova_info("Mig_sem (inode %lu) down_write (migrate_a_file_to_pmem)\n", sih->ino);
    down_write(&sih->mig_sem);
    return migrate_a_file_to_tier(inode, TIER_PMEM, true);
}

// Used only during migration (previously locked)
int migrate_a_file_to_tier_partial(struct inode *inode, int to, bool force, pgoff_t index, pgoff_t end_index, bool sync) {
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
    if (get_htier(inode) == to && get_ltier(inode) == to)  {
	    if (DEBUG_MIGRATION_SEM) nova_info("Mig_sem (inode %lu) up_write (migrate_a_file_to_tier_partial)\n", sih->ino);
        up_write(&sih->mig_sem);
        inode_unlock(inode);
        return 0;
    }
    else {
        return migrate_a_file_by_entries(inode, to, force, index, end_index, sync);
    }
}

// Used during foreground operations (not previously locked)
inline int migrate_a_file_to_pmem_partial(struct inode *inode, pgoff_t index, pgoff_t end_index, bool sync) {
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
    inode_lock(inode);
	if (DEBUG_MIGRATION_SEM) nova_info("Mig_sem (inode %lu) down_write (migrate_a_file_to_pmem_partial)\n", sih->ino);
    down_write(&sih->mig_sem);
    return migrate_a_file_to_tier_partial(inode, TIER_PMEM, true, index, end_index, sync);
}

int do_migrate_a_file_rotate(struct inode *inode) {
	if (DEBUG_MIGRATION) nova_info("[Migration-Rotate]\n");
    // We no longer care if inode is in the same tier or not.
    // ret = is_not_same_tier(inode);
    // if (ret) {
    //     if(DEBUG_MIGRATION) nova_info("Write entries of inode %lu is not in the same tier (index: %d)", inode->i_ino, ret);
    //     return -1;
    // }
    switch (get_ltier(inode)) {
        case TIER_PMEM:
            return migrate_a_file(inode, TIER_BDEV_LOW, true);
        case TIER_BDEV_LOW:
            if (DEBUG_XFSTESTS) 
                return migrate_a_file(inode, TIER_PMEM, true);
            else 
                return migrate_a_file(inode, TIER_BDEV_HIGH, true);
        case TIER_BDEV_LOW+1:
            return migrate_a_file(inode, TIER_PMEM, true);
        default:
            if(DEBUG_MIGRATION) 
                nova_info("Unsupported migration of inode %lu at tier %d", 
                    inode->i_ino, get_ltier(inode));
    }
    return -1;
}

int do_migrate_a_file_downward(struct super_block *sb, int cpu) {
	struct nova_sb_info *sbi = NOVA_SB(sb);
    struct inode *this = NULL;    
    int i;
	// if (DEBUG_MIGRATION) nova_info("[Migration-Downward]\n");
    
    nova_set_stage(1);
    if (!is_pmem_usage_high(sbi)) goto again_bdev;
again_pmem:
    if (kthread_should_stop()) return -1;
    if (is_pmem_usage_quite_high(sbi)) {
        if(DEBUG_MIGRATION_INFO) nova_info("[C%2d] \e[1;31mPMEM usage high.\e[0m\n", cpu);
        if (MODE_MIG_SELF && is_inode_lru_list_empty(sbi, TIER_PMEM, cpu))
            goto again_bdev;
        this = pop_an_inode_to_migrate(sbi, TIER_PMEM, this);
        if (!this) {
            if(DEBUG_MIGRATION_INFO) nova_info("[C%2d] PMEM usage is high yet no inode is found.\n", cpu);
            schedule();
            goto again_bdev;
        }
	    migrate_a_file(this, get_available_tier(sb, TIER_BDEV_LOW), false);
        nova_set_stage(9);
        schedule();
        // Multiple migration per loop
	    goto again_pmem;
    }
    else if(DEBUG_MIGRATION_INFO) nova_info("[C%2d] \e[1;32mPMEM usage low.\e[0m\n", cpu);
            
again_bdev:
    if (kthread_should_stop()) return -1;
    for (i=TIER_BDEV_LOW;i<TIER_BDEV_HIGH;++i) {
        if (is_bdev_usage_high(sbi, i)) {
            if(DEBUG_MIGRATION_INFO) nova_info("[C%2d] \e[1;31mB-T%d usage high.\e[0m\n", cpu, i);
            if (MODE_MIG_SELF && is_inode_lru_list_empty(sbi, TIER_PMEM, cpu))
                goto again_log;    
            this = pop_an_inode_to_migrate(sbi, i, this);
            if (!this) {
                if(DEBUG_MIGRATION_INFO) nova_info("[C%2d] B-T%d usage is high yet no inode is found.\n", cpu, i);
                goto again_log;
            }
            migrate_a_file(this, get_available_tier(sb, i+1), false);
            schedule();
            // One migration per loop
            goto again_log;
        }
        else if(DEBUG_MIGRATION_INFO) nova_info("[C%2d] \e[1;32mB-T%d usage low.\e[0m\n", cpu, i);
    }
    
again_log:
//  && is_pmem_usage_too_high(sbi)
    if (kthread_should_stop()) return -1;
    for (i=TIER_BDEV_LOW;i<=TIER_BDEV_HIGH;++i) {
        if (MODE_LOG_MIG && is_should_migrate_log()) {
            if(DEBUG_MIGRATION_INFO) nova_info("[C%2d] \e[1;31mPMEM usage too high.\e[0m\n", cpu);
            this = pop_an_inode_to_migrate(sbi, i, this);
            if (!this) {
                if(DEBUG_MIGRATION_INFO) nova_info("[C%2d] B-T%d no inode is found.\n", cpu, i);
                goto again_rev;
            }
            migrate_file_logs(this, get_available_tier(sb, i), false);
            schedule();
            // One migration per loop
            goto again_rev;
        }
        else if(DEBUG_MIGRATION_INFO) nova_info("[C%2d] \e[1;32mPMEM usage not too high.\e[0m\n", cpu);
    }
    
    if (MODE_REV_MIG) {
again_rev:
        if (kthread_should_stop()) return -1;
        if (sbi->stat->adv<3) return 0;
        for (i=TIER_BDEV_LOW;i<=TIER_BDEV_HIGH;++i) {
            if (!is_pmem_usage_quite_high(sbi)) {
                if(DEBUG_MIGRATION_INFO) nova_info("[C%2d] \e[1;31mPMEM usage quite low.\e[0m\n", cpu);
                this = pop_an_inode_to_migrate_reverse(sbi, i);
                if (!this) {
                    if(DEBUG_MIGRATION_INFO) nova_info("[C%2d] PMEM usage is quite low yet no inode is found.\n", cpu);
                    goto end;
                }
                migrate_a_file(this, get_available_tier(sb, TIER_PMEM), true);
                schedule();
                // One migration per loop
                goto end;
            }
            else if(DEBUG_MIGRATION_INFO) nova_info("[C%2d] \e[1;31mPMEM usage quite high.\e[0m\n", cpu);
        }
    }

end:
    return 0;
}

void wake_up_bm(struct nova_sb_info *sbi) {
    int i;
	if (sbi->bm_thread) {
		smp_mb();
        for (i=0; i<sbi->cpus; ++i) wake_up_process(sbi->bm_thread[i].nova_task);
	}
}

static int bm_thread_func(void *data) {
	struct nova_sb_info *sbi = data;
	struct super_block *sb = sbi->sb;
    int cpu = 0;
    do {
		// set_current_state(TASK_UNINTERRUPTIBLE);
		// schedule();
		schedule_timeout_interruptible(msecs_to_jiffies(BM_THREAD_SLEEP_TIME));
        cpu = smp_processor_id();
        if (DEBUG_KTHREAD) nova_info("---- [Background Migration Thread - C%2d] ----\n", cpu);
        if (MODE_BACK_MIG && MIGRATION_POLICY == MIGRATION_DOWNWARD ) do_migrate_a_file_downward(sb, cpu);
    } while(!kthread_should_stop());  
    return 0;
}

int start_bm_thread(struct nova_sb_info *sbi) {
	struct nova_kthread *bm_thread = NULL;
	int i, err = 0;
    int cpus = sbi->cpus;
    char stmp[100] = {0};
    
	sbi->bm_thread = NULL;
	/* Initialize background migration kthread */
	bm_thread = kcalloc(cpus, sizeof(struct nova_kthread), GFP_KERNEL);
	if (!bm_thread) {
		return -ENOMEM;
	}

	for (i=0; i<cpus; ++i) {
        init_waitqueue_head(&(bm_thread[i].wait_queue_head));
        bm_thread[i].index = i;
        bm_thread[i].stage = 0;
        sprintf(&stmp[0], "NOVA_BM_C%d",i);
        bm_thread[i].nova_task = kthread_create(bm_thread_func, sbi, stmp);
		kthread_bind(bm_thread[i].nova_task, i);

        if (IS_ERR(bm_thread[i].nova_task)) {
            err = PTR_ERR(bm_thread[i].nova_task);
            goto free;
        }
	}

	sbi->bm_thread = bm_thread;
    wake_up_bm(sbi);

	return 0;

free:
	kfree(bm_thread);
	return err;
}

void stop_bm_thread(struct nova_sb_info *sbi) {
    int i;
	if (sbi->bm_thread) {		
	    for (i=0; i<sbi->cpus; ++i) kthread_stop(sbi->bm_thread[i].nova_task);
		kfree(sbi->bm_thread);
		sbi->bm_thread = NULL;
	}
}

int nova_update_usage(struct super_block *sb) {
	struct nova_sb_info *sbi = NOVA_SB(sb);
    unsigned long used;
    unsigned long total;
    int tier;
    // nova_info("usage\n");

    /* VPMEM usage */
    set_should_migrate_log();
    set_is_pgcache_large();
    set_is_pgcache_ideal();
    set_is_pgcache_quite_small();
    set_is_pgcache_very_small();
    set_is_pgcache_small();

    /* PMEM usage */
    used = nova_pmem_used(sbi);
    total = nova_pmem_total(sbi);
    // Usage high: used / total > (MIGRATION_DOWN_PMEM_PERC-10) / 100
    if (DEBUG_MIGRATION_USAGE) nova_info("PMEM usage: U:%8lu G:%8lu T:%8lu.\n",
        used, (MIGRATION_DOWN_PMEM_PERC-10) * total / 100, total);
    sbi->stat->tier_usage_quite_high[TIER_PMEM]
        = used * 100 > (MIGRATION_DOWN_PMEM_PERC-10) * total;
    // Usage high: used / total > MIGRATION_DOWN_PMEM_PERC / 100
    if (DEBUG_MIGRATION_USAGE) nova_info("PMEM usage: U:%8lu G:%8lu T:%8lu.\n",
        used, MIGRATION_DOWN_PMEM_PERC * total / 100, total);
    sbi->stat->tier_usage_high[TIER_PMEM] 
        = used * 100 > MIGRATION_DOWN_PMEM_PERC * total;
    // Usage high: used / total > MIGRATION_FORCE_PERC / 100
    if (DEBUG_MIGRATION_USAGE) nova_info("PMEM usage: U:%8lu G:%8lu T:%8lu.\n",
        used, MIGRATION_FORCE_PERC * total / 100, total);
    sbi->stat->tier_usage_really_high[TIER_PMEM]
        = used * 100 > MIGRATION_FORCE_PERC * total;
    // Usage high: used / total > MIGRATION_MAX_PERC / 100
    if (DEBUG_MIGRATION_USAGE) nova_info("PMEM usage: U:%8lu G:%8lu T:%8lu.\n",
        used, MIGRATION_MAX_PERC * total / 100, total);
    sbi->stat->tier_usage_too_high[TIER_PMEM]
        = used * 100 > MIGRATION_MAX_PERC * total;

    /* BDEV usage */
    for (tier = TIER_BDEV_LOW; tier<= TIER_BDEV_HIGH; ++tier) {
        used = nova_bdev_used(sbi, tier);
        total = nova_bdev_total(sbi, tier);
        // Usage high: used / total > (MIGRATION_DOWN_BDEV_PERC-10) / 100
        if (DEBUG_MIGRATION_USAGE) nova_info("B-T%d usage: U:%8lu G:%8lu T:%8lu.\n", 
            tier, used, (MIGRATION_DOWN_BDEV_PERC-10) * total / 100, total);
        sbi->stat->tier_usage_quite_high[tier]
            = used * 100 > (MIGRATION_DOWN_BDEV_PERC-10) * total;
        // Usage high: used / total > MIGRATION_DOWN_BDEV_PERC / 100
        if (DEBUG_MIGRATION_USAGE) nova_info("B-T%d usage: U:%8lu G:%8lu T:%8lu.\n", 
            tier, used, MIGRATION_DOWN_BDEV_PERC * total / 100, total);
        sbi->stat->tier_usage_high[tier]
            = used * 100 > MIGRATION_DOWN_BDEV_PERC * total;
        // Usage high: used / total > MIGRATION_FORCE_PERC / 100
        if (DEBUG_MIGRATION_USAGE) nova_info("B-T%d usage: U:%8lu G:%8lu T:%8lu.\n", 
            tier, used, MIGRATION_FORCE_PERC * total / 100, total);
        sbi->stat->tier_usage_really_high[tier]
            = used * 100 > MIGRATION_FORCE_PERC * total;
        // Usage high: used / total > MIGRATION_MAX_PERC / 100
        if (DEBUG_MIGRATION_USAGE) nova_info("B-T%d usage: U:%8lu G:%8lu T:%8lu.\n",
            tier, used, MIGRATION_MAX_PERC * total / 100, total);
        sbi->stat->tier_usage_too_high[tier]
            = used * 100 > MIGRATION_MAX_PERC * total;        
    }
    return 0;
}

void wake_up_usage(struct nova_sb_info *sbi) {
	if (sbi->usage_thread) {
		smp_mb();
        wake_up_process(sbi->usage_thread->nova_task);
	}
}

static int usage_thread_func(void *data) {
	struct nova_sb_info *sbi = data;
	struct super_block *sb = sbi->sb;
    do {
		schedule_timeout_interruptible(msecs_to_jiffies(USAGE_THREAD_SLEEP_TIME));
        if (DEBUG_KTHREAD) nova_info("---- [Usage Migration Thread] ----\n");
        nova_update_usage(sb);
    } while(!kthread_should_stop());  
    return 0;
}

int start_usage_thread(struct nova_sb_info *sbi) {
	struct nova_kthread *usage_thread = NULL;
	int err = 0;
    char stmp[100] = "NOVA_USAGE";

	sbi->usage_thread = NULL;
	/* Initialize background usage info kthread */
	usage_thread = kzalloc(sizeof(struct nova_kthread), GFP_KERNEL);
	if (!usage_thread) {
		return -ENOMEM;
	}

    init_waitqueue_head(&(usage_thread->wait_queue_head));
    // sprintf(&stmp[0], "NOVA_USAGE");
    usage_thread->nova_task = kthread_create(usage_thread_func, sbi, stmp);
    kthread_bind(usage_thread->nova_task, sbi->cpus/2-1);

    if (IS_ERR(usage_thread->nova_task)) {
        err = PTR_ERR(usage_thread->nova_task);
        goto free;
    }

	sbi->usage_thread = usage_thread;
    wake_up_usage(sbi);

	return 0;

free:
	kfree(usage_thread);
	return err;
}

void stop_usage_thread(struct nova_sb_info *sbi) {
	if (sbi->usage_thread) {		
	    kthread_stop(sbi->usage_thread->nova_task);
		kfree(sbi->usage_thread);
		sbi->usage_thread = NULL;
	}
}