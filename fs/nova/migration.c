#include "nova.h"
#include "bdev.h"

/* 
 * [About Mini Buffer]
 * It is a temporary buffer solution for tiering file system.
 * Includes: (for each buffer page)
 *      mb_sem: the rw_semaphore
 *          down_read: mini-buffer in use
 *          down_write: under-migration
 *      tier: tier number
 *      blocknr: blocknr in this tier
 *      mb_pages: actual mini-buffer page
 */

// Allocate a DRAM buffer in sbi
int init_dram_buffer(struct nova_sb_info *sbi) {
    unsigned int i = 0;

	sbi->mb_sem = kcalloc(MINI_BUFFER_PAGES, sizeof(struct rw_semaphore), GFP_KERNEL);
	if (!sbi->mb_sem) return -ENOMEM;

	// sbi->mb_count = kcalloc(MINI_BUFFER_PAGES, sizeof(int), GFP_KERNEL);
	// if (!sbi->mb_count) return -ENOMEM;

	sbi->mb_tier = kcalloc(MINI_BUFFER_PAGES, sizeof(int), GFP_KERNEL);
	if (!sbi->mb_tier) return -ENOMEM;

	sbi->mb_blockoff = kcalloc(MINI_BUFFER_PAGES, sizeof(int), GFP_KERNEL);
	if (!sbi->mb_blockoff) return -ENOMEM;

	sbi->mini_buffer = kcalloc(MINI_BUFFER_PAGES, IO_BLOCK_SIZE, GFP_KERNEL);
	if (!sbi->mini_buffer) return -ENOMEM;

    sbi->mb_pages = kcalloc(MINI_BUFFER_PAGES, sizeof(struct page *), GFP_KERNEL);
	if (!sbi->mb_pages) return -ENOMEM;

	sbi->bdev_buffer = kcalloc(BDEV_BUFFER_PAGES, IO_BLOCK_SIZE, GFP_KERNEL);
	if (!sbi->bdev_buffer) return -ENOMEM;

    sbi->bb_pages = kcalloc(BDEV_BUFFER_PAGES, sizeof(struct page *), GFP_KERNEL);
	if (!sbi->bb_pages) return -ENOMEM;

	mutex_init(&sbi->mb_mutex);

	for (i = 0; i < MINI_BUFFER_PAGES; i++) {
    	init_rwsem(&sbi->mb_sem[i]);
        sbi->mb_pages[i] = virt_to_page(sbi->mini_buffer+i*IO_BLOCK_SIZE);
    }
    
	mutex_init(&sbi->bb_mutex);

	for (i = 0; i < BDEV_BUFFER_PAGES; i++) {
        sbi->bb_pages[i] = virt_to_page(sbi->bdev_buffer+i*IO_BLOCK_SIZE);
    }

    sbi->bal_head = kzalloc(sizeof(struct bio_async_list), GFP_KERNEL);
    
	INIT_LIST_HEAD(&sbi->bal_head->list);

    return 0;
}

/*
 * [ONLY FOR STARTUP TEST!]
 * Buffer a data block from bdev to DRAM
 *
 * Strategy: 
 *      Find the first unlock page (local offset)
 *      If none, wait on one according to page offset
 * Return buffer number (locked buffer)
 */ 
int buffer_data_block_from_bdev(struct nova_sb_info *sbi, int tier, unsigned long blockoff) {
    int i = 0;
    int ret = 0;
	struct page *pg;
	if (DEBUG_BUFFERING) nova_info("[Buffering] block:%lu\n" ,blockoff);

	mutex_lock(&sbi->mb_mutex);
	for (i = blockoff%MINI_BUFFER_PAGES; i < blockoff%MINI_BUFFER_PAGES+MINI_BUFFER_PAGES; i++)
		if (down_read_trylock(&sbi->mb_sem[i%MINI_BUFFER_PAGES])) {
            down_read(&sbi->mb_sem[i%MINI_BUFFER_PAGES]);
            goto copy;
        }
    // All mini-buffers are full
    down_read(&sbi->mb_sem[i%MINI_BUFFER_PAGES]);

copy:
	mutex_unlock(&sbi->mb_mutex);
    i = i%MINI_BUFFER_PAGES;
    pg = sbi->mb_pages[i];
    ret = nova_bdev_read_block(sbi, sbi->bdev_list[tier-TIER_BDEV_LOW].bdev_raw, blockoff, 1, pg, BIO_SYNC);

    // print_a_page(&sbi->mini_buffer[i]);
    if (ret) return -ret;
    
    sbi->mb_tier[i] = tier;
    sbi->mb_blockoff[i] = blockoff;
    
    return i;
}

/*
 * put_dram_buffer(): Release the spin lock of the buffer
 *      The buffer is still valid after put()
 * clear_dram_buffer(): Clear the metadata (and data) of the buffer
 *      The buffer is invalid after clear()
 * Must call put() before clear()
 * There is NO DIRTY BUFFER in NOVA, since COW is applied to every write
 */ 
inline int clear_dram_buffer(struct nova_sb_info *sbi, unsigned long number) {
    sbi->mb_tier[number] = TIER_PMEM;
    sbi->mb_blockoff[number] = 0;
    return 0;
}

inline int put_dram_buffer(struct nova_sb_info *sbi, unsigned long number) {
    if (rwsem_is_locked(&sbi->mb_sem[number])) up_read(&sbi->mb_sem[number]);
    return 0;
}

inline int free_dram_buffer(struct nova_sb_info *sbi, unsigned long number) {
    if (rwsem_is_locked(&sbi->mb_sem[number])) {
        // nova_info("mb_sem[%lu]->count = %ld.\n",number,sbi->mb_sem[number].count.counter);
        up_read(&sbi->mb_sem[number]);
    }
    return 0;
}

int free_dram_buffer_range(struct nova_sb_info *sbi, unsigned long number, unsigned long length) {
    unsigned long i;
    if (DEBUG_BUFFERING) print_wb_locks(sbi);
    if (DEBUG_BUFFERING) print_all_wb_locks(sbi);

	mutex_lock(&sbi->mb_mutex);
    for (i=number; i<number+length; ++i) {
        free_dram_buffer(sbi,i);
    }       
	mutex_unlock(&sbi->mb_mutex); 

    if (DEBUG_MIGRATION_FREE) nova_info("put off2 %lu, nr %lu\n",number,length);
    if (DEBUG_BUFFERING) print_wb_locks(sbi);
    if (DEBUG_BUFFERING) print_all_wb_locks(sbi);
    return 0;
}

int clear_dram_buffer_range(struct nova_sb_info *sbi, unsigned long number, int length) {
    unsigned long i;
    for (i=number; i<number+length; ++i) {
        clear_dram_buffer(sbi,i);
    }    
    return 0;
}

int put_dram_buffer_range(struct nova_sb_info *sbi, unsigned long number, unsigned long length) {
    unsigned long i;
    if (DEBUG_BUFFERING) print_wb_locks(sbi);
    if (DEBUG_BUFFERING) print_all_wb_locks(sbi);

	mutex_lock(&sbi->mb_mutex);
    for (i=number; i<number+length; ++i) {
        put_dram_buffer(sbi,i);
    }       
	mutex_unlock(&sbi->mb_mutex); 

    if (DEBUG_MIGRATION_FREE) nova_info("put off2 %lu, nr %lu\n",number,length);
    if (DEBUG_BUFFERING) print_wb_locks(sbi);
    if (DEBUG_BUFFERING) print_all_wb_locks(sbi);
    return 0;
}

bool is_dram_buffer_addr(struct nova_sb_info *sbi, void *addr) {
    unsigned long long a = (unsigned long long)(sbi->mini_buffer) >> (PAGE_SHIFT+MINI_BUFFER_PAGES_BIT);
    unsigned long long b = (unsigned long long)addr >> (PAGE_SHIFT+MINI_BUFFER_PAGES_BIT);
    // nova_info("A%llu\n",(unsigned long long)(sbi->mini_buffer) >> (PAGE_SHIFT+MINI_BUFFER_PAGES_BIT));
    // nova_info("B%llu\n",(unsigned long long)addr >> (PAGE_SHIFT+MINI_BUFFER_PAGES_BIT));
    return (a == b)||(a+1 == b);
}

// Convert from nova_get_block()
inline unsigned long get_dram_buffer_offset(struct nova_sb_info *sbi, void *buf) {
    return ((unsigned long long)buf-(unsigned long long)sbi->mini_buffer) >> PAGE_SHIFT;
}

// Convert from get_nvmm()
inline unsigned long get_dram_buffer_offset_off(struct nova_sb_info *sbi, unsigned long nvmm) {    
    return get_dram_buffer_offset(sbi, (void *)convert_from_logical_offset(nvmm << PAGE_SHIFT));
}

void print_all_wb_locks(struct nova_sb_info *sbi) {
    char* this = kzalloc(4, GFP_KERNEL);
	int wordline = 128;
	char* p = kzalloc(wordline*sizeof(char)+1,GFP_KERNEL);
	int i = 0;
	int j = 0;
    int k = 0;
	char space = ' ';
	p[wordline]='\0';

    nova_info("Locks\n");
	nova_info("----------------\n");
	while (i<MINI_BUFFER_PAGES) {
		p[0]='\0';
		for (j=0;j<wordline;j+=32) {
            do {
                this[0]='0'+sbi->mb_sem[i].count.counter;
                i++;
                strcat(&p[k],this);
            } while (i%32!=0);
			strcat(p,&space);
		}
		nova_info("%s\n",p);
		// i+=wordline;
	}
	nova_info("----------------\n");
}

void print_wb_locks(struct nova_sb_info *sbi) {
    int i = 0;
    int sum = 0;
    for (i = 0; i < MINI_BUFFER_PAGES; i++) {
        if (rwsem_is_locked(&sbi->mb_sem[i])) sum++;
    }
    nova_info("#lock=%d\n",sum);
}

// Return the tier of the first write entry
int current_tier(struct inode *inode) {
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;    
	struct nova_file_write_entry *entry = nova_get_write_entry(sb, sih, 0);
    if (entry) return entry->tier;
    else return -1;
}

// Return 0 if all write entries are in the same tier
// Else the block number of the first write entry with a different tier
unsigned long is_not_same_tier(struct inode *inode) {
	struct super_block *sb = inode->i_sb;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_entry *entry;
    int ct = current_tier(inode);	
    loff_t isize = i_size_read(inode);
    pgoff_t index = 0;
    pgoff_t end_index = (isize) >> PAGE_SHIFT;
    do {
        entry = nova_get_write_entry(sb, sih, index);
        if (entry) {
            if (entry->tier == ct) {
                index += entry->num_pages;
                continue;
            }
            else {
                return index;
            }
        }
        else index++;
    } while (index <= end_index);

    return 0;
}

/* 
 * Find the first continuous buffer which can fit `length`
 * This function should always succeed, it is DRAM buffer's job to allocate such buffer.
 * If space is not enough, swap some pages out to block device.
 */ 
int buffer_data_block_from_bdev_range(struct nova_sb_info *sbi, int tier, int blockoff, int length) {
    int i = 0;
    int j = 0;
    int index = 0; // index of the first block
    int unlock = 0; // number of spinlocks can be unlocked
    int match = 0; // number of matching blocks
    int ret = 0;
	struct page *pg;
    if (length<1) {
        nova_info("buffer_data_block_from_bdev_range length=%d\n",length);
        return -1;
    }

retry:
    index = blockoff%MINI_BUFFER_PAGES;
    match = 0;
    unlock = 0;

	if (DEBUG_BUFFERING) nova_info("[Buffering] block:%d, length:%d\n", blockoff, length);
    if (DEBUG_BUFFERING) print_wb_locks(sbi);
	for (i = blockoff%MINI_BUFFER_PAGES; i < MINI_BUFFER_PAGES; i++) {
        if (!rwsem_is_locked(&sbi->mb_sem[i])) {
            match = 0;
            unlock++;
            if (unlock==length) {
                if (DEBUG_BUFFERING) nova_info("[Buffering] suitable buffer found, off %d, nr %d\n",index,length);
                goto copy;
            }
        }
        else {
            if (sbi->mb_tier[i] == tier && sbi->mb_blockoff[i] == blockoff+match) {
                match++;
                if (match==length) {
                    if (DEBUG_BUFFERING) nova_info("[Buffering] matching buffer found, off %d, nr %d\n",i-length+1,length);
                    goto out;
                }
            }
            unlock = 0;
            index = i+1;
        }
    }
    match = 0;
    unlock = 0;
    index = 0;
    for (i = 0; i < blockoff%MINI_BUFFER_PAGES; i++) {
        if (!rwsem_is_locked(&sbi->mb_sem[i])) {
            match = 0;
            unlock++;
            if (unlock==length) {
                if (DEBUG_BUFFERING) nova_info("[Buffering] suitable buffer found, off %d, nr %d\n",index,length);
                goto copy;
            }
        }
        else {
            if (sbi->mb_tier[i] == tier && sbi->mb_blockoff[i] == blockoff+match) {
                match++;
                if (match==length) {
                    if (DEBUG_BUFFERING) nova_info("[Buffering] matching buffer found, off %d, nr %d\n",i-length+1,length);
                    goto out;
                }
            }
            unlock = 0;
            index = i+1;
        }
    }

/*
 * copy: new clean buffer slot is found
 * out: matching buffer is found
 * No other scenarios
 */
copy:
    // retry is no longer needed in large virtual address space
    if (unlock != length) {
        if (DEBUG_BUFFERING) nova_info("[Buffering] failed\n");
        if (DEBUG_BUFFERING) print_all_wb_locks(sbi);
        if (DEBUG_BUFFERING) nova_info("[Buffering] Retry\n");
		msleep(100);
        goto retry;
    }

    for (i=index;i<index+length;++i) {
        if (rwsem_is_locked(&sbi->mb_sem[i])) {
            if (DEBUG_BUFFERING) print_all_wb_locks(sbi);
            if (i==index) {
                nova_info("Spinlock error in mb[%d]: Try to save by retry.\n",i);
                goto retry;
            }
            nova_info("Spinlock error in mb[%d].\n",i);
            return 0;
        }
    }
    for (i=index;i<index+length;++i) {
        pg = sbi->mb_pages[i];
        ret = nova_bdev_read_block(sbi, sbi->bdev_list[tier-TIER_BDEV_LOW].bdev_raw, 
        get_raw_from_blocknr(sbi, blockoff) + i - index, 1, pg, BIO_SYNC);
        down_read(&sbi->mb_sem[i]);
        sbi->mb_tier[i] = tier;
        sbi->mb_blockoff[i] = blockoff+i-index;
    }

    // print_a_page(&sbi->mini_buffer[i]);
    if (ret) {
        if (DEBUG_BUFFERING) nova_info("[Buffering] nova_bdev_read_block failed.\n");
        return -ret;
    }
    
    return index;

out:

    for (j=i-length+1;j<i+1;++j) {
        down_read(&sbi->mb_sem[j]);
    }

    return i-length+1;
}

/*
 * Migrate continuous blocks from pmem to block device, with block number
 */
int migrate_blocks_pmem_to_bdev(struct nova_sb_info *sbi, 
    void *dax_mem, unsigned long nr, int tier, unsigned long blockoff) {
    struct block_device *bdev_raw = get_bdev_raw(sbi, tier);
    int ret = nova_bdev_write_block(sbi, bdev_raw, blockoff, nr, 
        address_to_page(dax_mem), BIO_ASYNC);
    return ret;
}

/*
 * Migrate continuous blocks from block device to pmem, with block number
 */
int migrate_blocks_bdev_to_pmem(struct nova_sb_info *sbi, 
    void *dax_mem, unsigned long nr, int tier, unsigned long blockoff) {
    struct block_device *bdev_raw = get_bdev_raw(sbi, tier);
    int ret = nova_bdev_read_block(sbi, bdev_raw, blockoff, nr, 
        address_to_page(dax_mem), BIO_ASYNC);
    return ret;
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
bool is_entry_busy(struct nova_sb_info *sbi, struct nova_file_write_entry *entry) {
    int i;
    unsigned long blockoff = entry->block;
    
    if (is_tier_migrating(entry->tier)) return 1;
    if (!is_tier_bdev(entry->tier)) return 0;
    for (i=blockoff%MINI_BUFFER_PAGES; i< blockoff%MINI_BUFFER_PAGES + entry->num_pages; ++i) {
        if (i>=MINI_BUFFER_PAGES) return 0;
        if (sbi->mb_tier[i] == entry->tier 
            && sbi->mb_blockoff[i] == blockoff-blockoff%MINI_BUFFER_PAGES+i
            && rwsem_is_locked(&sbi->mb_sem[i])) return 1;
    }
    
    return 0;
}

int migrate_entry_blocks(struct nova_sb_info *sbi, int from, int to,
    struct nova_inode_info *si, struct nova_file_write_entry *entry, unsigned long blocknr_hint) {
	// struct nova_inode_info_header *sih = &si->header;
    unsigned long blocknr = 0;
    int ret = 0;

    /* Step 1. Check */
    if (!entry) return ret;
    if (entry->tier != from) return ret;

    if (is_entry_busy(sbi, entry)) {
        if (DEBUG_MIGRATION_CHECK) nova_info("entry->block %lu is busy\n", 
            (unsigned long)entry->block);
        return -1;
    }

    /* Step 2. Allocate */
    entry->tier = TIER_MIGRATING;

    // TODOzsa: Could be wrong
    if (DEBUG_MIGRATION_ALLOC) nova_info("[Migration] entry->block %lu\n", 
        (unsigned long)entry->block);
    // print_a_page((void *) sbi->virt_addr + entry->block);

    if (blocknr_hint) {
        blocknr = blocknr_hint;
        if (DEBUG_MIGRATION_ALLOC) nova_info("[Migration] Hint blocknr:%lu number:%d.\n",
            blocknr, entry->num_pages);
    }
    else {
        ret = nova_alloc_block_tier(sbi, to, ANY_CPU, &blocknr, entry->num_pages, ALLOC_FROM_HEAD);
        // The &blocknr is global block number

        if (ret<0) {
            nova_info("[Migration] Block allocation error.\n");
            return ret;
        }
        if (DEBUG_MIGRATION_ALLOC) nova_info("[Migration] Allocate blocknr:%lu number:%d.\n",
            blocknr, entry->num_pages);
    }

    /* Step 3. Copy */
    ret = migrate_blocks(sbi, entry->block >> PAGE_SHIFT, entry->num_pages, from, to, blocknr);
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

    /* Step 4. Free */
    ret = nova_free_blocks_tier(sbi, entry->block >> PAGE_SHIFT, entry->num_pages);
    // Update tiering info
    entry->tier = to;    
    entry->block = blocknr << PAGE_SHIFT;

	nova_update_entry_csum(entry);
    return ret;
}

int migrate_group_entry_blocks(struct nova_sb_info *sbi, struct inode *inode, int from, int to,
    pgoff_t start_index, pgoff_t end_index) {
	struct super_block *sb = sbi->sb;
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
    struct nova_inode *pi = nova_get_block(sb, sih->pi_addr);
	struct nova_inode_update update;
    int ret = 0;
	u64 epoch_id;
	u32 time;
	u64 file_size = cpu_to_le64(inode->i_size);
	u64 begin_tail = 0;
    unsigned long blocknr = 0;
    unsigned int opt_size = 1 << sbi->bdev_list[to - TIER_BDEV_LOW].opt_size_bit;
	struct nova_file_write_entry *entry;
	struct nova_file_write_entry *entry_base = NULL;
	struct nova_file_write_entry *entry_first = nova_get_write_entry(sb, sih, start_index);
	struct nova_file_write_entry entry_data;
    pgoff_t index = start_index;
	unsigned int data_bits;
    unsigned int maxmtime = 0;
    ret = nova_alloc_block_tier(sbi, to, ANY_CPU, &blocknr, opt_size, ALLOC_FROM_TAIL);
    if (ret<0) {
        nova_info("[Migration] Block allocation error.\n");
        return ret;
    }

	update.tail = sih->log_tail;
	update.alter_tail = sih->alter_log_tail;

    do {
        entry = nova_get_write_entry(sb, sih, index);
        if (entry) {
            if (entry->tier == from) {
                if (entry->mtime > maxmtime) {
                    entry_base = entry;
                    maxmtime = entry->mtime;
                }
                if (DEBUG_MIGRATION) nova_info("[Migration] Migrating (group) write entry with index:%lu\n", index);
                ret = migrate_entry_blocks(sbi, from, to, si, entry, 
                    blocknr + (entry->pgoff & (opt_size - 1)));
                index += entry->num_pages;
            }
            else {
                index++;
            }
        }
        else index++;
    } while (index <= end_index);

    if (!entry_base) {
        nova_info("No entry_base\n");
        return -1;
    }
    entry = entry_base;
    if (DEBUG_MIGRATION_MERGE) nova_info("Merge entry: [Before] [entry] %llu,%llu,%u\n", 
        entry_first->block >> PAGE_SHIFT, entry_first->pgoff, entry_first->num_pages);

	epoch_id = nova_get_epoch_id(sb);
	time = current_time(inode).tv_sec;
    nova_init_file_write_entry(sb, sih, &entry_data, epoch_id,
		entry_first->pgoff, opt_size, 
        entry_first->block >> PAGE_SHIFT, time, file_size);
    entry_data.tier = to;    

	nova_update_entry_csum(&entry_data);
    ret = nova_append_file_write_entry(sb, pi, inode, &entry_data, &update);
    if (ret) {
        nova_dbg("%s: append inode entry failed\n", __func__);
        ret = -ENOSPC;
    }
    
	data_bits = blk_type_to_shift[sih->i_blk_type];
	sih->i_blocks += (opt_size << (data_bits - sb->s_blocksize_bits));

    begin_tail = update.curr_entry;
    nova_memunlock_inode(sb, pi);
	nova_update_inode(sb, inode, pi, &update, 1);
	nova_memlock_inode(sb, pi);
    
    ret = nova_reassign_file_tree(sb, sih, begin_tail, false);
	if (ret) return ret;

	inode->i_blocks = sih->i_blocks;
    
	sih->trans_id++;

    if (DEBUG_MIGRATION_MERGE) nova_info("Merge entry: [After ] [entry] %llu,%llu,%u\n", 
        entry_data.block >> PAGE_SHIFT, entry_data.pgoff, entry_data.num_pages);
    
    return ret;
}

bool is_entry_cross_boundary(struct nova_sb_info *sbi, struct nova_file_write_entry *entry, int tier) {
    unsigned int osb = sbi->bdev_list[tier - TIER_BDEV_LOW].opt_size_bit;
    if ( (entry->pgoff >> osb) !=  
        ( (entry->pgoff + entry->num_pages - 1) >> osb ) )
        return true;
    else return false;
}

// TODOzsa: concurrency
int nova_split_entry(struct super_block *sb, struct inode *inode,
    struct nova_file_write_entry *entry, int tier) {
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
    struct nova_inode *pi = nova_get_block(sb, sih->pi_addr);
	struct nova_inode_update update;
	struct nova_file_write_entry entry_data;
    int ret = 0;
	unsigned int data_bits;
	u64 epoch_id;
	u32 time;
	u64 file_size = cpu_to_le64(inode->i_size);
	u64 begin_tail = 0;
    unsigned int osb = sbi->bdev_list[tier - TIER_BDEV_LOW].opt_size_bit;
    unsigned long num_prev = ((entry->pgoff + entry->num_pages -1) >> osb << osb )- entry->pgoff;

	update.tail = sih->log_tail;
	update.alter_tail = sih->alter_log_tail;

    nova_info("Split entry: [Before] [entry] %llu,%llu,%u\n", entry->block >> PAGE_SHIFT, entry->pgoff, entry->num_pages);

	epoch_id = nova_get_epoch_id(sb);
	time = current_time(inode).tv_sec;
    nova_init_file_write_entry(sb, sih, &entry_data, epoch_id,
		entry->pgoff + num_prev, entry->num_pages - num_prev, 
        (entry->block >> PAGE_SHIFT) + num_prev, time, file_size);
    entry_data.tier = tier;    
    
	nova_update_entry_csum(&entry_data);
    entry->num_pages = num_prev;

    ret = nova_append_file_write_entry(sb, pi, inode, &entry_data, &update);
    if (ret) {
        nova_dbg("%s: append inode entry failed\n", __func__);
        ret = -ENOSPC;
    }
    
	data_bits = blk_type_to_shift[sih->i_blk_type];
	sih->i_blocks += ((entry->num_pages - num_prev) << (data_bits - sb->s_blocksize_bits));
    begin_tail = update.curr_entry;
    nova_memunlock_inode(sb, pi);
	nova_update_inode(sb, inode, pi, &update, 1);
	nova_memlock_inode(sb, pi);

    ret = nova_reassign_file_tree(sb, sih, begin_tail, false);
	if (ret) return ret;

	inode->i_blocks = sih->i_blocks;

	sih->trans_id++;

    nova_info("[After] [entry] %llu,%llu,%u [new_entry] %llu,%llu,%u\n", 
        entry->block >> PAGE_SHIFT, entry->pgoff, entry->num_pages,
        entry_data.block >> PAGE_SHIFT, entry_data.pgoff, entry_data.num_pages);

    return ret;
}

/*
 * Migrate a file from one tier to another
 * How migration works: Check -> Allocate -> Copy -> Free
 */ 


int migrate_a_file_by_entries(struct inode *inode, int from, int to)
{
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_entry *entry;
    pgoff_t index = 0;
    pgoff_t end_index = 0;
    int ret = 0;
    unsigned int nentry = 0;
    loff_t isize = 0;

    if (DEBUG_MIGRATION) nova_info("[Migration] Start migrating inode:%lu from:T%d to:T%d\n",
        inode->i_ino, from, to);

	isize = i_size_read(inode);
	end_index = (isize) >> PAGE_SHIFT;
    // nova_info("1 index:%lu end_index:%lu ret:%d\n", index, end_index, ret);
    do {
        entry = nova_get_write_entry(sb, sih, index);
        // nova_info("entry %p\n", entry);
        // nova_info("index:%lu ret:%d\n", index, ret);

        if (entry) {
            if (entry->tier == from) {
                if (DEBUG_MIGRATION) nova_info("[Migration] Migrating ( one ) write entry with index:%lu\n", index);
                ret = migrate_entry_blocks(sbi, from, to, si, entry, 0);
                index += entry->num_pages;
            }
            else {
                index++;
            }
            nentry++;
        }
        else index++;
    } while (index <= end_index);

    if (DEBUG_MIGRATION) nova_info("[Migration] End migrating inode:%lu from:T%d to:T%d\n",
        inode->i_ino, from, to);
        
    if (DEBUG_MIGRATION) nova_info("[Migration] End migrating inode:%lu (%d entries)\n",
        inode->i_ino, nentry);
    
    return ret;
}

int migrate_a_file(struct inode *inode, int from, int to)
{
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_file_write_entry *entry;
    pgoff_t index = 0;
    pgoff_t end_index = 0;
    int ret = 0;
    unsigned int i = 0;
    unsigned int nentry = 0;
    unsigned int n1 = 0;
    unsigned int n2 = 0;
    loff_t isize = 0;
    unsigned int osb = sbi->bdev_list[to - TIER_BDEV_LOW].opt_size_bit;

    if (is_tier_pmem(to)) return migrate_a_file_by_entries(inode, from, to);

    if (DEBUG_MIGRATION) nova_info("[Migration] Start migrating inode:%lu from:T%d to:T%d\n",
        inode->i_ino, from, to);

	isize = i_size_read(inode);
	end_index = (isize) >> PAGE_SHIFT;
    
    for (i=0;i<=end_index>>osb;++i) {
        n1 = 0;
        n2 = 0;
        index = i<<osb;
        do {
            entry = nova_get_write_entry(sb, sih, index);

            if (entry) {
                if (is_entry_cross_boundary(sbi, entry, to)) {
                    nova_split_entry(sb, inode, entry, to);
                }
                if (entry->tier == from) {
                    index += entry->num_pages;
                }
                else {
                    goto mig;
                }
                n1++;
            }
            else goto mig;
        } while (index < (i+1)<<osb);

        if (index == (i+1)<<osb) {
            if (n1!=1) {
                migrate_group_entry_blocks(sbi, inode, from, to, i<<osb, ((i+1)<<osb) -1);
                nentry += n1;
                continue;
            }
            else {
                ret = migrate_entry_blocks(sbi, from, to, si, entry, 0);
                nentry += 1;
                continue;
            }
        }
mig: 
        index = i<<osb;
        do {
            entry = nova_get_write_entry(sb, sih, index);
            // nova_info("entry %p\n", entry);
            // nova_info("index:%lu ret:%d\n", index, ret);

            if (entry) {
                if (is_entry_cross_boundary(sbi, entry, to)) {
                    nova_split_entry(sb, inode, entry, to);
                }
                if (entry->tier == from) {
                    if (DEBUG_MIGRATION) nova_info("[Migration] Migrating ( one ) write entry with index:%lu\n", index);
                    ret = migrate_entry_blocks(sbi, from, to, si, entry, 0);
                    index += entry->num_pages;
                }
                else {
                    index++;
                }
                n2++;
            }
            else index++;
        } while (index < (i+1)<<osb);
        nentry += n2;
    }
    
    if (DEBUG_MIGRATION) nova_info("[Migration] End migrating inode:%lu from:T%d to:T%d\n",
        inode->i_ino, from, to);
        
    if (DEBUG_MIGRATION) nova_info("[Migration] End migrating inode:%lu (%d entries)\n",
        inode->i_ino, nentry);

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
	nova_info("[Usage] PMEM: Used:  %4lu\n", used);
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
	nova_info("[Usage] PMEM: Total: %4lu\n", total);
    return total;
}

bool is_pmem_usage_high(struct nova_sb_info *sbi) {
    unsigned long used = nova_pmem_used(sbi);
    unsigned long total = nova_pmem_total(sbi);
    // Usage high: used / total > MIGRATION_DOWNWARD_PERC / 100
    nova_info("PMEM usage: %lu / %lu.\n", used * 100, MIGRATION_DOWNWARD_PERC * total);
    return used * 100 > MIGRATION_DOWNWARD_PERC * total;
}

unsigned long nova_bdev_used(struct nova_sb_info *sbi, int tier) {
    unsigned long used = 0;
    int i;
	struct bdev_free_list *bfl = NULL;
	for (i=0;i<sbi->cpus;++i) {
		bfl = nova_get_bdev_free_list(sbi,tier,i);
        used += bfl->num_total_blocks - bfl->num_free_blocks;
	}
	nova_info("[Usage] BDEV-T%d: Used:  %4lu\n", tier, used);
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
	nova_info("[Usage] BDEV-T%d: Total: %4lu\n", tier, total);
    return total;
}

bool is_bdev_usage_high(struct nova_sb_info *sbi, int tier) {
    unsigned long used = nova_bdev_used(sbi, tier);
    unsigned long total = nova_bdev_total(sbi, tier);
    // Usage high: used / total > MIGRATION_DOWNWARD_PERC / 100
    nova_info("BDEV T%d usage: %lu / %lu.\n", tier, used * 100, MIGRATION_DOWNWARD_PERC * total);
    return used * 100 > MIGRATION_DOWNWARD_PERC * total;
}

struct inode *pop_an_inode_to_migrate(struct nova_sb_info *sbi, int tier) {
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
                si = NOVA_I(ret);
                entry = nova_get_write_entry(sb, &si->header, 0);
                if (entry->tier == tier) {
                    nova_info("Inode %lu is poped.\n",ino);
                    return ret;
                }
            }
        }
        next = rb_next(next);
        goto more;
    }
    return NULL;
}

int migrate_a_file_to_pmem(struct inode *inode) {
    if (current_tier(inode) == TIER_PMEM) return 0;
    else return migrate_a_file_by_entries(inode, current_tier(inode), TIER_PMEM);
}

int do_migrate_a_file_rotate(struct inode *inode) {
    int ret;
	nova_info("[Migration-Rotate]\n");
    ret = is_not_same_tier(inode);
    if (ret) {
        nova_info("Write entries of inode %lu is not in the same tier (index: %d)", inode->i_ino, ret);
        return -1;
    }
    switch (current_tier(inode)) {
    case TIER_PMEM:
        return migrate_a_file(inode, TIER_PMEM, TIER_BDEV_LOW);
    case TIER_BDEV_LOW:
        return migrate_a_file(inode, TIER_BDEV_LOW, TIER_BDEV_HIGH);
    case TIER_BDEV_HIGH:
        return migrate_a_file(inode, TIER_BDEV_HIGH, TIER_PMEM);
    default:
        nova_info("Unsupported migration of inode %lu at tier %d", inode->i_ino, current_tier(inode));
    }
    return -1;
}

int do_migrate_a_file_downward(struct inode *inode) {
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);
    struct inode *this;
    int ret;
    int i;
	nova_info("[Migration-Downward]\n");
    ret = is_not_same_tier(inode);
    if (ret) {
        nova_info("Write entries of inode %lu is not in the same tier (index: %d)", inode->i_ino, ret);
        return -1;
    }
again:
    if (is_pmem_usage_high(sbi)) {
        nova_info("PMEM usage high.\n");
        this = pop_an_inode_to_migrate(sbi, TIER_PMEM);
        if (!this) {
            nova_info("PMEM usage is high yet no inode is found.\n");
        }
        migrate_a_file(this, TIER_PMEM, TIER_BDEV_LOW);
        goto again;
    }
    else nova_info("PMEM usage low.\n");

    for (i=TIER_BDEV_LOW;i<TIER_BDEV_HIGH;++i) {
        if (is_bdev_usage_high(sbi, i)) {
            nova_info("BDEV T%d usage high.\n",i);
            this = pop_an_inode_to_migrate(sbi, i);
            if (!this) {
                nova_info("BDEV T%d usage is high yet no inode is found.\n", i);
            }
            migrate_a_file(this, i, i+1);
            goto again;
        }
        else nova_info("BDEV T%d usage low.\n",i);
    }
    
    return 0;
}