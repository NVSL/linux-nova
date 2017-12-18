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

	mutex_init(&sbi->mb_mutex);

	for (i = 0; i < MINI_BUFFER_PAGES; i++) {
    	init_rwsem(&sbi->mb_sem[i]);
		// spin_lock_init(&sbi->mb_locks[i]);
        sbi->mb_pages[i] = virt_to_page(sbi->mini_buffer+i*IO_BLOCK_SIZE);
    }
    
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
    ret = nova_bdev_read_block(sbi->bdev_list[tier-TIER_BDEV_LOW].bdev_raw, blockoff, 1, pg, BIO_SYNC);

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
        nova_info("mb_sem[%lu]->count = %ld.\n",number,sbi->mb_sem[number].count.counter);
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

    nova_info("put off2 %lu, nr %lu\n",number,length);
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

    nova_info("put off2 %lu, nr %lu\n",number,length);
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
		msleep(500);
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
        ret = nova_bdev_read_block(sbi->bdev_list[tier-TIER_BDEV_LOW].bdev_raw, 
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
    return nova_bdev_write_block(bdev_raw, blockoff, nr, address_to_page(dax_mem), BIO_SYNC);
    // return nr;
}

/*
 * Migrate continuous blocks from block device to pmem, with block number
 */
int migrate_blocks_bdev_to_pmem(struct nova_sb_info *sbi, 
    void *dax_mem, unsigned long nr, int tier, unsigned long blockoff) {
    struct block_device *bdev_raw = get_bdev_raw(sbi, tier);
    return nova_bdev_read_block(bdev_raw, blockoff, nr, address_to_page(dax_mem), BIO_SYNC);
    // return nr;
}


// Migrate continuous blocks from pmem to block device

/*
long migrate_blocks_to_bdev(struct nova_sb_info *sbi, void *dax_mem,
    unsigned long nr, int tier, unsigned long *blocknr) {
    // long ret = nova_bdev_alloc_blocks(sbi, TIER_BDEV_LOW, ANY_CPU, blocknr, nr);
    // if (ret<0) return ret;
    long ret = migrate_blocks_to_bdev_with_blockoff(sbi, dax_mem, nr, tier, *blocknr);
    return ret;
}
*/
int migrate_blocks(struct nova_sb_info *sbi, unsigned long blockfrom, unsigned long nr,
    int from, int to, unsigned long blocknr) {
    unsigned long raw_blockfrom = get_raw_from_blocknr(sbi, blockfrom);
    if (is_tier_pmem(from) && is_tier_bdev(to)) 
        return migrate_blocks_pmem_to_bdev(sbi, (void *) sbi->virt_addr + (raw_blockfrom << PAGE_SHIFT), nr, to, blocknr);
    if (is_tier_bdev(from) && is_tier_pmem(to)) 
        return migrate_blocks_bdev_to_pmem(sbi, (void *) sbi->virt_addr + (blocknr << PAGE_SHIFT), nr, from, raw_blockfrom);
    if (is_tier_bdev(from) && is_tier_bdev(to)) 
        return -2;
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
    struct nova_inode_info *si, struct nova_file_write_entry *entry) {
	// struct nova_inode_info_header *sih = &si->header;
    unsigned long blocknr = 0;
    int ret = 0;

    /* Step 1. Check */
    if (!entry) return ret;
    if (entry->tier != from) return ret;

    if (is_entry_busy(sbi, entry)) {
        if (DEBUG_MIGRATION_CHECK) nova_info("entry->block %lu is busy\n", (unsigned long)entry->block);
        return -1;
    }

    /* Step 2. Allocate */
    entry->tier = TIER_MIGRATING;
    
    // TODOzsa: Could be wrong
    if (DEBUG_MIGRATION_ALLOC) nova_info("[Migration] entry->block %lu\n", (unsigned long)entry->block);
    // print_a_page((void *) sbi->virt_addr + entry->block);

    ret = nova_alloc_block_tier(sbi, to, ANY_CPU, &blocknr, entry->num_pages);
    // The &blocknr is local block number

    if (ret<0) {
        nova_info("[Migration] Block allocation error.\n");
        return ret;
    }
    if (DEBUG_MIGRATION_ALLOC) nova_info("[Migration] Allocate blocknr:%lu number:%d.\n",
        blocknr, entry->num_pages);

    /* Step 3. Copy */
    ret = migrate_blocks(sbi, entry->block >> PAGE_SHIFT, entry->num_pages, from, to, blocknr);
    if (ret<0) {
        nova_info("[Migration] Block allocation error.\n");
        if (ret == -2) nova_info("[Migration] Unsupported migration attempt.\n");
        return ret;
    }

    /* Step 4. Free */
    ret = nova_free_blocks_tier(sbi, entry->block >> PAGE_SHIFT, entry->num_pages);
    // Update tiering info
    entry->tier = to;
    entry->block = (get_blocknr_from_raw(sbi, to, blocknr)) << PAGE_SHIFT;

	nova_update_entry_csum(entry);
    return ret;
}

/*
 * Migrate a file from one tier to another
 * How migration works: Check -> Allocate -> Copy -> Free
 */ 
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
    loff_t isize = 0;

    // TODOzsa: Concurrent lock & check
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
                if (DEBUG_MIGRATION) nova_info("[Migration] Migrating write entry with index:%lu\n", index);
                // TODOzsa
                ret = migrate_entry_blocks(sbi, from, to, si, entry);
                index += entry->num_pages;
            }
            else {
                index++;
            }
        }
        else index++;
    } while (index <= end_index);

    if (DEBUG_MIGRATION) nova_info("[Migration] End migrating inode:%lu from:T%d to:T%d\n",
        inode->i_ino, from, to);
    
    return ret;
}

int do_migrate_a_file(struct inode *inode) {
    if (is_not_same_tier(inode)) {
        nova_info("Write entries of inode %lu is not in the same tier", inode->i_ino);
        return -1;
    }
    switch (current_tier(inode)) {
    case TIER_PMEM:
        return migrate_a_file(inode, TIER_PMEM, TIER_BDEV_LOW);
    case TIER_BDEV_LOW:
        return migrate_a_file(inode, TIER_BDEV_LOW, TIER_PMEM);
    default:
        nova_info("Unsupported migration of inode %lu at tier %d", inode->i_ino, current_tier(inode));
    }
    return -1;
}