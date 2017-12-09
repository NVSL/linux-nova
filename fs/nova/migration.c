#include "nova.h"
#include "bdev.h"

/* 
 * [About Mini Buffer]
 * It is a temporary buffer solution for tiering file system.
 * Includes: (for each buffer page)
 *      mb_locks: the spinlock 
 *      tier: tier number
 *      blocknr: blocknr in this tier
 *      mb_pages: actual mini-buffer page
 */

// Allocate a DRAM buffer in sbi
int init_dram_buffer(struct nova_sb_info *sbi) {
    unsigned int i = 0;

	sbi->mb_locks = kcalloc(MINI_BUFFER_PAGES, sizeof(spinlock_t), GFP_KERNEL);
	if (!sbi->mb_locks) return -ENOMEM;

	sbi->tier = kcalloc(MINI_BUFFER_PAGES, sizeof(int), GFP_KERNEL);
	if (!sbi->tier) return -ENOMEM;

	sbi->blockoff = kcalloc(MINI_BUFFER_PAGES, sizeof(int), GFP_KERNEL);
	if (!sbi->blockoff) return -ENOMEM;

	sbi->mini_buffer = kcalloc(MINI_BUFFER_PAGES, IO_BLOCK_SIZE, GFP_KERNEL);
	if (!sbi->mini_buffer) return -ENOMEM;

    sbi->mb_pages = kcalloc(MINI_BUFFER_PAGES, sizeof(struct page *), GFP_KERNEL);

	for (i = 0; i < MINI_BUFFER_PAGES; i++) {
		spin_lock_init(&sbi->mb_locks[i]);
        sbi->mb_pages[i] = virt_to_page(sbi->mini_buffer+i*IO_BLOCK_SIZE);
    }
    
    return 0;
}

/*
 * Buffer a data block from bdev to DRAM
 *
 * Strategy: 
 *      Find the first unlock page
 *      If none, wait on one according to page offset
 * Return buffer number (locked buffer)
 */ 
int buffer_data_block_from_bdev(struct nova_sb_info *sbi, int tier, unsigned long blockoff) {
    int i = 0;
    int ret = 0;
	struct page *pg;
	if (DEBUG_BUFFERING) nova_info("[Buffering] block:%lu\n" ,blockoff);
	for (i = blockoff%MINI_BUFFER_PAGES; i < blockoff%MINI_BUFFER_PAGES+MINI_BUFFER_PAGES; i++)
		if (spin_trylock(&sbi->mb_locks[i%MINI_BUFFER_PAGES])) goto copy;
    // All mini-buffers are full
    spin_lock(&sbi->mb_locks[i%MINI_BUFFER_PAGES]);

copy:
    i = i%MINI_BUFFER_PAGES;
    pg = sbi->mb_pages[i];
    ret = nova_bdev_read_block(sbi->bdev_list[tier-TIER_BDEV_LOW].bdev_raw, blockoff, 1, pg, BIO_SYNC);

    // print_a_page(&sbi->mini_buffer[i]);
    if (ret) return -ret;

    sbi->tier[i] = tier;
    sbi->blockoff[i] = blockoff;
    
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
    sbi->tier[number] = TIER_PMEM;
    sbi->blockoff[number] = 0;
    return 0;
}

inline int put_dram_buffer(struct nova_sb_info *sbi, unsigned long number) {
    spin_unlock(&sbi->mb_locks[number]);
    return 0;
}

int clear_dram_buffer_range(struct nova_sb_info *sbi, unsigned long number, int length) {
    unsigned long i;
    for (i=number; i<number+length; ++i) {
        clear_dram_buffer(sbi,i);
    }    
    return 0;
}

int put_dram_buffer_range(struct nova_sb_info *sbi, unsigned long number, int length) {
    unsigned long i;
    for (i=number; i<number+length; ++i) {
        put_dram_buffer(sbi,i);
    }    
    return 0;
}

inline bool is_dram_buffer_addr(struct nova_sb_info *sbi, void *addr) {
    // nova_info("A%llu\n",(unsigned long long)(sbi->mini_buffer) >> (PAGE_SHIFT+MINI_BUFFER_PAGES_BIT));
    // nova_info("B%llu\n",(unsigned long long)addr >> (PAGE_SHIFT+MINI_BUFFER_PAGES_BIT));
    return ((unsigned long long)(sbi->mini_buffer) >> (PAGE_SHIFT+MINI_BUFFER_PAGES_BIT) == 
    (unsigned long long)addr >> (PAGE_SHIFT+MINI_BUFFER_PAGES_BIT));
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
    int i = 0;
    char* buf = kzalloc(MINI_BUFFER_PAGES+2, GFP_KERNEL);
    for (i = 0; i < MINI_BUFFER_PAGES; i++) {
        if (spin_can_lock(&sbi->mb_locks[i])) strcat(&buf[0],"0");
        else strcat(&buf[0],"1");
    }
    nova_info("lock\n");
    nova_info("%s\n",buf);
}
/* 
 * Find the first continuous buffer which can fit `length`
 * This function should always succeed, it is DRAM buffer's job to allocate such buffer.
 * If space is not enough, swap some pages out to block device.
 */ 
int buffer_data_block_from_bdev_range(struct nova_sb_info *sbi, int tier, int blockoff, int length) {
    int i = 0;
    int index = blockoff%MINI_BUFFER_PAGES; // index of the first block
    int unlock = 0; // number of spinlocks can be unlocked
    int match = 0; // number of matching blocks
    int ret = 0;
	struct page *pg;
    if (length<1) {
        nova_info("buffer_data_block_from_bdev_range length=%d\n",length);
        return -1;
    }
	if (DEBUG_BUFFERING) nova_info("[Buffering] block:%d, length:%d\n", blockoff, length);
	for (i = blockoff%MINI_BUFFER_PAGES; i < MINI_BUFFER_PAGES; i++) {
        if (spin_can_lock(&sbi->mb_locks[i])) {
            match = 0;
            unlock++;
            if (unlock==length) {
                if (DEBUG_BUFFERING) nova_info("[Buffering] suitable buffer found, index:%d\n",index);
                goto copy;
            }
        }
        else {
            if (sbi->tier[i] == tier && sbi->blockoff[i] == blockoff+match) {
                match++;
                if (match==length) {
                    if (DEBUG_BUFFERING) nova_info("[Buffering] matching buffer found\n");
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
        if (spin_can_lock(&sbi->mb_locks[i])) {
            match = 0;
            unlock++;
            if (unlock==length) {
                if (DEBUG_BUFFERING) nova_info("[Buffering] suitable buffer found\n");
                goto copy;
            }
        }
        else {
            if (sbi->tier[i] == tier && sbi->blockoff[i] == blockoff+match) {
                match++;
                if (match==length) {
                    if (DEBUG_BUFFERING) nova_info("[Buffering] matching buffer found\n");
                    goto out;
                }
            }
            unlock = 0;
            index = i+1;
        }
    }

copy:
    if (unlock != length) {
        if (DEBUG_BUFFERING) nova_info("[Buffering] failed\n");
        return -1;
    }
    for (i=index;i<index+length;++i) {
        if (!spin_trylock(&sbi->mb_locks[i])) {
            nova_info("Spinlock error in mb[%d].\n",i);
            return 0;
        }
    }
    for (i=index;i<index+length;++i) {
        pg = sbi->mb_pages[i];
        ret = nova_bdev_read_block(sbi->bdev_list[tier-TIER_BDEV_LOW].bdev_raw, blockoff+i-index, 1, pg, BIO_SYNC);
        sbi->tier[i] = tier;
        sbi->blockoff[i] = blockoff+i-index;
    }

    // print_a_page(&sbi->mini_buffer[i]);
    if (ret) return -ret;
    
    return index;

out:
    return i-length+1;
}

/*
 * Migrate continuous blocks from pmem to block device, with block number
 */
int migrate_blocks_to_bdev(struct nova_sb_info *sbi, 
    void *dax_mem, unsigned long nr, int tier, unsigned long blockoff) {
    struct block_device *bdev_raw = get_bdev_raw(sbi, tier);
    return nova_bdev_write_block(bdev_raw, blockoff, nr, address_to_page(dax_mem), BIO_SYNC);
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
    if (is_tier_pmem(from) && is_tier_bdev_low(to)) 
        return migrate_blocks_to_bdev(sbi, (void *) sbi->virt_addr + blockfrom, nr, to, blocknr);
    return -2;
}

int migrate_entry_blocks(struct nova_sb_info *sbi, int from, int to,
    struct nova_inode_info *si, struct nova_file_write_entry *entry) {
	// struct nova_inode_info_header *sih = &si->header;
    unsigned long blocknr = 0;
    int ret = 0;
    if (!entry) return ret;
    if (entry->tier != from) return ret;

    // TODOzsa: Could be wrong
    if (DEBUG_MIGRATION_RW) nova_info("[Migration] entry->block %p\n", sbi->virt_addr + entry->block);
    // print_a_page((void *) sbi->virt_addr + entry->block);

    ret = nova_alloc_block_tier(sbi, to, ANY_CPU, &blocknr, entry->num_pages);
    if (ret<0) {
        nova_info("[Migration] Block allocation error.\n");
        return ret;
    }
    if (DEBUG_MIGRATION_RW) nova_info("[Migration] Allocate blocknr:%lu number:%d.\n",
        blocknr, entry->num_pages);

    ret = migrate_blocks(sbi, entry->block, entry->num_pages, from, to, blocknr);
    if (ret<0) {
        nova_info("[Migration] Block allocation error.\n");
        if (ret == -2) nova_info("[Migration] Unsupported migration attempt.\n");
        return ret;
    }

    // Not enough page in DRAM is an exception 
    // since DRAM should be enough to handle at least one request
    if (ret != entry->num_pages) {
        nova_info("migrate_entry_blocks() no enough page: %d, %lu, %d\n", ret, blocknr, entry->num_pages);
        return ret;
    }
    // Free blocks
	// ret = nova_free_blocks(sb, entry->block >> PAGE_SHIFT, entry->num_pages, sih->i_blk_type, 0);
    ret = nova_free_blocks_tier(sbi, entry->block >> PAGE_SHIFT, entry->num_pages);
    // Change tiering info
    entry->tier = to;
    entry->block = blocknr << PAGE_SHIFT;

	nova_update_entry_csum(entry);
    return ret;
}

/*
 * Migrate a file from one tier to another
 * How migration works: Allocate -> Copy -> Free
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
    if (DEBUG_MIGRATION_RW) nova_info("[Migration] Start migrating inode:%lu from:T%d to:T%d\n",
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
                if (DEBUG_MIGRATION_RW) nova_info("[Migration] Migrating write entry with index:%lu\n", index);
                // TODOzsa
                ret = migrate_entry_blocks(sbi, from, to, si, entry);
                index += entry->num_pages;
            }
        }
        if (!entry || entry->tier != from) index++;
    } while (index < end_index);

    if (DEBUG_MIGRATION_RW) nova_info("[Migration] End migrating inode:%lu from:T%d to:T%d\n",
        inode->i_ino, from, to);
    
    return ret;
}

int migrate_a_file_to_bdev(struct file *filp) {
	struct inode *inode = filp->f_mapping->host;
    return migrate_a_file(inode, TIER_PMEM, TIER_BDEV_LOW);
}