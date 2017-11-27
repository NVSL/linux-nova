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

// buffer a data block from bdev to DRAM
// tier: pmem-0; DRAM-1; bdev-2,3,... 
// Strategy: 
//      Find the first unlock page
//      If none, wait on one according to page offset
// Return buffer number (locked buffer)
int buffer_data_block_from_bdev(struct nova_sb_info *sbi, int tier, int blockoff) {
    int i = 0;
    int ret = 0;
	struct page *pg;
	nova_info("[Buffering] block:%d\n" ,blockoff);
	for (i = blockoff%MINI_BUFFER_PAGES; i < blockoff%MINI_BUFFER_PAGES+MINI_BUFFER_PAGES; i++)
		if(spin_trylock(&sbi->mb_locks[i%MINI_BUFFER_PAGES])) goto copy;
    // All mini-buffers are full
    spin_lock(&sbi->mb_locks[i%MINI_BUFFER_PAGES]);

copy:
    i = i%MINI_BUFFER_PAGES;
    pg = sbi->mb_pages[i];
    ret = nova_bdev_read_block(sbi->bdev_list[tier-TIER_BDEV].bdev_raw, blockoff, 1, pg, BIO_SYNC);

    // print_a_page(&sbi->mini_buffer[i]);
    if (ret) return -ret;

    sbi->tier[i] = tier;
    sbi->blockoff[i] = blockoff;
    
    return i;
}

int put_dram_buffer(struct nova_sb_info *sbi, int number) {
    spin_unlock(&sbi->mb_locks[number]);

    sbi->tier[number] = TIER_PMEM;
    sbi->blockoff[number] = 0;

    // Clear the buffer?
    return 0;
}

// First continuous buffer
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
	nova_info("[Buffering] block:%d, length:%d\n", blockoff, length);
	for (i = blockoff%MINI_BUFFER_PAGES; i < MINI_BUFFER_PAGES; i++) {
        if(spin_can_lock(&sbi->mb_locks[i])) {
            match = 0;
            unlock++;
            if (unlock==length) {
                nova_info("[Buffering] suitable buffer found\n");
                goto copy;
            }
        }
        else {
            if (sbi->tier[i] == tier && sbi->blockoff[i] == blockoff+match) {
                match++;
                if (match==length) {
                    nova_info("[Buffering] matching buffer found\n");
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
        if(spin_can_lock(&sbi->mb_locks[i])) {
            match = 0;
            unlock++;
            if (unlock==length) {
                nova_info("[Buffering] suitable buffer found\n");
                goto copy;
            }
        }
        else {
            if (sbi->tier[i] == tier && sbi->blockoff[i] == blockoff+match) {
                match++;
                if (match==length) {
                    nova_info("[Buffering] matching buffer found\n");
                    goto out;
                }
            }
            unlock = 0;
            index = i+1;
        }
    }

copy:
    if (unlock != length) {
        nova_info("[Buffering] failed\n");
        return -1;
    }
    for (i=index;i<index+length;++i) {
        if(!spin_trylock(&sbi->mb_locks[i])) {
            nova_info("Spinlock error in mb[%d].\n",i);
            return 0;
        }
    }
    for (i=index;i<index+length;++i) {
        pg = sbi->mb_pages[i];
        ret = nova_bdev_read_block(sbi->bdev_list[tier-TIER_BDEV].bdev_raw, blockoff+i-index, 1, pg, BIO_SYNC);
        sbi->tier[i] = tier;
        sbi->blockoff[i] = blockoff+i-index;
    }

    // print_a_page(&sbi->mini_buffer[i]);
    if (ret) return -ret;
    
    return index;

out:
    return i-length+1;
}

int put_dram_buffer_range(struct nova_sb_info *sbi, unsigned long number, int length) {
    int i;
    for (i=number;i<number+length;++i) {
        spin_unlock(&sbi->mb_locks[i]);

        sbi->tier[i] = TIER_PMEM;
        sbi->blockoff[i] = 0;
    }    

    // Clear the buffer?
    return 0;
}

/*
 * Migrate continuous blocks from pmem to block device, with block number
 */
int migrate_blocks_to_bdev_with_blockoff(struct nova_sb_info *sbi, 
    void *dax_mem, unsigned long nr, int tier, unsigned long blockoff) {
    struct block_device *bdev_raw = get_bdev_raw(sbi, tier);
	return nova_bdev_write_block(bdev_raw, blockoff, nr, address_to_page(dax_mem), BIO_SYNC);
}

// Migrate continuous blocks from pmem to block device
int migrate_blocks_to_bdev(struct nova_sb_info *sbi, void *dax_mem,
    unsigned long nr, int tier, unsigned long *blocknr) {
    int ret = nova_bdev_alloc_blocks(sbi, blocknr, nr);
    if (ret<0) return ret;
    return migrate_blocks_to_bdev_with_blockoff(sbi, dax_mem, nr, tier, *blocknr);
}
	
int migrate_entry_blocks_to_bdev(struct nova_sb_info *sbi, int tier,
    struct nova_inode_info *si, struct nova_file_write_entry *entry) {
	struct super_block *sb = sbi->sb;
	struct nova_inode_info_header *sih = &si->header;
    unsigned long blocknr = 0;
    int ret = 0;
    ret = migrate_blocks_to_bdev(sbi, (void *) entry->block, entry->num_pages, tier, &blocknr);
    if (ret<0) return ret;
    // Not enough page in DRAM is an exception 
    // since DRAM should be enough to handle at least one request
    if (ret != entry->num_pages) {
        nova_info("migrate_entry_blocks_to_bdev() no enough page: %d\n", ret);
        return ret;
    }
    // Free nvm block
	ret = nova_free_blocks(sb, entry->block, entry->num_pages, sih->i_blk_type, 0);
    // Change tiering info
    entry->tier = tier;
    entry->block = blocknr;

	nova_update_entry_csum(entry);
    return ret;
}

// TODOzsa: migrate back to NVM

