#include "nova.h"
#include "bdev.h"

// DRAM buffer

// Allocate a DRAM buffer in sbi
// The number is MINI_BUFFER_PAGES
int init_dram_buffer(struct nova_sb_info *sbi) {
    int i = 0;

	sbi->mb_locks = kcalloc(MINI_BUFFER_PAGES, sizeof(spinlock_t),
				     GFP_KERNEL);
	if (!sbi->mb_locks) return -ENOMEM;

	sbi->mini_buffer = kcalloc(MINI_BUFFER_PAGES, IO_BLOCK_SIZE,
				     GFP_KERNEL);
	if (!sbi->mini_buffer) return -ENOMEM;

	for (i = 0; i < MINI_BUFFER_PAGES; i++)
		spin_lock_init(&sbi->mb_locks[i]);
    
    return 0;
}

// buffer a data block from bdev to DRAM
// tier: pmem-0; bdev-1,2,... 
// Strategy: 
//      Find the first unlock page
//      If none, wait on one according to page offset
// Return buffer number (locked buffer)
int buffer_data_block_from_bdev(struct nova_sb_info *sbi, int tier, int blockoff) {
    int i = 0;
    int ret = 0;
	struct page *pg;
	for (i = 0; i < MINI_BUFFER_PAGES; i++)
		if(spin_trylock(&sbi->mb_locks[i])) goto copy;
    // All mini-buffers are full
    i = blockoff%MINI_BUFFER_PAGES;
    spin_lock(&sbi->mb_locks[i]);

copy:
    pg = virt_to_page(&sbi->mini_buffer[i]);
    ret = nova_bdev_read_block(sbi->bdev_list[tier-1].bdev_raw, blockoff, 1, pg, BIO_SYNC);

    print_a_page(&sbi->mini_buffer[i]);
    if (ret) return -ret;
    else return i;
}

int put_dram_buffer(struct nova_sb_info *sbi, int number) {
    spin_unlock(&sbi->mb_locks[number]);
    // Clear the buffer?
    return 0;
}