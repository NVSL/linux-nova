#ifndef __BDEV_H
#define __BDEV_H

/*
 * Block device static status
 */
struct bdev_info {
	char bdev_path[16];
	char bdev_name[16];
    unsigned int major;
    unsigned int minors;
    unsigned long capacity_page;
    unsigned long capacity_sector;
	struct block_device *bdev_raw;
};

/*
 * Block device free list
 * TODO: per-CPU or not?
 */ 
struct bdev_free_list {
	spinlock_t s_lock;

	int tier; 
	int cpu;

	struct rb_root block_free_tree;
	struct nova_range_node *first_node; // lowest address free range
	struct nova_range_node *last_node; // highest address free range

	unsigned long	num_total_blocks;
	unsigned long	num_free_blocks;

	/* Start and end of allocatable range, inclusive. Excludes csum and
	 * parity blocks.
	 */
	unsigned long	block_start;
	unsigned long	block_end;

	/* How many nodes in the rb tree? */
	unsigned long	num_blocknode;
};

/* A node in the RB tree representing a range of pages */
struct nova_bdev_range_node {
	struct rb_node node;
	unsigned long start_blk;
	unsigned long end_blk;
};

static inline
struct bdev_free_list *nova_get_bdev_free_list(struct nova_sb_info *sbi, int tier, int cpu)
{
	return &sbi->bdev_free_list[(tier-1)*sbi->cpus + cpu];
}

static inline
struct bdev_free_list *nova_get_bdev_free_list_flat(struct nova_sb_info *sbi, int num)
{
	return &sbi->bdev_free_list[num];
}

static inline int bfl_index_cal(struct nova_sb_info *sbi, int tier, int cpu) {
	return (tier-TIER_BDEV_LOW)*sbi->cpus + cpu;
}

static inline int bfl_index(struct nova_sb_info *sbi, struct bdev_free_list *bfl) {
	return (bfl->tier-TIER_BDEV_LOW)*sbi->cpus + bfl->cpu;
}

// tier of bdevs starts from TIER_BDEV_LOW
static inline struct block_device *get_bdev_raw(struct nova_sb_info *sbi, int tier) {
	return sbi->bdev_list[tier-TIER_BDEV_LOW].bdev_raw;
}

static inline struct page *address_to_page(void *dax_mem) {
	return virt_to_page(dax_mem);
}

static inline void *page_to_address(struct page *pg) {
	return page_address(pg);
}

char* find_a_raw_sata(void);
char* find_a_raw_nvme(void);
void print_all_bdev(struct nova_sb_info *sbi);
void bdev_test(struct nova_sb_info *sbi);
void bfl_test(struct nova_sb_info *sbi);
void nova_delete_bdev_free_list(struct super_block *sb);
long nova_bdev_alloc_blocks(struct nova_sb_info *sbi, int tier, int cpuid, unsigned long *blocknr,
	unsigned int num_blocks);

#endif