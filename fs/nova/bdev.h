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
struct bdev_free_list *nova_get_bdev_free_list(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	return sbi->bdev_free_list;
}

char* find_a_raw_bdev(void);
void print_a_bdev(struct nova_sb_info *sbi);
void bdev_test(struct nova_sb_info *sbi);
void bfl_test(struct nova_sb_info *sbi);
void nova_delete_bdev_free_list(struct super_block *sb);

#endif