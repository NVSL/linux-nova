#ifndef __BDEV_H
#define __BDEV_H

/*
 * Block device static status
 */
struct bdev_info {
    bool valid;
	char bdev_path[16];
	char bdev_name[16];
    unsigned int major;
    unsigned int minors;
    unsigned long capacity_page;
    unsigned long capacity_sector;
	struct block_device *bdev_raw;
};

void print_a_bdev(struct nova_sb_info *sbi);
void bdev_test(struct nova_sb_info *sbi); 

#define MAX_TIERS 4
extern char *bdev_paths[MAX_TIERS]; // block devices for tiering
extern int bdev_count;

#endif