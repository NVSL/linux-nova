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

void print_a_bdev(struct bdev_info *bdi);
void bdev_test(struct bdev_info *bdi); 

#define MAX_TIERS 4
extern bdev_info bdev_list[MAX_TIERS];
extern char *bdev_paths[MAX_TIERS]; // block devices for tiering
extern int bdev_count;

#endif