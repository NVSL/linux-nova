#ifndef __BDEV_H
#define __BDEV_H

#define SECTOR_SIZE_BIT 9
#define IO_BLOCK_SIZE_BIT 12
#define IO_BLOCK_SIZE 4096
#define VFS_IO_TEST 0

#define BIO_ASYNC 0
#define BIO_SYNC 1

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

int nova_bdev_read_block(struct block_device *device, unsigned long offset,
        unsigned long size, struct page *page, bool sync);
int nova_bdev_write_block(struct block_device *device, unsigned long offset,
        unsigned long size, struct page *page, bool sync);
void print_a_bdev(struct bdev_info *bdi);
int nova_get_bdev_info(char *bdev_path, int i);
void bdev_test(struct bdev_info *bdi); 

#define MAX_TIERS 4
extern struct bdev_info bdev_list[MAX_TIERS];
extern char *bdev_paths[MAX_TIERS]; // block devices for tiering
extern int bdev_count;
extern unsigned long nova_total_size;

#endif
