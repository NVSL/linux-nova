#include "nova.h"


#define IO_BLOCK_SIZE_BIT 12
#define IO_BLOCK_SIZE 4096
#define VFS_IO_TEST 0

// This function is used for a raw block device lookup in /dev
char* find_a_raw_bdev(void) {
	struct file *fp;
	char* bdev = kzalloc(20*sizeof(char),GFP_KERNEL);
		
	fp = filp_open("/dev/sda1", O_RDONLY, 0644);
	if(fp == (struct file *)-ENOENT) {
		strcat(bdev, "/dev/sda\0");
		nova_info("sda\n");
		return bdev;
	}
	fp = filp_open("/dev/sdb1", O_RDONLY, 0644);
	if(fp == (struct file *)-ENOENT) {
		strcat(bdev, "/dev/sdb\0");
		nova_info("sdb\n");
		return bdev;
	}
	return NULL;
}

// VFS write to disk
static void vfs_write_test(void) {
	struct file *file;
	loff_t pos = 4;
	int i;
	char* name = kmalloc(sizeof(char)*4,GFP_KERNEL);
    mm_segment_t oldfs;
	name[0] = 't';
	name[1] = 'o';
	name[3] = '\0';
	nova_info("vfs write test in %lu.\n",sizeof(char));
    oldfs = get_fs();
    set_fs(get_ds());
	file = filp_open("/dev/sda", O_WRONLY, 0644);
	for (i=0;i<10000;++i){
		name[2]='a'+i%26;
		pos+=16;
		vfs_write(file, name, sizeof(char)*4, &pos);
	}
	// vfs_fsync(file,0);
	// filp_close(file,NULL);
    set_fs(oldfs);
	nova_info("vfs write test out.\n");
}

// VFS read from disk
static void vfs_read_test(void) {
	struct file *file;
	loff_t pos = 80;
	struct inode *blk_inode;
	struct address_space *blk_mapping;
	struct address_space *blk_data;
	// char* get = kzalloc(sizeof(char)*10, GFP_KERNEL);
	char* c = kzalloc(sizeof(char)*13, GFP_KERNEL);
    mm_segment_t oldfs;
	nova_info("vfs read test in.\n");
 
    oldfs = get_fs();
	set_fs(get_ds());
	file = filp_open("/dev/sda", O_RDONLY, 0644);
	
	blk_inode = file->f_inode;
	nova_info("vfs read test mid1.\n");

	nova_info("vfs read test i_rdev:%u, i_size:%lld.\n",blk_inode->i_rdev,blk_inode->i_size);

	nova_info("vfs read test i_blkbits:%u, i_bytes:%u, i_blocks:%lu.\n",blk_inode->i_blkbits,blk_inode->i_bytes,blk_inode->i_blocks);
	
	nova_info("vfs read test i_ino:%lu.\n",blk_inode->i_ino);
	blk_mapping = blk_inode->i_mapping;
	blk_data = &blk_inode->i_data;
	// address space i_mapping
	nova_info("vfs read test mapping: i_ino:%lu.\n",blk_mapping->host->i_ino);
	nova_info("vfs read test mapping: nrpages:%lu.\n",blk_mapping->nrpages);

	// address space i_data
	// nova_info("vfs read test data: i_ino:%lu.\n",blk_data->host->i_ino);
	nova_info("vfs read test data: nrpages:%lu.\n",blk_data->nrpages);

	vfs_read(file, c,sizeof(char)*12, &pos);
	nova_info("vfs read test %s.\n",c);
	nova_info("vfs read test out.\n");

    set_fs(oldfs);
}

// Key: the first character
// 0 = A | 1 = B | ... | 25 = Z
int modify_a_page(void* addr, int key) {
	char* c = addr;
	int i = 0;
	char* word = kmalloc(26*sizeof(char)*5+1,GFP_KERNEL);
	while (i<26*5) {
		word[i]='A'+i%26;
		i++;
	}
	for (i=0;i<64;++i) {
		strncat(c+i*64,&word[key+i%26],64);
	}
	if (i<64) return -1;
	return 0;
}

// Print the page in terminal
void print_a_page(void* addr) {
	char* c = addr;
	// wordline: how many characters are shown in one line
	int wordline = 128;
	char* p = kmalloc(wordline*sizeof(char)+1,GFP_KERNEL);
	int i = 0;
	int j = 0;
	char space = ' ';
	p[wordline]='\0';
	nova_info("Page data (Start with: %c)\n",c[i]);
	nova_info("----------------\n");
	while (i<IO_BLOCK_SIZE) {
		p[0]='\0';
		for (j=0;j<wordline;j+=32) {
			strncat(p,c+i+j,32);
			strcat(p,&space);
		}
		nova_info("%p %s\n",addr+i,p);
		i+=wordline;
	}
	nova_info("----------------\n");
}

int nova_bdev_write_byte(struct block_device *device, unsigned int offset,
	unsigned int size, struct page *page) {
   	int ret = 0;
	struct bio *bio = bio_alloc(GFP_NOIO, 1);
	struct bio_vec *bv = kzalloc(sizeof(struct bio_vec), GFP_KERNEL);
	nova_info("size: %u\n",size);
	bio->bi_bdev = device;
	bio->bi_iter.bi_sector = 0;
	bio->bi_iter.bi_size = size;
	bio->bi_vcnt = 1;
	bv->bv_page = page;
	bv->bv_len = size;
	bv->bv_offset = offset;
	bio->bi_io_vec = bv;
	bio_set_op_attrs(bio, REQ_OP_WRITE, 0);
	nova_info("writePage 1\n");
	// This is synchronized bio. 
	// Call submit_bio for asynchronized bio.
	submit_bio_wait(bio);
   	nova_info("writePage 2\n");
	bio_put(bio);
	nova_info("writePage 3\n");
	return ret;
}

int nova_bdev_read_byte(struct block_device *device, unsigned int offset,
	unsigned int size, struct page *page) {
	int ret = 0;
	struct bio *bio = bio_alloc(GFP_NOIO, 1);
	struct bio_vec *bv = kzalloc(sizeof(struct bio_vec), GFP_KERNEL);
	nova_info("size: %u\n",size);
	bio->bi_bdev = device;
	bio->bi_iter.bi_sector = 0;
	bio->bi_iter.bi_size = size;
	bio->bi_vcnt = 1;
	bv->bv_page = page;
	bv->bv_len = size;
	bv->bv_offset = offset;
	bio->bi_io_vec = bv;
	bio_set_op_attrs(bio, REQ_OP_READ, 0);
	nova_info("readPage 1\n");
	// This is synchronized bio. 
	// Call submit_bio for asynchronized bio.
	submit_bio_wait(bio);
	nova_info("readPage 2\n");
	bio_put(bio);
	nova_info("readPage 3\n");
	return ret;
}

void bdev_test(void) {
	struct block_device *bdev_raw;
	const fmode_t mode = FMODE_READ | FMODE_WRITE;
	
	struct page *pg;
	struct page *pg2;
	void *pg_vir_addr = NULL;
	void *pg_vir_addr2 = NULL;
	int ret=0;
	char *bdfile;

    nova_info("Block device test in.\n");
    
	bdfile = find_a_raw_bdev();
	nova_info("Find raw block device: %s\n",bdev);

	bdev_raw = lookup_bdev(bdfile);
	if (IS_ERR(bdev_raw))
	{
		printk("bdev: error opening raw device <%lu>\n", PTR_ERR(bdev_raw));
	}
	if (!bdget(bdev_raw->bd_dev))
	{
		printk("bdev: error bdget()\n");
	}
	if (blkdev_get(bdev_raw, mode, NULL))
	{
		printk("bdev: error blkdev_get()\n");
		bdput(bdev_raw);
	}
	
	nova_info("size: %u\n",bdev_raw->bd_block_size);

	pg = alloc_page(GFP_KERNEL|__GFP_ZERO);
	pg2 = alloc_page(GFP_KERNEL|__GFP_ZERO);
	pg_vir_addr = page_address(pg);
	pg_vir_addr2 = page_address(pg2);
	nova_info("cc %s ",(char *)pg_vir_addr);
	print_a_page(pg_vir_addr);
	modify_a_page(pg_vir_addr,9);
	print_a_page(pg_vir_addr);
	print_a_page(pg_vir_addr2);

    if (VFS_IO_TEST) {
        vfs_write_test();
        vfs_read_test();
    }

	// Sector write:
	// ret = writePage(bdev_raw, 0, bdev_logical_block_size(bdev_raw), pg);
	// Sector read:
	// ret = readPage(bdev_raw, 0, bdev_logical_block_size(bdev_raw), pg2);

	// Page write
	ret = nova_bdev_write_byte(bdev_raw, 0, IO_BLOCK_SIZE, pg);
	// Page read
	ret = nova_bdev_read_byte(bdev_raw, 0, IO_BLOCK_SIZE, pg2);
	
	// vfs_write_test(void);
	// vfs_read_test(void);

	nova_info("ret:%d\n",ret);
	print_a_page(pg_vir_addr2);

	nova_info("Block device test out %u.\n",bdev_raw->bd_block_size);
}