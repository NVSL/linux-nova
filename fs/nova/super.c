/*
 * BRIEF DESCRIPTION
 *
 * Super block operations.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 *
 * This program is free software; you can redistribute it and/or modify it
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/parser.h>
#include <linux/vfs.h>
#include <linux/uaccess.h>
#include <linux/io.h>
#include <linux/seq_file.h>
#include <linux/mount.h>
#include <linux/mm.h>
#include <linux/ctype.h>
#include <linux/bitops.h>
#include <linux/magic.h>
#include <linux/exportfs.h>
#include <linux/random.h>
#include <linux/cred.h>
#include <linux/list.h>
#include <linux/dax.h>
#include "nova.h"
#include "journal.h"
#include "super.h"
#include "inode.h"
#include "vpmem.h"
#include "bdev.h"
#include "debug.h"

int measure_timing = 1;
int metadata_csum;
int wprotect;
int data_csum;
int data_parity;
int dram_struct_csum;
int support_clwb;
int inplace_data_updates;

module_param(measure_timing, int, 0444);
MODULE_PARM_DESC(measure_timing, "Timing measurement");

module_param(metadata_csum, int, 0444);
MODULE_PARM_DESC(metadata_csum, "Protect metadata structures with replication and checksums");

module_param(wprotect, int, 0444);
MODULE_PARM_DESC(wprotect, "Write-protect pmem region and use CR0.WP to allow updates");

module_param(data_csum, int, 0444);
MODULE_PARM_DESC(data_csum, "Detect corruption of data pages using checksum");

module_param(data_parity, int, 0444);
MODULE_PARM_DESC(data_parity, "Protect file data using RAID-5 style parity.");

module_param(inplace_data_updates, int, 0444);
MODULE_PARM_DESC(inplace_data_updates, "Perform data updates in-place (i.e., not atomically)");

module_param(dram_struct_csum, int, 0444);
MODULE_PARM_DESC(dram_struct_csum, "Protect key DRAM data structures with checksums");

module_param(nova_dbgmask, int, 0444);
MODULE_PARM_DESC(nova_dbgmask, "Control debugging output");

static struct super_operations nova_sops;
static const struct export_operations nova_export_ops;
static struct kmem_cache *nova_inode_cachep;
static struct kmem_cache *nova_range_node_cachep;
static struct kmem_cache *nova_snapshot_info_cachep;

/* FIXME: should the following variable be one per NOVA instance? */
unsigned int nova_dbgmask;

void nova_error_mng(struct super_block *sb, const char *fmt, ...)
{
	va_list args;

	printk(KERN_CRIT "nova error: ");
	va_start(args, fmt);
	vprintk(fmt, args);
	va_end(args);

	if (test_opt(sb, ERRORS_PANIC))
		panic("nova: panic from previous error\n");
	if (test_opt(sb, ERRORS_RO)) {
		printk(KERN_CRIT "nova err: remounting filesystem read-only");
		sb->s_flags |= MS_RDONLY;
	}
}

static void nova_set_blocksize(struct super_block *sb, unsigned long size)
{
	int bits;

	/*
	 * We've already validated the user input and the value here must be
	 * between NOVA_MAX_BLOCK_SIZE and NOVA_MIN_BLOCK_SIZE
	 * and it must be a power of 2.
	 */
	bits = fls(size) - 1;
	sb->s_blocksize_bits = bits;
	sb->s_blocksize = (1 << bits);
}

static int nova_get_nvmm_info(struct super_block *sb,
	struct nova_sb_info *sbi)
{
	void *virt_addr = NULL;
	pfn_t __pfn_t;
	long size;
	struct dax_device *dax_dev;
	int ret;

	ret = bdev_dax_supported(sb, PAGE_SIZE);
	nova_dbg_verbose("%s: dax_supported = %d; bdev->super=0x%p",
			 __func__, ret, sb->s_bdev->bd_super);
	if (ret) {
		nova_err(sb, "device does not support DAX\n");
		return ret;
	}

	sbi->s_bdev = sb->s_bdev;

	dax_dev = fs_dax_get_by_host(sb->s_bdev->bd_disk->disk_name);
	if (!dax_dev) {
		nova_err(sb, "Couldn't retrieve DAX device.\n");
		return -EINVAL;
	}
	sbi->s_dax_dev = dax_dev;

	size = dax_direct_access(sbi->s_dax_dev, 0, LONG_MAX/PAGE_SIZE,
				&virt_addr, &__pfn_t) * PAGE_SIZE;
	if (size <= 0) {
		nova_err(sb, "direct_access failed\n");
		return -EINVAL;
	}
	if (sbi->initsize) size = sbi->initsize;

	sbi->virt_addr = virt_addr;

	if (!sbi->virt_addr) {
		nova_err(sb, "ioremap of the nova image failed(1)\n");
		return -EINVAL;
	}

	sbi->phys_addr = pfn_t_to_pfn(__pfn_t) << PAGE_SHIFT;
	if (!sbi->initsize) sbi->initsize = size;
	sbi->replica_reserved_inodes_addr = virt_addr + size -
			(sbi->tail_reserved_blocks << PAGE_SHIFT);
	sbi->replica_sb_addr = virt_addr + size - PAGE_SIZE;

	nova_dbg("%s: dev %s, phys_addr 0x%llx, virt_addr %p, size %ld\n",
		__func__, sbi->s_bdev->bd_disk->disk_name,
		sbi->phys_addr, sbi->virt_addr, sbi->initsize);

	return 0;
}

// TODO: Link with mount option
static char *find_block_device(struct nova_sb_info *sbi, int tier) {
	if (DEBUG_XFSTESTS) {
		return find_a_raw_sata_auto(sbi);
	}
	else {
		if (tier == TIER_BDEV_LOW) return find_a_raw_nvme();
		if (tier == TIER_BDEV_LOW+1) return find_a_raw_sata();
	}
	return NULL;
}

int nova_get_bdev_info(struct nova_sb_info *sbi){
	struct block_device *bdev_raw;
	char *bdev_path = NULL;
	struct gendisk*	bd_disk = NULL;
	unsigned long nsector;
	int i=0;
	const fmode_t mode = FMODE_READ | FMODE_WRITE;
	
	sbi->bdev_list = kcalloc(BDEV_COUNT_MAX, sizeof(struct bdev_info), GFP_KERNEL);	
	if (!sbi->bdev_list) return -ENOMEM;
	for (i=0;i<=(1-DEBUG_XFSTESTS);++i) {	
		bdev_path = find_block_device(sbi, i+1);
		if (!bdev_path) return -ENOENT;

		bdev_raw = lookup_bdev(bdev_path);
		if (IS_ERR(bdev_raw))
		{
			nova_info("bdev: error opening raw device <%lu>\n", PTR_ERR(bdev_raw));
			return -ENOENT;
		}
		if (!bdget(bdev_raw->bd_dev))
		{
			nova_info("bdev: error bdget()\n");
			return -ENOENT;
		}
		if (blkdev_get(bdev_raw, mode, NULL))
		{
			nova_info("bdev: error blkdev_get()\n");
			bdput(bdev_raw);
			return -ENOENT;
		}	

		sbi->bdev_list[i].bdev_raw = bdev_raw;
		strcat(sbi->bdev_list[i].bdev_path, bdev_path);
		kfree(bdev_path);

		bd_disk = bdev_raw->bd_disk;
		nsector = get_capacity(bd_disk);
		sbi->bdev_list[i].major = bd_disk->major;
		sbi->bdev_list[i].minors = bd_disk->minors;
		sbi->bdev_list[i].capacity_sector = nsector;
		sbi->bdev_list[i].capacity_page = nsector>>3;
		sbi->bdev_list[i].opt_size_bit = BDEV_OPT_SIZE_BIT + i; //temp value
		strcat(sbi->bdev_list[i].bdev_name,bd_disk->disk_name);
		TIER_BDEV_HIGH++;
	}

	return 0;
}

int nova_get_one_bdev_info(struct nova_sb_info *sbi, char *bdev_path, unsigned long size){
	struct block_device *bdev_raw;
	struct gendisk*	bd_disk = NULL;
	unsigned long nsector;
	int i=TIER_BDEV_HIGH;
	const fmode_t mode = FMODE_READ | FMODE_WRITE;

	if (sbi->bdev_list==NULL) {
		sbi->bdev_list = kcalloc(BDEV_COUNT_MAX, sizeof(struct bdev_info), GFP_KERNEL);	
	}
	
	if (!bdev_path) return -ENOENT;

	bdev_raw = lookup_bdev(bdev_path);
	if (IS_ERR(bdev_raw))
	{
		nova_info("bdev: error opening raw device <%lu>\n", PTR_ERR(bdev_raw));
		return -ENOENT;
	}
	if (!bdget(bdev_raw->bd_dev))
	{
		nova_info("bdev: error bdget()\n");
		return -ENOENT;
	}
	if (blkdev_get(bdev_raw, mode, NULL))
	{
		nova_info("bdev: error blkdev_get()\n");
		bdput(bdev_raw);
		return -ENOENT;
	}	

	sbi->bdev_list[i].bdev_raw = bdev_raw;
	strcat(sbi->bdev_list[i].bdev_path, bdev_path);

	bd_disk = bdev_raw->bd_disk;
	nsector = get_capacity(bd_disk);
	sbi->bdev_list[i].major = bd_disk->major;
	sbi->bdev_list[i].minors = bd_disk->minors;
	if (size!=0) nsector = size << 21;
	sbi->bdev_list[i].capacity_sector = nsector;
	sbi->bdev_list[i].capacity_page = nsector>>3;
	sbi->bdev_list[i].opt_size_bit = BDEV_OPT_SIZE_BIT; //temp value
	strcat(sbi->bdev_list[i].bdev_name,bd_disk->disk_name);
	TIER_BDEV_HIGH++;
	nova_info("Tier %d is set to %s\n", TIER_BDEV_HIGH, bdev_path);
		
	return 0;
}

static loff_t nova_max_size(int bits)
{
	loff_t res;

	res = (1ULL << 63) - 1;

	if (res > MAX_LFS_FILESIZE)
		res = MAX_LFS_FILESIZE;

	nova_dbg_verbose("max file size %llu bytes\n", res);
	return res;
}

enum {
	Opt_bpi, Opt_init, Opt_snapshot, Opt_mode, Opt_uid,
	Opt_gid, Opt_blocksize, Opt_wprotect, Opt_bdev, Opt_bsize, Opt_osb, Opt_psize, Opt_vsize,
	Opt_err_cont, Opt_err_panic, Opt_err_ro,
	Opt_dbgmask, Opt_err
};

static const match_table_t tokens = {
	{ Opt_bpi,	     "bpi=%u"		  },
	{ Opt_init,	     "init"		  },
	{ Opt_snapshot,	     "snapshot=%u"	  },
	{ Opt_mode,	     "mode=%o"		  },
	{ Opt_uid,	     "uid=%u"		  },
	{ Opt_gid,	     "gid=%u"		  },
	{ Opt_wprotect,	     "wprotect"		  },
	{ Opt_bdev,	     "bdev=%s"		  },
	{ Opt_bsize,	     "bsize=%u"		  },
	{ Opt_osb,	     "osb=%u"		  },
	{ Opt_psize,	     "psize=%u"		  },
	{ Opt_vsize,	     "vsize=%u"		  },
	{ Opt_err_cont,	     "errors=continue"	  },
	{ Opt_err_panic,     "errors=panic"	  },
	{ Opt_err_ro,	     "errors=remount-ro"  },
	{ Opt_dbgmask,	     "dbgmask=%u"	  },
	{ Opt_err,	     NULL		  },
};

static int nova_parse_tiering_options(struct nova_sb_info *sbi, char *options)
{
	char *p;
	unsigned int input = 0;
	unsigned long size = 0;
	substring_t args[MAX_OPT_ARGS];
	char *bdev_path = kmalloc(20*sizeof(char),GFP_KERNEL); // block devices for tiering

	if (!options)
		return 0;

	vpmem_reset();
	
	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		if(token == Opt_psize) {
			if (match_int(&args[0], &input)){
				return -EINVAL;
			}
			// psize is in GB
			sbi->initsize = (unsigned long) input << 30;
		}
		if(token == Opt_vsize) {
			if (match_int(&args[0], &input)){
				return -EINVAL;
			}
			// vsize is in MB
			VPMEM_MAX_PAGES_QTR = (int) input*64;
		}
		if(token == Opt_bsize) {
			if (match_int(&args[0], &input)){
				return -EINVAL;
			}
			// bsize is in GB
			size = (unsigned long) input;
		}
		if(token == Opt_osb) {
			if (match_int(&args[0], &input)){
				return -EINVAL;
			}
			BDEV_OPT_SIZE_BIT = (unsigned long) input;
		}
		if(token == Opt_bdev) {
			bdev_path = match_strdup(args);
			if (!bdev_path) {
				return -EINVAL;
			}
			if (strcmp(bdev_path,"auto")==0) {
				return nova_get_bdev_info(sbi);
			}
			if (nova_get_one_bdev_info(sbi,bdev_path,size) != 0) {
				nova_info("Get bdev [%s] failed!\n", bdev_path);
				continue;
			}
			input = 0;
			size = 0;		
		}
	}

	kfree(bdev_path);
	return 0;
}

static int nova_parse_options(char *options, struct nova_sb_info *sbi,
			       bool remount)
{
	char *p;
	substring_t args[MAX_OPT_ARGS];
	int option;
	kuid_t uid;

	if (!options)
		return 0;

	while ((p = strsep(&options, ",")) != NULL) {
		int token;

		if (!*p)
			continue;

		token = match_token(p, tokens, args);
		switch (token) {
		case Opt_bpi:
			if (match_int(&args[0], &option))
				goto bad_val;
			if (remount && sbi->bpi)
				goto bad_opt;
			sbi->bpi = option;
			break;
		case Opt_uid:
			if (match_int(&args[0], &option))
				goto bad_val;
			uid = make_kuid(current_user_ns(), option);
			if (remount && !uid_eq(sbi->uid, uid))
				goto bad_opt;
			sbi->uid = uid;
			break;
		case Opt_gid:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->gid = make_kgid(current_user_ns(), option);
			break;
		case Opt_mode:
			if (match_octal(&args[0], &option))
				goto bad_val;
			sbi->mode = option & 01777U;
			break;
		case Opt_init:
			if (remount)
				goto bad_opt;
			set_opt(sbi->s_mount_opt, FORMAT);
			break;
		case Opt_snapshot:
			if (match_int(&args[0], &option))
				goto bad_val;
			sbi->mount_snapshot = 1;
			sbi->mount_snapshot_epoch_id = option;
			break;
		case Opt_err_panic:
			clear_opt(sbi->s_mount_opt, ERRORS_CONT);
			clear_opt(sbi->s_mount_opt, ERRORS_RO);
			set_opt(sbi->s_mount_opt, ERRORS_PANIC);
			break;
		case Opt_err_ro:
			clear_opt(sbi->s_mount_opt, ERRORS_CONT);
			clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
			set_opt(sbi->s_mount_opt, ERRORS_RO);
			break;
		case Opt_err_cont:
			clear_opt(sbi->s_mount_opt, ERRORS_RO);
			clear_opt(sbi->s_mount_opt, ERRORS_PANIC);
			set_opt(sbi->s_mount_opt, ERRORS_CONT);
			break;
		case Opt_wprotect:
			if (remount)
				goto bad_opt;
			set_opt(sbi->s_mount_opt, PROTECT);
			nova_info("NOVA: Enabling new Write Protection (CR0.WP)\n");
			break;
		case Opt_bdev:
			break;
		case Opt_bsize:
			break;
		case Opt_osb:
			break;
		case Opt_dbgmask:
			if (match_int(&args[0], &option))
				goto bad_val;
			nova_dbgmask = option;
			break;
		default: {
			goto bad_opt;
		}
		}
	}

	return 0;

bad_val:
	nova_info("Bad value '%s' for mount option '%s'\n", args[0].from,
	       p);
	return -EINVAL;
bad_opt:
	nova_info("Bad mount option: \"%s\"\n", p);
	return -EINVAL;
}


/* Make sure we have enough space */
static bool nova_check_size(struct super_block *sb, unsigned long size)
{
	unsigned long minimum_size;

	/* space required for super block and root directory.*/
	minimum_size = (HEAD_RESERVED_BLOCKS + TAIL_RESERVED_BLOCKS + 1)
			  << sb->s_blocksize_bits;

	if (size < minimum_size)
		return false;

	return true;
}

static inline int nova_check_super_checksum(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u32 crc = 0;

	// Check CRC but skip c_sum, which is the 4 bytes at the beginning
	crc = nova_crc32c(~0, (__u8 *)sbi->nova_sb + sizeof(__le32),
			sizeof(struct nova_super_block) - sizeof(__le32));

	if (sbi->nova_sb->s_sum == cpu_to_le32(crc))
		return 0;
	else
		return 1;
}

inline void nova_sync_super(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_super_block *super = nova_get_super(sb);
	struct nova_super_block *super_redund;

	nova_memunlock_super(sb);

	super_redund = nova_get_redund_super(sb);

	memcpy_to_pmem_nocache((void *)super, (void *)sbi->nova_sb,
		sizeof(struct nova_super_block));
	PERSISTENT_BARRIER();

	memcpy_to_pmem_nocache((void *)super_redund, (void *)sbi->nova_sb,
		sizeof(struct nova_super_block));
	PERSISTENT_BARRIER();

	nova_memlock_super(sb);
}

/* Update checksum for the DRAM copy */
inline void nova_update_super_crc(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u32 crc = 0;

	sbi->nova_sb->s_wtime = cpu_to_le32(get_seconds());
	sbi->nova_sb->s_sum = 0;
	crc = nova_crc32c(~0, (__u8 *)sbi->nova_sb + sizeof(__le32),
			sizeof(struct nova_super_block) - sizeof(__le32));
	sbi->nova_sb->s_sum = cpu_to_le32(crc);
}


static inline void nova_update_mount_time(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u64 mnt_write_time;

	mnt_write_time = (get_seconds() & 0xFFFFFFFF);
	mnt_write_time = mnt_write_time | (mnt_write_time << 32);

	sbi->nova_sb->s_mtime = cpu_to_le64(mnt_write_time);
	nova_update_super_crc(sb);

	nova_sync_super(sb);
}

static struct nova_inode *nova_init(struct super_block *sb,
				      unsigned long size)
{
	unsigned long blocksize;
	struct nova_inode *root_i, *pi;
	struct nova_super_block *super;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct nova_inode_update update;
	u64 epoch_id;
	timing_t init_time;

	NOVA_START_TIMING(new_init_t, init_time);
	nova_info("creating an empty nova of size %lu\n", size);
	sbi->num_blocks = ((unsigned long)(size) >> PAGE_SHIFT);

	nova_dbgv("nova: Default block size set to 4K\n");
	sbi->blocksize = blocksize = NOVA_DEF_BLOCK_SIZE_4K;
	nova_set_blocksize(sb, sbi->blocksize);

	if (!nova_check_size(sb, size)) {
		nova_warn("Specified NOVA size too small 0x%lx.\n", size);
		return ERR_PTR(-EINVAL);
	}

	nova_dbgv("max file name len %d\n", (unsigned int)NOVA_NAME_LEN);

	super = nova_get_super(sb);

	nova_memunlock_reserved(sb, super);
	/* clear out super-block and inode table */
	memset_nt(super, 0, sbi->head_reserved_blocks * sbi->blocksize);

	pi = nova_get_inode_by_ino(sb, NOVA_BLOCKNODE_INO);
	pi->nova_ino = NOVA_BLOCKNODE_INO;
	nova_flush_buffer(pi, CACHELINE_SIZE, 1);

	pi = nova_get_inode_by_ino(sb, NOVA_SNAPSHOT_INO);
	pi->nova_ino = NOVA_SNAPSHOT_INO;
	nova_flush_buffer(pi, CACHELINE_SIZE, 1);

	memset(&update, 0, sizeof(struct nova_inode_update));
	nova_update_inode(sb, &sbi->snapshot_si->vfs_inode, pi, &update, 1);

	nova_memlock_reserved(sb, super);

	nova_init_blockmap(sb, 0);

	nova_init_bdev_blockmap(sb, 0);

	if (nova_lite_journal_hard_init(sb) < 0) {
		nova_err(sb, "Lite journal hard initialization failed\n");
		return ERR_PTR(-EINVAL);
	}

	if (nova_init_inode_inuse_list(sb) < 0)
		return ERR_PTR(-EINVAL);

	if (nova_init_inode_table(sb) < 0)
		return ERR_PTR(-EINVAL);


	sbi->nova_sb->s_size = cpu_to_le64(size);
	sbi->nova_sb->s_blocksize = cpu_to_le32(blocksize);
	sbi->nova_sb->s_magic = cpu_to_le32(NOVA_SUPER_MAGIC);
	sbi->nova_sb->s_epoch_id = 0;
	sbi->nova_sb->s_metadata_csum = metadata_csum;
	sbi->nova_sb->s_data_csum = data_csum;
	sbi->nova_sb->s_data_parity = data_parity;
	nova_update_super_crc(sb);

	nova_sync_super(sb);

	root_i = nova_get_inode_by_ino(sb, NOVA_ROOT_INO);
	nova_dbgv("%s: Allocate root inode @ 0x%p\n", __func__, root_i);

	nova_memunlock_inode(sb, root_i);
	root_i->i_mode = cpu_to_le16(sbi->mode | S_IFDIR);
	root_i->i_uid = cpu_to_le32(from_kuid(&init_user_ns, sbi->uid));
	root_i->i_gid = cpu_to_le32(from_kgid(&init_user_ns, sbi->gid));
	root_i->i_links_count = cpu_to_le16(2);
	root_i->i_blk_type = NOVA_BLOCK_TYPE_4K;
	root_i->i_flags = 0;
	root_i->i_size = cpu_to_le64(sb->s_blocksize);
	root_i->i_atime = root_i->i_mtime = root_i->i_ctime =
		cpu_to_le32(get_seconds());
	root_i->nova_ino = cpu_to_le64(NOVA_ROOT_INO);
	root_i->valid = 1;
	/* nova_sync_inode(root_i); */
	nova_flush_buffer(root_i, sizeof(*root_i), false);
	nova_memlock_inode(sb, root_i);

	epoch_id = nova_get_epoch_id(sb);
	nova_append_dir_init_entries(sb, root_i, NOVA_ROOT_INO,
					NOVA_ROOT_INO, epoch_id);

	PERSISTENT_MARK();
	PERSISTENT_BARRIER();
	NOVA_END_TIMING(new_init_t, init_time);
	nova_info("NOVA initialization finish\n");
	return root_i;
}

static inline void set_default_opts(struct nova_sb_info *sbi)
{
	set_opt(sbi->s_mount_opt, HUGEIOREMAP);
	set_opt(sbi->s_mount_opt, ERRORS_CONT);
	sbi->head_reserved_blocks = HEAD_RESERVED_BLOCKS;
	sbi->tail_reserved_blocks = TAIL_RESERVED_BLOCKS;
	sbi->cpus = num_online_cpus();
	sbi->map_id = 0;
}

static void nova_root_check(struct super_block *sb, struct nova_inode *root_pi)
{
	if (!S_ISDIR(le16_to_cpu(root_pi->i_mode)))
		nova_warn("root is not a directory!\n");
}

/* Check super block magic and checksum */
static int nova_check_super(struct super_block *sb,
	struct nova_super_block *ps)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int rc;

	rc = memcpy_mcsafe(sbi->nova_sb, ps,
				sizeof(struct nova_super_block));

	if (rc < 0)
		return rc;

	if (le32_to_cpu(sbi->nova_sb->s_magic) != NOVA_SUPER_MAGIC)
		return -EIO;

	if (nova_check_super_checksum(sb))
		return -EIO;

	return 0;
}

/* Check if we disable protection previously and enable it now */
/* FIXME */
static int nova_check_module_params(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	if (sbi->nova_sb->s_metadata_csum != metadata_csum) {
		nova_dbg("%s metadata checksum\n",
			sbi->nova_sb->s_metadata_csum ? "Enable" : "Disable");
		metadata_csum = sbi->nova_sb->s_metadata_csum;
	}

	if (sbi->nova_sb->s_data_csum != data_csum) {
		nova_dbg("%s data checksum\n",
			sbi->nova_sb->s_data_csum ? "Enable" : "Disable");
		data_csum = sbi->nova_sb->s_data_csum;
	}

	if (sbi->nova_sb->s_data_parity != data_parity) {
		nova_dbg("%s data parity\n",
			sbi->nova_sb->s_data_parity ? "Enable" : "Disable");
		data_parity = sbi->nova_sb->s_data_parity;
	}

	return 0;
}

static int nova_check_integrity(struct super_block *sb)
{
	struct nova_super_block *super = nova_get_super(sb);
	struct nova_super_block *super_redund;
	int rc;

	super_redund = nova_get_redund_super(sb);

	/* Do sanity checks on the superblock */
	rc = nova_check_super(sb, super);
	if (rc < 0) {
		rc = nova_check_super(sb, super_redund);
		if (rc < 0) {
			nova_err(sb, "Can't find a valid nova partition\n");
			return rc;
		} else
			nova_warn("Error in super block: try to repair it with the other copy\n");
		
	}

	nova_sync_super(sb);

	nova_check_module_params(sb);
	return 0;
}

static int nova_fill_super(struct super_block *sb, void *data, int silent)
{
	struct nova_inode *root_pi;
	struct nova_sb_info *sbi = NULL;
	struct inode *root_i = NULL;
	struct inode_map *inode_map;
	unsigned long blocksize;
	size_t strp_size = NOVA_STRIPE_SIZE;
	u32 random = 0;
	int retval = -EINVAL;
	int i;
	timing_t mount_time;

	NOVA_START_TIMING(mount_t, mount_time);

	BUILD_BUG_ON(sizeof(struct nova_super_block) > NOVA_SB_SIZE);
	BUILD_BUG_ON(sizeof(struct nova_inode) > NOVA_INODE_SIZE);
	BUILD_BUG_ON(sizeof(struct nova_inode_log_page) != PAGE_SIZE);

	BUILD_BUG_ON(sizeof(struct journal_ptr_pair) > CACHELINE_SIZE);
	BUILD_BUG_ON(PAGE_SIZE/sizeof(struct journal_ptr_pair) < MAX_CPUS);
	BUILD_BUG_ON(PAGE_SIZE/sizeof(struct nova_lite_journal_entry) <
		     NOVA_MAX_JOURNAL_LENGTH);

	BUILD_BUG_ON(sizeof(struct nova_inode_page_tail) +
		     LOG_BLOCK_TAIL != PAGE_SIZE);

	sbi = kzalloc(sizeof(struct nova_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	sbi->nova_sb = kzalloc(sizeof(struct nova_super_block), GFP_KERNEL);
	if (!sbi->nova_sb) {
		kfree(sbi);
		return -ENOMEM;
	}

	sb->s_fs_info = sbi;
	sbi->sb = sb;

	set_default_opts(sbi);

	/* Currently the log page supports 64 journal pointer pairs */
	if (sbi->cpus > MAX_CPUS) {
		nova_err(sb, "NOVA needs more log pointer pages to support more than "
			  __stringify(MAX_CPUS) " cpus.\n");
		goto out;
	}

	TIER_BDEV_HIGH = 0;
	sbi->initsize = 0;
	retval = nova_parse_tiering_options(sbi, data);
	if (retval) {
		nova_err(sb, "%s: Failed to get block device info.",
			 __func__);
		goto out;
	}
	if (TIER_BDEV_HIGH == 0) {
		nova_info("No block device is found, invoking Auto Get.");
		nova_get_bdev_info(sbi);
	}

	retval = nova_get_nvmm_info(sb, sbi);
	if (retval) {
		nova_err(sb, "%s: Failed to get nvmm info.",
			 __func__);
		goto out;
	}

	sbi->num_blocks = sbi->initsize >> PAGE_SHIFT;
	
	print_all_bdev(sbi);
	// nova_info("size of unsigned long:%lu\n",sizeof(unsigned long));
		
	// nova_dbg("%s: dev pmem, phys_addr 0x%llx, virt_addr %p, size %ld\n",
    //             __func__, sbi->phys_addr, sbi->virt_addr, sbi->initsize);

	vpmem_get(sbi, 0);
	nova_dbg("%s: dev vpmem, phys_addr 0x%llx, virt_addr %p, size %ld\n",
		__func__, sbi->phys_addr, sbi->virt_addr, sbi->initsize);

	if (DEBUG_STARTUP_TEST) bdev_test(sbi);

	retval = start_usage_thread(sbi);
	if (retval)
		goto out;

	retval = start_bm_thread(sbi);
	if (retval)
		goto out;

	nova_dbg("measure timing %d, metadata checksum %d, inplace update %d, wprotect %d, data checksum %d, data parity %d, DRAM checksum %d\n",
		measure_timing, metadata_csum,
		inplace_data_updates, wprotect,	 data_csum,
		data_parity, dram_struct_csum);

	get_random_bytes(&random, sizeof(u32));
	atomic_set(&sbi->next_generation, random);

	/* Init with default values */
	sbi->mode = (0755);
	sbi->uid = current_fsuid();
	sbi->gid = current_fsgid();
	set_opt(sbi->s_mount_opt, DAX);
	set_opt(sbi->s_mount_opt, HUGEIOREMAP);

	mutex_init(&sbi->vma_mutex);
	INIT_LIST_HEAD(&sbi->mmap_sih_list);

	sbi->inode_maps = kcalloc(sbi->cpus, sizeof(struct inode_map),
					GFP_KERNEL);
	if (!sbi->inode_maps) {
		retval = -ENOMEM;
		nova_dbg("%s: Allocating inode maps failed.",
			 __func__);
		goto out;
	}

	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		mutex_init(&inode_map->inode_table_mutex);
		inode_map->inode_inuse_tree = RB_ROOT;
	}

	mutex_init(&sbi->s_lock);

	/* tiering */
	retval = init_dram_buffer(sbi);
	if (retval) {
		nova_err(sb, "%s: Failed to allocate DRAM buffer.",
			 __func__);
		goto out;
	}

	sbi->zeroed_page = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!sbi->zeroed_page) {
		retval = -ENOMEM;
		nova_dbg("%s: sbi->zeroed_page failed.",
			 __func__);
		goto out;
	}

	for (i = 0; i < 8; i++)
		sbi->zero_csum[i] = nova_crc32c(NOVA_INIT_CSUM,
				sbi->zeroed_page, strp_size);
	sbi->zero_parity = kzalloc(strp_size, GFP_KERNEL);

	if (!sbi->zero_parity) {
		retval = -ENOMEM;
		nova_err(sb, "%s: sbi->zero_parity failed.",
			 __func__);
		goto out;
	}

	sbi->snapshot_si = kmem_cache_alloc(nova_inode_cachep, GFP_NOFS);
	nova_snapshot_init(sb);

	retval = nova_parse_options(data, sbi, 0);
	if (retval) {
		nova_err(sb, "%s: Failed to parse nova command line options.",
			 __func__);
		goto out;
	}

	if (nova_alloc_block_free_lists(sb)) {
		retval = -ENOMEM;
		nova_err(sb, "%s: Failed to allocate block free lists.",
			 __func__);
		goto out;
	}

	if (nova_alloc_bdev_block_free_lists(sb)) {
		retval = -ENOMEM;
		nova_err(sb, "%s: Failed to allocate bdev block free lists.",
			 __func__);
		goto out;
	}

	if (nova_alloc_inode_lru_lists(sb)) {
		retval = -ENOMEM;
		nova_err(sb, "%s: Failed to allocate bdev block free lists.",
			 __func__);
		goto out;
	}

	if (nova_init_tiering_stat(sb)) {
		retval = -ENOMEM;
		nova_err(sb, "%s: Failed to allocate bdev block free lists.",
			 __func__);
		goto out;
	}

	nova_sysfs_init(sb);

	/* Init a new nova instance */
	if (sbi->s_mount_opt & NOVA_MOUNT_FORMAT) {
		root_pi = nova_init(sb, sbi->initsize);
		retval = -ENOMEM;
		if (IS_ERR(root_pi)) {
			nova_err(sb, "%s: root_pi error.",
				 __func__);

			goto out;
		}
		goto setup_sb;
	}
	
	nova_dbg_verbose("checking physical address 0x%016llx for nova image\n",
		  (u64)sbi->phys_addr);

	if (nova_check_integrity(sb) < 0) {
		nova_dbg("Memory contains invalid nova %x:%x\n",
			le32_to_cpu(sbi->nova_sb->s_magic), NOVA_SUPER_MAGIC);
		goto out;
	}

	if (nova_lite_journal_soft_init(sb)) {
		retval = -EINVAL;
		nova_err(sb, "Lite journal initialization failed\n");
		goto out;
	}

	if (sbi->mount_snapshot) {
		retval = nova_mount_snapshot(sb);
		if (retval) {
			nova_err(sb, "Mount snapshot failed\n");
			goto out;
		}
	}

	blocksize = le32_to_cpu(sbi->nova_sb->s_blocksize);
	nova_set_blocksize(sb, blocksize);

	nova_dbg_verbose("blocksize %lu\n", blocksize);

	/* Read the root inode */
	root_pi = nova_get_inode_by_ino(sb, NOVA_ROOT_INO);

	/* Check that the root inode is in a sane state */
	nova_root_check(sb, root_pi);

	/* Set it all up.. */
setup_sb:
	sb->s_magic = le32_to_cpu(sbi->nova_sb->s_magic);
	sb->s_op = &nova_sops;
	sb->s_maxbytes = nova_max_size(sb->s_blocksize_bits);
	sb->s_time_gran = 1000000000; // 1 second.
	sb->s_export_op = &nova_export_ops;
	sb->s_xattr = NULL;
	sb->s_flags |= MS_NOSEC;

	/* If the FS was not formatted on this mount, scan the meta-data after
	 * truncate list has been processed
	 */
	if ((sbi->s_mount_opt & NOVA_MOUNT_FORMAT) == 0)
		nova_recovery(sb);

	root_i = nova_iget(sb, NOVA_ROOT_INO);
	if (IS_ERR(root_i)) {
		retval = PTR_ERR(root_i);
		nova_err(sb, "%s: failed to get root inode",
			 __func__);

		goto out;
	}

	sb->s_root = d_make_root(root_i);
	if (!sb->s_root) {
		nova_err(sb, "get nova root inode failed\n");
		retval = -ENOMEM;
		goto out;
	}

	if (!(sb->s_flags & MS_RDONLY))
		nova_update_mount_time(sb);

	nova_print_curr_epoch_id(sb);

	retval = 0;

	if (DEBUG_BFL_INFO) print_all_bfl(sb);
	// if (DEBUG_STARTUP_TEST) bfl_test(sbi);

	NOVA_END_TIMING(mount_t, mount_time);
	return retval;
out:
	kfree(sbi->zeroed_page);
	sbi->zeroed_page = NULL;

	kfree(sbi->zero_parity);
	sbi->zero_parity = NULL;

	kfree(sbi->free_lists);
	sbi->free_lists = NULL;

	kfree(sbi->bdev_free_list);
	sbi->bdev_free_list = NULL;

	kfree(sbi->bdev_list);
	sbi->bdev_list = NULL;

	kfree(sbi->journal_locks);
	sbi->journal_locks = NULL;

	kfree(sbi->stat);
	sbi->stat = NULL;

	kfree(sbi->bb_pages);
	sbi->bb_pages = NULL;

	kfree(sbi->bdev_buffer);
	sbi->bdev_buffer = NULL;

	kfree(sbi->bal_head);
	sbi->bal_head = NULL;

	kfree(sbi->inode_maps);
	sbi->inode_maps = NULL;

	nova_sysfs_exit(sb);

	kfree(sbi->nova_sb);
	kfree(sbi);
	return retval;
}

int nova_statfs(struct dentry *d, struct kstatfs *buf)
{
	struct super_block *sb = d->d_sb;
	struct nova_sb_info *sbi = (struct nova_sb_info *)sb->s_fs_info;

	buf->f_type = NOVA_SUPER_MAGIC;
	buf->f_bsize = sb->s_blocksize;

	buf->f_blocks = nova_count_total_blocks(sb);
	buf->f_bfree = buf->f_bavail = nova_count_free_blocks(sb);
	buf->f_files = LONG_MAX;
	buf->f_ffree = LONG_MAX - sbi->s_inodes_used_count;
	buf->f_namelen = NOVA_NAME_LEN;
	nova_dbg_verbose("nova_stats: total 4k free blocks 0x%llx\n",
		buf->f_bfree);
	return 0;
}

static int nova_show_options(struct seq_file *seq, struct dentry *root)
{
	struct nova_sb_info *sbi = NOVA_SB(root->d_sb);

	//seq_printf(seq, ",physaddr=0x%016llx", (u64)sbi->phys_addr);
	//if (sbi->initsize)
	//     seq_printf(seq, ",init=%luk", sbi->initsize >> 10);
	//if (sbi->blocksize)
	//	 seq_printf(seq, ",bs=%lu", sbi->blocksize);
	//if (sbi->bpi)
	//	seq_printf(seq, ",bpi=%lu", sbi->bpi);
	if (sbi->mode != (0777 | S_ISVTX))
		seq_printf(seq, ",mode=%03o", sbi->mode);
	if (uid_valid(sbi->uid))
		seq_printf(seq, ",uid=%u", from_kuid(&init_user_ns, sbi->uid));
	if (gid_valid(sbi->gid))
		seq_printf(seq, ",gid=%u", from_kgid(&init_user_ns, sbi->gid));
	if (test_opt(root->d_sb, ERRORS_RO))
		seq_puts(seq, ",errors=remount-ro");
	if (test_opt(root->d_sb, ERRORS_PANIC))
		seq_puts(seq, ",errors=panic");
	/* memory protection disabled by default */
	if (test_opt(root->d_sb, PROTECT))
		seq_puts(seq, ",wprotect");
	//if (test_opt(root->d_sb, DAX))
	//	seq_puts(seq, ",dax");

	return 0;
}

int nova_remount(struct super_block *sb, int *mntflags, char *data)
{
	unsigned long old_sb_flags;
	unsigned long old_mount_opt;
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret = -EINVAL;

	/* Store the old options */
	mutex_lock(&sbi->s_lock);
	old_sb_flags = sb->s_flags;
	old_mount_opt = sbi->s_mount_opt;

	ret = nova_parse_tiering_options(sbi, data);
	if (ret) {
		nova_err(sb, "%s: Failed to get block device info.",
			 __func__);
		goto restore_opt;
	}
	if (TIER_BDEV_HIGH == 0) {
		nova_info("No block device is found, invoking Auto Get.");
		nova_get_bdev_info(sbi);
	}

	if (nova_parse_options(data, sbi, 1))
		goto restore_opt;

	sb->s_flags = (sb->s_flags & ~MS_POSIXACL) |
		      ((sbi->s_mount_opt & NOVA_MOUNT_POSIX_ACL) ?
		       MS_POSIXACL : 0);

	if ((*mntflags & MS_RDONLY) != (sb->s_flags & MS_RDONLY))
		nova_update_mount_time(sb);

	mutex_unlock(&sbi->s_lock);
	ret = 0;
	return ret;

restore_opt:
	sb->s_flags = old_sb_flags;
	sbi->s_mount_opt = old_mount_opt;
	mutex_unlock(&sbi->s_lock);
	return ret;
}

static void nova_put_super(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	struct inode_map *inode_map;
	int i;

	nova_info("*****************\n");
	nova_info("*  NOVA umount  *\n");
	nova_info("*****************\n");

	if (DEBUG_BFL_INFO) print_all_bfl(sb);
	nova_print_curr_epoch_id(sb);

	stop_bm_thread(sbi);
	stop_usage_thread(sbi);
		
	/* It's unmount time, so unmap the nova memory */
//	nova_print_free_lists(sb);
	if (sbi->virt_addr) {
		nova_save_snapshots(sb);
		kmem_cache_free(nova_inode_cachep, sbi->snapshot_si);
		nova_save_inode_list_to_log(sb);
		/* Save everything before blocknode mapping! */
		nova_save_blocknode_mappings_to_log(sb);
		sbi->virt_addr = NULL;
	}

	vpmem_put();

	nova_delete_free_lists(sb);
	nova_delete_bdev_free_list(sb);

	kfree(sbi->zeroed_page);
	kfree(sbi->zero_parity);
	nova_dbgmask = 0;
	kfree(sbi->free_lists);
	kfree(sbi->bdev_free_list);
	kfree(sbi->bdev_list);
	kfree(sbi->journal_locks);
	kfree(sbi->stat);
	kfree(sbi->bb_pages);
	kfree(sbi->bal_head);
	kfree(sbi->bdev_buffer);
	
	for (i = 0; i < sbi->cpus; i++) {
		inode_map = &sbi->inode_maps[i];
		nova_dbgv("CPU %d: inode allocated %d, freed %d\n",
			i, inode_map->allocated, inode_map->freed);
	}

	kfree(sbi->inode_maps);

	nova_sysfs_exit(sb);

	kfree(sbi->nova_sb);
	kfree(sbi);
	sb->s_fs_info = NULL;
}

inline void nova_free_range_node(struct nova_range_node *node)
{
	kmem_cache_free(nova_range_node_cachep, node);
}


inline void nova_free_inode_node(struct super_block *sb,
	struct nova_range_node *node)
{
	nova_free_range_node(node);
}

inline void nova_free_vma_item(struct super_block *sb,
	struct vma_item *item)
{
	nova_free_range_node((struct nova_range_node *)item);
}

inline struct snapshot_info *nova_alloc_snapshot_info(struct super_block *sb)
{
	struct snapshot_info *p;

	p = (struct snapshot_info *)
		kmem_cache_alloc(nova_snapshot_info_cachep, GFP_NOFS);
	return p;
}

inline void nova_free_snapshot_info(struct snapshot_info *info)
{
	kmem_cache_free(nova_snapshot_info_cachep, info);
}

inline struct nova_range_node *nova_alloc_range_node(struct super_block *sb)
{
	struct nova_range_node *p;

	p = (struct nova_range_node *)
		kmem_cache_zalloc(nova_range_node_cachep, GFP_NOFS);
	return p;
}


inline struct nova_range_node *nova_alloc_inode_node(struct super_block *sb)
{
	return nova_alloc_range_node(sb);
}

inline struct vma_item *nova_alloc_vma_item(struct super_block *sb)
{
	return (struct vma_item *)nova_alloc_range_node(sb);
}


static struct inode *nova_alloc_inode(struct super_block *sb)
{
	struct nova_inode_info *vi;

	vi = kmem_cache_alloc(nova_inode_cachep, GFP_NOFS);
	if (!vi)
		return NULL;

	vi->vfs_inode.i_version = 1;

	return &vi->vfs_inode;
}

static void nova_i_callback(struct rcu_head *head)
{
	struct inode *inode = container_of(head, struct inode, i_rcu);
	struct nova_inode_info *vi = NOVA_I(inode);

	nova_dbg_verbose("%s: ino %lu\n", __func__, inode->i_ino);
	kmem_cache_free(nova_inode_cachep, vi);
}

static void nova_destroy_inode(struct inode *inode)
{
	nova_dbgv("%s: %lu\n", __func__, inode->i_ino);
	call_rcu(&inode->i_rcu, nova_i_callback);
}

static void init_once(void *foo)
{
	struct nova_inode_info *vi = foo;

	inode_init_once(&vi->vfs_inode);
}


static int __init init_rangenode_cache(void)
{
	nova_range_node_cachep = kmem_cache_create("nova_range_node_cache",
					sizeof(struct nova_range_node),
					0, (SLAB_RECLAIM_ACCOUNT |
					SLAB_MEM_SPREAD), NULL);
	if (nova_range_node_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static int __init init_snapshot_info_cache(void)
{
	nova_snapshot_info_cachep = kmem_cache_create(
					"nova_snapshot_info_cache",
					sizeof(struct snapshot_info),
					0, (SLAB_RECLAIM_ACCOUNT |
					SLAB_MEM_SPREAD), NULL);
	if (nova_snapshot_info_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static int __init init_inodecache(void)
{
	nova_inode_cachep = kmem_cache_create("nova_inode_cache",
					       sizeof(struct nova_inode_info),
					       0, (SLAB_RECLAIM_ACCOUNT |
						   SLAB_MEM_SPREAD), init_once);
	if (nova_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
}

static void destroy_inodecache(void)
{
	/*
	 * Make sure all delayed rcu free inodes are flushed before
	 * we destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(nova_inode_cachep);
}

static void destroy_rangenode_cache(void)
{
	kmem_cache_destroy(nova_range_node_cachep);
}

static void destroy_snapshot_info_cache(void)
{
	kmem_cache_destroy(nova_snapshot_info_cachep);
}

/*
 * the super block writes are all done "on the fly", so the
 * super block is never in a "dirty" state, so there's no need
 * for write_super.
 */
static struct super_operations nova_sops = {
	.alloc_inode	= nova_alloc_inode,
	.destroy_inode	= nova_destroy_inode,
	.write_inode	= nova_write_inode,
	.dirty_inode	= nova_dirty_inode,
	.evict_inode	= nova_evict_inode,
	.put_super	= nova_put_super,
	.statfs		= nova_statfs,
	.remount_fs	= nova_remount,
	.show_options	= nova_show_options,
};

static struct dentry *nova_mount(struct file_system_type *fs_type,
				  int flags, const char *dev_name, void *data)
{
	nova_info("*****************\n");
	nova_info("*  NOVA  mount  *\n");
	nova_info("*****************\n");
	return mount_bdev(fs_type, flags, dev_name, data, nova_fill_super);
}

static struct file_system_type nova_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "NOVA",
	.mount		= nova_mount,
	.kill_sb	= kill_block_super,
};

static struct inode *nova_nfs_get_inode(struct super_block *sb,
					 u64 ino, u32 generation)
{
	struct inode *inode;

	if (ino < NOVA_ROOT_INO)
		return ERR_PTR(-ESTALE);

	if (ino > LONG_MAX)
		return ERR_PTR(-ESTALE);

	inode = nova_iget(sb, ino);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	if (generation && inode->i_generation != generation) {
		/* we didn't find the right inode.. */
		iput(inode);
		return ERR_PTR(-ESTALE);
	}

	return inode;
}

static struct dentry *nova_fh_to_dentry(struct super_block *sb,
					 struct fid *fid, int fh_len,
					 int fh_type)
{
	return generic_fh_to_dentry(sb, fid, fh_len, fh_type,
				    nova_nfs_get_inode);
}

static struct dentry *nova_fh_to_parent(struct super_block *sb,
					 struct fid *fid, int fh_len,
					 int fh_type)
{
	return generic_fh_to_parent(sb, fid, fh_len, fh_type,
				    nova_nfs_get_inode);
}

static const struct export_operations nova_export_ops = {
	.fh_to_dentry	= nova_fh_to_dentry,
	.fh_to_parent	= nova_fh_to_parent,
	.get_parent	= nova_get_parent,
};

static int __init init_nova_fs(void)
{
	int rc = 0;
	timing_t init_time;

	NOVA_START_TIMING(init_t, init_time);
	nova_dbg("%s: %d cpus online\n", __func__, num_online_cpus());
	if (arch_has_clwb())
		support_clwb = 1;

	nova_info("Arch new instructions support: CLWB %s\n",
			support_clwb ? "YES" : "NO");

	nova_proc_root = proc_mkdir(proc_dirname, NULL);

	nova_dbg("Data structure size: inode %lu, log_page %lu, file_write_entry %lu, dir_entry(max) %d, setattr_entry %lu, link_change_entry %lu\n",
		sizeof(struct nova_inode),
		sizeof(struct nova_inode_log_page),
		sizeof(struct nova_file_write_entry),
		NOVA_DIR_LOG_REC_LEN(NOVA_NAME_LEN),
		sizeof(struct nova_setattr_logentry),
		sizeof(struct nova_link_change_entry));

	rc = init_rangenode_cache();
	if (rc)
		return rc;

	rc = init_inodecache();
	if (rc)
		goto out1;

	rc = init_snapshot_info_cache();
	if (rc)
		goto out2;

	rc = nova_init_bio();
	if (rc)
		goto out3;

	rc = register_filesystem(&nova_fs_type);
	if (rc)
		goto out4;

    rc = vpmem_init();
	if (rc)
		goto out5;

	nova_info("init out");
	NOVA_END_TIMING(init_t, init_time);
	return 0;

out5:
	vpmem_put();
out4:
	nova_destroy_bio();
out3:
	destroy_snapshot_info_cache();
out2:
	destroy_inodecache();
out1:
	destroy_rangenode_cache();
	return rc;
}

static void __exit exit_nova_fs(void)
{
	unregister_filesystem(&nova_fs_type);
	remove_proc_entry(proc_dirname, NULL);
	destroy_snapshot_info_cache();
	destroy_inodecache();
	destroy_rangenode_cache();
	nova_destroy_bio();
}

MODULE_AUTHOR("Andiry Xu <jix024@cs.ucsd.edu>");
MODULE_DESCRIPTION("NOVA: A Persistent Memory File System");
MODULE_LICENSE("GPL");

module_init(init_nova_fs)
module_exit(exit_nova_fs)
