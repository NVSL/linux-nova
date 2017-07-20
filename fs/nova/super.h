#ifndef __SUPER_H
#define __SUPER_H
/*
 * Structure of the NOVA super block in PMEM
 *
 * The fields are partitioned into static and dynamic fields. The static fields
 * never change after file system creation. This was primarily done because
 * nova_get_block() returns NULL if the block offset is 0 (helps in catching
 * bugs). So if we modify any field using journaling (for consistency), we
 * will have to modify s_sum which is at offset 0. So journaling code fails.
 * This (static+dynamic fields) is a temporary solution and can be avoided
 * once the file system becomes stable and nova_get_block() returns correct
 * pointers even for offset 0.
 */
struct nova_super_block {
	/* static fields. they never change after file system creation.
	 * checksum only validates up to s_start_dynamic field below
	 */
	__le32		s_sum;			/* checksum of this sb */
	__le32		s_magic;		/* magic signature */
	__le32		s_padding32;
	__le32		s_blocksize;		/* blocksize in bytes */
	__le64		s_size;			/* total size of fs in bytes */
	char		s_volume_name[16];	/* volume name */

	/* all the dynamic fields should go here */
	__le64		s_epoch_id;		/* Epoch ID */

	/* s_mtime and s_wtime should be together and their order should not be
	 * changed. we use an 8 byte write to update both of them atomically
	 */
	__le32		s_mtime;		/* mount time */
	__le32		s_wtime;		/* write time */

	/* Metadata and data protections */
	u8		s_padding8;
	u8		s_metadata_csum;
	u8		s_data_csum;
	u8		s_data_parity;
} __attribute((__packed__));


/* ======================= Reserved blocks ========================= */

/*
 * The first block contains super blocks;
 * The second block contains reserved inodes;
 * The third block contains replica reserved inodes;
 * The fourth block contains pointers to journal pages.
 * The fifth/sixth block contains pointers to inode tables.
 * The seventh/eighth blocks are void by now.
 *
 * If data protection is enabled, more blocks are reserverd for checksums and
 * parities and the number is derived according to the whole storage size.
 */
#define	HEAD_RESERVED_BLOCKS	8

#define	RESERVE_INODE_START	1
#define	JOURNAL_START		3
#define	INODE_TABLE0_START	4
#define	INODE_TABLE1_START	5

/* For redundant super block and replica basic inodes */
#define	TAIL_RESERVED_BLOCKS	2

/* ======================= Reserved inodes ========================= */

/* We have space for 31 reserved inodes */
#define NOVA_ROOT_INO		(1)
#define NOVA_INODETABLE_INO	(2)	/* Temporaty inode table */
#define NOVA_BLOCKNODE_INO	(3)
#define NOVA_INODELIST_INO	(4)
#define NOVA_LITEJOURNAL_INO	(5)
#define NOVA_INODELIST1_INO	(6)
#define NOVA_SNAPSHOT_INO	(7)	/* Fake snapshot inode */
#define NOVA_TEST_PERF_INO	(8)


/* Normal inode starts at 32 */
#define NOVA_NORMAL_INODE_START      (32)


/* If this is part of a read-modify-write of the super block,
 * nova_memunlock_super() before calling!
 */
static inline struct nova_super_block *nova_get_super(struct super_block *sb)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	return (struct nova_super_block *)sbi->virt_addr;
}

extern struct super_block *nova_read_super(struct super_block *sb, void *data,
	int silent);
extern int nova_statfs(struct dentry *d, struct kstatfs *buf);
extern int nova_remount(struct super_block *sb, int *flags, char *data);
void *nova_ioremap(struct super_block *sb, phys_addr_t phys_addr,
	ssize_t size);
extern struct nova_range_node *nova_alloc_range_node(struct super_block *sb);
extern void nova_free_range_node(struct nova_range_node *node);
extern void nova_update_super_crc(struct super_block *sb);
extern void nova_sync_super(struct super_block *sb);
	
#endif
