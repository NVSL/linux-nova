#ifndef __INODE_H
#define __INODE_H

struct nova_inode_info_header;
struct nova_inode;

#include "super.h"
#include "log.h"

enum nova_new_inode_type {
	TYPE_CREATE = 0,
	TYPE_MKNOD,
	TYPE_SYMLINK,
	TYPE_MKDIR
};


/*
 * Structure of an inode in PMEM
 * Keep the inode size to within 120 bytes: We use the last eight bytes
 * as inode table tail pointer.
 */
struct nova_inode {

	/* first 40 bytes */
	u8	i_rsvd;		 /* reserved. used to be checksum */
	u8	valid;		 /* Is this inode valid? */
	u8	deleted;	 /* Is this inode deleted? */
	u8	i_blk_type;	 /* data block size this inode uses */
	__le32	i_flags;	 /* Inode flags */
	__le64	i_size;		 /* Size of data in bytes */
	__le32	i_ctime;	 /* Inode modification time */
	__le32	i_mtime;	 /* Inode b-tree Modification time */
	__le32	i_atime;	 /* Access time */
	__le16	i_mode;		 /* File mode */
	__le16	i_links_count;	 /* Links count */

	__le64	i_xattr;	 /* Extended attribute block */

	/* second 40 bytes */
	__le32	i_uid;		 /* Owner Uid */
	__le32	i_gid;		 /* Group Id */
	__le32	i_generation;	 /* File version (for NFS) */
	__le32	i_create_time;	 /* Create time */
	__le64	nova_ino;	 /* nova inode number */

	__le64	log_head;	 /* Log head pointer */
	__le64	log_tail;	 /* Log tail pointer */

	/* last 40 bytes */
	__le64	alter_log_head;	 /* Alternate log head pointer */
	__le64	alter_log_tail;	 /* Alternate log tail pointer */

	__le64	create_epoch_id; /* Transaction ID when create */
	__le64	delete_epoch_id; /* Transaction ID when deleted */

	struct {
		__le32 rdev;	 /* major/minor # */
	} dev;			 /* device inode */

	__le32	csum;            /* CRC32 checksum */

	/* Leave 8 bytes for inode table tail pointer */
} __attribute((__packed__));

/*
 * Inode table.  It's a linked list of pages.
 */
struct inode_table {
	__le64 log_head;
};

/*
 * NOVA-specific inode state kept in DRAM
 */
struct nova_inode_info_header {
	/* Map from file offsets to write log entries. */
	struct radix_tree_root tree;
	struct rb_root rb_tree;		/* RB tree for directory */
	struct rb_root vma_tree;	/* Write vmas */
	struct list_head list;		/* SB list of mmap sih */
	int num_vmas;
	unsigned short i_mode;		/* Dir or file? */
	unsigned int i_flags;
	unsigned long log_pages;	/* Num of log pages */
	unsigned long i_size;
	unsigned long i_blocks;
	unsigned long ino;
	unsigned long pi_addr;
	unsigned long alter_pi_addr;
	unsigned long valid_entries;	/* For thorough GC */
	unsigned long num_entries;	/* For thorough GC */
	u64 last_setattr;		/* Last setattr entry */
	u64 last_link_change;		/* Last link change entry */
	u64 last_dentry;		/* Last updated dentry */
	u64 trans_id;			/* Transaction ID */
	u64 log_head;			/* Log head pointer */
	u64 log_tail;			/* Log tail pointer */
	u64 alter_log_head;		/* Alternate log head pointer */
	u64 alter_log_tail;		/* Alternate log tail pointer */
	u8  i_blk_type;
};

/* For rebuild purpose, temporarily store pi infomation */
struct nova_inode_rebuild {
	u64	i_size;
	u32	i_flags;	/* Inode flags */
	u32	i_ctime;	/* Inode modification time */
	u32	i_mtime;	/* Inode b-tree Modification time */
	u32	i_atime;	/* Access time */
	u32	i_uid;		/* Owner Uid */
	u32	i_gid;		/* Group Id */
	u32	i_generation;	/* File version (for NFS) */
	u16	i_links_count;	/* Links count */
	u16	i_mode;		/* File mode */
	u64	trans_id;
};

/*
 * DRAM state for inodes
 */
struct nova_inode_info {
	struct nova_inode_info_header header;
	struct inode vfs_inode;
};


static inline struct nova_inode_info *NOVA_I(struct inode *inode)
{
	return container_of(inode, struct nova_inode_info, vfs_inode);
}

static inline struct nova_inode_info_header *NOVA_IH(struct inode *inode)
{
	struct nova_inode_info *si = NOVA_I(inode);
	return &si->header;
}

static inline struct nova_inode *nova_get_alter_inode(struct super_block *sb,
	struct inode *inode)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode fake_pi;
	void *addr;
	int rc;

	if (metadata_csum == 0)
		return NULL;

	addr = nova_get_block(sb, sih->alter_pi_addr);
	rc = memcpy_mcsafe(&fake_pi, addr, sizeof(struct nova_inode));
	if (rc)
		return NULL;

	return (struct nova_inode *)addr;
}

static inline int nova_update_alter_inode(struct super_block *sb,
	struct inode *inode, struct nova_inode *pi)
{
	struct nova_inode *alter_pi;

	if (metadata_csum == 0)
		return 0;

	alter_pi = nova_get_alter_inode(sb, inode);
	if (!alter_pi)
		return -EINVAL;

	memcpy_to_pmem_nocache(alter_pi, pi, sizeof(struct nova_inode));
	return 0;
}


static inline int nova_update_inode_checksum(struct nova_inode *pi)
{
	u32 crc = 0;

	if (metadata_csum == 0)
		goto persist;

	crc = nova_crc32c(~0, (__u8 *)pi,
			(sizeof(struct nova_inode) - sizeof(__le32)));

	pi->csum = crc;
persist:
	nova_flush_buffer(pi, sizeof(struct nova_inode), 1);
	return 0;
}

static inline int nova_check_inode_checksum(struct nova_inode *pi)
{
	u32 crc = 0;

	if (metadata_csum == 0)
		return 0;

	crc = nova_crc32c(~0, (__u8 *)pi,
			(sizeof(struct nova_inode) - sizeof(__le32)));

	if (pi->csum == cpu_to_le32(crc))
		return 0;
	else
		return 1;
}



static inline void nova_update_tail(struct nova_inode *pi, u64 new_tail)
{
	INIT_TIMING(update_time);

	NOVA_START_TIMING(update_tail_t, update_time);

	PERSISTENT_BARRIER();
	pi->log_tail = new_tail;
	nova_flush_buffer(&pi->log_tail, CACHELINE_SIZE, 1);

	NOVA_END_TIMING(update_tail_t, update_time);
}

static inline void nova_update_alter_tail(struct nova_inode *pi, u64 new_tail)
{
	INIT_TIMING(update_time);

	if (metadata_csum == 0)
		return;

	NOVA_START_TIMING(update_tail_t, update_time);

	PERSISTENT_BARRIER();
	pi->alter_log_tail = new_tail;
	nova_flush_buffer(&pi->alter_log_tail, CACHELINE_SIZE, 1);

	NOVA_END_TIMING(update_tail_t, update_time);
}



/* Update inode tails and checksums */
static inline void nova_update_inode(struct super_block *sb,
	struct inode *inode, struct nova_inode *pi,
	struct nova_inode_update *update, int update_alter)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;

	sih->log_tail = update->tail;
	sih->alter_log_tail = update->alter_tail;
	nova_update_tail(pi, update->tail);
	if (metadata_csum)
		nova_update_alter_tail(pi, update->alter_tail);

	nova_update_inode_checksum(pi);
	if (inode && update_alter)
		nova_update_alter_inode(sb, inode, pi);
}


static inline
struct inode_table *nova_get_inode_table(struct super_block *sb,
	int version, int cpu)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int table_start;

	if (cpu >= sbi->cpus)
		return NULL;

	if ((version & 0x1) == 0)
		table_start = INODE_TABLE0_START;
	else
		table_start = INODE_TABLE1_START;

	return (struct inode_table *)((char *)nova_get_block(sb,
		NOVA_DEF_BLOCK_SIZE_4K * table_start) +
		cpu * CACHELINE_SIZE);
}

static inline unsigned int
nova_inode_blk_shift(struct nova_inode_info_header *sih)
{
	return blk_type_to_shift[sih->i_blk_type];
}

static inline uint32_t nova_inode_blk_size(struct nova_inode_info_header *sih)
{
	return blk_type_to_size[sih->i_blk_type];
}

static inline u64 nova_get_reserved_inode_addr(struct super_block *sb,
	u64 inode_number)
{
	return (NOVA_DEF_BLOCK_SIZE_4K * RESERVE_INODE_START) +
			inode_number * NOVA_INODE_SIZE;
}

static inline u64 nova_get_alter_reserved_inode_addr(struct super_block *sb,
	u64 inode_number)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	return nova_get_addr_off(sbi, sbi->replica_reserved_inodes_addr) +
			inode_number * NOVA_INODE_SIZE;
}

static inline struct nova_inode *nova_get_reserved_inode(struct super_block *sb,
	u64 inode_number)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u64 addr;

	addr = nova_get_reserved_inode_addr(sb, inode_number);

	return (struct nova_inode *)(sbi->virt_addr + addr);
}

static inline struct nova_inode *
nova_get_alter_reserved_inode(struct super_block *sb,
	u64 inode_number)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	u64 addr;

	addr = nova_get_alter_reserved_inode_addr(sb, inode_number);

	return (struct nova_inode *)(sbi->virt_addr + addr);
}

/* If this is part of a read-modify-write of the inode metadata,
 * nova_memunlock_inode() before calling!
 */
static inline struct nova_inode *nova_get_inode_by_ino(struct super_block *sb,
						  u64 ino)
{
	if (ino == 0 || ino >= NOVA_NORMAL_INODE_START)
		return NULL;

	return nova_get_reserved_inode(sb, ino);
}

static inline struct nova_inode *nova_get_inode(struct super_block *sb,
	struct inode *inode)
{
	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	struct nova_inode fake_pi;
	void *addr;
	int rc;

	addr = nova_get_block(sb, sih->pi_addr);
	rc = memcpy_mcsafe(&fake_pi, addr, sizeof(struct nova_inode));
	if (rc)
		return NULL;

	return (struct nova_inode *)addr;
}



extern const struct address_space_operations nova_aops_dax;
int nova_init_inode_inuse_list(struct super_block *sb);
extern int nova_init_inode_table(struct super_block *sb);
int nova_get_alter_inode_address(struct super_block *sb, u64 ino,
	u64 *alter_pi_addr);
unsigned long nova_get_last_blocknr(struct super_block *sb,
	struct nova_inode_info_header *sih);
int nova_get_inode_address(struct super_block *sb, u64 ino, int version,
	u64 *pi_addr, int extendable, int extend_alternate);
int nova_set_blocksize_hint(struct super_block *sb, struct inode *inode,
	struct nova_inode *pi, loff_t new_size);
extern struct inode *nova_iget(struct super_block *sb, unsigned long ino);
extern void nova_evict_inode(struct inode *inode);
extern int nova_write_inode(struct inode *inode, struct writeback_control *wbc);
extern void nova_dirty_inode(struct inode *inode, int flags);
extern int nova_notify_change(struct dentry *dentry, struct iattr *attr);
extern int nova_getattr(const struct path *path, struct kstat *stat,
			u32 request_mask, unsigned int query_flags);
extern void nova_set_inode_flags(struct inode *inode, struct nova_inode *pi,
	unsigned int flags);
extern unsigned long nova_find_region(struct inode *inode, loff_t *offset,
		int hole);
int nova_delete_file_tree(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long start_blocknr,
	unsigned long last_blocknr, bool delete_nvmm,
	bool delete_dead, u64 trasn_id);
u64 nova_new_nova_inode(struct super_block *sb, u64 *pi_addr);
extern struct inode *nova_new_vfs_inode(enum nova_new_inode_type,
	struct inode *dir, u64 pi_addr, u64 ino, umode_t mode,
	size_t size, dev_t rdev, const struct qstr *qstr, u64 epoch_id);

#endif
