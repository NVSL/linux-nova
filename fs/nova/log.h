#ifndef __LOG_H
#define __LOG_H

#include "balloc.h"
#include "inode.h"

/* ======================= Log entry ========================= */
/* Inode entry in the log */

#define	MAIN_LOG	0
#define	ALTER_LOG	1

#define	PAGE_OFFSET_MASK	4095
#define	BLOCK_OFF(p)	((p) & ~PAGE_OFFSET_MASK)

#define	ENTRY_LOC(p)	((p) & PAGE_OFFSET_MASK)

#define	LOG_BLOCK_TAIL	4064
#define	PAGE_TAIL(p)	(BLOCK_OFF(p) + LOG_BLOCK_TAIL)

/*
 * Log page state and pointers to next page and the replica page
 */
struct nova_inode_page_tail {
	__le32	invalid_entries;
	__le32	num_entries;
	__le64	epoch_id;	/* For snapshot list page */
	__le64	alter_page;	/* Corresponding page in the other log */
	__le64	next_page;
} __attribute((__packed__));

/* Fit in PAGE_SIZE */
struct	nova_inode_log_page {
	char padding[LOG_BLOCK_TAIL];
	struct nova_inode_page_tail page_tail;
} __attribute((__packed__));

#define	EXTEND_THRESHOLD	256

enum nova_entry_type {
	FILE_WRITE = 1,
	DIR_LOG,
	SET_ATTR,
	LINK_CHANGE,
	MMAP_WRITE,
	SNAPSHOT_INFO,
	NEXT_PAGE,
};

static inline u8 nova_get_entry_type(void *p)
{
	u8 type;
	int rc;

	rc = memcpy_mcsafe(&type, p, sizeof(u8));
	if (rc)
		return rc;

	return type;
}

static inline void nova_set_entry_type(void *p, enum nova_entry_type type)
{
	*(u8 *)p = type;
}

/*
 * Write log entry.  Records a write to a contiguous range of PMEM pages.
 *
 * Documentation/filesystems/nova.txt contains descriptions of some fields.
 */
struct nova_file_write_entry {
	u8	entry_type;
	u8	reassigned;	/* Data is not latest */
	u8	updating;	/* Data is being written */
	u8	dedup_flag; /* NOVA DEDUP KHJ */
	__le32	num_pages;
	__le64	block;          /* offset of first block in this write */
	__le64	pgoff;          /* file offset at the beginning of this write */
	__le32	invalid_pages;	/* For GC */
	/* For both ctime and mtime */
	__le32	mtime;
	__le64	size;           /* File size after this write */
	__le64	epoch_id;
	__le64	trans_id;
	__le32	csumpadding;
	__le32	csum;
} __attribute((__packed__));

#define WENTRY(entry)	((struct nova_file_write_entry *) entry)

/*
 * Log entry for adding a file/directory to a directory.
 *
 * Update DIR_LOG_REC_LEN if modify this struct!
 */
struct nova_dentry {
	u8	entry_type;
	u8	name_len;		/* length of the dentry name */
	u8	reassigned;		/* Currently deleted */
	u8	invalid;		/* Invalid now? */
	__le16	de_len;			/* length of this dentry */
	__le16	links_count;
	__le32	mtime;			/* For both mtime and ctime */
	__le32	csum;			/* entry checksum */
	__le64	ino;			/* inode no pointed to by this entry */
	__le64	padding;
	__le64	epoch_id;
	__le64	trans_id;
	char	name[NOVA_NAME_LEN + 1];	/* File name */
} __attribute((__packed__));

#define DENTRY(entry)	((struct nova_dentry *) entry)

#define NOVA_DIR_PAD			8	/* Align to 8 bytes boundary */
#define NOVA_DIR_ROUND			(NOVA_DIR_PAD - 1)
#define NOVA_DENTRY_HEADER_LEN		48
#define NOVA_DIR_LOG_REC_LEN(name_len) \
	(((name_len + 1) + NOVA_DENTRY_HEADER_LEN \
	 + NOVA_DIR_ROUND) & ~NOVA_DIR_ROUND)

#define NOVA_MAX_ENTRY_LEN		NOVA_DIR_LOG_REC_LEN(NOVA_NAME_LEN)

/*
 * Log entry for updating file attributes.
 */
struct nova_setattr_logentry {
	u8	entry_type;
	u8	attr;       /* bitmap of which attributes to update */
	__le16	mode;
	__le32	uid;
	__le32	gid;
	__le32	atime;
	__le32	mtime;
	__le32	ctime;
	__le64	size;        /* File size after truncation */
	__le64	epoch_id;
	__le64	trans_id;
	u8	invalid;
	u8	paddings[3];
	__le32	csum;
} __attribute((__packed__));

#define SENTRY(entry)	((struct nova_setattr_logentry *) entry)

/* Link change log entry.
 *
 * TODO: Do we need this to be 32 bytes?
 */
struct nova_link_change_entry {
	u8	entry_type;
	u8	invalid;
	__le16	links;
	__le32	ctime;
	__le32	flags;
	__le32	generation;    /* for NFS handles */
	__le64	epoch_id;
	__le64	trans_id;
	__le32	csumpadding;
	__le32	csum;
} __attribute((__packed__));

#define LCENTRY(entry)	((struct nova_link_change_entry *) entry)

/*
 * MMap entry.  Records the fact that a region of the file is mmapped, so
 * parity and checksums are inoperative.
 */
struct nova_mmap_entry {
	u8	entry_type;
	u8	invalid;
	u8	paddings[6];
	__le64	epoch_id;
	__le64	pgoff;
	__le64	num_pages;
	__le32	csumpadding;
	__le32	csum;
} __attribute((__packed__));

#define MMENTRY(entry)	((struct nova_mmap_entry *) entry)

/*
 * Log entry for the creation of a snapshot.  Only occurs in the log of the
 * dedicated snapshot inode.
 */
struct nova_snapshot_info_entry {
	u8	type;
	u8	deleted;
	u8	paddings[6];
	__le64	epoch_id;
	__le64	timestamp;
	__le64	nvmm_page_addr;
	__le32	csumpadding;
	__le32	csum;
} __attribute((__packed__));

#define SNENTRY(entry)	((struct nova_snapshot_info_entry *) entry)


/*
 * Transient DRAM structure that describes changes needed to append a log entry
 * to an inode
 */
struct nova_inode_update {
	u64 head;
	u64 alter_head;
	u64 tail;
	u64 alter_tail;
	u64 curr_entry;
	u64 alter_entry;
	struct nova_dentry *create_dentry;
	struct nova_dentry *delete_dentry;
};


/*
 * Transient DRAM structure to parameterize the creation of a log entry.
 */
struct nova_log_entry_info {
	enum nova_entry_type type;
	struct iattr *attr;
	struct nova_inode_update *update;
	void *data;	/* struct dentry */
	u64 epoch_id;
	u64 trans_id;
	u64 curr_p;	/* output */
	u64 file_size;	/* de_len for dentry */
	u64 ino;
	u32 time;
	int link_change;
	int inplace;	/* For file write entry */
};



static inline size_t nova_get_log_entry_size(struct super_block *sb,
	enum nova_entry_type type)
{
	size_t size = 0;

	switch (type) {
	case FILE_WRITE:
		size = sizeof(struct nova_file_write_entry);
		break;
	case DIR_LOG:
		size = NOVA_DENTRY_HEADER_LEN;
		break;
	case SET_ATTR:
		size = sizeof(struct nova_setattr_logentry);
		break;
	case LINK_CHANGE:
		size = sizeof(struct nova_link_change_entry);
		break;
	case MMAP_WRITE:
		size = sizeof(struct nova_mmap_entry);
		break;
	case SNAPSHOT_INFO:
		size = sizeof(struct nova_snapshot_info_entry);
		break;
	default:
		break;
	}

	return size;
}


int nova_invalidate_logentry(struct super_block *sb, void *entry,
	enum nova_entry_type type, unsigned int num_free);
int nova_reassign_logentry(struct super_block *sb, void *entry,
	enum nova_entry_type type);
int nova_inplace_update_log_entry(struct super_block *sb,
	struct inode *inode, void *entry,
	struct nova_log_entry_info *entry_info);
void nova_clear_last_page_tail(struct super_block *sb,
	struct inode *inode, loff_t newsize);
unsigned int nova_free_old_entry(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry,
	unsigned long pgoff, unsigned int num_free,
	bool delete_dead, u64 epoch_id);
int nova_free_inode_log(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih);
int nova_update_alter_pages(struct super_block *sb, struct nova_inode *pi,
	u64 curr, u64 alter_curr);
struct nova_file_write_entry *nova_find_next_entry(struct super_block *sb,
	struct nova_inode_info_header *sih, pgoff_t pgoff);
int nova_allocate_inode_log_pages(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long num_pages,
	u64 *new_block, int cpuid, enum nova_alloc_direction from_tail);
int nova_free_contiguous_log_blocks(struct super_block *sb,
	struct nova_inode_info_header *sih, u64 head);
u64 nova_get_append_head(struct super_block *sb, struct nova_inode *pi,
	struct nova_inode_info_header *sih, u64 tail, size_t size, int log_id,
	int thorough_gc, int *extended);
int nova_handle_setattr_operation(struct super_block *sb, struct inode *inode,
	struct nova_inode *pi, unsigned int ia_valid, struct iattr *attr,
	u64 epoch_id);
int nova_invalidate_link_change_entry(struct super_block *sb,
	u64 old_link_change);
int nova_append_link_change_entry(struct super_block *sb,
	struct nova_inode *pi, struct inode *inode,
	struct nova_inode_update *update, u64 *old_linkc, u64 epoch_id);
int nova_set_write_entry_updating(struct super_block *sb,
	struct nova_file_write_entry *entry, int set);
int nova_inplace_update_write_entry(struct super_block *sb,
	struct inode *inode, struct nova_file_write_entry *entry,
	struct nova_log_entry_info *entry_info);
int nova_append_mmap_entry(struct super_block *sb, struct nova_inode *pi,
	struct inode *inode, struct nova_mmap_entry *data,
	struct nova_inode_update *update, struct vma_item *item);
int nova_append_file_write_entry(struct super_block *sb, struct nova_inode *pi,
	struct inode *inode, struct nova_file_write_entry *data,
	struct nova_inode_update *update);
int nova_append_snapshot_info_entry(struct super_block *sb,
	struct nova_inode *pi, struct nova_inode_info *si,
	struct snapshot_info *info, struct nova_snapshot_info_entry *data,
	struct nova_inode_update *update);
int nova_assign_write_entry(struct super_block *sb,
	struct nova_inode_info_header *sih,
	struct nova_file_write_entry *entry,
	struct nova_file_write_entry *entryc, bool free);


void nova_print_curr_log_page(struct super_block *sb, u64 curr);
void nova_print_nova_log(struct super_block *sb,
	struct nova_inode_info_header *sih);
int nova_get_nova_log_pages(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_inode *pi);
void nova_print_nova_log_pages(struct super_block *sb,
	struct nova_inode_info_header *sih);

#endif
