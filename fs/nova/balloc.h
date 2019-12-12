#ifndef __BALLOC_H
#define __BALLOC_H

#include "inode.h"

/* DRAM structure to hold a list of free PMEM blocks */
struct free_list {
	spinlock_t s_lock;
	struct rb_root	block_free_tree;
	struct nova_range_node *first_node; // lowest address free range
	struct nova_range_node *last_node; // highest address free range

	int		index; // Which CPU do I belong to?

	/* Where are the data checksum blocks */
	unsigned long	csum_start;
	unsigned long	replica_csum_start;
	unsigned long	num_csum_blocks;

	/* Where are the data parity blocks */
	unsigned long	parity_start;
	unsigned long	replica_parity_start;
	unsigned long	num_parity_blocks;

	/* Start and end of allocatable range, inclusive. Excludes csum and
	 * parity blocks.
	 */
	unsigned long	block_start;
	unsigned long	block_end;

	unsigned long	num_free_blocks;

	/* How many nodes in the rb tree? */
	unsigned long	num_blocknode;

	u32		csum;		/* Protect integrity */

	/* Statistics */
	unsigned long	alloc_log_count;
	unsigned long	alloc_data_count;
	unsigned long	free_log_count;
	unsigned long	free_data_count;
	unsigned long	alloc_log_pages;
	unsigned long	alloc_data_pages;
	unsigned long	freed_log_pages;
	unsigned long	freed_data_pages;

	u64		padding[8];	/* Cache line break */
};

static inline
struct free_list *nova_get_free_list(struct super_block *sb, int cpu)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);

	return &sbi->free_lists[cpu];
}

enum nova_alloc_direction {ALLOC_FROM_HEAD = 0,
			   ALLOC_FROM_TAIL = 1};

enum nova_alloc_init {ALLOC_NO_INIT = 0,
		      ALLOC_INIT_ZERO = 1};

enum alloc_type {
	LOG = 1,
	DATA,
};

int nova_alloc_block_free_lists(struct super_block *sb);
void nova_delete_free_lists(struct super_block *sb);
struct nova_range_node *nova_alloc_blocknode(struct super_block *sb);
struct nova_range_node *nova_alloc_inode_node(struct super_block *sb);
struct nova_range_node *nova_alloc_dir_node(struct super_block *sb);
struct vma_item *nova_alloc_vma_item(struct super_block *sb);
void nova_free_range_node(struct nova_range_node *node);
void nova_free_snapshot_info(struct snapshot_info *info);
void nova_free_blocknode(struct nova_range_node *bnode);
void nova_free_inode_node(struct nova_range_node *bnode);
void nova_free_dir_node(struct nova_range_node *bnode);
void nova_free_vma_item(struct super_block *sb,
	struct vma_item *item);
extern void nova_init_blockmap(struct super_block *sb, int recovery);
extern int nova_free_data_blocks(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long blocknr, int num);
extern int nova_free_log_blocks(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long blocknr, int num);
extern int nova_new_data_blocks(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long *blocknr,
	unsigned long start_blk, unsigned int num,
	enum nova_alloc_init zero, int cpu,
	enum nova_alloc_direction from_tail);
extern int nova_new_log_blocks(struct super_block *sb,
	struct nova_inode_info_header *sih,
	unsigned long *blocknr, unsigned int num,
	enum nova_alloc_init zero, int cpu,
	enum nova_alloc_direction from_tail);
extern unsigned long nova_count_free_blocks(struct super_block *sb);
extern unsigned long nova_count_total_blocks(struct super_block *sb);
inline int nova_search_inodetree(struct nova_sb_info *sbi,
	unsigned long ino, struct nova_range_node **ret_node);
int nova_insert_blocktree(struct rb_root *tree,
	struct nova_range_node *new_node);
int nova_insert_inodetree(struct nova_sb_info *sbi,
	struct nova_range_node *new_node, int cpu);
int nova_find_free_slot(struct rb_root *tree, unsigned long range_low,
	unsigned long range_high, struct nova_range_node **prev,
	struct nova_range_node **next);

extern int nova_insert_range_node(struct rb_root *tree,
	struct nova_range_node *new_node, enum node_type type);
extern int nova_find_range_node(struct rb_root *tree,
	unsigned long key, enum node_type type,
	struct nova_range_node **ret_node);
extern void nova_destroy_range_node_tree(struct super_block *sb,
	struct rb_root *tree);
#endif
