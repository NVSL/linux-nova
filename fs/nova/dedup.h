#ifndef __DEDUP_H
#define __DEDUP_H

#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/falloc.h>
#include <asm/mman.h>
#include <linux/radix-tree.h>
#include <linux/list.h>

#include "nova.h"
#include "inode.h"

#define DATABLOCK_SIZE 4096
#define FINGERPRINT_SIZE 16
/* nova_dedup_queue
	 queue of entries that needs to be deduplicated
	 */
struct nova_dedup_queue{
	u64 write_entry_address;
	struct list_head list;
};

extern struct nova_dedup_queue nova_dedup_queue_head;

/* NOVA_DEDUP_RADIX_TREE_NODE 
	Leaf node of radix tree, it cotains
	the address of the matching 
	dedup table entry.
 */
struct nova_dedup_radix_tree_node{
  loff_t dedup_table_entry;
};


/* nova_dedup_table_entry
	 Used to read from the dedup_table
	 size should be 32B
		fingerprint: 16B
		block_address: 8B
		referenc count: 4B
		flag: 4B
 */
struct nova_dedup_table_entry{
  char fingerprint[16];
  loff_t block_address;
  int reference_count;
  int flag;
};

/* nova_dedup_test
	 for debugging + test
 */
int nova_dedup_test(struct file *);
int nova_dedup_queue_push(u64);
int nova_dedup_queue_init(void);

#endif
