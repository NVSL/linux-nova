#ifndef __DEDUP_H
#define __DEDUP_H

#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/falloc.h>
#include <linux/sched/xacct.h>
#include <asm/mman.h>
#include <asm/uaccess.h>
#include <linux/radix-tree.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>

// SHA1
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <linux/crypto.h>

#include "nova.h"
#include "inode.h"

#define DATABLOCK_SIZE 4096
#define FINGERPRINT_SIZE 20
#define MAX_DATAPAGE_PER_WRITEENTRY 32
/* nova_dedup_queue
	 queue of entries that needs to be deduplicated
	 */
struct nova_dedup_queue{
	u64 write_entry_address;
	u64 target_inode_number;
	struct list_head list;
};

/* SHA1 */
struct sdesc {
  struct shash_desc shash;
  char ctx[];
};

/* FACT table entry */
struct fact_entry{
	unsigned char fingerprint[FINGERPRINT_SIZE];
	u64 block_address;
	u32 count; // 28bit -> reference, 4bit -> update
	u32 next;
	u32 delete_target;
};

/* For Fingerprint lookup */
struct fingerprint_lookup_data{
		unsigned char fingerprint[FINGERPRINT_SIZE]; // fingerprint of entry
		u32 index; // index of entry
		u64 block_address; // Actual address of this entry(where the data block is)
};

extern struct nova_dedup_queue nova_dedup_queue_head;


/* nova_dedup_test
	 for debugging + test
 */
int nova_dedup_test(struct file *);
int nova_dedup_queue_push(u64,u64);
int nova_dedup_queue_init(void);

#endif
