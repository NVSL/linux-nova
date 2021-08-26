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

#define DEDUP_DONE 0
#define DEDUP_NEEDED 1
#define IN_PROCESS 2

/* nova_dedup_queue
	 queue of entries that needs to be deduplicated
*/
struct nova_dedup_queue_entry{
  u64 write_entry_address;
  u64 target_inode_number;
  struct list_head list;
};

struct nova_dedup_queue{
  struct nova_dedup_queue_entry head;	// head of dqueue
  struct mutex lock;
};

extern struct nova_dedup_queue dqueue;

/* SHA1 */
struct sdesc {
  struct shash_desc shash;
  char ctx[];
};

/* FACT table entry */
struct fact_entry{
  u64 count; // 32bit reference count, 32bit update count
  unsigned char fingerprint[FINGERPRINT_SIZE];
  u64 block_address;
  u64 prev;
	u64 next;
  u64 delete_entry;
  u32 padding;
}__attribute((__packed__));

/* FACT free list */
struct DeNOVA_bm{
	unsigned long bitmap_size;
	unsigned long *bitmap;
};

/* For Fingerprint lookup */
struct fingerprint_lookup_data{
  unsigned char fingerprint[FINGERPRINT_SIZE]; // fingerprint of entry
  u64 index; // index of entry
  u64 block_address; // Actual address of this entry(where the data block is)
};

// DEDUP QUEUE //
int nova_dedup_queue_init(void);
int nova_dedup_queue_push(u64 new_address, u64 target_inode_number);
u64 nova_dedup_queue_get_next_entry(u64 *target_inode_number);

// Fingerprinting //
static struct sdesc *init_sdesc(struct crypto_shash *alg);
static int calc_hash(struct crypto_shash *alg, const unsigned char *data, unsigned int datalen, unsigned char *digest);
int nova_dedup_fingerprint(unsigned char* datapage, unsigned char * ret_fingerprint);

// Checks integrity of inode, write-entry, data-page //
int nova_dedup_crosscheck(struct nova_file_write_entry *entry, struct nova_inode_info_header *sih, unsigned long pgoff);

// FACT handling //
int nova_dedup_FACT_init(struct super_block *sb);
int nova_dedup_FACT_index_check(u64 index);
int nova_dedup_FACT_update_count(struct super_block *sb, u64 index);
int nova_dedup_FACT_read(struct super_block *sb, u64 index);
int nova_dedup_is_empty(struct fact_entry target);
int nova_dedup_FACT_insert(struct super_block *sb, struct fingerprint_lookup_data* lookup);

// Updates FACT + dedup_flags in write-entry of TargetWriteEntry //
int nova_dedup_TWE_update(struct super_block *sb,struct nova_inode_info_header *sih,u64 curr_p, short *duplicate_check);
// Updates FACT + dedup_flags in write-entry of new write entry //
int nova_dedup_entry_update(struct super_block *sb, struct nova_inode_info_header *sih, u64 begin_tail);
// Checks if target block has multiple ReferenceCount & Delete FACT entry //
int nova_dedup_is_duplicate(struct super_block *sb, unsigned long blocknr, bool check);


// Main function //
int nova_dedup_test(struct file *);



#endif
