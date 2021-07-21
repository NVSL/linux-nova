#ifndef __DEDUP_H
#define __DEDUP_H

#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/falloc.h>
#include <asm/mman.h>
#include <linux/radix-tree.h>
#include "nova.h"
#include "inode.h"

struct dedup_node{
  long long dedup_table_entry;
};

struct dedup_table_entry{
  char fingerprint[16];
  loff_t block_address;
  int reference_count;
  int flag;
};


int dedup_test(struct file *);

#endif
