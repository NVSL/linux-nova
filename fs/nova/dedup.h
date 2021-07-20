#ifndef __DEDUP_H
#define __DEDUP_H

#include "nova.h"
#include "inode.h"
#include <linux/radix-tree.h>


// Radix tree1 key(FingerPrint)
// Radix tree2 key(Data Page Address)

int dedup_test(struct file *);

#endif
