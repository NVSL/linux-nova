#include <linux/slab.h>
#include <linux/uio.h>
#include <linux/uaccess.h>
#include <linux/falloc.h>
#include <asm/mman.h>

#include "nova.h"
#include "inode.h"
#include "dedup.h"

struct dedup_node{
	long long dedup_table_entry;
};


void nova_init_dedup_entry(struct dedup_node * entry){
	memset(entry,0,sizeof(struct dedup_node));
	entry->dedup_table_entry = 1;
}


int dedup_test(struct file * filp){
	struct dedup_node temp;
	void ** temp2; 
	struct dedup_node *temp3;

	struct address_space *mapping = filp->f_mapping;	
	struct inode *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);

	printk("fs/nova/dedup.c\n");

	INIT_RADIX_TREE(&sbi->dedup_tree_fingerprint,GFP_KERNEL);	
	printk("Radix Tree Initialized\n");

	nova_init_dedup_entry(&temp);

	radix_tree_insert(&sbi->dedup_tree_fingerprint,32,&temp);	
	printk("Inserted!\n");
	temp2 = radix_tree_lookup_slot(&sbi->dedup_tree_fingerprint,32);

	if(temp2){
		printk("Found Entry\n");
		temp3 = radix_tree_deref_slot(temp2);
		printk("%lld\n",temp3->dedup_table_entry);
	}

	return 0;
}


