#include "nova.h"
#include "inode.h"
#include "dedup.h"

struct nova_dedup_queue nova_dedup_queue_head;

// Initialize Dedup Queue
int nova_dedup_queue_init(void){
	INIT_LIST_HEAD(&nova_dedup_queue_head.list);
	nova_dedup_queue_head.write_entry_address=0;
	return 0;
}

// Insert Write Entries to Dedup Queue
int nova_dedup_queue_push(u64 new_address){
	struct nova_dedup_queue *new_data;
	new_data = kmalloc(sizeof(struct nova_dedup_queue), GFP_KERNEL);
	list_add_tail(&new_data->list, &nova_dedup_queue_head.list);
	new_data->write_entry_address = new_address;
	printk("PUSH to queue: %llu\n",new_address);
	return 0;
}

// Get next write entry to dedup
u64 nova_dedup_queue_get_next_entry(void){
	struct nova_dedup_queue *ptr;
	u64 ret = 0;
	if(!list_empty(&nova_dedup_queue_head.list)){
		ptr = list_entry(nova_dedup_queue_head.list.next, struct nova_dedup_queue, list);
		ret = ptr->write_entry_address;
		list_del(nova_dedup_queue_head.list.next);
		kfree(ptr);
		printk("POP from queue: %llu\n",ret);
	}
	return ret;
}

// Initialize a raidx_tree leaf node
void nova_dedup_init_radix_tree_node(struct nova_dedup_radix_tree_node * node, loff_t entry_address){
	memset(node,0,sizeof(struct nova_dedup_radix_tree_node));
	node->dedup_table_entry = entry_address;
}


// For Fingerprint
void nova_fingerprint(char* datapage, char * ret_fingerprint){


}



int nova_dedup_test(struct file * filp){
	struct nova_dedup_radix_tree_node temp;
	void ** temp2; 
	struct nova_dedup_radix_tree_node *temp3;

	struct address_space *mapping = filp->f_mapping;	
	struct inode *inode = mapping->host;
	struct super_block *sb = inode->i_sb;
	struct nova_sb_info *sbi = NOVA_SB(sb);



	printk("fs/nova/dedup.c\n");

	INIT_RADIX_TREE(&sbi->dedup_tree_fingerprint,GFP_KERNEL);	
	INIT_RADIX_TREE(&sbi->dedup_tree_address,GFP_KERNEL);
	printk("Radix Tree Initialized\n");



	// 1. Determine Write Entry
	//   1.1 Read Data Pages
	//   1.2 For each Data page

	// 2. Save Start address of Data Page
	// 3. Fingerprint Data Page
	// 4. Lookup Fingerprint
	// 5. 

	
	//nova_dedup_queue_init();
	//printk("Dedup queue initialized\n");

	if(nova_dedup_queue_get_next_entry()!=0){ }
  else printk("no entry!\n");
	
	if(nova_dedup_queue_get_next_entry()!=0){ }
  else printk("no entry!\n");
	
	if(nova_dedup_queue_get_next_entry()!=0){ }
  else printk("no entry!\n");

	if(nova_dedup_queue_get_next_entry()!=0){ }
  else printk("no entry!\n");

	nova_dedup_init_radix_tree_node(&temp,1);

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

/* TODO
	 1. Find place to initialize dedup queue + Radix Trees
	 2. Try reading from write entry
	 3. Try fiingerprinting each data page
	 4. Think of how to save the Dedup Table
	 5. 
 */
