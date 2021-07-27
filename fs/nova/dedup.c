#include "nova.h"
#include "inode.h"
#include "dedup.h"
#include <linux/rbtree.h>

struct rb_node temp_rb_node;
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


/*
Many user space methods cannot be used when writing kernel modules, such as Openssl.
But Linux itself provides a Crypto API for various encryption calculations of data.
Using this API, you can perform some encryption and signature operations in the kernel module.
The following is an example of sha1.
*/
// ----------------------------------------------------------------------------------------------------------------
struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    sdesc->shash.flags = 0x0;
    return sdesc;
}

static int calc_hash(struct crypto_shash *alg,
             const unsigned char *data, unsigned int datalen,
             unsigned char *digest)
{
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}

// For Fingerprint
int nova_dedup_fingerprint(char* datapage, char * ret_fingerprint){
	struct crypto_shash *alg;
	char *hash_alg_name = "sha1";
	int ret;

	alg = crypto_alloc_shash(hash_alg_name,0,0);
	if(IS_ERR(alg)){
		pr_info("can't alloc alg %s\n",hash_alg_name);
		return PTR_ERR(alg);
	}
	ret = calc_hash(alg,datapage,DATABLOCK_SIZE,ret_fingerprint);
	crypto_free_shash(alg);
	return ret;
}

// ------------------------------------------------------------------------------------------------------------------


// Append a new dedup table entry
ssize_t dedup_table_update(struct file *file, const void *buf, size_t count, loff_t *pos){
	mm_segment_t old_fs;
	ssize_t ret = -EINVAL;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	if (!(file->f_mode & FMODE_WRITE))
		return -EBADF;
	if (!(file->f_mode & FMODE_CAN_WRITE))
		return -EINVAL;
	if (unlikely(!access_ok(buf, count)))
		return -EFAULT;

	//ret = rw_verify_area(WRITE, file, pos, count);
	if (count > MAX_RW_COUNT)
		count =  MAX_RW_COUNT;
	file_start_write(file);

	if(file->f_op->write)
		ret = nova_inplace_file_write(file,buf,count,pos);

	if (ret > 0) { 
		fsnotify_modify(file);
		add_wchar(current, ret);
	}    
	inc_syscw(current);
	file_end_write(file);

	set_fs(old_fs);
	return ret;
}



int nova_dedup_test(struct file * filp){
	// for radix tree
	/*
		 struct nova_dedup_radix_tree_node temp;
		 void ** temp2; 
		 struct nova_dedup_radix_tree_node *temp3;
		 char test_key[20] = "L9ThxnotKPzthJ7hu3bnORuT6xI=";
		 char compare_key[20] = "L9ThxnotKPzthJ7hu3bnORuT6xI=";
	 */
	// Super Block
	struct address_space *mapping = filp->f_mapping;	
	struct inode *inode = mapping->host;
	struct super_block *sb = inode->i_sb;

	// For write entry 
	struct nova_file_write_entry *target_entry;
	u64 entry_address;
	char *buf;
	char *fingerprint;
	unsigned long left;
	pgoff_t index;
	int i, j, data_page_number =0;
	unsigned long nvmm;
	void *dax_mem = NULL;

	printk("Initialize Buffer, Fingerprint\n");
	buf = kmalloc(DATABLOCK_SIZE,GFP_KERNEL);
	fingerprint = kmalloc(FINGERPRINT_SIZE,GFP_KERNEL);

	// Pop Write Entry
	entry_address = nova_dedup_queue_get_next_entry();

	if(entry_address!=0){
		// TODO Should Lock File responding to write entry

		// Read write_entry
		target_entry = nova_get_block(sb, entry_address);
		printk("write entries block info: num_pages:%d, block: %lld, pgoff: %lld\n",target_entry->num_pages, target_entry->block, target_entry->pgoff);

		// Read Each Data Page from the write entry
		index = target_entry->pgoff;
		data_page_number = target_entry->num_pages;
		for(i=0;i<data_page_number;i++){
			printk("Daga Page number %d\n",i+1);
			nvmm = (unsigned long) (target_entry->block >> PAGE_SHIFT) + index - target_entry->pgoff;
			dax_mem = nova_get_block(sb,(nvmm << PAGE_SHIFT));
			memset(buf,0,DATABLOCK_SIZE);
			memset(fingerprint,0,FINGERPRINT_SIZE);
			left = __copy_to_user(buf,dax_mem,DATABLOCK_SIZE);
			if(left){
				nova_dbg("%s ERROR!: left %lu\n",__func__,left);
				return 0;
			}
			// Fingerprint each datapage
			nova_dedup_fingerprint(buf,fingerprint);
			for(j=0;j<FINGERPRINT_SIZE;j++)
				printk("%08X",fingerprint[j]);
			printk("\n");
			index++;
		}
		// TODO Lookup for duplicate datapages

		// TODO add new 'DEDUP-TABLE' entry
		// TODO do normal 'write' for unique datapages
		// TODO append new write entries
		// TODO update tail of that file
	}
	else printk("no entry!\n");	



	// DEDUP TABLE should be updated (testing)
	dedup_table_update(filp,buf,32,&filp->f_pos);
	printk("Dedup Table Update Finsihed\n");


	// RADIX TREE TEST (testing)
	/*
		 INIT_RADIX_TREE(&sbi->dedup_tree_fingerprint,GFP_KERNEL); 
		 INIT_RADIX_TREE(&sbi->dedup_tree_address,GFP_KERNEL);
		 printk("Radix Tree Initialized\n");	

		 nova_dedup_init_radix_tree_node(&temp,1);

		 radix_tree_insert(&sbi->dedup_tree_fingerprint,test_key,&temp);	
		 printk("Inserted!\n");
		 temp2 = radix_tree_lookup_slot(&sbi->dedup_tree_fingerprint,compare_key);

		 if(temp2){
		 printk("Found Entry\n");
		 temp3 = radix_tree_deref_slot(temp2);
		 printk("%lld\n",temp3->dedup_table_entry);
		 }
	 */

	kfree(buf);
	kfree(fingerprint);
	return 0;
}

