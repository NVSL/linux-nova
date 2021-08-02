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
int nova_dedup_queue_push(u64 new_address, u64 target_inode_number){
	struct nova_dedup_queue *new_data;
	new_data = kmalloc(sizeof(struct nova_dedup_queue), GFP_KERNEL);
	list_add_tail(&new_data->list, &nova_dedup_queue_head.list);
	new_data->write_entry_address = new_address;
	new_data->target_inode_number = target_inode_number;
	printk("PUSH to queue: %llu %llu\n",new_address,target_inode_number);
	return 0;
}

// Get next write entry to dedup
u64 nova_dedup_queue_get_next_entry(u64 *target_inode_number){
	struct nova_dedup_queue *ptr;
	u64 ret = 0;
	if(!list_empty(&nova_dedup_queue_head.list)){
		ptr = list_entry(nova_dedup_queue_head.list.next, struct nova_dedup_queue, list);

		ret = ptr->write_entry_address;
		*target_inode_number = ptr->target_inode_number;

		list_del(nova_dedup_queue_head.list.next);
		kfree(ptr);
		printk("POP from queue: %llu %llu\n",ret,*target_inode_number);
	}
	return ret;
}

// For SHA1
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

// For SHA1
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

// For SHA1
int nova_dedup_fingerprint(unsigned char* datapage, unsigned char * ret_fingerprint){
	struct crypto_shash *alg;
	char *hash_alg_name = "sha1";
	//char *hash_alg_name = "md5";
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

// DEDUPLICATION FUNCITON //
int nova_dedup_test(struct file * filp){
	// Read Super Block
	struct address_space *mapping = filp->f_mapping;	
	struct inode *inode = mapping->host;
	struct super_block *sb = inode->i_sb;

	// For write entry 
	struct nova_file_write_entry *target_entry;	// Target write entry to deduplicate
	struct inode *target_inode;		// Inode of target write entry
	u64 entry_address;	// Address of target write entry(TWE)
	u64 target_inode_number=0; // Number of target inode (TI)
	struct nova_inode *target_pi;	// nova_inode of TI
	struct nova_inode_info *target_si;
	struct nova_inode_info_header *target_sih;

	unsigned char *buf;	// Read Buffer
	unsigned char *fingerprint; // Fingerprint result

	unsigned long left;
	pgoff_t index;
	int i, j, num_pages =0;
	unsigned long nvmm;
	void *dax_mem = NULL;

	// For new write entry
	int new_entry_num=0;
	u64 new_entry_address[MAX_DATAPAGE_PER_WRITEENTRY];
	struct fingerprint_lookup_data *lookup_data;

	// kmalloc buf, fingerprint
	buf = kmalloc(DATABLOCK_SIZE,GFP_KERNEL);
	fingerprint = kmalloc(FINGERPRINT_SIZE,GFP_KERNEL);

	do{
		// Pop TWE(Target Write Entry)
		entry_address = nova_dedup_queue_get_next_entry(&target_inode_number);
		new_entry_num=0;
		memset(new_entry_address,0,MAX_DATAPAGE_PER_WRITEENTRY*8);

		// target_inode_number should exist
		if (target_inode_number < NOVA_NORMAL_INODE_START && target_inode_number != NOVA_ROOT_INO) {
			//nova_info("%s: invalid inode %llu.", __func__,target_inode_number);
			printk("No entry\n");
			continue;
		}
		if(entry_address!=0){
			// Read TI(Target Inode)
			target_inode = nova_iget(sb, target_inode_number);
			// Inode Could've been deleted, 
			if (target_inode == ERR_PTR(-ESTALE)) {
				nova_info("%s: inode %llu does not exist.", __func__,target_inode_number);
				continue;
			}
			target_si = NOVA_I(target_inode);
			target_sih = &target_si->header;
			target_pi = nova_get_inode(sb,target_inode);

			printk("number of inode?: %llu\n",target_pi->nova_ino);

			// TODO cross check inode <-> write entry

			// Read Lock Acquire
			INIT_TIMING(dax_read_time);
			NOVA_START_TIMING(dax_read_t, dax_read_time);
			inode_lock_shared(target_inode);

			// Read TWE
			target_entry = nova_get_block(sb, entry_address);

			printk("write entries block info: num_pages:%d, block: %lld, pgoff: %lld\n",target_entry->num_pages, target_entry->block, target_entry->pgoff);

			// Read Each Data Page from the write entry
			index = target_entry->pgoff;
			num_pages = target_entry->num_pages;
			lookup_data = kmalloc(num_pages*sizeof(struct fingerprint_lookup_data),GFP_KERNEL);

			for(i=0;i<num_pages;i++){
				printk("Daga Page number %d\n",i+1);
				memset(buf,0,DATABLOCK_SIZE);
				memset(fingerprint,0,FINGERPRINT_SIZE);

				nvmm = get_nvmm(sb,target_sih,target_entry,index);
				dax_mem = nova_get_block(sb,(nvmm << PAGE_SHIFT));

				left = __copy_to_user(buf,dax_mem,DATABLOCK_SIZE);
				if(left){
					nova_dbg("%s ERROR!: left %lu\n",__func__,left);
					return 0;
				}
				// Fingerprint each datapage
				printk("Fingerprint Start\n");
				nova_dedup_fingerprint(buf,fingerprint);
				printk("Fingerprint End\n");
				for(j=0;j<FINGERPRINT_SIZE;j++){
					lookup_data[i].fingerprint[j] = fingerprint[j];
				}
				index++;
			}
			// TODO Lookup for duplicate datapages
			for(i=0;i<num_pages;i++){
					for(j=0;j<FINGERPRINT_SIZE;j++){
							printk("%02X",lookup_data[i].fingerprint[j]);
					}
					printk("\n");
			}
			// TODO add new 'DEDUP-Table' Entries


			// Read Unlock	
			inode_unlock_shared(target_inode);
			NOVA_END_TIMING(dax_read_t, dax_read_time);


			// NO MORE READING!!!!!!

			// Write Lock
			INIT_TIMING(time);
			NOVA_START_TIMING(cow_write_t,time);
			sb_start_write(target_inode->i_sb);
			inode_lock(target_inode);

			
			// TODO append new write entries
			/* Should know
			 - how many entries needed
			 - where is the starting block address
			 - dedup_flag should be set to 2
			 - num pages are 1
			 */


			// TODO update tail

			// TODO update 'update-count', 'reference count'

			// TODO update 'dedup-flag' - inplace

			// Write Unlock
			inode_unlock(target_inode);
			sb_end_write(target_inode->i_sb);
			NOVA_END_TIMING(cow_write_t,time);
		}
		else printk("no entry!\n");	
	}while(0);


	kfree(buf);
	kfree(fingerprint);
	return 0;
}

// TODO 
// Implementation : How are we going to make the 'dedup table'? --> Static Table
// Design : How to search 'dedup table' for deduplication -> indexing
// Design : How to search 'dedup table' for deletion -> indirect indexing
// Implementation : How to gain file lock from 'write entry' -> nova_get_inode, nonva_iget

