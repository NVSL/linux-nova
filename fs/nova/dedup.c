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

// Return the number of new write entries needed
int nova_dedup_num_new_write_entry(bool *target, int num_pages){
	int ret=1;
	int i;
	for(i=0;i<num_pages-1;i++){
		if(target[i] != target[i+1])
			ret++;
	}
	return ret;
}

// TODO update 'update-count', 'reference count'
// TODO update 'dedup-flag' - inplace
// Update FACT table + dedup_flags in write entry
int nova_dedup_update_FACT(struct super_block *sb, 
		struct nova_inode_info_header *sih, u64 begin_tail){
	void *addr;
	struct nova_file_write_entry *entry;
	struct nova_file_write_entry *entryc, entry_copy;
	u64 curr_p = begin_tail;
	size_t entry_size = sizeof(struct nova_file_write_entry);
	unsigned long irq_flags=0;


	while(curr_p && curr_p != sih->log_tail){
		if(is_last_entry(curr_p,entry_size))
			curr_p = next_log_page(sb,curr_p);
		if(curr_p ==0)
			break;
		addr = (void*) nova_get_block(sb,curr_p);
		entry = (struct nova_file_write_entry *)addr;

		// Update FACT Table responding to new write entry

		// Update Write New Write Entry 'dedup_flag'
		nova_memunlock_range(sb,entry,CACHELINE_SIZE,&irq_flags);
		entry->dedup_flag=0;
		nova_update_entry_csum(entry);
		nova_update_alter_entry(sb,entry);
		nova_memlock_range(sb,entry,CACHELINE_SIZE,&irq_flags);
	}
	return 0;
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
	struct nova_inode *target_pi, inode_copy;	// nova_inode of TI
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
	int num_new_entry=0;
	struct fingerprint_lookup_data *lookup_data;
	struct nova_inode_update update;
	struct nova_file_write_entry new_entry; // new write entry
	bool *duplicate_check;
	u64 file_size;
	unsigned long blocknr =0;
	unsigned long num_blocks =0;
	unsigned long irq_flags=0;
	u64 begin_tail =0;
	u64 epoch_id;
	u32 time;

	// Other
	ssize_t ret;
	INIT_TIMING(dax_read_time);
	INIT_TIMING(cow_write_time);
	// -------------------------------------------------------//
	// kmalloc buf, fingerprint
	buf = kmalloc(DATABLOCK_SIZE,GFP_KERNEL);
	fingerprint = kmalloc(FINGERPRINT_SIZE,GFP_KERNEL);

	do{
		// Pop TWE(Target Write Entry)
		entry_address = nova_dedup_queue_get_next_entry(&target_inode_number);
		num_new_entry=0;

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

			// Read Lock Acquire---------------------------------------------------------------
			NOVA_START_TIMING(dax_read_t, dax_read_time);
			inode_lock_shared(target_inode);

			// Read TWE
			target_entry = nova_get_block(sb, entry_address);

			printk("write entry: num_pages:%d, block(address): %lld, pgoff(of file): %lld\n\
					",target_entry->num_pages, target_entry->block, target_entry->pgoff);

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

			duplicate_check = kmalloc(sizeof(bool)*num_pages,GFP_KERNEL);
			memset(duplicate_check,false,sizeof(bool)*num_pages);
			// TODO Lookup for duplicate datapages
			// TODO add new FACT table Entries

			// Get the number of new write entries needed to be appended.
			num_new_entry = nova_dedup_num_new_write_entry(duplicate_check,num_pages);

			// For Debugging
			for(i=0;i<num_pages;i++){
				for(j=0;j<FINGERPRINT_SIZE;j++){
					printk("%02X",lookup_data[i].fingerprint[j]);
				}
				printk("\n");
			}
			// Read Unlock	------------------------------------------------------------------
			inode_unlock_shared(target_inode);
			NOVA_END_TIMING(dax_read_t, dax_read_time);


			// NO MORE READING!!!!!!

			// Write Lock --------------------------------------------------------------------
			NOVA_START_TIMING(cow_write_t,cow_write_time);
			sb_start_write(target_inode->i_sb);
			inode_lock(target_inode);


			if(nova_check_inode_integrity(sb,target_sih->ino,target_sih->pi_addr,
						target_sih->alter_pi_addr, &inode_copy,0) <0){
				ret = -EIO;
					goto out;
			}	

			// set time
			inode->i_ctime = inode->i_mtime = current_time(inode);
			time = current_time(inode).tv_sec;

			epoch_id = nova_get_epoch_id(sb);
			update.tail = target_sih->log_tail;
			update.alter_tail = target_sih->alter_log_tail;


			// TODO Append Write Entry 
			/*
				 for(i=0;i<num_new_entry;i++){
			// start_blk - block offset inside the file (0,1 ...)
			// num_blocks - number of blocks
			// blocknr - block starting address(Data Page) (2341413 something like this)
			// file_size - size of file after write (does not change)
			file_size = cpu_to_le64(inode->i_size); 

			nova_init_file_write_entry(sb,target_sih, &entry_data, epoch_id,
			start_blk, num_blocks,blocknr, time,
			file_size);
			entry_data.dedup_flag = 2; // flag is set to 2
			ret = nova_append_file_write_entry(sb,target_pi,inode,&entry_data,&update);
			if(ret){
			nova_dpg("%s: append inode entry failed\n",__func__);
			ret = -ENOSPC;
			//goto out
			}
			if(begin_tail == 0)
			begin_tail = update.curr_entry;
			}
			 */


			// Update tail
			nova_memunlock_inode(sb,target_pi,&irq_flags);
			nova_update_inode(sb,inode,target_pi,&update,1);
			nova_memlock_inode(sb,target_pi,&irq_flags);


			// Update FACT TABLE + dedup_flag
			nova_dedup_update_FACT(sb,target_sih,begin_tail);

			// Update Radix Tree
			ret = nova_reassign_file_tree(sb,target_sih,begin_tail);
			if(ret)
				goto out;
			inode->i_blocks = target_sih->i_blocks;
out:
			if(ret<0)
				printk("Clean up incomplete deduplication\n");
				//nova_cleanup_incomplete_write(sb,target_sih,blocknr,num_blocks,begin_tail,update.tail);

			// Write Unlock ------------------------------------------------------------
			inode_unlock(target_inode);
			sb_end_write(target_inode->i_sb);
			NOVA_END_TIMING(cow_write_t,cow_write_time);

			kfree(lookup_data);
			kfree(duplicate_check);
			iput(target_inode);
			printk("DEDUP COMPLETE\n");
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

