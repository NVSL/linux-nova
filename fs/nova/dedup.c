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
int nova_dedup_num_new_write_entry(short *target, int num_pages){
	int ret=1; // divided data pages
	int invalid_count =0; // Invalid data pages
	int i;
	for(i=0;i<num_pages-1;i++){
		if(target[i] != target[i+1]){
			if(target[i]==2)
				invalid_count++;
			else if(i==num_pages-2 && target[i+1]==2)
				invalid_count++;
			ret++;
		}
	}
	if(ret==1){
		if(target[0]==2)
			ret=0;
	}
	return ret-invalid_count;
}

// Cross check if 'Inode', 'WriteEntry', 'Datapage' was invalidated
// Return 1 if Inode-writeentry-datapage is all valid
int nova_dedup_crosscheck(struct nova_file_write_entry *entry
		,struct nova_inode_info_header *sih, unsigned long pgoff){
	struct nova_file_write_entry *referenced_entry;
	void ** pentry;
	pentry = radix_tree_lookup_slot(&sih->tree, pgoff);
	if(!pentry)
		return 0;
	referenced_entry = radix_tree_deref_slot(pentry);

	if(referenced_entry == entry)
		return 1;
	else{
		printk("Invalid DataPage Detected\n");
		return 0;
	}
}


// Functions for FACT table

// Find FACT entry with index(of FACT)
int nova_dedup_FACT_update_count(struct super_block *sb, u64 index){
	u32 count = 0;
	u8 compare = (1<<5)-1;
	struct fact_entry* target_entry;
	unsigned long irq_flags=0;
	u64 target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + index * NOVA_FACT_ENTRY_SIZE;

	target_entry = (struct fact_entry *)nova_get_block(sb,target_index);
	count = target_entry->count;

	if(compare | count){
		// decrease update count 1
		// increase reference count 1
		count += 15;
		if(count > ((1UL<<32)-1)){
			printk("ERRO Overflow\n");
			return 1;
		}
	}
	// Reference count, update count Atomic Update
	nova_memunlock_range(sb,target_entry,NOVA_FACT_ENTRY_SIZE, &irq_flags);
	PERSISTENT_BARRIER();
	target_entry->count = count;
	nova_memlock_range(sb,target_entry,NOVA_FACT_ENTRY_SIZE, &irq_flags);

	return 0;
}
int nova_dedup_FACT_read(struct super_block *sb, u64 index){
	int r_count,u_count;
	struct fact_entry* target;

	u64 target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + index * NOVA_FACT_ENTRY_SIZE;

	target = (struct fact_entry*)nova_get_block(sb,target_index);
	r_count = target->count;
	u_count = target->count;
	r_count >>= 4;
	u_count &= 15;

	printk("FACT table insert complete, reference count: %d, update count: %d\n",r_count,u_count);
	return 0;
}

// Is fact entry empty?
int nova_dedup_is_empty(struct fact_entry target){
	if(target.count ==0)
		return 1;
	return 0;
}


// TODO insert delete entries too

// Insert new FACT entry
int nova_dedup_FACT_insert(struct super_block *sb, struct fingerprint_lookup_data* lookup){
	unsigned long irq_flags=0;
	struct fact_entry  te; // target entry
	struct fact_entry* pmem_te; // pmem target entry
	u64 index = 0;
	int ret=0;

	index = lookup->fingerprint[0];
	index = index<<8 | lookup->fingerprint[1];
	index = index<<8 | lookup->fingerprint[2];

	// Read Entries until it finds a match, or finds a empty slot
	do{
		u64 target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + index * NOVA_FACT_ENTRY_SIZE;
		pmem_te = (struct fact_entry*)nova_get_block(sb,target_index);
		__copy_to_user(&te,pmem_te,sizeof(struct fact_entry));
		if(strncmp(te.fingerprint, lookup->fingerprint,FINGERPRINT_SIZE) == 0){ // duplicate
			ret = 1;
			break;
		}
		if(nova_dedup_is_empty(te)){ // unique
			ret =0;
			break;
		}
		// TODO add pointer to the entry and add a new entry at the end of fact table
	}
	while(0);

	// 
	if(ret){ // duplicate data page detected
		if((te.count & ((1<<5)-1)) > (1<<5)){
			printk("ERRO: more than 16 updates to this entry\n");
			return -1;
		}
		te.count++;
	}
	else{ // new entry should be written
		strncpy(te.fingerprint,lookup->fingerprint,FINGERPRINT_SIZE);
		te.block_address = lookup->block_address;
		te.count=1;
		te.next = 0;
	}

	// copy target_entry to pmem
	nova_memunlock_range(sb,pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
	memcpy_to_pmem_nocache(pmem_te, &te, NOVA_FACT_ENTRY_SIZE - 4); // don't write 'delete' area
	nova_memlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);

	lookup->index = index;
	lookup->block_address = te.block_address;
	return ret;
}


// TODO update 'update-count', 'reference count'
// Update FACT table + dedup_flags in write entry
int nova_dedup_entry_update(struct super_block *sb, struct nova_inode_info_header *sih, u64 begin_tail){
	void *addr;
	struct nova_file_write_entry *entry;
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
		// 1. Know data page address(blocknr)
		// 2. Know the index of that datapage in FACT table
		// 3. call nova_dedup_FACT_update

		// Update Write New Write Entry 'dedup_flag'
		nova_memunlock_range(sb,entry,CACHELINE_SIZE,&irq_flags);
		entry->dedup_flag=0;
		nova_update_entry_csum(entry);
		nova_update_alter_entry(sb,entry);
		nova_memlock_range(sb,entry,CACHELINE_SIZE,&irq_flags);
		curr_p += entry_size;
	}
	return 0;
}

// DEDUPLICATION FUNCITON //
int nova_dedup_test(struct file * filp){
	// Read Super Block
	struct address_space *mapping = filp->f_mapping;	
	struct inode *garbage_inode = mapping->host;
	struct super_block *sb = garbage_inode->i_sb;


	// TEST FACT table

	// For read phase
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

	// For write phase
	int num_new_entry=0;
	int start, end;
	struct fingerprint_lookup_data *lookup_data;
	struct nova_inode_update update;
	struct nova_file_write_entry entry_data; // new write entry
	short *duplicate_check;
	u64 file_size;
	unsigned long original_start_blk, start_blk;
	unsigned long blocknr =0;
	unsigned long num_blocks =0;
	unsigned long irq_flags=0;
	u64 begin_tail =0;
	u64 epoch_id;
	u32 time;
	u32 valid_page_num=0;

	// Other
	ssize_t ret=0;
	// -------------------------------------------------------//
	// kmalloc buf, fingerprint
	buf = kmalloc(DATABLOCK_SIZE,GFP_KERNEL);
	fingerprint = kmalloc(FINGERPRINT_SIZE,GFP_KERNEL);

	do{
		// Pop TWE(Target Write Entry)
		entry_address = nova_dedup_queue_get_next_entry(&target_inode_number);
		// target_inode_number should exist
		if (target_inode_number < NOVA_NORMAL_INODE_START && target_inode_number != NOVA_ROOT_INO) {
			//nova_info("%s: invalid inode %llu.", __func__,target_inode_number);
			printk("No entry\n");
			continue;
		}
		// Read TI(Target Inode)
		target_inode = nova_iget(sb,target_inode_number);
		// Inode Could've been deleted
		if(target_inode == ERR_PTR(-ESTALE)){
			nova_info("%s: inode %llu does not exist.", __func__,target_inode_number);
			continue;
		}

		if(entry_address!=0){
			//Initialize variables
			ret =0;
			num_new_entry=0;
			valid_page_num=0;
			original_start_blk = 0;
			begin_tail=0;
			irq_flags=0;

			target_si = NOVA_I(target_inode);
			target_sih = &target_si->header;
			target_pi = nova_get_inode(sb,target_inode);

			// ---------------------------Lock Acquire---------------------------------------------------------------
			sb_start_write(target_inode->i_sb);
			inode_lock(target_inode);

			// Read TWE
			target_entry = nova_get_block(sb, entry_address);
			original_start_blk = target_entry->pgoff;

			index = target_entry->pgoff;
			num_pages = target_entry->num_pages;
			lookup_data = kmalloc(num_pages*sizeof(struct fingerprint_lookup_data),GFP_KERNEL);
			duplicate_check = kmalloc(sizeof(short)*num_pages,GFP_KERNEL);
			memset(duplicate_check,false,sizeof(short)*num_pages);

			printk("write entry: num_pages:%d, block(address): %lld, pgoff(of file): %lld\n",target_entry->num_pages, target_entry->block, target_entry->pgoff);

			// Read Each Data Page from TWE
			for(i=0;i<num_pages;i++){
				if(nova_dedup_crosscheck(target_entry,target_sih,index)==0){
					duplicate_check[i] = 2; // Data page i in invalid, target write entry does not point to it!
					index++;
					continue;
				}
				valid_page_num++;
				memset(buf,0,DATABLOCK_SIZE);
				memset(fingerprint,0,FINGERPRINT_SIZE);

				nvmm = get_nvmm(sb,target_sih,target_entry,index);
				dax_mem = nova_get_block(sb,(nvmm << PAGE_SHIFT));
				left = __copy_to_user(buf,dax_mem,DATABLOCK_SIZE); // Read data page
				if(left){
					nova_dbg("%s ERROR!: left %lu\n",__func__,left);
					return 0;
				}
				// Fingerprint each datapage
				nova_dedup_fingerprint(buf,fingerprint);
				for(j=0;j<FINGERPRINT_SIZE;j++){
					lookup_data[i].fingerprint[j] = fingerprint[j];
				}
				lookup_data[i].block_address = nvmm;
				index++;
			}



			// Lookup & Add to FACT table
			for(i=0;i<num_pages;i++)
				if(duplicate_check[i] != 2)
					duplicate_check[i] = nova_dedup_FACT_insert(sb,&lookup_data[i]);
			// Test
			for(i=0;i<num_pages;i++)
				if(duplicate_check[i] != 2)
					nova_dedup_FACT_read(sb, lookup_data[i].index);

			// Get the number of new write entries needed to be appended.
			num_new_entry = nova_dedup_num_new_write_entry(duplicate_check,num_pages);
			if(num_new_entry ==0){
				printk("No Valid Datapages\n");
				goto out;
			}

			// ------------------- Write Phase -----------------------
			if(nova_check_inode_integrity(sb,target_sih->ino,target_sih->pi_addr,
						target_sih->alter_pi_addr, &inode_copy,0) <0){
				ret = -EIO;
				goto out;
			}	

			// set time
			target_inode->i_ctime  = current_time(target_inode);
			time = current_time(target_inode).tv_sec;

			epoch_id = nova_get_epoch_id(sb);
			update.tail = target_sih->log_tail;
			update.alter_tail = target_sih->alter_log_tail;


			for(i=0;i<num_pages;i++){
				start = i;
				end = i;

				if(duplicate_check[i] == 0){ // unique
					for(j=i;j<num_pages-1;j++){
						if(duplicate_check[j+1] == 0) end = j+1; //unique
						else break; // duplicate or invalid
					}
					// start ~ end is unique, 
					i=j;
				}
				else if(duplicate_check[i]==2) continue; // invalid

				// start ~ end should go into data pages
				// start_blk - block offset inside the file (0,1 ...) = offset of 'start'
				start_blk = original_start_blk + start;
				// num_blocks - number of blocks = (end-start+1)
				num_blocks = (end-start)+1;
				// blocknr - block starting address(Data Page) (2341413 something like this) = blocknr of start
				blocknr = lookup_data[start].block_address;
				// file_size - size of file after write (does not change)
				file_size = cpu_to_le64(target_inode->i_size);
				if(duplicate_check[start]==1){
					printk("file size shrink\n");
					file_size -= DATABLOCK_SIZE;
				}
				
				printk("NEW WRITE ENTRY: start pgoff: %lu, number of pages: %lu\n",start_blk,num_blocks);

				nova_init_file_write_entry(sb,target_sih, &entry_data, epoch_id,
						start_blk, num_blocks,blocknr, time, file_size);
				entry_data.dedup_flag = 2; // flag is set to 2
				ret = nova_append_file_write_entry(sb,target_pi,target_inode,&entry_data,&update);
				if(ret){
					nova_dbg("%s: append inode entry failed\n",__func__);
					ret = -ENOSPC;
					//goto out;
				}
				if(begin_tail == 0)
					begin_tail = update.curr_entry;
				valid_page_num -= num_blocks;
			}
			if(valid_page_num!=0){
				printk("Datapage assign error! %d left\n",valid_page_num);
				goto out;
			}


			// Update tail
			nova_memunlock_inode(sb,target_pi,&irq_flags);
			nova_update_inode(sb,target_inode,target_pi,&update,1);
			nova_memlock_inode(sb,target_pi,&irq_flags);

			// Update FACT TABLE + dedup_flag
			nova_dedup_entry_update(sb,target_sih,begin_tail);

			// Update Radix Tree
			ret = nova_reassign_file_tree(sb,target_sih,begin_tail);
			if(ret)
				goto out;
			target_inode->i_blocks = target_sih->i_blocks;
out:
			if(ret<0)
				printk("Clean up incomplete deduplication\n");
			//nova_cleanup_incomplete_write(sb,target_sih,blocknr,num_blocks,begin_tail,update.tail);

			// Unlock ------------------------------------------------------------
			inode_unlock(target_inode);
			sb_end_write(target_inode->i_sb);

			kfree(lookup_data);
			kfree(duplicate_check);
			iput(target_inode);
			printk("----------DEDUP COMPLETE----------\n");
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


