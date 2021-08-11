#include "nova.h"
#include "inode.h"
#include "dedup.h"

/******************** DEDUP QUEUE ********************/
struct nova_dedup_queue dqueue;

// Initialize Dedup Queue
int nova_dedup_queue_init(void){
	INIT_LIST_HEAD(&dqueue.head.list);
	mutex_init(&dqueue.lock);
	dqueue.head.write_entry_address = 0;
	return 0;
}

// Insert Write Entries to Dedup Queue
int nova_dedup_queue_push(u64 new_address, u64 target_inode_number){
	struct nova_dedup_queue_entry *new_data;
	
	mutex_lock(&dqueue.lock);
	new_data = kmalloc(sizeof(struct nova_dedup_queue_entry), GFP_KERNEL);
	list_add_tail(&new_data->list, &dqueue.head.list);
	new_data->write_entry_address = new_address;
	new_data->target_inode_number = target_inode_number;
	mutex_unlock(&dqueue.lock);
	
	printk("PUSH(Write Entry Address: %llu, Inode Number: %llu)\n",new_address,target_inode_number);
	return 0;
}

// Get next write entry to dedup
u64 nova_dedup_queue_get_next_entry(u64 *target_inode_number){
	struct nova_dedup_queue_entry *ptr;
	u64 ret = 0;

	mutex_lock(&dqueue.lock);
	if(!list_empty(&dqueue.head.list)){
		ptr = list_entry(dqueue.head.list.next, struct nova_dedup_queue_entry, list);

		ret = ptr->write_entry_address;
		*target_inode_number = ptr->target_inode_number;

		list_del(dqueue.head.list.next);
		kfree(ptr);
		printk("POP(Write Entry Address: %llu, Inode Number: %llu)\n",ret,*target_inode_number);
	}
	mutex_unlock(&dqueue.lock);
	return ret;
}

/******************** SHA1 ********************/

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


/******************** OTHER ********************/

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
int nova_dedup_reassign_file_tree(struct super_block *sb, 
		struct nova_inode_info_header *sih, u64 begin_tail)
{
	void *addr;
	struct nova_file_write_entry *entry;
	struct nova_file_write_entry *entryc, entry_copy;
	u64 curr_p = begin_tail;
	size_t entry_size = sizeof(struct nova_file_write_entry);

	entryc = (metadata_csum == 0) ? entry : &entry_copy;

	while (curr_p && curr_p != sih->log_tail) {
		if (is_last_entry(curr_p, entry_size))
			curr_p = next_log_page(sb, curr_p);

		if (curr_p == 0) { 
			nova_err(sb, "%s: File inode %lu log is NULL!\n",
					__func__, sih->ino);
			return -EINVAL;
		}    

		addr = (void *) nova_get_block(sb, curr_p);
		entry = (struct nova_file_write_entry *) addr;

		if (metadata_csum == 0)
			entryc = entry;
		else if (!nova_verify_entry_csum(sb, entry, entryc))
			return -EIO;

		if (nova_get_entry_type(entryc) != FILE_WRITE) {
			nova_dbg("%s: entry type is not write? %d\n",
					__func__, nova_get_entry_type(entry));
			curr_p += entry_size;
			continue;
		}    

		nova_assign_write_entry(sb, sih, entry, entryc, false);
		curr_p += entry_size;
	}

	return 0;
}


int nova_dedup_invalidate_target_entry(struct super_block *sb, 
		struct nova_inode_info_header *sih,	struct nova_file_write_entry *target_entry){

	unsigned long start_pgoff = target_entry->pgoff;
	unsigned int num = target_entry->num_pages;
	unsigned long curr_pgoff;
	unsigned long start_blocknr = (target_entry->block)>>PAGE_SHIFT;
	unsigned long curr_blocknr;
	int i;
	int ret = 0;
	for (i = 0; i < num; i++) { 
		curr_pgoff = start_pgoff + i;
		curr_blocknr = start_blocknr + i;

		// duplicate: Free (not inside dedup table)
		if(nova_dedup_is_duplicate(sb,curr_blocknr,true) == 2)
			nova_free_old_entry(sb, sih,target_entry,
					curr_pgoff,1,false,target_entry->epoch_id);
		// unique: Don't Free
		else
			nova_invalidate_write_entry(sb,target_entry,1,1);
	} 
	nova_invalidate_write_entry(sb, target_entry, 1, 0);
	return ret;
}


/******************** FACT ********************/
// TODO Range Lock in FACT table
// Find FACT entry with index(of FACT)
int nova_dedup_FACT_index_check(u64 index){
	if(index > FACT_TABLE_INDEX_MAX){
		printk("Index Out of Range: %lu\n",index);
		return 1;
	}
	return 0;
}

int nova_dedup_FACT_update_count(struct super_block *sb, u64 index){
	u32 count = 0;
	u8 compare = (1<<4)-1;
	struct fact_entry* target_entry;
	unsigned long irq_flags=0;
	u64 target_index;

	if(nova_dedup_FACT_index_check(index))
		return 1;

	// Read Actual Index
	target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + index * NOVA_FACT_ENTRY_SIZE;
	target_entry = (struct fact_entry *)nova_get_block(sb,target_index);
	target_index = target_entry->delete_target;

	if(nova_dedup_FACT_index_check(target_index))
		return 1;

	// Read Count of Actual Index
	target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + target_index * NOVA_FACT_ENTRY_SIZE;
	target_entry = (struct fact_entry*) nova_get_block(sb,target_index);
	count = target_entry->count;
	// IF update Count > 0
	if(compare & count){
		// decrease update count 1
		// increase reference count 1
		count += 15;
		if(count > ((1UL<<32)-1)){
			printk("ERROR: Overflow\n");
			return 1;
		}
		// Reference count, update count Atomic Update
		nova_memunlock_range(sb,target_entry,NOVA_FACT_ENTRY_SIZE, &irq_flags);
		PERSISTENT_BARRIER();
		target_entry->count = count;
		nova_memlock_range(sb,target_entry,NOVA_FACT_ENTRY_SIZE, &irq_flags);
	}
	return 0;
}

// For debugging
int nova_dedup_FACT_read(struct super_block *sb, u64 index){
	int r_count,u_count;
	struct fact_entry* target;
	u64 target_index;

	if(nova_dedup_FACT_index_check(index))
		return 1;

	target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + index * NOVA_FACT_ENTRY_SIZE;
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

// Insert new FACT entry
int nova_dedup_FACT_insert(struct super_block *sb, struct fingerprint_lookup_data* lookup){
	unsigned long irq_flags=0;
	struct fact_entry  te; // target entry
	struct fact_entry* pmem_te; // pmem target entry
	u64 index = 0;
	u64 target_index;
	int ret=0;

	/* Index SIZE */
	/* 4GB Environment - 19 bit */
	index = lookup->fingerprint[0];
	index = index<<8 | lookup->fingerprint[1];
	index = index<<3 | ((lookup->fingerprint[2] & 224)>>5);
	
	/* 1TB Environment - 27 bit */
	/*
	index = lookup->fingerprint[0];
	index = index << 8 | lookup->fingerprint[1];
	index = index << 8 | lookup->fingerprint[2];
	index = index << 3 | ((lookup->fingerprint[3] & 224)>>5);
	*/
	
	if(nova_dedup_FACT_index_check(index))
		return 2;

	// Read Entries until it finds a match, or finds a empty slot
	do{
		target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + index * NOVA_FACT_ENTRY_SIZE;
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
		// 1. Get new available index --> new function needed
		// 2. Set 'next' as the index
		// 3. return the entry in that index
	
	}
	while(0);

	// 
	if(ret){ // duplicate data page detected
		if((te.count & ((1<<4)-1)) == ((1<<4)-1)){
			printk("ERRO: more than 16 updates to this entry\n");
			return -1;
		}
		te.count++;
		printk("Duplicate Page detected, count is %d\n",te.count);
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

	// update lookup data
	lookup->index = index;
	lookup->block_address = te.block_address;

	if(nova_dedup_FACT_index_check(te.block_address))
		return 2;

	// Add FACT entry for delete
	target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + te.block_address * NOVA_FACT_ENTRY_SIZE;
	pmem_te = (struct fact_entry*)nova_get_block(sb,target_index);
	__copy_to_user(&te,pmem_te,sizeof(struct fact_entry));

	te.delete_target = index;

	nova_memunlock_range(sb,pmem_te,NOVA_FACT_ENTRY_SIZE,&irq_flags);
	memcpy_to_pmem_nocache(pmem_te,&te,NOVA_FACT_ENTRY_SIZE);
	nova_memlock_range(sb,pmem_te, NOVA_FACT_ENTRY_SIZE,&irq_flags);

	return ret;
}


// Update FACT table + dedup_flags in write entry
int nova_dedup_entry_update(struct super_block *sb, struct nova_inode_info_header *sih, u64 begin_tail){
	void *addr;
	struct nova_file_write_entry *entry;
	u64 curr_p = begin_tail;
	size_t entry_size = sizeof(struct nova_file_write_entry);
	unsigned long irq_flags=0;
	unsigned long curr_index;
	unsigned long start_index;
	unsigned int num=0;
	int i;

	while(curr_p && curr_p != sih->log_tail){
		if(is_last_entry(curr_p,entry_size))
			curr_p = next_log_page(sb,curr_p);
		if(curr_p ==0)
			break;
		addr = (void*) nova_get_block(sb,curr_p);
		entry = (struct nova_file_write_entry *)addr;

		num = entry->num_pages;
		start_index = entry->block >> PAGE_SHIFT;
		for(i=0;i<num;i++){
			curr_index = start_index + i;
			nova_dedup_FACT_update_count(sb,curr_index); // Update FACT 'update, reference count'
		}
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


// Check if target block has multiple Reference Count
// Return 1 if it's okay to delete - reference count = 0
// Return 0 if it's not okay to delete - reference count > 0
// Return 2 if it's not in FACT table - reference count < 0
int nova_dedup_is_duplicate(struct super_block *sb, unsigned long blocknr, bool check){
	unsigned long irq_flags=0;
	struct fact_entry  te; // target entry
	struct fact_entry* pmem_te; // pmem target entry
	u64 index = 0;
	u64 target_index;
	int ret=0;

	if(nova_dedup_FACT_index_check(blocknr))
		return 3;

	target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + blocknr * NOVA_FACT_ENTRY_SIZE;

	pmem_te = (struct fact_entry*)nova_get_block(sb,target_index);
	__copy_to_user(&te,pmem_te,sizeof(struct fact_entry));

	index = te.delete_target;

	if(nova_dedup_FACT_index_check(index))
		return 2;

	target_index = NOVA_DEF_BLOCK_SIZE_4K * FACT_TABLE_START + index * NOVA_FACT_ENTRY_SIZE;
	pmem_te = (struct fact_entry*)nova_get_block(sb,target_index);
	__copy_to_user(&te,pmem_te,sizeof(struct fact_entry));

	ret = te.count >> 4;

	if(ret <= 0){ // It's not in dedup table
		return 2;
	}
	else{ // It's okay to delete, this entry can also be deleted
		if(!check){
			te.count -= 16;
			nova_memunlock_range(sb,pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
			memcpy_to_pmem_nocache(pmem_te, &te, NOVA_FACT_ENTRY_SIZE - 4); // don't write 'delete' area
			nova_memlock_range(sb, pmem_te, NOVA_FACT_ENTRY_SIZE, &irq_flags);
		}
		if(ret == 1) // Can delete
			return 1;
		else
			return 0; // Can't delete
	}

}


/******************** DEDUPLICATION MAIN FUNCTION ********************/
int nova_dedup_test(struct file * filp){
	// Read Super Block
	struct address_space *mapping = filp->f_mapping;	
	struct inode *garbage_inode = mapping->host;
	struct super_block *sb = garbage_inode->i_sb;

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
	ssize_t ret=0;

	// kmalloc buf, fingerprint
	buf = kmalloc(DATABLOCK_SIZE,GFP_KERNEL);
	fingerprint = kmalloc(FINGERPRINT_SIZE,GFP_KERNEL);

	do{
		printk("----------DEDUP START----------\n");
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
				if(duplicate_check[i] != 2){
					duplicate_check[i] = nova_dedup_FACT_insert(sb,&lookup_data[i]);
				}
			/* Test
			for(i=0;i<num_pages;i++)
				if(duplicate_check[i] != 2){
					nova_dedup_FACT_read(sb, lookup_data[i].index);
				}
			*/

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
			file_size = cpu_to_le64(target_inode -> i_size);
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

				start_blk = original_start_blk + start; // start_blk - block offset inside the file (0,1 ...) = offset of 'start'
				num_blocks = (end-start)+1; // num_blocks - number of blocks = (end-start+1)
				blocknr = lookup_data[start].block_address; // blocknr - block starting address(Data Page) 
				if(duplicate_check[start]==1){ // If duplicate...
					//file_size -= DATABLOCK_SIZE;
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
			if(valid_page_num!=0){ // Not appended pages exists
				printk("Datapage assign error! %d left\n",valid_page_num);
				goto out;
			}


			// Update tail
			nova_memunlock_inode(sb,target_pi,&irq_flags);
			nova_update_inode(sb,target_inode,target_pi,&update,1);
			nova_memlock_inode(sb,target_pi,&irq_flags);

			// Update FACT TABLE + dedup_flag
			nova_dedup_entry_update(sb,target_sih,begin_tail);

			// Update Radix Tree - use unique function
			ret = nova_dedup_reassign_file_tree(sb,target_sih,begin_tail);
			if(ret)
				goto out;
			
			// Invalidate target entry, since it's not used any more
			ret = nova_dedup_invalidate_target_entry(sb,target_sih,target_entry);
			if(ret)
				goto out;

			target_inode->i_blocks = target_sih->i_blocks;
			target_sih->trans_id++;
		
			
			//i_size_write(target_inode, file_size);
			//target_sih->i_size = file_size;
			
out:
			if(ret<0)
				nova_cleanup_incomplete_write(sb,target_sih,blocknr,num_blocks,begin_tail,update.tail);

			// Unlock ------------------------------------------------------------
			inode_unlock(target_inode);
			sb_end_write(target_inode->i_sb);

			kfree(lookup_data);
			kfree(duplicate_check);
			iput(target_inode);	// Release Inode
		}
		else printk("no entry!\n");	
		printk("----------DEDUP COMPLETE----------\n");
	}while(0);

	kfree(buf);
	kfree(fingerprint);
	return 0;
}
