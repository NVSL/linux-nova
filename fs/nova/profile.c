#include <linux/list.h>
#include "nova.h"

#define SYNC_BIT        20
#define SEQ_BIT         2
#define RESET_BIT       36  /* 64 seconds */

// Profiler module #1
// Synchronize vs. Asynchronous

bool is_wcount_time_out(struct super_block *sb, struct nova_inode_info_header *sih) {
    unsigned int interval = 30;  /* 30 seconds */
    struct nova_inode *pi = nova_get_block(sb, sih->pi_addr);
    if ( timespec_trunc(current_kernel_time(),sb->s_time_gran).tv_sec
        - pi->i_mtime > interval) return true;
    else return false;    
}

inline int nova_sih_increase_wcount(struct super_block *sb, 
    struct nova_inode_info_header *sih, size_t len) {
    if (is_wcount_time_out(sb, sih)) {
        sih->wcount = len;
        return 0;
    }
    if (unlikely(sih->wcount >> 62 == 1)) {
        nova_info("Max wcount %lu is reached\n", sih->wcount);
        return -1;
    }
    sih->wcount += len;
    return 0;
}

inline bool nova_sih_is_sync(struct nova_inode_info_header *sih) {
    if (sih->wcount >> 63 == 1) return true;
    else return false;
}

inline bool nova_sih_judge_sync(struct nova_inode_info_header *sih) {
    if ((sih->wcount & ((1UL << 63) - 1)) >> SYNC_BIT == 0) {
        if (DEBUG_PROF_SYNC) nova_info("Inode sih %lu is async (%lu).\n", sih->ino, sih->wcount);
        sih->wcount = 0;
        return false;
    }
    else {
        if (DEBUG_PROF_SYNC) nova_info("Inode sih %lu is sync (%lu).\n", sih->ino, sih->wcount);
        sih->wcount = 1UL << 63;
        return true;
    }
}

// Judge and reset wcount
inline bool nova_prof_judge_sync(struct file *file) {
	struct nova_inode_info *si = NOVA_I(file->f_mapping->host);
	return nova_sih_judge_sync(&si->header);
}

// Profiler module #2
// Sequential vs. Random

bool is_entry_time_out(struct super_block *sb, struct nova_file_write_entry *entry) {
    unsigned int interval = 30;  /* 30 seconds */
    if ( timespec_trunc(current_kernel_time(),sb->s_time_gran).tv_sec
         - entry->mtime > interval) return true;
    else return false;    
}

unsigned int nova_get_prev_seq_count(struct super_block *sb, struct nova_inode_info_header *sih, 
    unsigned long pgoff, int num_pages) {
	struct nova_file_write_entry *entry;
    entry = nova_find_next_entry(sb, sih, pgoff);
    if (!entry) return 0;
    if (is_entry_time_out(sb, entry)) return 0;
    if (entry->pgoff > pgoff || entry->pgoff + entry->num_pages < pgoff + num_pages) return 0;
    return entry->seq_count + 1;
}

inline bool nova_prof_judge_seq(unsigned int seq_count) {
    if (seq_count >> SEQ_BIT == 0) return false;
    else return true;
}

// Judge seq_count
inline bool nova_entry_judge_seq(struct nova_file_write_entry *entry) {
    if (entry->seq_count >> SEQ_BIT == 0) {
        if (DEBUG_PROF_SEQ) nova_info("Entry index %llu is random (%u).\n", entry->pgoff, entry->seq_count);
        return false;
    }
    else {
        if (DEBUG_PROF_SEQ) nova_info("Entry index %llu is sequential (%u).\n", entry->pgoff, entry->seq_count);
        return true;
    }
}

// Profiler module #3
// Hot vs. Cold
int nova_alloc_inode_lru_lists(struct super_block *sb) {
	struct nova_sb_info *sbi = NOVA_SB(sb);
    int i;
    sbi->inode_lru_lists = kcalloc((TIER_BDEV_HIGH + 1)*sbi->cpus, sizeof(struct list_head), GFP_KERNEL);
    for (i=0;i<(TIER_BDEV_HIGH + 1)*sbi->cpus;++i) {
	    INIT_LIST_HEAD(&sbi->inode_lru_lists[i]);
    }
	if (!sbi->inode_lru_lists)
		return -ENOMEM;
    return 0;
}

inline struct list_head *nova_get_inode_lru_lists(struct nova_sb_info *sbi, int tier, int cpu) {
    return &sbi->inode_lru_lists[tier*sbi->cpus+cpu];
}

int nova_move_inode_lru_list(struct nova_sb_info *sbi, struct nova_inode_info_header *sih, int tier) {
    int cpu = sih->ino % sbi->cpus;
    struct list_head *new_list = nova_get_inode_lru_lists(sbi, tier, cpu); 
    if (sih->lru_list.next != &sih->lru_list && sih->lru_list.prev != &sih->lru_list) {
            list_del(&sih->lru_list);
        }        
    list_add_tail(&sih->lru_list, new_list);
    sih->ltier = tier;
    return 0;
}

int nova_update_sih_tier(struct super_block *sb, struct nova_inode_info_header *sih, int tier) {
	struct nova_sb_info *sbi = NOVA_SB(sb);
    return nova_move_inode_lru_list(sbi, sih, tier);
}

int nova_unlink_inode_lru_list(struct nova_sb_info *sbi, struct nova_inode_info_header *sih) {
    if (sih->lru_list.next != &sih->lru_list && sih->lru_list.prev != &sih->lru_list) {
        list_del(&sih->lru_list);
    }
    return 0;
}
