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

// Judge and reset wcount
inline bool nova_prof_judge_sync(struct nova_inode_info_header *sih) {
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

inline bool nova_file_judge_sync(struct file *file) {
	struct nova_inode_info *si = NOVA_I(file->f_mapping->host);
	return nova_prof_judge_sync(&si->header);
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

// Judge seq_count
inline bool nova_prof_judge_seq(struct nova_file_write_entry *entry) {
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


// Action