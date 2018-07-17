#include <linux/list.h>
#include "nova.h"
#include "bdev.h"

#define SYNC_BIT        20
#define SEQ_BIT         2
#define RESET_BIT       36  /* 64 seconds */

inline int most_sig_lbit(unsigned long v) {
    int r = 0;
    while (v >>= 1) r++;
    return r;
}

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
    if ((sih->wcount & ((1UL << 63) - 1)) >> SYNC_BIT > 0) {
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
    entry = nova_find_next_entry_lockfree(sb, sih, pgoff);
    if (!entry) goto tail;
    if (is_entry_time_out(sb, entry)) goto tail;
    if (entry->pgoff <= pgoff && entry->pgoff + entry->num_pages - 1 >= pgoff + num_pages/2) 
        return entry->seq_count + 1;
tail:
    entry = nova_find_next_entry_lockfree(sb, sih, pgoff + num_pages/2);
    if (!entry) return 0;
    if (is_entry_time_out(sb, entry)) return 0;
    if (entry->pgoff <= pgoff + num_pages/2 && entry->pgoff + entry->num_pages >= pgoff + num_pages) 
        return entry->seq_count + 1;
    return 0;
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
    sbi->il_mutex = kcalloc((TIER_BDEV_HIGH + 1)*sbi->cpus, sizeof(struct mutex), GFP_KERNEL);
    for (i=0;i<(TIER_BDEV_HIGH + 1)*sbi->cpus;++i) {
	    INIT_LIST_HEAD(&sbi->inode_lru_lists[i]);
	    mutex_init(&sbi->il_mutex[i]);
    }
	if (!sbi->inode_lru_lists)
		return -ENOMEM;
	if (!sbi->il_mutex)
		return -ENOMEM;
    return 0;
}

inline struct list_head *nova_get_inode_lru_lists(struct nova_sb_info *sbi, int tier, int cpu) {
    return &sbi->inode_lru_lists[tier*sbi->cpus+cpu];
}

inline struct mutex *nova_get_inode_lru_mutex(struct nova_sb_info *sbi, int tier, int cpu) {
    return &sbi->il_mutex[tier*sbi->cpus+cpu];
}

inline bool is_inode_lru_list_empty(struct nova_sb_info *sbi, int tier, int cpu) {
    return list_empty(nova_get_inode_lru_lists(sbi, tier, cpu));
}

int nova_remove_inode_lru_list(struct nova_sb_info *sbi, struct nova_inode_info_header *sih, int tier) {
    int i;
    int cpu = sih->ino % sbi->cpus;
	struct mutex *mutex;
    for (i=0;i<=tier;++i) {
        if (sih->lru_list[i].next != &sih->lru_list[i] || sih->lru_list[i].prev != &sih->lru_list[i]) {
            mutex = nova_get_inode_lru_mutex(sbi, i, cpu);
            mutex_lock(mutex);
            list_del_init(&sih->lru_list[i]);
            mutex_unlock(mutex);
        }
    }     
    return 0;
}

int nova_renew_inode_lru_list(struct nova_sb_info *sbi, struct nova_inode_info_header *sih) {
    int i;
    int cpu = sih->ino % sbi->cpus;
	struct mutex *mutex;
    struct list_head *new_list;
    for (i=0;i<=TIER_BDEV_HIGH;++i) {
        if (sih->lru_list[i].next != &sih->lru_list[i] || sih->lru_list[i].prev != &sih->lru_list[i]) {
            mutex = nova_get_inode_lru_mutex(sbi, i, cpu);
            new_list = nova_get_inode_lru_lists(sbi, i, cpu);
            mutex_lock(mutex);
            list_move_tail(&sih->lru_list[i], new_list);
            mutex_unlock(mutex);
        }
    }     
    return 0;
}

int nova_unlink_inode_lru_list(struct nova_sb_info *sbi, struct nova_inode_info_header *sih) {
    struct nova_inode_info *si = container_of(sih, struct nova_inode_info, header);
	timing_t rmsih_time;

    if (!S_ISREG(si->vfs_inode.i_mode)) {
        if (DEBUG_PROF_HOT) nova_info("Error: si is not a regular file.\n");
        return -2;
    }
	NOVA_START_TIMING(rmsih_t, rmsih_time);
    if (DEBUG_MIGRATION_SEM) nova_info("Mig_sem (inode %lu) down_up_write (nova_unlink_inode_lru_list)\n", sih->ino);
    down_write(&sih->mig_sem);
    // if (!down_write_trylock(&sih->mig_sem)) {
	//     NOVA_END_TIMING(rmsih_t, rmsih_time);
    //     return 0;
    // }
    nova_remove_inode_lru_list(sbi, sih, TIER_BDEV_HIGH);
	up_write(&sih->mig_sem);
	NOVA_END_TIMING(rmsih_t, rmsih_time);
    return 0;
}

int nova_calibrate_sih_list(struct super_block *sb, struct nova_inode_info_header *sih,
    int tier, struct list_head *new_list) {
    struct nova_inode_info_header *prev_sih;
    if (sih->lru_list[tier].prev == new_list) return 0;
    prev_sih = container_of(sih->lru_list[tier].prev, struct nova_inode_info_header, lru_list[tier]);
    if (prev_sih->avg_atime > sih->avg_atime) 
        list_move_tail(&prev_sih->lru_list[tier], new_list);
    return 0;
}

int nova_update_avg_atime(struct super_block *sb, struct nova_inode_info_header *sih, 
    unsigned long len) {
    unsigned long prev_bit, len_bit, prev_atime;
    unsigned long atime = current_kernel_time().tv_sec;
    prev_bit = most_sig_lbit(sih->i_size);
    len_bit = most_sig_lbit(len);
    prev_atime = sih->avg_atime;
    if (len_bit >= prev_bit) sih->avg_atime = atime;
    sih->avg_atime = prev_atime + ((atime-prev_atime) >> (prev_bit-len_bit));
    return 0;
}

/*
 * Update htier and ltier in sih
 * mode: 1 - force migration
 *       2 - reload information during rebuild
 *       3 - include this tier
 *       4 - partial migration
 *       5 - interrupted migration
 */
int nova_update_sih_tier(struct super_block *sb, struct nova_inode_info_header *sih, 
    int tier, int mode) {
	struct nova_sb_info *sbi = NOVA_SB(sb);
    int cpu = sih->ino % sbi->cpus;
    int i;
	struct mutex *mutex = nova_get_inode_lru_mutex(sbi, tier, cpu);
    struct list_head *new_list = nova_get_inode_lru_lists(sbi, tier, cpu);
    struct nova_inode_info *si = container_of(sih, struct nova_inode_info, header);

	timing_t usih_time;

	NOVA_START_TIMING(usih_t, usih_time);

    if (unlikely(!si)) {
        nova_info("Error: si is NULL.\n");
        return -1;
    }
    if (!S_ISREG(sih->i_mode)) {
        if (DEBUG_PROF_HOT) nova_info("Error: si is not a regular file.\n");
        return -2;
    }

    switch (mode) {
	    case 1:
            nova_remove_inode_lru_list(sbi, sih, TIER_BDEV_HIGH);
            mutex_lock(mutex);
            list_add_tail(&sih->lru_list[tier], new_list);
            mutex_unlock(mutex);
            sih->htier = tier;
            sih->ltier = tier;
		    break;
	    case 2:
            for (i=sih->ltier; i<=sih->htier; ++i) {
                mutex = nova_get_inode_lru_mutex(sbi, i, cpu);
                new_list = nova_get_inode_lru_lists(sbi, i, cpu);
                mutex_lock(mutex);
                list_move_tail(&sih->lru_list[i], new_list);
                mutex_unlock(mutex);
            }
            sih->avg_atime = current_kernel_time().tv_sec;
		    break;
	    case 3:
            mutex_lock(mutex);
            list_move_tail(&sih->lru_list[tier], new_list);
            nova_calibrate_sih_list(sb, sih, tier, new_list);
            mutex_unlock(mutex);
            if (sih->ltier > tier) sih->ltier = tier;
            if (sih->htier < tier) sih->htier = tier;
		    break;
	    case 4:
            nova_remove_inode_lru_list(sbi, sih, tier);
            mutex_lock(mutex);
            list_add_tail(&sih->lru_list[tier], new_list);
            mutex_unlock(mutex);
            if (sih->ltier < tier) sih->ltier = tier;       
            if (sih->htier < sih->ltier) sih->htier = sih->ltier;    
		    break;   
	    case 5:
            nova_renew_inode_lru_list(sbi, sih);
            mutex_lock(mutex);
            list_move_tail(&sih->lru_list[tier], new_list);
            mutex_unlock(mutex);
            if (sih->ltier < tier) sih->ltier = tier;       
            if (sih->htier < sih->ltier) sih->htier = sih->ltier;
		    break;
    }
    
	NOVA_END_TIMING(usih_t, usih_time);

    return 0;
}

// Profiler module #4
// Read vs. Write
// The threshold of PMEM should be (#read)/(#read+#write)
int nova_give_advise(struct nova_sb_info *sbi) {
    int invalid = 0;
    unsigned long total_read = 0;
    unsigned long total_write = 0;
    int bitr, bitw, i, adv;
    for (i=0;i<4;++i) {
        total_read += sbi->stat->fread[i];
        total_write += sbi->stat->fwrite[i];
        if (sbi->stat->fread[i]==0 && sbi->stat->fwrite[i]==0) invalid++;
    }
    if (invalid > 1) return 0;
    bitr = most_sig_lbit(total_read);
    bitw = most_sig_lbit(total_write);
    i = bitr - bitw;
    sbi->stat->adv = i;
    adv = MIGRATION_DOWN_PMEM_PERC_INIT + i*5;
    if (adv>90) adv = 90;
    if (adv<50) adv = 50;
    MIGRATION_DOWN_PMEM_PERC = adv;
    // MIGRATION_DOWN_PMEM_PERC = adv>MIGRATION_DOWN_PMEM_PERC_INIT ? adv:MIGRATION_DOWN_PMEM_PERC_INIT;
    return 0;
}

int nova_update_stat(struct nova_sb_info *sbi, size_t len, bool read) {
    int cur = current_kernel_time().tv_sec & (unsigned int)3;
    if (sbi->stat->cur != cur) {
        sbi->stat->cur = cur;
        nova_give_advise(sbi);
        sbi->stat->fread[cur] = 0;
        sbi->stat->fwrite[cur] = 0;
    }
    if (read) sbi->stat->fread[cur] += len;
    else sbi->stat->fwrite[cur] += len;
    return 0;
}