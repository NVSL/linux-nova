#include "nova.h"

#define SYNC_BIT        20

// Profiler module 1
// Synchronize vs. Asynchronous

inline int nova_sih_increase_wcount(struct nova_inode_info_header *sih, size_t len){
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
inline bool nova_sih_judge_sync(struct nova_inode_info_header *sih) {
    if ((sih->wcount & ((1UL << 63) - 1)) >> SYNC_BIT == 0) {
        sih->wcount = 0;
        if (DEBUG_PROF_SYNC) nova_info("Inode sih %lu is async.\n", sih->ino);
        return false;
    }
    else {
        sih->wcount = 1UL << 63;
        if (DEBUG_PROF_SYNC) nova_info("Inode sih %lu is sync.\n", sih->ino);
        return true;
    }
}

inline bool nova_file_judge_sync(struct file *file) {
	struct nova_inode_info *si = NOVA_I(file->f_mapping->host);
	return nova_sih_judge_sync(&si->header);
}