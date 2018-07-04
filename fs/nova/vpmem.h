// #ifndef __VPMEM_H
// #define __VPMEM_H

#include "nova.h"
#include "super.h"
#include <linux/types.h>

// #define VPMEM_MAX_PAGES_QTR          8192    // 32MB per-cpu
// Hard limit is VPMEM_MAX_PAGES_QTR*4*TIER_BDEV_HIGH*sbi->cpus
#define VPMEM_RES_PAGES             64       // 32KB per-cpu

extern unsigned long vpmem_start;
extern unsigned long vpmem_end;

int vpmem_init(void);
// int vpmem_setup(struct nova_sb_info *sbi, unsigned long);
// void vpmem_cleanup(void);

int pgc_tier_free_order(int tier);
inline int pgc_total_size(void);
inline bool is_should_migrate_log(void);
inline bool is_pgcache_large(void);
inline bool is_pgcache_ideal(void);
inline bool is_pgcache_quite_small(void);

int vpmem_get(struct nova_sb_info *sbi, unsigned long offset);
void vpmem_put(void);

void vpmem_reset(void);

inline bool vpmem_valid_address(unsigned long address);
bool vpmem_do_page_fault_range(unsigned long address, unsigned long address_end, unsigned long entry_end);
bool vpmem_do_page_fault_lite(void *address_from, void *address_to);

// int vpmem_pin(unsigned long vaddr, int count);            
// int vpmem_unpin(unsigned long vaddr, int count);
int vpmem_cache_pages(unsigned long vaddr, unsigned long count, bool load);   // To cache a particular page
// int vpmem_cache_pages_safe(unsigned long vaddr, unsigned long count);
int vpmem_flush_pages(unsigned long vaddr, unsigned long count);   // To free a cached page if it was presented
int vpmem_flush_pages_sync(unsigned long address, unsigned long count);
int vpmem_invalidate_pages(unsigned long vaddr, unsigned long count); 
int vpmem_renew_pages(void *addr, unsigned long address, unsigned long count);
void *vpmem_lru_refer(unsigned long vaddr);
unsigned long vpmem_cached(unsigned long vaddr, unsigned long count);        // To check if a particular page is present in the cache

void set_should_migrate_log(void);
inline void set_is_pgcache_large(void);
inline void set_is_pgcache_ideal(void);
inline void set_is_pgcache_quite_small(void);
void set_is_pgcache_very_small(void);
void set_is_pgcache_small(void);

// int vpmem_range_rwsem_set(unsigned long vaddr, unsigned long count, bool down);
// bool vpmem_is_range_rwsem_locked(unsigned long vaddr, unsigned long count);

inline unsigned long virt_to_blockoff(unsigned long vaddr);
inline unsigned long virt_to_block(unsigned long vaddr);
inline unsigned long block_to_virt(unsigned long block);
inline unsigned long blockoff_to_virt(unsigned long blockoff);

// #endif // __VPMEM_H
