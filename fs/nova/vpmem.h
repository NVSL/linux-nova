#ifndef __VPMEM_H
#define __VPMEM_H

#include "nova.h"

extern unsigned long vpmem_start;
extern unsigned long vpmem_end;

int  vpmem_init(void);
int  vpmem_setup(struct nova_sb_info *sbi, unsigned long);
void vpmem_cleanup(void);
void vpmem_reset(void);
// int vpmem_pin(unsigned long vaddr, int count);            
// int vpmem_unpin(unsigned long vaddr, int count);
int vpmem_cache_pages(unsigned long vaddr, int count);   // To cache a particular page
int vpmem_flush_pages(unsigned long vaddr, int count);   // To free a cached page if it was presented
int vpmem_cached(unsigned long vaddr, int count);        // To check if a particular page is present in the cache


#endif // __VPMEM_H
