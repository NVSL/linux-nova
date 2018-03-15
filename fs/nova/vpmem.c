#include "vpmem.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/uaccess.h>	/* for put_user */
#include <asm/traps.h>	/* for put_user */
#include <linux/vmalloc.h>
#include <linux/slab.h> /* kmalloc */
#include <asm/current.h> /* current */
#include <linux/rmap.h>
#include <asm/ptrace.h>
#include <asm/pgtable_64.h>
#include <asm/tlbflush.h>
#include <asm/pgalloc.h>
#include <linux/bootmem.h>
#include <linux/preempt.h>
#include <../mm/mm_internal.h>
#include <linux/mutex.h>
#include <linux/kthread.h>
#include "bdev.h"

#ifdef QT_WA
#define KERN_INFO
#endif

#define VPMEM_SIZE_TB     _AC(16, UL)
#define VPMEM_START       (VMALLOC_START + _AC(16UL << 40, UL))
#define VPMEM_END         (VPMEM_START + _AC((VPMEM_SIZE_TB << 40) - 1, UL))

#define MAX_PAGES           1280000
#define SPM_META_SIZE_MB    _AC(1, UL)
#define SPM_META_SIZE       _AC(SPM_META_SIZE_MB << 20, UL)
#define SPM_PGCACHE_SIZE_MB _AC(50, UL)
#define SPM_PGCACHE_SIZE    _AC(SPM_PGCACHE_SIZE_MB << 20, UL)
#define USE_PMEM_CACHE      0

struct nova_sb_info *vsbi;

unsigned long vpmem_start=0;
unsigned long vpmem_end=0;
unsigned long map_page[BDEV_COUNT_MAX]={0};
bool map_valid[BDEV_COUNT_MAX]={0};

static unsigned long faults=0;
static unsigned long bdev_read=0;
static unsigned long bdev_write=0;

struct pmem_t {
    void *virt_addr;
	phys_addr_t	phys_addr;
    unsigned long size;
} pmem;

enum x86_pf_error_code {
    PF_PROT  = 1 << 0,
    PF_WRITE = 1 << 1,
    PF_USER  = 1 << 2,
    PF_RSVD  = 1 << 3,
    PF_INSTR = 1 << 4,
    PF_PK    = 1 << 5,
};

static __ref void *spp_getpage(void)
{
    void *ptr;

    ptr = (void *) get_zeroed_page(GFP_ATOMIC | __GFP_NOTRACK);

    if (!ptr || ((unsigned long)ptr & ~PAGE_MASK)) {
        panic("set_pte_phys: cannot allocate page data after bootmem\n");
    }

    pr_debug("spp_getpage %p\n", ptr);

    return ptr;
}

static p4d_t *fill_p4d(pgd_t *pgd, unsigned long vaddr)
{
    if (pgd_none(*pgd)) {
        p4d_t *p4d = (p4d_t *)spp_getpage();
        pgd_populate(&init_mm, pgd, p4d);
        if (p4d != p4d_offset(pgd, 0))
            printk(KERN_ERR "PAGETABLE BUG #00! %p <-> %p\n",
                   p4d, p4d_offset(pgd, 0));
    }
    return p4d_offset(pgd, vaddr);
}

static pud_t *fill_pud(p4d_t *p4d, unsigned long vaddr)
{
    if (p4d_none(*p4d)) {
        pud_t *pud = (pud_t *)spp_getpage();
        p4d_populate(&init_mm, p4d, pud);
        if (pud != pud_offset(p4d, 0))
            printk(KERN_ERR "PAGETABLE BUG #01! %p <-> %p\n",
                   pud, pud_offset(p4d, 0));
    }
    return pud_offset(p4d, vaddr);
}

static pmd_t *fill_pmd(pud_t *pud, unsigned long vaddr)
{
    if (pud_none(*pud)) {
        pmd_t *pmd = (pmd_t *) spp_getpage();
        pud_populate(&init_mm, pud, pmd);
        if (pmd != pmd_offset(pud, 0))
            printk(KERN_ERR "PAGETABLE BUG #02! %p <-> %p\n",
                   pmd, pmd_offset(pud, 0));
    }
    return pmd_offset(pud, vaddr);
}

static pte_t *fill_pte(pmd_t *pmd, unsigned long vaddr)
{
    if (pmd_none(*pmd)) {
        pte_t *pte = (pte_t *) spp_getpage();
        pmd_populate_kernel(&init_mm, pmd, pte);
        if (pte != pte_offset_kernel(pmd, 0))
            printk(KERN_ERR "PAGETABLE BUG #03!\n");
    }
    return pte_offset_kernel(pmd, vaddr);
}

/*
inline int get_bdev(unsigned long pgidx) {
    int i;
    for(i=0; i<TIER_BDEV_HIGH; i++) {
        if(map_valid[i] && pgidx < map_page[i])
            return i;
    }
    return -EINVAL;
}
*/

inline unsigned long virt_to_block(unsigned long vaddr) {
	struct super_block *sb = vsbi->sb;
	struct nova_super_block *ps = nova_get_super(sb);
    if ( vaddr > vpmem_start ) return virt_to_blockoff(vaddr);
    else return ( vaddr - (unsigned long)ps ) >> PAGE_SHIFT;
}

inline unsigned long block_to_virt(unsigned long block) {
    return vpmem_start - (vsbi->num_blocks << PAGE_SHIFT) + block;
}

// Virtual address to global block offset
inline unsigned long virt_to_blockoff(unsigned long vaddr) {
    // return (vaddr-vpmem_start + vsbi->initsize) >> PAGE_SHIFT;
    return (vaddr-vpmem_start + (vsbi->num_blocks << PAGE_SHIFT)) >> PAGE_SHIFT;
}

// Global block offset to virtual address
inline unsigned long blockoff_to_virt(unsigned long blockoff) {
    return vpmem_start - (vsbi->num_blocks << PAGE_SHIFT) + ( blockoff << PAGE_SHIFT);
}

inline int get_entry_tier(struct nova_file_write_entry *entry) {
	return get_tier(vsbi, entry->block >> PAGE_SHIFT);
}

typedef struct vpte_t vpte_t;
struct vpte_t {
    struct vpte_t *next;
    struct vpte_t *prev;
    struct page *page;
    pte_t pte;

    unsigned long vaddr;

    unsigned long blockoff;
    struct rw_semaphore rwsem;

    // int bdev_index;
    // unsigned long block_offset;
    // unsigned long block;
};

pte_t *pte_lookup(unsigned long address);

void flush_tlb_all(void)
{
    __flush_tlb_all();
}

struct pagetable_t {
    int size;
    vpte_t* head;
    vpte_t* tail;
    unsigned long byte;
};
struct pagetable_t *pagetable;

static void do_flush_page(void *vaddr)
{
    __flush_tlb_one((u64)vaddr);
}

void flush_page(vpte_t *p) {
    int ret = 0;
    if(p == NULL) {
        return;
    }
    if(p->next) p->next->prev = NULL;
    if(p == pagetable->tail)
        pagetable->tail = NULL;
    pagetable->head = p->next;
    // TODO: What if kernel flushes the page?
    pagetable->size--;

    // unlock_page(p->page);
    if(pte_dirty(p->pte)) { 
        ret = nova_bdev_write_blockoff(vsbi, p->blockoff, 1, p->page, BIO_SYNC);
        if(ret) {
            printk("vpmem: error: could not write to bdev (%d)\n", ret);
        } else {
            bdev_write++;
        }
    }
    pte_clear(&init_mm, p->vaddr, &p->pte);
    on_each_cpu(do_flush_page, (void*)p->vaddr, 1);
    p->page = 0;

}

void invalidate_page(vpte_t *p) {
    if(p == NULL) {
        return;
    }
    if(p->next) p->next->prev = NULL;
    if(p == pagetable->tail)
        pagetable->tail = NULL;
    pagetable->head = p->next;
    // TODO: What if kernel flushes the page?
    pagetable->size--;

    // unlock_page(p->page);
    
    pte_clear(&init_mm, p->vaddr, &p->pte);
    on_each_cpu(do_flush_page, (void*)p->vaddr, 1);
    p->page = 0;

}

void vpmem_pagecache_init(void) {        
    pagetable->head = NULL;
    pagetable->tail = NULL;
    pagetable->byte = sizeof(struct pagetable_t);
    pagetable->size = 0;
}

void vpmem_pagecache_cleanup(void) {
    unsigned long m=0;
    vpte_t *curr, *p;
    if(!pagetable) return;
    curr = pagetable->head;
    m = pagetable->size;
    printk("vpmem: pagetable->size = %lu\n", m);
    while(curr) {
        p = curr;
        curr = curr->next;
        flush_page(p);
    }
}

#if USE_PMEM_CACHE == 1
static void *pmalloc(unsigned long size) {
    void *ret=0;
    if(unlikely(pagetable->byte + size > SPM_META_SIZE))
        pagetable->byte = sizeof(struct pagetable_t);
    ret = (void *)(pagetable->byte + (unsigned long) pagetable);
    pagetable->byte += size;
    return ret;
}

static unsigned long pgidx=0;
static struct page *palloc_page(void) {
    struct page *page;
    unsigned long addr;
    pgidx++;
    addr = pmem.phys_addr+pmem.size-(pgidx<<PAGE_SHIFT);
    page = pfn_to_page(addr >> PAGE_SHIFT);
    if(pgidx == MAX_PAGES) pgidx=0;
    return page;
}
#endif

vpte_t *newpage(unsigned long vaddr) {
    vpte_t *p = NULL;
    
    if(pagetable->size >= MAX_PAGES)
        flush_page(pagetable->head);

#if USE_PMEM_CACHE == 1
    p = (vpte_t*)pmalloc(sizeof(vpte_t));
#else
    p = (vpte_t*)kmalloc(sizeof(vpte_t), GFP_KERNEL);
#endif

    p->next = p->prev=0;

#if USE_PMEM_CACHE == 1
    p->page = palloc_page();
#else
    p->page = alloc_page(GFP_KERNEL|__GFP_ZERO);
#endif

    // lock_page(p->page);
    
    if(pagetable->head==NULL) pagetable->head=p;
    if(pagetable->tail) {
        pagetable->tail->next=p;
        p->prev=pagetable->tail;
    }
    pagetable->tail=p;
    pagetable->size++;

    p->blockoff = virt_to_blockoff(vaddr);
    p->vaddr = vaddr;
    init_rwsem(&p->rwsem);
    return p;
}

pte_t *pte_lookup(unsigned long address)
{
        pte_t *pte;
        unsigned int level;

        pte = lookup_address(address, &level);
        if (!pte) return NULL;

        return pte;
}

struct vpte_t *create_page(unsigned long vaddr) {
    int ret = 0;
    vpte_t *p=0;
    
    p = newpage(vaddr);
    
    // nova_info("vaddr:%p,blockoff:%lu page:%p\n", (void *)vaddr, p->blockoff, p->page);

    ret = nova_bdev_read_blockoff(vsbi, p->blockoff, 1, p->page, BIO_SYNC);

    p->pte = pte_mkclean(mk_pte(p->page, PAGE_KERNEL));
    if(ret) {
        printk("vpmem: error: could not read from bdev (%d)\n", ret);
    } else {
        bdev_read++;
    }

    return p;
}

static DEFINE_SPINLOCK(pgt_lock);
void insert_tlb(struct vpte_t *page) {
    unsigned long vaddr = page->vaddr;
    unsigned long flags;
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    
	spin_lock_irqsave(&pgt_lock, flags);
    pgd = (pgd_t *)__va(read_cr3_pa()) + pgd_index(vaddr);
    p4d = fill_p4d(pgd, vaddr);
    pud = fill_pud(p4d, vaddr);
    pmd = fill_pmd(pud, vaddr);
    pte = fill_pte(pmd, vaddr);
    *pte = pte_mkclean(*pte);
    set_pte(pte, page->pte);
    __flush_tlb_one(vaddr);
	spin_unlock_irqrestore(&pgt_lock, flags);
}

int vpmem_cache_pages(unsigned long vaddr, unsigned long count)
{
    unsigned long i;
    struct vpte_t *page = NULL;
    for(i=0; i<count; i++) {
        page = create_page(vaddr & PAGE_MASK);
        insert_tlb(page);
    }
    return 0;
}

int vpmem_flush_pages(unsigned long vaddr, unsigned long count)
{
    unsigned long m=0;
    vpte_t *curr, *p;
    unsigned long end = 0; 
    if(!pagetable) return -EINVAL;
    vaddr &= PAGE_MASK;
    end = vaddr + (count << PAGE_SHIFT);
    m = count;
    curr = pagetable->head;
    while(curr && m > 0) {
        p = curr;
        curr = curr->next;
        if(p->vaddr >= vaddr && p->vaddr < end) {
            flush_page(p);
            m--;
        }
    }
    return 0;
}

int vpmem_invalidate_pages(unsigned long vaddr, unsigned long count)
{
    unsigned long m=0;
    vpte_t *curr, *p;
    unsigned long end = 0; 
    if(!pagetable) return -EINVAL;
    vaddr &= PAGE_MASK;
    end = vaddr + (count << PAGE_SHIFT);
    m = count;
    curr = pagetable->head;
    while(curr && m > 0) {
        p = curr;
        curr = curr->next;
        if(p->vaddr >= vaddr && p->vaddr < end) {
            invalidate_page(p);
            m--;
        }
    }
    return 0;
}

int vpmem_range_rwsem_set(unsigned long vaddr, unsigned long count, bool down)
{
    unsigned long m=0;
    vpte_t *curr, *p;
    unsigned long end = 0; 
    if(!pagetable) return -EINVAL;
    vaddr &= PAGE_MASK;
    end = vaddr + (count << PAGE_SHIFT);
    m = count;
    curr = pagetable->head;
    while(curr && m > 0) {
        p = curr;
        curr = curr->next;
        if(p->vaddr >= vaddr && p->vaddr < end) {
            if (down) down_read(&p->rwsem);
            else if(rwsem_is_locked(&p->rwsem)) up_read(&p->rwsem);
            m--;
        }
    }
    return 0;
}

bool vpmem_is_range_rwsem_locked(unsigned long vaddr, unsigned long count)
{
    unsigned long m=0;
    vpte_t *curr, *p;
    unsigned long end = 0; 
    if(!pagetable) return -EINVAL;
    vaddr &= PAGE_MASK;
    end = vaddr + (count << PAGE_SHIFT);
    m = count;
    curr = pagetable->head;
    while(curr && m > 0) {
        p = curr;
        curr = curr->next;
        if(p->vaddr >= vaddr && p->vaddr < end) {
            if(rwsem_is_locked(&p->rwsem)) return true;
            m--;
        }
    }
    return false;
}

unsigned long vpmem_cached(unsigned long block, unsigned long count)
{
    unsigned long m=0;
    vpte_t *curr, *p;
    if(!pagetable) return -EINVAL;
    m = count;
    curr = pagetable->head;
    while(curr && m > 0) {
        p = curr;
        curr = curr->next;
        if(p->vaddr >= block && p->vaddr < block+count) {
            m--;
        }
    }
    return count-m;
}

int vpmem_cache_pages_safe(unsigned long vaddr, unsigned long count) {
    unsigned long num = vpmem_cached(virt_to_blockoff(vaddr), count);
    if (num == 0) return vpmem_cache_pages(vaddr, count);
    else {
        vpmem_flush_pages(vaddr, count);
        return vpmem_cache_pages(vaddr, count);
    }
}

bool vpmem_do_page_fault(struct pt_regs *regs, unsigned long error_code, unsigned long vaddr)
{
    struct vpte_t *page = NULL;
    if (vaddr >= TASK_SIZE_MAX) {
        /* Make sure we are in reserved area: */
        if (vaddr >= vpmem_start && vaddr < vpmem_end) {
            faults++;
            page = create_page(vaddr & PAGE_MASK);
            insert_tlb(page);
            return true;
        } else {
            return false;
        }
    }
    return false;
}

int vpmem_init(void)
{
    vpmem_reset();
    return 0;

} 

int vpmem_setup(struct nova_sb_info *sbi, unsigned long offset) 
{
    int i;
    unsigned long size=0;

    vsbi = sbi;
    
    flush_tlb_all();
    vpmem_start = (VPMEM_START + (offset << 30));

    sbi->vpmem = (char *)vpmem_start;
    
    install_vpmem_fault(vpmem_do_page_fault);

    for(i=0; i<TIER_BDEV_HIGH; i++) {
        size += sbi->bdev_list[i].capacity_page;
        map_page[i] = size;
        map_valid[i] = true;
    }
    
    sbi->vpmem_num_blocks = size;
    
    // print_all_bdev(sbi);

    printk(KERN_INFO "vpmem: vpmem starts at %016lx (%lu GB)\n", 
        vpmem_start, size >> 18);
        
    vpmem_end = vpmem_start + (size << 12);

    pmem.phys_addr = sbi->phys_addr;
    pmem.virt_addr = sbi->virt_addr;
    pmem.size = sbi->initsize;

    if (size > 0) {
        pagetable = kmalloc(sizeof(struct pagetable_t), GFP_KERNEL);
        // sbi->virt_addr = vpmem_start;
        // sbi->initsize = size;
        // sbi->replica_reserved_inodes_addr = vpmem_start + size -
        //      (sbi->tail_reserved_blocks << PAGE_SHIFT);
        // sbi->replica_sb_addr = vpmem_start + size - PAGE_SIZE;
        vpmem_pagecache_init();
    }

    printk(KERN_INFO "vpmem: vpmem_setup finished (size = %lu MB)\n", size >> 8);

    return 0;
}

void vpmem_cleanup(void)
{
    vpmem_pagecache_cleanup();

    install_vpmem_fault(0);
    flush_tlb_all();
    printk(KERN_INFO "vpmem: faults = %ld reads = %ld writes = %ld\n", faults, bdev_read, bdev_write);
}

void vpmem_reset(void)
{
    int i;
    vpmem_end = 0;
    for(i=0; i<TIER_BDEV_HIGH; i++) {
        map_valid[i] = false;
        map_page[i] = 0;
    }
}

