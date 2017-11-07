#include "tiering.h"
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
#include <../mm/mm_internal.h>
#include "bdev.h"

#define PAGECACHE_SIZE

#ifdef QT_WA
#define KERN_INFO
#endif

char *vpmem=0;
void *pgcache=0;
int pgidx=0;
bool full=false;
unsigned long map_page[MAX_TIERS]={0};
bool map_valid[MAX_TIERS]={0};

/*
 * Page fault error code bits:
 *
 *   bit 0 ==	 0: no page found      1: protection fault
 *   bit 1 ==	 0: read access	       1: write access
 *   bit 2 ==	 0: kernel-mode access 1: user-mode access
 *   bit 3 ==                          1: use of reserved bit detected
 *   bit 4 ==                          1: fault was an instruction fetch
 *   bit 5 ==                          1: protection keys block access
 */

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

inline unsigned long virt_to_phys_page(unsigned long vaddr) {
    return (vaddr-(unsigned long)vpmem) >> 30;
}

typedef struct page_t page_t;
struct page_t {
    int idx;
    struct page_t *next;
    struct page_t *prev;
    struct page *page;
    unsigned long pgidx;
};

static page_t* head=0;
static page_t* tail=0;

page_t *newpage(unsigned long vaddr) {
    page_t *p = (page_t*)kmalloc(sizeof(page_t), GFP_KERNEL|GFP_ATOMIC);
    p->next=p->prev=0;
    p->idx=pgidx=(pgidx+1)%16;
    p->page=alloc_page(GFP_KERNEL|__GFP_ZERO);
    if(head==0) head=p;
    if(tail) {
        tail->next=p;
        p->prev=tail;
    }
    tail=p;
    p->pgidx = virt_to_phys_page(vaddr);
    return p;
}

void rmpage(page_t *p) {
    if(p->prev) p->prev->next = p->next;
    if(p->next) p->next->prev = p->prev;
    if(p==tail) tail=p->prev;
    if(p==head) head=p->next;
    __free_page(p->page);
    kfree(p);
}

inline pte_t *get_pte(unsigned long address) {
    return pte_offset_kernel(
        pmd_offset(
            pud_offset(
                p4d_offset(
                    (pgd_t *)__va(read_cr3_pa()) + pgd_index(address),
                    address),
                address),
            address),
        address);
}

inline int get_bdev(unsigned long pgidx) {
    int i,r=-1;
    for(i=0; i<bdev_count; i++) {
        if(map_valid[i] && pgidx < map_page[i]) 
        return i;
    }
    return r;
}

struct page *get_new_page(unsigned long vaddr) {
    page_t *p=newpage(vaddr);
    if(pgidx==15) full=true;
    if(full) {
        unsigned long address = (unsigned long)page_address(head->page);
        pte_t pte = *get_pte(address);
        if(pte_dirty(pte)) {
            int bdev_idx = get_bdev(head->pgidx);
            if(bdev_idx == -1) {
                // TODO: physical pmem
            } else {
                nova_bdev_write_block(bdev_list[bdev_idx].bdev_raw, head->pgidx, 1, head->page, BIO_SYNC);
            }
        }
        rmpage(head);
    }
    //printk(KERN_INFO "nova: page %d is created\n", p->idx);
    return p->page;
}

bool nova_do_page_fault(struct pt_regs *regs, unsigned long error_code, unsigned long vaddr)
{
    if (vaddr >= TASK_SIZE_MAX) {
        pgd_t *pgd;
        p4d_t *p4d;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;
        struct page *page;
        unsigned long address;// = (unsigned long)pgcache + ((unsigned long)(pgidx=(pgidx+1)%16) << PAGE_SHIFT);
        unsigned long phys_page = virt_to_phys_page(vaddr);
	int bdev_idx = get_bdev(phys_page);

        /* Make sure we are in reserved area: */
        if (!(vaddr >= (unsigned long)vpmem && vaddr < VMALLOC_END))
            return false;

        printk(KERN_INFO "nova: a page fault happened at address %016lx\n", vaddr);

        page = get_new_page(vaddr);
        address = (unsigned long)page_address(page);

        if(bdev_idx == -1) {
            // TODO: physical pmem 
        } else {
            printk(KERN_INFO "nova: reading page %ld from tier %d (%s)\n", phys_page, bdev_idx, bdev_list[bdev_idx].bdev_path);
            nova_bdev_read_block(bdev_list[bdev_idx].bdev_raw, phys_page, 1, page, BIO_SYNC);
        }
        pgd = (pgd_t *)__va(read_cr3_pa()) + pgd_index(vaddr);
        p4d = fill_p4d(pgd, vaddr);
        pud = fill_pud(p4d, vaddr);
        pmd = fill_pmd(pud, vaddr);
        pte = fill_pte(pmd, vaddr);
        pte_mkclean(*pte);

        set_pte(pte, *get_pte(address));

        __flush_tlb_one(vaddr);
        return true;
    }

    return false;
}

int nova_init_tiering(unsigned long offset)
{
    __flush_tlb_all();
    vpmem = (char*)(VMALLOC_START + offset);
    install_custom_page_fault_handler(nova_do_page_fault);

    return 0;
} 

int nova_setup_tiering(struct nova_sb_info *sbi) 
{
    int i;
    unsigned long size=0;
    for(i=0; i<bdev_count; i++) {
        nova_get_bdev_info(bdev_paths[i], i);
        size += bdev_list[i].capacity_page;
        map_page[i] = size;
        map_valid[i] = true;
        print_a_bdev(&bdev_list[i]);
//        bdev_test(&bdev_list[i]);
    }

    printk(KERN_INFO "nova: vpmem starts at %016lx (%lu GB)\n", 
        (unsigned long)vpmem, 
        size >> 18);
    nova_total_size = (size <<= 12);

    if (size > 0) {
        sbi->virt_addr = vpmem;
        sbi->initsize = size;
        sbi->replica_reserved_inodes_addr = vpmem + size -
             (sbi->tail_reserved_blocks << PAGE_SHIFT);
        sbi->replica_sb_addr = vpmem + size - PAGE_SIZE;
    }

    printk(KERN_INFO "nova: nova_setup_tiering finished (size = %lu B)\n", size);

    return 0;
}

void nova_cleanup_tiering(void)
{
    install_custom_page_fault_handler(0);
    nova_persist_page_cache();
}

void nova_reset_tiering(void)
{
    int i;
    bdev_count = 0;
    nova_total_size = 0;
    for(i=0; i<MAX_TIERS; i++) {
        map_valid[i] = false;
        map_page[i] = 0;
    }
}

void nova_persist_page_cache(void) {
    while(head) {
        unsigned long address = (unsigned long)page_address(head->page);
        pte_t pte = *get_pte(address);
        if(pte_dirty(pte)) {
            int bdev_idx = get_bdev(head->pgidx);
            if(bdev_idx == -1) {
                // TODO: physical pmem
            } else {
                nova_bdev_write_block(bdev_list[bdev_idx].bdev_raw, head->pgidx, 1, head->page, BIO_SYNC);
            }
        }
        rmpage(head);
    }
}
