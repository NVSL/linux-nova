#include "vpmem.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <asm/uaccess.h>	/* for put_user */
#include <asm/traps.h>	    /* for put_user */
#include <linux/vmalloc.h>
#include <linux/slab.h>     /* kmalloc */
#include <asm/current.h>    /* current */
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
#include <linux/rbtree.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include "bdev.h"
#include "nova.h"

#ifdef QT_WA
#define KERN_INFO
#endif

#define VPMEM_SIZE_TB     _AC(16, UL)
#define VPMEM_START       (VMALLOC_START + _AC(16UL << 40, UL))
#define VPMEM_END         (VPMEM_START + _AC((VPMEM_SIZE_TB << 40) - 1, UL))

#define MAX_PAGES           32768  // 128MB  32768*4
#define SPM_META_SIZE_MB    _AC(1, UL)
#define SPM_META_SIZE       _AC(SPM_META_SIZE_MB << 20, UL)
#define SPM_PGCACHE_SIZE_MB _AC(50, UL)
#define SPM_PGCACHE_SIZE    _AC(SPM_PGCACHE_SIZE_MB << 20, UL)

#define TRUE                1
#define FALSE               0
#define RB_TREE_PAGECACHE   1
#define RING_BUF_PAGECACHE  2

#define PAGECACHE_DSTRUCT   RB_TREE_PAGECACHE
// #define USE_PMEM_CACHE   
#define ENABLE_WRITEBACK 
#define ENABLE_WRITE        
// #define ENABLE_NETLINK   
#define USE_LOCK           
#define PAGECACHE_PREALLOC

#ifdef ENABLE_NETLINK
#   define nl_send(...)  vpmem_nl_send_msg(__VA_ARGS__)
#else
#   define nl_send(...) do { } while(0)
#endif

// #define current_mm ((current->mm)?current->mm:&init_mm)
#define current_mm (&init_mm)

#define check_pointer(s, p) \
    if((u64)p < TASK_SIZE_MAX && p != 0) { \
        printk("ERROR: in %s  " #p " = %p\n", s, p); \
    }

unsigned long vpmem_start=0;
unsigned long vpmem_end=0;
// unsigned long map_page[MAX_TIERS]={0};
// bool map_valid[MAX_TIERS]={0};
unsigned long map_page[BDEV_COUNT_MAX]={0};
bool map_valid[BDEV_COUNT_MAX]={0};

unsigned long faults=0;
unsigned long bdev_read=0;
unsigned long bdev_write=0;
unsigned long pte_not_present=0;
unsigned long pte_not_found=0;
unsigned long pgcache_full=0;
unsigned long lru_refers=0;
unsigned long evicts=0;
unsigned long dif_mm=0;
unsigned long dif_mm2=0;
unsigned long dif_mm3=0;
unsigned long dif_mm4=0;
unsigned long already_cached=0;
unsigned long leaked=0;

enum x86_pf_error_code {
    PF_PROT  = 1 << 0,
    PF_WRITE = 1 << 1,
    PF_USER  = 1 << 2,
    PF_RSVD  = 1 << 3,
    PF_INSTR = 1 << 4,
    PF_PK    = 1 << 5,
};

struct pmem_t {
    void *virt_addr;
    phys_addr_t	phys_addr;
    unsigned long size;
} pmem;

struct nova_sb_info *vsbi;

#define NETLINK_USER 31

#ifdef ENABLE_NETLINK
struct sock *nl_sk = NULL;
int pid=0;

void vpmem_nl_recv_msg(struct sk_buff *skb) {
    struct nlmsghdr *nlh = (struct nlmsghdr *)skb->data;
    printk(KERN_INFO "Netlink received msg payload: '%s'\n", (char *)nlmsg_data(nlh));
    pid = nlh->nlmsg_pid; /*pid of sending process */
}

void vpmem_nl_send_msg(const char *fmt, ...) {
    va_list args;
    char msg[512];
    struct nlmsghdr *nlh;
    int msg_size;
    struct sk_buff *skb_out;

    if(pid==0) return;

    va_start(args, fmt);
    vsprintf(msg, fmt, args);
    va_end(args);

    msg_size = strlen(msg);
    skb_out = nlmsg_new(msg_size, 0);
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    strncpy(nlmsg_data(nlh), msg, msg_size);

    if (nlmsg_unicast(nl_sk, skb_out, pid) < 0) {
        // pid = 0;
        // printk(KERN_INFO "Error while sending bak to user\n");
    }
}

int vpmem_nl_init(void) {
    //This is for 3.6 kernels and above.
    struct netlink_kernel_cfg cfg = {
        .input = vpmem_nl_recv_msg,
    };

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk)
    {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }

    return 0;
}

void vmpem_nl_cleanup(void) {
    printk(KERN_INFO "exiting hello module\n");
    netlink_kernel_release(nl_sk);
}
#endif

/*********** Page Cache ***********/
struct pgcache_node {
#if PAGECACHE_DSTRUCT == RB_TREE_PAGECACHE
    struct rb_node rb_node;
    struct pgcache_node *lru_prev, *lru_next; // lru list
    struct pgcache_node *evict_next;    // eviction list
    struct pgcache_node *wb_next;    // write-back list
    bool pinned;
    struct mutex lock;
    bool writing;
    bool evicting;
#endif
    struct mm_struct *mm;
    unsigned long address;
    // unsigned long pfn;
    struct page *page;
};

pte_t *pte_lookup(pgd_t *pgd, unsigned long address);
inline bool writeback(void);
inline void pop_from_evict_list(void);
inline void push_to_evict_list(struct pgcache_node *pg);
inline void push_to_wb_list(struct pgcache_node *pg);
inline void push_victim_to_wb_list(unsigned int i);
bool vpmem_load_block(unsigned long address, struct page *p);

static struct rb_root pgcache = RB_ROOT;
static struct pgcache_node *lru_head=0, *lru_tail=0;
static struct pgcache_node *wb_head=0, *wb_tail=0;
static struct pgcache_node *evict_head=0, *evict_tail=0;
static unsigned int pgcache_size=0;
static unsigned int wb_list_size=0;
static unsigned int evict_list_size=0;
static DEFINE_MUTEX(lru_lock);
static DEFINE_MUTEX(wb_lock);
static DEFINE_MUTEX(evict_lock);
static DEFINE_MUTEX(pgcache_lock);
static DEFINE_MUTEX(bdev_lock);

// #ifdef PAGECACHE_PREALLOC
// struct free_nodes {
//     struct pgcache_node node;
//     struct list_head list;
// };
// #endif

#ifdef USE_LOCK
#   define LOCK(x) mutex_lock(&x)
#   define UNLOCK(x) mutex_unlock(&x)
#else
#   define LOCK(x) do {} while (0)
#   define UNLOCK(x) do {} while (0)
#endif

#define lru_victim ((lru_head)?lru_head->address:0)

struct pgcache_node *__pgcache_lookup(unsigned long address)
{
    struct rb_node *n = pgcache.rb_node;
    struct pgcache_node *ans;

    while (n)
    {
        ans = rb_entry(n, struct pgcache_node, rb_node);

        if (address < ans->address)
            n = n->rb_left;
        else if (address > ans->address)
            n = n->rb_right;
        else
            return ans;
    }
    return NULL;
}

struct pgcache_node *pgcache_lookup(unsigned long address)
{
    struct pgcache_node *r;
    LOCK(pgcache_lock);
    r = __pgcache_lookup(address);
    UNLOCK(pgcache_lock);
    return r;
}

void pgcache_lru_refer(struct pgcache_node *target)
{
    lru_refers++;
    LOCK(lru_lock);
    if(target == lru_tail) {
        UNLOCK(lru_lock);
        return;
    }
    if(target == lru_head) lru_head = target->lru_next;
    if(target->lru_prev) target->lru_prev->lru_next = target->lru_next;
    if(target->lru_next) target->lru_next->lru_prev = target->lru_prev;
    target->lru_prev = lru_tail;
    target->lru_next = NULL;
    if(lru_tail) lru_tail->lru_next = target;
    if(!lru_head) lru_head = target;
    lru_tail = target;
    UNLOCK(lru_lock);
}

struct pgcache_node *__pgcache_insert(unsigned long address, struct mm_struct *mm, bool *new)
{
    struct pgcache_node *p, *newp;
    struct rb_node **link = &pgcache.rb_node, *parent=NULL;

    if(new) *new=false;

    /* Go to the bottom of the tree */
    while (*link)
    {
        parent = *link;
        p = rb_entry(parent, struct pgcache_node, rb_node);

        if (p->address > address)
            link = &(*link)->rb_left;
        else if(p->address < address)
            link = &(*link)->rb_right;
        else {
            LOCK(p->lock);
            already_cached++;
            pgcache_lru_refer(p);
            p->mm = mm;
            p->writing = false;
            p->evicting = false;
            UNLOCK(p->lock);
            return p;
        }
    }

    newp = (struct pgcache_node *)kmalloc(sizeof(struct pgcache_node), GFP_KERNEL | GFP_ATOMIC);
    newp->page = alloc_page(GFP_KERNEL | GFP_ATOMIC);
    if(!newp->page) {
        printk("vpmem: NO PAGE LEFT!\n");
    }
    // newp->pfn = page_to_pfn(newp->page);
    newp->address = address;
    newp->mm = mm;
    newp->evict_next = 0;
    newp->wb_next = 0;
    newp->pinned = false;
    newp->writing = false;
    newp->evicting = false;
    newp->lru_next = 0;
    lock_page(newp->page);
    mutex_init(&newp->lock);
    LOCK(lru_lock);
    newp->lru_prev = lru_tail;
    if(lru_tail) lru_tail->lru_next = newp;
    if(!lru_head) lru_head = newp;
    lru_tail = newp;
    UNLOCK(lru_lock);
     
    if(new) *new=true;
    pgcache_size++;
    /* Put the new node there */
    rb_link_node(&newp->rb_node, parent, link);
    rb_insert_color(&newp->rb_node, &pgcache);

    return newp;
}

struct pgcache_node *pgcache_insert(unsigned long address, struct mm_struct *mm, bool *new)
{
    struct pgcache_node *r;
    LOCK(pgcache_lock);
    r = __pgcache_insert(address, mm, new);
    UNLOCK(pgcache_lock);
    return r;
}

void __pgcache_erase(struct pgcache_node *victim)
{
    rb_erase(&victim->rb_node, &pgcache);
    if(pgcache_size==0) printk("PROBLEM\n");
    pgcache_size--;
}

void pgcache_remove(struct pgcache_node *victim)
{
    if(victim) {
        LOCK(pgcache_lock);
        LOCK(lru_lock);
        if(victim == lru_head) lru_head = victim->lru_next;
        if(victim == lru_tail) lru_tail = victim->lru_prev;
        if(victim->lru_prev) victim->lru_prev->lru_next = victim->lru_next;
        if(victim->lru_next) victim->lru_next->lru_prev = victim->lru_prev;
        victim->lru_next = victim->lru_prev = NULL;
        UNLOCK(lru_lock);
        __pgcache_erase(victim);
        UNLOCK(pgcache_lock);
    }
}

void pgcache_flush_all(void)
{
#ifdef ENABLE_WRITEBACK
    pop_from_evict_list();
    push_victim_to_wb_list(pgcache_size);
    LOCK(pgcache_lock);
    while(writeback()) ;
    UNLOCK(pgcache_lock);
    pop_from_evict_list();
#endif
}

void *vpmem_lru_refer(unsigned long address)
{
    // if(bdev_count > 0) {
    if(TIER_BDEV_HIGH > 0) {
        struct pgcache_node *target;
        LOCK(pgcache_lock);
        target = __pgcache_lookup(address & PAGE_MASK);
        if(target) pgcache_lru_refer(target);
        UNLOCK(pgcache_lock);
    }
    return (void*) address;
}

inline void *spp_getpage(void)
{
    void *ptr;

    ptr = (void *) get_zeroed_page(GFP_ATOMIC | __GFP_NOTRACK);

    if (!ptr || ((unsigned long)ptr & ~PAGE_MASK)) {
        panic("set_pte_phys: cannot allocate page data after bootmem\n");
    }

    pr_debug("spp_getpage %p\n", ptr);

    return ptr;
}

inline p4d_t *fill_p4d(struct mm_struct *mm, pgd_t *pgd, unsigned long address)
{
    if (pgd_none(*pgd)) {
        p4d_t *p4d = (p4d_t *)spp_getpage();
        pgd_populate(mm, pgd, p4d);
        if (p4d != p4d_offset(pgd, 0))
            printk(KERN_ERR "PAGETABLE BUG #00! %p <-> %p\n",
                   p4d, p4d_offset(pgd, 0));
    }
    return p4d_offset(pgd, address);
}

inline pud_t *fill_pud(struct mm_struct *mm, p4d_t *p4d, unsigned long address)
{
    if (p4d_none(*p4d)) {
        pud_t *pud = (pud_t *)spp_getpage();
        p4d_populate(mm, p4d, pud);
        if (pud != pud_offset(p4d, 0))
            printk(KERN_ERR "PAGETABLE BUG #01! %p <-> %p\n",
                   pud, pud_offset(p4d, 0));
    }
    return pud_offset(p4d, address);
}

inline pmd_t *fill_pmd(struct mm_struct *mm, pud_t *pud, unsigned long address)
{
    if (pud_none(*pud)) {
        pmd_t *pmd = (pmd_t *) spp_getpage();
        pud_populate(mm, pud, pmd);
        if (pmd != pmd_offset(pud, 0))
            printk(KERN_ERR "PAGETABLE BUG #02! %p <-> %p\n",
                   pmd, pmd_offset(pud, 0));
    }
    return pmd_offset(pud, address);
}

inline pte_t *fill_pte(struct mm_struct *mm, pmd_t *pmd, unsigned long address)
{
    if (pmd_none(*pmd)) {
        pte_t *pte = (pte_t *) spp_getpage();
        pmd_populate_kernel(mm, pmd, pte);
        if (pte != pte_offset_kernel(pmd, 0))
            printk(KERN_ERR "PAGETABLE BUG #03!\n");
    }
    return pte_offset_kernel(pmd, address);
}

inline int get_bdev(unsigned long pgidx) {
    int i;
    // for(i=0; i<bdev_count; i++) {
    for(i=0; i<TIER_BDEV_HIGH; i++) {
        if(map_valid[i] && pgidx < map_page[i])
            return i;
    }
    return -EINVAL;
}

inline unsigned long virt_to_phys_block(unsigned long address) {
    return (address-vpmem_start) >> PAGE_SHIFT;
}

pte_t *pte_lookup(pgd_t *, unsigned long);

void flush_tlb_all(void)
{
    __flush_tlb_all();
}

/******************* TLB Flusher *******************/
struct task_struct *wb_thread=0;

inline bool writeback(void)
{
    struct page *p=0;
    struct pgcache_node *pg;
    unsigned long address=0;
    bool ret=false;
    LOCK(wb_lock);
    pg=wb_head;
    if(pg) {
        LOCK(pg->lock);
        wb_head=pg->wb_next;
        pg->wb_next=NULL;
        wb_list_size--;
        if(!pg->writing) {
            UNLOCK(pg->lock);
            UNLOCK(wb_lock);
            return true;
        }
        p = pg->page; // pfn_to_page(pg->pfn);
        address = pg->address;
        ret = true;
    }
    UNLOCK(wb_lock);

    if(p) {
        // if(PageDirty(p)) {
            unsigned long block_offset = virt_to_phys_block(address);
            int bdev_idx = get_bdev(block_offset), i;
            for(i=bdev_idx-1; i>-1; i--) {
                // block_offset -= bdev_list[i].capacity_page;
                block_offset -= vsbi->bdev_list[i].capacity_page;
            }

            nl_send("wb %20lu %16lu %2d", address, block_offset, bdev_idx);
            LOCK(bdev_lock);
            // if((i=nova_bdev_write_block(bdev_list[bdev_idx].bdev_raw, block_offset, 1, p, BIO_SYNC))) {
            if((i=nova_bdev_write_block(vsbi, vsbi->bdev_list[bdev_idx].bdev_raw, block_offset, 1, p, BIO_SYNC))) {
                printk("vpmem:\033[1;32m could not write to bdev (%d) %lu\033[0m\n", i, ++dif_mm2);
            } else {
                bdev_write++;
            }
            UNLOCK(bdev_lock);
        // }
    } 

    if(pg) {
        push_to_evict_list(pg);
        UNLOCK(pg->lock);
    }
    return ret;
}

int wb_thread_worker(void *arg)
{
    schedule();
    printk(KERN_INFO "vpmem: Start Write-Back thread.\n");
    while(1) {
        if(kthread_should_stop()) {
            break;
        }
        schedule();
        if(pgcache_size >= MAX_PAGES) {
            // printk("vpmem: REACHED THE MAX SIZE. Evicting %u pages\n", pgcache_size-MAX_PAGES+32);
            push_victim_to_wb_list(pgcache_size-MAX_PAGES+32);
        }
        while(writeback()) schedule();
        pop_from_evict_list();
    }

    set_current_state(TASK_INTERRUPTIBLE);
    while (!kthread_should_stop())
    {
       schedule();
       set_current_state(TASK_INTERRUPTIBLE);
    }
    set_current_state(TASK_RUNNING);

    return 0;
}

void wb_thread_init(void) {
#ifdef ENABLE_WRITEBACK 
    wb_thread = kthread_run(wb_thread_worker, NULL, "Write-Back thread");
#endif
}

void wb_thread_cleanup(void) {
#ifdef ENABLE_WRITEBACK
    if(wb_thread) {
        int r=1;
        if(wb_thread) r = kthread_stop(wb_thread);
        if(!r) {
            wb_thread=0;
            printk(KERN_INFO "vpmem: Stop Write-Back thread.\n");
        }
    }
#endif
}

pte_t newpage(unsigned long address, struct mm_struct *mm, struct page **pout) {
    struct pgcache_node *p = 0;
    pte_t pte;
    bool new=false;

    p = pgcache_insert(address, mm, &new);
    pte = mk_pte(p->page, PAGE_KERNEL);
    if(new) {
        *pout = p->page;
    } else {
        *pout = 0;
    }

    return pte;
}

pte_t *pte_lookup(pgd_t *pgd, unsigned long address)
{
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;

    if(pgd==0) {
        printk("vpmem:\033[1;32m pgd is null address = %p \033[0m\n", (void*)address);
        return NULL;
    }

    if (pgd_none(*pgd)) {
        printk("vpmem:\033[1;34m pgd is none address = %p \033[0m\n", (void*)address);
        return NULL;
    }

    p4d = p4d_offset(pgd, address);
    if (p4d_none(*p4d))
        return NULL;

    if (p4d_large(*p4d) || !p4d_present(*p4d))
        return (pte_t *)p4d;

    pud = pud_offset(p4d, address);
    if (pud_none(*pud))
        return NULL;

    if (pud_large(*pud) || !pud_present(*pud))
        return (pte_t *)pud;

    pmd = pmd_offset(pud, address);
    if (pmd_none(*pmd))
        return NULL;

    if (pmd_large(*pmd) || !pmd_present(*pmd))
        return (pte_t *)pmd;

    return pte_offset_kernel(pmd, address);
}

bool insert_tlb(pte_t ptein, unsigned long address) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct mm_struct *mm = current_mm;

	smp_mb();

    spin_lock(&mm->page_table_lock);

    // pgd = __va(read_cr3_pa()) + pgd_index(address); // pgd_offset(current->mm, address);
    pgd = pgd_offset(mm, address);
    p4d = fill_p4d(mm, pgd, address); // p4d_alloc(mm, pgd, address); 
    pud = fill_pud(mm, p4d, address); // pud_alloc(mm, p4d, address); 
    pmd = fill_pmd(mm, pud, address); // pmd_alloc(mm, pud, address); 
    pte = fill_pte(mm, pmd, address);
	
    *pte = pte_mkclean(*pte);
    set_pte(pte, ptein);
    spin_unlock(&mm->page_table_lock);

    smp_mb();

    __flush_tlb_one(address);
    return true;
}

int vpmem_cache_pages(unsigned long address, unsigned long count)
{
    if(likely(count != 0)) {
        address &= PAGE_MASK;
        while(count-- > 0) {
            struct page *p=0;
            if(insert_tlb(newpage(address, current_mm, &p), address)) {
                if(p) {
                    vpmem_load_block(address, p);
                }
            } else {
                return 1;
            }
            address += PAGE_SIZE;
        }
    }
    return 0;
}

int vpmem_flush_pages(unsigned long address, unsigned long count)
{
    struct pgcache_node *pg;
    if(likely(count != 0)) {
        address &= PAGE_MASK;
        while(count-- > 0) {
            pg = pgcache_lookup(address);
            if(pg) {
                LOCK(pg->lock);
                push_to_wb_list(pg);
                UNLOCK(pg->lock);
            }
            address += PAGE_SIZE;
        }
    }
    while(writeback()) ;
    pop_from_evict_list();
    return 0;
}

int vpmem_invalidate_pages(unsigned long address, unsigned long count)
{
    struct pgcache_node *pg;
    if(likely(count != 0)) {
        address &= PAGE_MASK;
        while(count-- > 0) {
            dif_mm4++;
            pg = pgcache_lookup(address);
            if(pg) {
                LOCK(pg->lock);
                push_to_evict_list(pg);
                UNLOCK(pg->lock);
                // push_to_wb_list(pg);
            }
            address += PAGE_SIZE;
        }
    }
    // while(writeback()) ;
    pop_from_evict_list();
    return 0;
}

unsigned long vpmem_cached(unsigned long address, unsigned long count)
{
    unsigned long cnt=0;
    struct pgcache_node *pg;
    if(likely(count != 0)) {
        address &= PAGE_MASK;
        while(count-- > 0) {
            pg = pgcache_lookup(address);
            if(pg) {
                cnt++;
            }
            address += PAGE_SIZE;
        }
    }
    return cnt;
}

int vpmem_pin_pages(unsigned long address, unsigned long count)
{
    struct pgcache_node *pg=pgcache_lookup((address &= PAGE_MASK));
    unsigned long last = address + (count << PAGE_SHIFT);
    while(pg && (address < last)) {
        LOCK(pg->lock);
        pg->pinned = true;
        UNLOCK(pg->lock);
        address += PAGE_SIZE;
        pg = pgcache_lookup(address);
    }
    return 0;
}

inline unsigned long virt_to_block(unsigned long address) {
	struct super_block *sb = vsbi->sb;
	struct nova_super_block *ps = nova_get_super(sb);
    if ( address > vpmem_start ) return virt_to_blockoff(address);
    else return ( address - (unsigned long)ps ) >> PAGE_SHIFT;
}

inline unsigned long block_to_virt(unsigned long block) {
    return vpmem_start - (vsbi->num_blocks << PAGE_SHIFT) + block;
}

// Virtual address to global block offset
inline unsigned long virt_to_blockoff(unsigned long address) {
    // return (address-vpmem_start + vsbi->initsize) >> PAGE_SHIFT;
    return (address-vpmem_start + (vsbi->num_blocks << PAGE_SHIFT)) >> PAGE_SHIFT;
}

// Global block offset to virtual address
inline unsigned long blockoff_to_virt(unsigned long blockoff) {
    return vpmem_start - (vsbi->num_blocks << PAGE_SHIFT) + ( blockoff << PAGE_SHIFT);
}

inline int get_entry_tier(struct nova_file_write_entry *entry) {
	return get_tier(vsbi, entry->block >> PAGE_SHIFT);
}

struct fpage {
    struct page *p;
    unsigned long address;
};
struct fpage pgs[8];
int pgsh=0,pgst=0;

bool vpmem_load_block(unsigned long address, struct page *p)
{
    unsigned long block_offset=virt_to_phys_block(address);
    int bdev_idx=get_bdev(block_offset), i;

    if(pgsh!=pgst) {
        printk("vpmem: if(pgsh!=pgst) h=%d t=%d\n", pgsh, pgst);
    }

    for(i=bdev_idx-1; i>-1; i--) {
        // block_offset -= bdev_list[i].capacity_page;
        block_offset -= vsbi->bdev_list[i].capacity_page;
    }
    native_irq_enable();
    LOCK(bdev_lock);
    // if((i=nova_bdev_read_block(bdev_list[bdev_idx].bdev_raw, block_offset, 1, p, BIO_SYNC))) {
    if((i=nova_bdev_read_block(vsbi, vsbi->bdev_list[bdev_idx].bdev_raw, block_offset, 1, p, BIO_SYNC))) {
        UNLOCK(bdev_lock);
        printk("vpmem:\033[1;33m could not read from bdev (%d) %lu\033[0m\n", i, ++dif_mm2);
        return false;
    } else {
        UNLOCK(bdev_lock);
        bdev_read++;
        return true;
    }
}

inline void pop_from_evict_list(void)
{
    // pte_t *pte;
    struct pgcache_node *pg;
    struct page *p;
    LOCK(evict_lock);
    while((pg = evict_head)) {
        LOCK(pg->lock);
        evict_head = pg->evict_next;
        pg->evict_next = NULL;
        evict_list_size--;
        if(!pg->evicting) {
            UNLOCK(pg->lock);
            continue;
        }
        pgcache_remove(pg);
        nl_send("ev %20lu %16lu %2d", pg->address, 0, 0);

        p = pg->page;// pfn_to_page(pg->pfn); 
        if(p) unlock_page(p);
        {
            // pte_t *ptep = pte_lookup(pgd_offset(current_mm, pg->address), pg->address);
            // if(ptep) {
            //     pte_clear(current_mm, pg->address, ptep);
            // }
        }
        // pte = pte_lookup(pgd_offset(current_mm, pg->address), pg->address);
        // if(pte) {
        //     pte_clear(current_mm, pg->address, pte);
        // }

        // if(current->mm != pg->mm) {
        //     if(pg->mm) {
        //         if(atomic_read(&pg->mm->mm_count)) {
        //             pte_t *ptep;
        //             ptep = pte_lookup(pgd_offset(pg->mm, pg->address), pg->address);
        //             if(ptep) pte_clear(pg->mm, pg->address, ptep);
        //         }
        //     }
        // }
        evicts++;
        __flush_tlb_one(pg->address);

        kfree(pg);
        UNLOCK(pg->lock);
        pg=0;
    }
    UNLOCK(evict_lock);
}

inline void push_to_evict_list(struct pgcache_node *pg)
{
    if(pg->evicting) return;
    LOCK(evict_lock);
    if(!evict_head) {
        evict_head = evict_tail = pg;
    } else {
        if(evict_tail) evict_tail->evict_next = pg;
        evict_tail = pg;
    }
    evict_list_size++;
    UNLOCK(evict_lock);
    pg->evicting=true;
}

inline void push_to_wb_list(struct pgcache_node *pg)
{
    if(pg->writing) return;
    LOCK(wb_lock);
    if(!wb_head) wb_head = wb_tail = pg;
    else if(wb_tail) wb_tail->wb_next = pg;
    wb_tail = pg;
    wb_list_size++;
    UNLOCK(wb_lock);
    pg->writing = true;
}

inline void push_victim_to_wb_list(unsigned int i)
{
    struct pgcache_node *pg;
    while(i-->0) {  
        LOCK(lru_lock);
        pg = lru_head;
        if(pg) {
            LOCK(pg->lock);
            if(lru_head) lru_head = lru_head->lru_next;
            if(lru_head) lru_head->lru_prev = 0;
            if(pg->lru_prev) pg->lru_prev->lru_next = pg->lru_next;
            if(pg->lru_next) pg->lru_next->lru_prev = pg->lru_prev;
            if(lru_tail == pg) lru_tail = lru_head = NULL;
            pg->lru_next = pg->lru_prev = NULL;
            push_to_wb_list(pg);
            UNLOCK(pg->lock);
            UNLOCK(lru_lock);
        } else {
            UNLOCK(lru_lock);
            break;
        }
    }
}

bool vpmem_do_page_fault(struct pt_regs *regs, unsigned long error_code, unsigned long address)
{
    if (address >= TASK_SIZE_MAX) {
        /* Make sure we are in reserved area: */
        if (address >= VPMEM_START && address < vpmem_end) {
            struct page *p=0;
            faults++;
            address &= PAGE_MASK;

#ifdef ENABLE_WRITEBACK
            // 1. Evicting pages from the page cache which are already written-back
            // pop_from_evict_list();
            // if(pgcache_size >= MAX_PAGES) leaked++;

#endif

            // 2. Handling the page fault
            if(insert_tlb(newpage(address, current_mm, &p), address)) {
                if(p) {
                    vpmem_load_block(address, p);
                }
                goto check_cache;
            }
            return false;

check_cache:
#ifdef ENABLE_WRITEBACK
            // 3. Checking if the page cache is full and push the lru_victim to the wb_list
            // if(pgcache_size >= MAX_PAGES) {
            //     push_victim_to_wb_list(pgcache_size-MAX_PAGES+2);
            // }
#endif
            return true;
        } else {
            return false;
        }
    }
    return false;
}

static DEFINE_MUTEX(checkout_lock);
bool vpmem_checkout(unsigned long address)
{
    LOCK(checkout_lock);
    if(pgsh!=pgst) {
        struct fpage *p=&pgs[(pgsh++)%8];
        vpmem_load_block(p->address, p->p);
    }
    UNLOCK(checkout_lock);
    return true;
}

int vpmem_init(void)
{
#ifdef ENABLE_NETLINK
    vpmem_nl_init();
#endif
    vpmem_reset();
    wb_thread_init();
    return 0;
}

int vpmem_get(struct nova_sb_info *sbi, unsigned long offset)
{
    int i;
    unsigned long size=0;

    vsbi = sbi;

    flush_tlb_all();
    vpmem_start = VPMEM_START + (offset << 30);
    
    // vpmem_operations.do_page_fault = vpmem_do_page_fault;
    // vpmem_operations.do_checkout = vpmem_checkout;
    install_vpmem_fault(vpmem_do_page_fault);

    sbi->vpmem = (char *)vpmem_start;

    /// for(i=0; i<bdev_count; i++) {
    ///     nova_get_bdev_info(bdev_paths[i], i);
    ///     size += bdev_list[i].capacity_page;
    for(i=0; i<TIER_BDEV_HIGH; i++) {
        size += sbi->bdev_list[i].capacity_page;
        map_page[i] = size;
        map_valid[i] = true;
        /// print_a_bdev(&bdev_list[i]);
    }

    printk(KERN_INFO "vpmem: vpmem starts at %016lx (%lu GB)\n",
        vpmem_start,
        size >> 18);
        
    sbi->vpmem_num_blocks = size;
    size <<= PAGE_SHIFT;
    vpmem_end = vpmem_start + size;

    pmem.phys_addr = sbi->phys_addr;
    pmem.virt_addr = sbi->virt_addr;
    pmem.size = sbi->initsize;

    // if (size > 0) {
    //     sbi->virt_addr = (void*)vpmem_start;
    //     sbi->initsize = size;
    //     sbi->replica_reserved_inodes_addr = (void*)vpmem_start + size -
    //          (sbi->tail_reserved_blocks << PAGE_SHIFT);
    //     sbi->replica_sb_addr = (void*)vpmem_start + size - PAGE_SIZE;
    // }

#ifdef USE_PMEM_CACHE
    flist_init();
#endif

    printk(KERN_INFO "vpmem: vpmem_get finished (size = %lu KB)\n", size >> 10);

    return 0;
}

void vpmem_put(void)
{
    wb_thread_cleanup();
    printk(KERN_INFO "vpmem: pgcache_size = %u\n", pgcache_size);
    printk(KERN_INFO "vpmem: wb_list_size = %u\n", wb_list_size);
    printk(KERN_INFO "vpmem: evict_list_size = %u\n", evict_list_size);
    pgcache_flush_all();

    // vpmem_operations.do_page_fault = 0;
    // vpmem_operations.do_checkout = 0;
    install_vpmem_fault(0);

    flush_tlb_all();
    printk(KERN_INFO "vpmem: faults = %lu reads = %lu writes = %lu pte_not_present=%lu pte_not_found=%lu pgcache_full=%lu\n",
                faults, bdev_read, bdev_write, pte_not_present, pte_not_found, pgcache_full);
    printk(KERN_INFO "vpmem: lru_refers = %lu evicts = %lu dif_mm = %lu already_cached = %lu dif_mm2 = %lu leaked = %lu\n",
                lru_refers, evicts, dif_mm, already_cached, dif_mm2, leaked);
    printk(KERN_INFO "vpmem: dif_mm3 = %lu dif_mm4 = %lu\n",
                dif_mm3, dif_mm4);
#ifdef ENABLE_NETLINK
    vmpem_nl_cleanup();
#endif
#ifdef USE_PMEM_CACHE
    flist_cleanup();
#endif
}

void vpmem_reset(void)
{
    int i;
    // bdev_count = 0;
    // nova_total_size = 0;
    vpmem_end = 0;
    // for(i=0; i<MAX_TIERS; i++) {
    for(i=0; i<BDEV_COUNT_MAX; i++) {
        map_valid[i] = false;
        map_page[i] = 0;
        // bdev_paths[i] = NULL;
    }
}