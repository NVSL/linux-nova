#include "vpmem.h"
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
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

#define WB_THREAD_SLEEP_TIME 100
#define WB_THRESHOLD 5

#define VPMEM_SIZE_TB     _AC(16, UL)
#define VPMEM_START       (VMALLOC_START + _AC(16UL << 40, UL))
#define VPMEM_END         (VPMEM_START + _AC((VPMEM_SIZE_TB << 40) - 1, UL))

#define SPM_META_SIZE_MB    _AC(1, UL)
#define SPM_META_SIZE       _AC(SPM_META_SIZE_MB << 20, UL)
#define SPM_PGCACHE_SIZE_MB _AC(50, UL)
#define SPM_PGCACHE_SIZE    _AC(SPM_PGCACHE_SIZE_MB << 20, UL)

// #define USE_PMEM_CACHE   
#define ENABLE_WRITEBACK 
#define ENABLE_WRITE        
// #define ENABLE_NETLINK   
#define USE_LOCK           
#define PAGECACHE_PREALLOC

#ifdef MODE_KEEP_STAT_VPMEM
#define VPMEM_DEBUG
#endif

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
int *wb_empty;

int VPMEM_MAX_PAGES_QTR = VPMEM_MAX_PAGES_QTR_INIT;
int BDEV_OPT_SIZE_BIT = BDEV_OPT_SIZE_BIT_INIT;

struct kmem_cache *nova_vpmem_pgnp;

unsigned long map_page[BDEV_COUNT_MAX]={0};
bool map_valid[BDEV_COUNT_MAX]={0};

atomic_t faults;
atomic_t bdev_read;
atomic_t writes;
atomic_t bdev_write;
atomic_t evicts;
unsigned long pte_not_present=0;
unsigned long pte_not_found=0;
unsigned long pgcache_full=0;
unsigned long lru_refers=0;
unsigned long dif_mm=0;
unsigned long dif_mm2=0;
unsigned long dif_mm3=0;
unsigned long dif_mm4=0;
unsigned long hit=0;
unsigned long miss1=0;
unsigned long miss2=0;
unsigned long already_cached=0;
unsigned long leaked=0;
unsigned long renew=0;
unsigned long lite=0;
unsigned long range=0;
unsigned long invalidate=0;

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
/*
 * Current size: 128 bytes
 */
struct pgcache_node {
    /* First 64-byte */
    unsigned long address;
    struct page *page;
    struct list_head lru_node;
    struct list_head wb_node;
    struct list_head evict_node;
    /* Second 64-byte */
    struct rb_node rb_node;
    struct mm_struct *mm;
    int index;
    pte_t *pte;
	u64	padding[2];
    // struct mutex lock;
};

pte_t *pte_lookup(pgd_t *pgd, unsigned long address);
inline pte_t *vpmem_get_pte(struct pgcache_node *pgn);
inline pte_t *vpmem_get_pte_addr(unsigned long address);

bool clear_evict_list(int index, bool clear);
bool push_victim_to_wb_list(int index, bool all, bool del_lru);
bool vpmem_load_block(unsigned long address, struct page *p, int count);

#ifdef USE_LOCK
#   define LOCK(x) mutex_lock(&x)
#   define UNLOCK(x) mutex_unlock(&x)
#else
#   define LOCK(x) do {} while (0)
#   define UNLOCK(x) do {} while (0)
#endif

static inline int get_index_tc(int tier, int cpu) {
    return (tier-TIER_BDEV_LOW)*vsbi->cpus+cpu;
}

inline int most_sig_bit(unsigned int v) {
    int r = 0;
    while (v >>= 1) r++;
    return r;
}

int pgc_tier_free_order(int tier) {
    unsigned int used = 0;
    unsigned int total, free;
    int i;
    if (tier == TIER_PMEM) {
        used = nova_pmem_used(vsbi);
        total = nova_pmem_total(vsbi);
    }
    else {
        for (i=(tier-TIER_BDEV_LOW)*vsbi->cpus;i<(tier-TIER_BDEV_LOW+1)*vsbi->cpus;++i) 
            used += atomic_read(&vsbi->pgcache_size[i]);
        total = VPMEM_MAX_PAGES_QTR*4*vsbi->cpus;
    }
    free = total - used;
    return most_sig_bit(total) - most_sig_bit(free);
}

inline int pgc_total_size(void) {
    int ret = 0;
    int i;
    for (i=0;i<TIER_BDEV_HIGH*vsbi->cpus;++i) ret += atomic_read(&vsbi->pgcache_size[i]);
    return ret;
}

// Setup stage message for debug in proc
inline void nova_set_stage(int n) {
    if (DEBUG_PROC_LOCK) vsbi->bm_thread[smp_processor_id()].stage=n;
}

void set_should_migrate_log(void) {
    bool ans = true;
    int i;
    for (i=0;i<vsbi->cpus;++i) {
        if (!is_inode_lru_list_empty(vsbi, TIER_PMEM, i)) {
            ans = false;
            break;
        }
    }
    vsbi->stat->should_migrate_log = ans;
}

inline void set_is_pgcache_large(void) {
    vsbi->stat->pgcache_large =  pgc_total_size() > VPMEM_MAX_PAGES_QTR * 4 * TIER_BDEV_HIGH * vsbi->cpus;
}

inline void set_is_pgcache_ideal(void) {
    vsbi->stat->pgcache_ideal = pgc_total_size() * 100 < (MIGRATION_IDEAL_PERC-10) * VPMEM_MAX_PAGES_QTR * 4 * TIER_BDEV_HIGH * vsbi->cpus;
}

inline void set_is_pgcache_quite_small(void) {
    vsbi->stat->pgcache_quite_small = pgc_total_size() * 100 < (MIGRATION_IDEAL_PERC) * VPMEM_MAX_PAGES_QTR * 4 * TIER_BDEV_HIGH * vsbi->cpus;
}

// Exit write back
void set_is_pgcache_very_small(void) {
    int i;
    for (i=0; i<vsbi->cpus; ++i) {
        vsbi->stat->pgcache_very_small[i] = is_pgcache_quite_small() ||
            atomic_read(&vsbi->pgcache_size[i]) <= VPMEM_MAX_PAGES_QTR * 3;
    }
}

// Enter write back
void set_is_pgcache_small(void) {
    int i;
    for (i=0; i<vsbi->cpus; ++i) {
        vsbi->stat->pgcache_small[i] = is_pgcache_quite_small() ||
            atomic_read(&vsbi->pgcache_size[i]) <= VPMEM_MAX_PAGES_QTR * 3 + VPMEM_RES_PAGES;
    }
}

inline bool is_should_migrate_log(void) {
    return vsbi->stat->should_migrate_log;
}

inline bool is_pgcache_large(void) {
    return vsbi->stat->pgcache_large;
}

inline bool is_pgcache_ideal(void) {
    return vsbi->stat->pgcache_ideal;
}

inline bool is_pgcache_quite_small(void) {
    return vsbi->stat->pgcache_quite_small;
}

// Exit write back
inline bool is_pgcache_very_small(int index) {
    return vsbi->stat->pgcache_very_small[index];
}

// Enter write back
inline bool is_pgcache_small(int index) {
    return vsbi->stat->pgcache_small[index];
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
    if (unlikely(address<vpmem_start)) 
        nova_info("Error in virt_to_blockoff address %lx\n", address);
    address &= PAGE_MASK;
    return ((address - vpmem_start) >> PAGE_SHIFT) + vsbi->num_blocks;
}

// Global block offset to virtual address
inline unsigned long blockoff_to_virt(unsigned long blockoff) {
    if (unlikely(blockoff<vsbi->num_blocks)) 
        nova_info("Error in blockoff_to_virt blockoff %lu\n", blockoff);
    return vpmem_start + ((blockoff - vsbi->num_blocks) << PAGE_SHIFT);
}

/* 
 * This is specific for TNOVA's existing block device data structure.
 * An alternate implementation can be added to this.
 * But please do NOT modify this one.
 */
// TODO: Change virtual address layout for hotplug
inline int vpmem_get_cpuid(unsigned long address) {
    return get_tier_cpu(vsbi, virt_to_blockoff(address));
}

inline int vpmem_get_tier(unsigned long address) {
    return get_tier(vsbi, virt_to_blockoff(address));
}

inline int vpmem_get_index(unsigned long address) {
    return get_bfl_index(vsbi, virt_to_blockoff(address));
}

inline int vpmem_get_range_index(unsigned long address, unsigned long count) {
    int index = vpmem_get_index(address);
    if (unlikely(index != vpmem_get_index(address + ((count-1) << PAGE_SHIFT))))
        nova_info("Error in vpmem_get_range_index index %d v %lx, %lu \n", index, address, count-1);
    return index;
}

inline int vpmem_get_pgn_cpuid(struct pgcache_node *pgn) {
    return vpmem_get_cpuid(pgn->address);
}

inline int vpmem_get_pgn_tier(struct pgcache_node *pgn) {
    return vpmem_get_tier(pgn->address);
}

inline int vpmem_get_pgn_index(struct pgcache_node *pgn) {
    return pgn->index;
    // return vpmem_get_index(pgn->address);
}

inline void vpmem_check_pgn_index(struct pgcache_node *pgn, int index, int id) {
    if (vpmem_get_index(pgn->address) != index) 
        nova_info("%d block %lu %d index %d cpu %d", id, virt_to_blockoff(pgn->address), pgn->index, index, smp_processor_id());
}

inline int get_entry_tier(struct nova_file_write_entry *entry) {
	return get_tier(vsbi, entry->block >> PAGE_SHIFT);
}

void pop_from_lru_list(struct pgcache_node *pgn) {
    int index = pgn->index;
    if (!list_empty(&pgn->lru_node)) {
        mutex_lock(&vsbi->vpmem_lru_mutex[index]);
        list_del_init(&pgn->lru_node);
        mutex_unlock(&vsbi->vpmem_lru_mutex[index]);
    }
}

void pop_from_wb_list(struct pgcache_node *pgn) {
    int index = pgn->index;
    if (!list_empty(&pgn->wb_node)) {
        mutex_lock(&vsbi->vpmem_wb_mutex[index]);
        list_del_init(&pgn->wb_node);
        mutex_unlock(&vsbi->vpmem_wb_mutex[index]);
    }
}

void pop_from_evict_list(struct pgcache_node *pgn) {
    int index = pgn->index;
    if (!list_empty(&pgn->evict_node)) {
        mutex_lock(&vsbi->vpmem_evict_mutex[index]);
        list_del_init(&pgn->evict_node);
        mutex_unlock(&vsbi->vpmem_evict_mutex[index]);
    }
}

void push_to_lru_list(struct pgcache_node *pgn) {
    int index = pgn->index;
    if (list_empty(&pgn->lru_node)) {
        mutex_lock(&vsbi->vpmem_lru_mutex[index]);
        list_add_tail(&pgn->lru_node, &vsbi->vpmem_lru_list[index]);
        mutex_unlock(&vsbi->vpmem_lru_mutex[index]);
    }
}

void push_to_wb_list(struct pgcache_node *pgn) {
    int index = pgn->index;
    if (list_empty(&pgn->wb_node)) {
        mutex_lock(&vsbi->vpmem_wb_mutex[index]);
        list_add_tail(&pgn->wb_node, &vsbi->vpmem_wb_list[index]);
        mutex_unlock(&vsbi->vpmem_wb_mutex[index]);
    }
}

// Make sure lru_node is empty before calling this function
void push_to_evict_list(struct pgcache_node *pgn) {
    int index = pgn->index;
    if (list_empty(&pgn->evict_node)) {
        mutex_lock(&vsbi->vpmem_evict_mutex[index]);
        list_add_tail(&pgn->evict_node, &vsbi->vpmem_evict_list[index]);
        mutex_unlock(&vsbi->vpmem_evict_mutex[index]);
    }
}

inline void wait_until_pgn_is_valid(struct pgcache_node *pgn) {
    while (unlikely(pgn && (!pgn->page || !pgn->pte))) {
        // nova_info("Wait %p %p addr %lx", pgn->page, pgn->pte, pgn->address);
        schedule();
    }
}

struct pgcache_node *pgcache_lookup(unsigned long address)
{
    int index = vpmem_get_index(address);
    struct rb_node *n = vsbi->vpmem_rb_tree[index].rb_node;
    struct pgcache_node *ans;

    mutex_lock(&vsbi->vpmem_rb_mutex[index]);
    while (n)
    {
        ans = rb_entry(n, struct pgcache_node, rb_node);

        if (address < ans->address)
            n = n->rb_left;
        else if (address > ans->address)
            n = n->rb_right;
        else {
            mutex_unlock(&vsbi->vpmem_rb_mutex[index]);
            wait_until_pgn_is_valid(ans);
            return ans;
        }
    }
    mutex_unlock(&vsbi->vpmem_rb_mutex[index]);
    return NULL;
}

inline bool is_pgcache_hint_hit(struct pgcache_node *hint, unsigned long address) {
    if (!hint) {
        miss1++;
        return false;
    }
    if (hint->address == address) {
        hit++;
        return true;
    }
    else {
        miss2++;
        return false;
    }
}

struct pgcache_node *pgcache_get_hint(struct pgcache_node *prev) {
    struct rb_node *n;
    int index;
    if (!prev) return NULL;
    index = vpmem_get_pgn_index(prev);
    mutex_lock(&vsbi->vpmem_rb_mutex[index]);
    n = rb_next(&prev->rb_node);
    mutex_unlock(&vsbi->vpmem_rb_mutex[index]);
    if (!n) return NULL;
    return container_of(n, struct pgcache_node, rb_node);
}

void pgcache_lru_refer(struct pgcache_node *pgn) {
    int index = vpmem_get_pgn_index(pgn);
    lru_refers++;
    pop_from_evict_list(pgn);
    mutex_lock(&vsbi->vpmem_lru_mutex[index]);
    list_move_tail(&pgn->lru_node, &vsbi->vpmem_lru_list[index]);
    mutex_unlock(&vsbi->vpmem_lru_mutex[index]);
}

bool is_pgn_dirty(struct pgcache_node *pgn) {
    pte_t *ptep;
    if (!pgn) return false;
    if (!pgn->page) return false;
    if (!vpmem_valid_address(pgn->address)) return false;
    ptep = vpmem_get_pte(pgn);
    if (!ptep) return false;
    return pte_dirty(*ptep) != 0;
}

bool is_pgn_dirty_addr(unsigned long address) {
    pte_t *ptep;
    if (!address) return false;
    ptep = vpmem_get_pte_addr(address);    
    if (!ptep) return false;
    return pte_dirty(*ptep) != 0;
}

bool is_pgn_young_reset(struct pgcache_node *pgn) {
    pte_t *ptep = vpmem_get_pte(pgn);
    if (!ptep) {
        nova_info("Error in is_pgn_young_reset young %p %lu\n", pgn, pgn->address);
        return false;
    }
    if (pte_young(*ptep)) {
	    *ptep = pte_mkold(*ptep);
        // smp_wmb();
        return true;
    }
    else return false;
}

int set_pgn_clean(struct pgcache_node *pgn) {
    pte_t *ptep;
    wait_until_pgn_is_valid(pgn);
    ptep = vpmem_get_pte(pgn);
    if (unlikely(!ptep)) {
        nova_info("Error in set_pgn_clean %lx\n", pgn->address);
        return -1;
    }
	*ptep = pte_mkold(*ptep);
	*ptep = pte_mkclean(*ptep);
    // smp_mb();
    return 0;
}

int set_pgn_clean_addr(unsigned long address) {
    pte_t *ptep = vpmem_get_pte_addr(address);
    if (unlikely(!ptep)) {
        nova_info("Error in set_pgn_clean_addr\n");
        return -1;
    }
	*ptep = pte_mkold(*ptep);
	*ptep = pte_mkclean(*ptep);
    // smp_mb();
    return 0;
}

void vpmem_invalidate_pgn(struct pgcache_node *pgn);
void vpmem_clear_pgn(struct pgcache_node *pgn, int index, unsigned long flags);
bool insert_tlb(struct pgcache_node *pgn);

inline bool vpmem_valid_address(unsigned long address) {
    if (address < TASK_SIZE_MAX || address < VPMEM_START || address > vpmem_end) return false;
    else return true;
}

struct pgcache_node *pgcache_insert(unsigned long address, struct mm_struct *mm, bool *new)
{
    struct pgcache_node *p, *newp;
    int index = vpmem_get_index(address);
    struct rb_node **link = &vsbi->vpmem_rb_tree[index].rb_node;
    struct rb_node *parent = NULL;
	unsigned long flags;

    *new = false;

    while (is_pgcache_large()) schedule();
redo:
    mutex_lock(&vsbi->vpmem_rb_mutex[index]);
    local_irq_save(flags);
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
            // nova_info("Warning in pgcache_insert address %lx addr %lx page %p p %p\n",
            //     address, p->address, p->page, page_address(p->page));
            // mutex_lock(&p->lock);
            // vpmem_invalidate_pgn(p);
            if (unlikely(!p->page||!p->pte)) {
                nova_info("Warning in pgcache_insert address %lx\n", address);
                schedule();
                mutex_unlock(&vsbi->vpmem_rb_mutex[index]);
                local_irq_restore(flags);
                goto redo;
                p->page = alloc_page(GFP_KERNEL|__GFP_ZERO);
                if (unlikely(!p->page)) {
                    printk("vpmem: NO PAGE LEFT!\n");
                }
                lock_page(p->page);
                vpmem_load_block(address, p->page, 1);
                insert_tlb(p);
            }
            wait_until_pgn_is_valid(p);
            // else {
            //     nova_info("Warning 2 in pgcache_insert address %lx addr %lx page %p p %p\n",
            //         address, p->address, p->page, page_address(p->page));
            // }


            // nova_info("Warning 3 in pgcache_insert address %lx addr %lx page %p p %p\n",
            //     address, p->address, p->page, page_address(p->page));

            // mutex_unlock(&p->lock);
            smp_mb();
            mutex_unlock(&vsbi->vpmem_rb_mutex[index]);
            local_irq_restore(flags);

            // pgcache_lru_refer(p);

            already_cached++;
            return p;
        }
    }

    // newp = (struct pgcache_node *)kmalloc(sizeof(struct pgcache_node), GFP_KERNEL | GFP_ATOMIC);
    newp = kmem_cache_alloc(nova_vpmem_pgnp, GFP_NOFS);
    // mutex_init(&newp->lock);
    // mutex_lock(&newp->lock);
    newp->page = alloc_page(GFP_KERNEL|__GFP_ZERO);
    if (unlikely(!newp->page)) {
        printk("vpmem: NO PAGE LEFT!\n");
    }
    // memset(page_address(newp->page), 0, PAGE_SIZE);
    // newp->pfn = page_to_pfn(newp->page);
    newp->address = address;
    newp->mm = mm;
    newp->index = vpmem_get_index(address);

    RB_CLEAR_NODE(&newp->rb_node);
	INIT_LIST_HEAD(&newp->lru_node);
	INIT_LIST_HEAD(&newp->wb_node);
	INIT_LIST_HEAD(&newp->evict_node);

    lock_page(newp->page);

    *new = true;
    atomic_inc_return(&vsbi->pgcache_size[index]);
    /* Put the new node there */
    rb_link_node(&newp->rb_node, parent, link);
    rb_insert_color(&newp->rb_node, &vsbi->vpmem_rb_tree[index]);
    smp_mb();

    mutex_unlock(&vsbi->vpmem_rb_mutex[index]);
    local_irq_restore(flags);

    return newp;
}

void *vpmem_lru_refer(unsigned long address)
{
    struct pgcache_node *pgn = pgcache_lookup(address & PAGE_MASK);
    if (likely(pgn)) pgcache_lru_refer(pgn);
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

pte_t *pte_lookup(pgd_t *, unsigned long);

void flush_tlb_all(void)
{
    __flush_tlb_all();
}

void vpmem_print_status(void) {
    int i;
    char *empty = "\e[0;32m   Empty\e[0m|";
    char *nopty = "\e[0;31mNotEmpty\e[0m|";
    char stmp[100] = {0};
    printk(KERN_INFO "--------------------------------------------------------\n");
    printk(KERN_INFO "|Tier|#CPU|    size| rb_tree|lru_list| wb_list|evt_list|\n");
    for (i=0;i<TIER_BDEV_HIGH*vsbi->cpus;++i) {
        stmp[0] = '\0';
        if (!vsbi->vpmem_rb_tree[i].rb_node) strncat(stmp, empty, 20);
        else strncat(stmp, nopty, 20);
        if (list_empty(&vsbi->vpmem_lru_list[i])) strncat(stmp, empty, 20);
        else strncat(stmp, nopty, 20);
        if (list_empty(&vsbi->vpmem_wb_list[i])) strncat(stmp, empty, 20);
        else strncat(stmp, nopty, 20);        
        if (list_empty(&vsbi->vpmem_evict_list[i])) strncat(stmp, empty, 20);
        else strncat(stmp, nopty, 20);
        if (i%vsbi->cpus==smp_processor_id())
            printk(KERN_INFO "|%3d |\e[1;34m%3d\e[0m |%8d|%s\n", i/vsbi->cpus, i%vsbi->cpus, atomic_read(&vsbi->pgcache_size[i]), stmp);
        else
            printk(KERN_INFO "|%3d |%3d |%8d|%s\n", i/vsbi->cpus, i%vsbi->cpus, atomic_read(&vsbi->pgcache_size[i]), stmp);
    }
    printk(KERN_INFO "--------------------------------------------------------\n");
}

int vpmem_write_to_bdev(unsigned long address, unsigned long count, struct page *page) {   
    unsigned long blockoff, raw_blockto;
    int tier;
    address &= PAGE_MASK;
    blockoff = virt_to_blockoff(address);
    tier = get_tier(vsbi, blockoff);
    raw_blockto = get_raw_from_blocknr(vsbi, blockoff);
    if (unlikely(address<vpmem_start)) 
        nova_info("Error write address %lx count %lu blockoff %lu tier %d raw_blockto %lu\n", 
        address, count, blockoff, tier, raw_blockto);
    return nova_bdev_write_block(vsbi, get_bdev_raw(vsbi, tier), raw_blockto, count,
        page, BIO_SYNC);
}

int vpmem_read_from_bdev(unsigned long address, unsigned long count, struct page *page) {   
    unsigned long blockoff, raw_blockto;
    int tier;
    address &= PAGE_MASK;
    blockoff = virt_to_blockoff(address);
    tier = get_tier(vsbi, blockoff);
    raw_blockto = get_raw_from_blocknr(vsbi, blockoff);
    if (unlikely(address<vpmem_start)) 
        nova_info("Error read address %lx count %lu blockoff %lu tier %d raw_blockto %lu\n", 
        address, count, blockoff, tier, raw_blockto);
    return nova_bdev_read_block(vsbi, get_bdev_raw(vsbi, tier), raw_blockto, count,
        page, BIO_SYNC);
}

int vpmem_write_to_bdev_range(unsigned long address, unsigned long count, struct page **page) {   
    unsigned long blockoff, raw_blockto;
    int tier;
    address &= PAGE_MASK;
    blockoff = virt_to_blockoff(address);
    tier = get_tier(vsbi, blockoff);
    raw_blockto = get_raw_from_blocknr(vsbi, blockoff);
    if (unlikely(address<vpmem_start)) 
        nova_info("Error write address %lx count %lu blockoff %lu tier %d raw_blockto %lu\n", 
        address, count, blockoff, tier, raw_blockto);
    return nova_bdev_write_block_range(vsbi, get_bdev_raw(vsbi, tier), raw_blockto, count,
        page, BIO_SYNC);
}

int vpmem_read_from_bdev_range(unsigned long address, unsigned long count, struct page **page) {   
    unsigned long blockoff, raw_blockto;
    int tier;
    address &= PAGE_MASK;
    blockoff = virt_to_blockoff(address);
    tier = get_tier(vsbi, blockoff);
    raw_blockto = get_raw_from_blocknr(vsbi, blockoff);
    if (unlikely(address<vpmem_start)) 
        nova_info("Error read address %lx count %lu blockoff %lu tier %d raw_blockto %lu\n", 
        address, count, blockoff, tier, raw_blockto);
    return nova_bdev_read_block_range(vsbi, get_bdev_raw(vsbi, tier), raw_blockto, count,
        page, BIO_SYNC);
}

/******************* TLB Flusher *******************/
struct task_struct *wb_thread = NULL;

int get_wb_smart_range(struct pgcache_node *pgn, unsigned long *start_addr) {
    struct pgcache_node *tpgn;
    struct rb_node *rbn= NULL;
    int index;
	struct bdev_free_list *bfl;
    unsigned long address, blockoff, begin, end, bflbegin, bflend;
    unsigned int osb;
    int count1 = 0; // Dirty pages in the right: [pgn, tpgn]
    int count2 = 0; // Dirty pages in the left: [tpgn, pgn]
    
    if (!pgn || !pgn->page) return 1;
    address = pgn->address;
    *start_addr = address;
    if (!MODE_SR_WB) return 1;
    
    blockoff = virt_to_blockoff(address);
    osb = vsbi->bdev_list[get_tier(vsbi, blockoff)-TIER_BDEV_LOW].opt_size_bit + PAGE_SHIFT;
    begin = (address >> osb) << osb;
    end = ((address >> osb) + 1) << osb;

    index = get_bfl_index(vsbi, blockoff);
    bfl = nova_get_bdev_free_list_flat(vsbi,index);
    bflbegin = blockoff_to_virt(bfl->block_start);
    bflend = blockoff_to_virt(bfl->block_end + 1);
    if (begin < bflbegin) begin = bflbegin;
    if (end > bflend) end = bflend;

    /* Count 1: address -> valid */    
    if (!pgn || !pgn->page) return 1;
    tpgn = pgn;
    while (is_pgn_dirty(tpgn) && tpgn->address == address && tpgn->address < end) {
        if (!tpgn || !tpgn->page || !list_empty(&tpgn->evict_node)) break;
        count1++;
        address += PAGE_SIZE;
        mutex_lock(&vsbi->vpmem_rb_mutex[index]);
        rbn = rb_next(&tpgn->rb_node);
        mutex_unlock(&vsbi->vpmem_rb_mutex[index]);
        if (!rbn) break;
        tpgn = container_of(rbn, struct pgcache_node, rb_node);
    }
    if (unlikely(count1<1)) {
        // if (!is_pgn_dirty(tpgn)) nova_info("pgn not dirty\n");
        // nova_info("Warning in get_wb_smart_range count1 %d count2 %d %lx %lx %lx\n", 
        //     count1, count2, tpgn->address, begin, bflbegin);
        return 1;
    }
    return count1;
    
    /* Count 2: valid <- address */
    address = pgn->address;
    tpgn = pgn;
    while (is_pgn_dirty(tpgn) && tpgn->address == address && tpgn->address >= begin) {
        if (!tpgn || !tpgn->page || !list_empty(&tpgn->evict_node)) break;
        count2++;
        mutex_lock(&vsbi->vpmem_rb_mutex[index]);
        rbn = rb_prev(&tpgn->rb_node);
        mutex_unlock(&vsbi->vpmem_rb_mutex[index]);
        if (!rbn) break;
        tpgn = container_of(rbn, struct pgcache_node, rb_node);
        *start_addr = address;
        address -= PAGE_SIZE;
    }
    
    if (unlikely(count1<1||count2<1)) {
        if (!is_pgn_dirty(tpgn)) nova_info("pgn not dirty\n");
        nova_info("Warning in get_wb_smart_range count1 %d count2 %d %lx %lx %lx\n", 
            count1, count2, tpgn->address, begin, bflbegin);
        return 1;
    }

    return count1 + count2 - 1;
}

// page_array is allocated here, freed elsewhere.
int vpmem_prepare_page_array(unsigned long address, unsigned long count, struct page **page_array) {
    struct pgcache_node *pgn = NULL;
    int i;
    address &= PAGE_MASK;
    for (i=0;i<count;++i) {
        pgn = pgcache_lookup(address);
        wait_until_pgn_is_valid(pgn);
        if (pgn) {
            page_array[i] = pgn->page;
        }
        else {
            nova_info("Warning in vpmem_prepare_page_array addr %lx i %d count %lu\n", address, i, count);
            break;
        }
        address += PAGE_SIZE;
    }
    return i;
}

int set_pgn_clean_range(unsigned long address, unsigned long count) {
    struct pgcache_node *pgn = NULL;
    unsigned long ret = 0;
    address &= PAGE_MASK;
    while (count-- > 0) {
        pgn = pgcache_lookup(address);
        if (likely(pgn)) {
            set_pgn_clean(pgn);
        }
        address += PAGE_SIZE;
    }
    return ret;
}

// Return true if the writeback list is below threshold -> kthread can sleep
bool vpmem_writeback(int index, bool clear) {
    struct page *p = NULL;
    struct pgcache_node *pgn;
    unsigned long address = 0;
    int counter = 0;
    unsigned long start_addr = 0;
    int sr, ret = 0;
    struct page **page_array = NULL;

    if (unlikely(clear)) {
        push_victim_to_wb_list(index, true, true);
    }
    else {
        if (!is_pgcache_small(index)) {
            push_victim_to_wb_list(index, false, true);
        }
        if (list_empty(&vsbi->vpmem_wb_list[index])) {
            wb_empty[index]++;
            if (wb_empty[index] < WB_THRESHOLD) return true;
            push_victim_to_wb_list(index, true, false);
        }
    }

again:
    if (unlikely(!clear) && ++counter > VPMEM_MAX_PAGES_QTR) return false;

    mutex_lock(&vsbi->vpmem_wb_mutex[index]);

    if (list_empty(&vsbi->vpmem_wb_list[index])) {
        wb_empty[index] = 0;
        mutex_unlock(&vsbi->vpmem_wb_mutex[index]);
        return true;
    }
    
    pgn = container_of(vsbi->vpmem_wb_list[index].next, struct pgcache_node, wb_node);
    if (unlikely(!pgn)) {
        printk(KERN_INFO "vpmem: pgcache_node error in vpmem_writeback().\n");
        mutex_unlock(&vsbi->vpmem_wb_mutex[index]);
        return true;
    }

    list_del_init(&pgn->wb_node);
    p = pgn->page; // pfn_to_page(pgn->pfn);
    address = pgn->address;

    if (!is_pgn_dirty(pgn)) {
        set_pgn_clean(pgn);
        goto end;
    }

    if (unlikely(address<vpmem_start))
        nova_info("Error in vpmem_writeback address %lx p %p\n", address, page_address(p));

    if (is_pgn_dirty(pgn)) {

        sr = get_wb_smart_range(pgn, &start_addr);
        // nova_info("vpmem_writeback address %lx sr %d\n", address, sr);
        
        if (!is_pgn_dirty(pgn)) {
            set_pgn_clean(pgn);
            goto end;
        }

        page_array = kcalloc(sr, sizeof(struct page *), GFP_KERNEL);
        sr = vpmem_prepare_page_array(start_addr, sr, page_array);        
        if (sr!=0) ret = vpmem_write_to_bdev_range(start_addr, sr, page_array);

        counter += sr;
        set_pgn_clean_range(start_addr, sr);

        kfree(page_array);

        if(unlikely(ret)) {
            printk("vpmem:\033[1;32m could not write to bdev %lu\033[0m\n", ++dif_mm2);
        } else {
            #ifdef VPMEM_DEBUG
                atomic_inc_return(&writes);
                atomic_add_return(sr, &bdev_write);
            #endif
        }
    }
    
end:
    if (list_empty(&pgn->lru_node)) {
        push_to_evict_list(pgn);
    }

    mutex_unlock(&vsbi->vpmem_wb_mutex[index]);

    schedule();
    goto again;

    return false;
}

int wb_thread_worker(void *data) {
    bool ret = true;
    struct nova_kthread *this = data;
    int index = this->index;
    schedule();
    do {
		if (ret) schedule_timeout_interruptible(msecs_to_jiffies(WB_THREAD_SLEEP_TIME));
        ret = vpmem_writeback(index, false);
        clear_evict_list(index, false);
    } while(!kthread_should_stop());  

#ifdef ENABLE_WRITEBACK
    vpmem_print_status();
    vpmem_writeback(index, true);
    vpmem_print_status();
    clear_evict_list(index, true);
    vpmem_print_status();
#endif

    return 0;
}

int wb_thread_init(struct nova_sb_info *sbi) {
#ifdef ENABLE_WRITEBACK 
	struct nova_kthread *wb_thread = NULL;
	int i, err = 0;
    char stmp[100] = {0};
    int count = TIER_BDEV_HIGH*sbi->cpus;

	sbi->wb_thread = NULL;
	/* Initialize background migration kthread */
	wb_thread = kcalloc(count, sizeof(struct nova_kthread), GFP_KERNEL);
	if (!wb_thread) {
		return -ENOMEM;
	}

	for (i=0; i<count; ++i) {
        init_waitqueue_head(&(wb_thread[i].wait_queue_head));
        wb_thread[i].index = i;
        sprintf(&stmp[0], "NOVA_WB_T%d_C%d",i/sbi->cpus+TIER_BDEV_LOW,i%sbi->cpus);
        wb_thread[i].nova_task = kthread_create(wb_thread_worker, &wb_thread[i], stmp);
		kthread_bind(wb_thread[i].nova_task, i%sbi->cpus);

        if (IS_ERR(wb_thread[i].nova_task)) {
            err = PTR_ERR(wb_thread[i].nova_task);
            goto free;
        }
	}

    sbi->wb_thread = wb_thread;

	if (sbi->wb_thread) {
		smp_mb();
        for (i=0; i<count; ++i) wake_up_process(sbi->wb_thread[i].nova_task);
	}

	return 0;

free:
	kfree(wb_thread);
	return err;
#endif
}

void wb_thread_cleanup(void) {
#ifdef ENABLE_WRITEBACK
    int i;
	if (vsbi->wb_thread) {		
	    for (i=0; i<TIER_BDEV_HIGH*vsbi->cpus; ++i) {
            kthread_stop(vsbi->wb_thread[i].nova_task);
            nova_info("kthread %d stopped\n", i);
        }
		kfree(vsbi->wb_thread);
		vsbi->wb_thread = NULL;
	}
#endif
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

inline pte_t *vpmem_get_pte(struct pgcache_node *pgn) {
    return pgn->pte;
    // return pte_lookup(pgd_offset_k(pgn->address), pgn->address);
}

inline pte_t *vpmem_get_pte_addr(unsigned long address) {
    return pte_lookup(pgd_offset_k(address), address);
}

bool insert_tlb(struct pgcache_node *pgn) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    pte_t ptein = mk_pte(pgn->page, PAGE_KERNEL);
    struct mm_struct *mm = current_mm;
    unsigned long address = pgn->address;
	unsigned long flags;

	// smp_mb();

    spin_lock(&mm->page_table_lock);
    local_irq_save(flags);

    // pgd = __va(read_cr3_pa()) + pgd_index(address); // pgd_offset(current->mm, address);
    pgd = pgd_offset(mm, address);
    p4d = fill_p4d(mm, pgd, address); // p4d_alloc(mm, pgd, address); 
    pud = fill_pud(mm, p4d, address); // pud_alloc(mm, p4d, address); 
    pmd = fill_pmd(mm, pud, address); // pmd_alloc(mm, pud, address); 
    pte = fill_pte(mm, pmd, address);
	
    *pte = pte_mkyoung(*pte);
    *pte = pte_mkclean(*pte);

    set_pte(pte, ptein);
    pgn->pte = pte;
    spin_unlock(&mm->page_table_lock);
    local_irq_restore(flags);

    __flush_tlb_one(address);

    smp_mb();

	*pte = pte_mkclean(*pte);
    
    return true;
}

bool insert_tlb_lock_free(pte_t ptein, unsigned long address) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct mm_struct *mm = current_mm;

    // pgd = __va(read_cr3_pa()) + pgd_index(address); // pgd_offset(current->mm, address);
    pgd = pgd_offset(mm, address);
    p4d = fill_p4d(mm, pgd, address); // p4d_alloc(mm, pgd, address); 
    pud = fill_pud(mm, p4d, address); // pud_alloc(mm, p4d, address); 
    pmd = fill_pmd(mm, pud, address); // pmd_alloc(mm, pud, address); 
    pte = fill_pte(mm, pmd, address);
	
    *pte = pte_mkclean(*pte);
    set_pte(pte, ptein);

    __flush_tlb_one(address);
    return true;
}

int pgcache_lru_refer_range(unsigned long address, unsigned long count) {
    struct pgcache_node *pgn = NULL;
    unsigned long ret = 0;
    address &= PAGE_MASK;
    while (count-- > 0) {
        pgn = pgcache_lookup(address);
        if (likely(pgn)) {   
            pgcache_lru_refer(pgn);
        }
        address += PAGE_SIZE;
    }
    return ret;
}

int vpmem_cache_pages(unsigned long address, unsigned long count, bool load)
{
    struct pgcache_node *pgn = NULL;
    unsigned long addr;
    bool new = false;
    address &= PAGE_MASK;
    addr = address;
    if (unlikely(!vpmem_valid_address(addr))) {
        nova_info("Error in vpmem_cache_pages %lu\n", addr);
    }
    while (count-- > 0) {        
        pgn = pgcache_lookup(addr);
        if (pgn) {
            addr += PAGE_SIZE;
            continue;
        }
        pgn = pgcache_insert(addr, current_mm, &new);
        if (new) {
            insert_tlb(pgn);
            // mutex_unlock(&pgn->lock);
            pgcache_lru_refer(pgn);
        }
        addr += PAGE_SIZE;
    }
    // Warning: load here is never called(tested) for now
    if (load) {
        vpmem_load_block(address, address_to_page((void *)address), count);
    }    
    return 0;
}


inline int vpmem_write_behind_pages(unsigned long address, unsigned long count, void *dax_mem) {    
    return vpmem_write_to_bdev(address, count, address_to_page(dax_mem));
}

// This is sync flush
int vpmem_flush_pages_sync(unsigned long address, unsigned long count) {
    struct pgcache_node *pgn = NULL;
    unsigned long ret = 0;
    address &= PAGE_MASK;
    while (count-- != 0) {
        pgn = pgcache_lookup(address);
        if (pgn&pgn->page) {
            if (is_pgn_dirty(pgn)) {
                push_to_wb_list(pgn);
                ret++;
                set_pgn_clean(pgn);
            }
        }
        address += PAGE_SIZE;
    }
    return ret;
}

/*
 * APIs for VPMEM writeback
 * |             | Has writeback |  Valid after  |
 * | Write_back  |      Yes      |      Yes      | 
 * | Flush       |      Yes      |       No      |
 * | Invalidate  |       No      |       No      |
 * Valid after: If the page is still in lru list, then it is considered as valid.
 */
int vpmem_write_back_pages(unsigned long address, unsigned long count) {
    struct pgcache_node *pgn = NULL;
    address &= PAGE_MASK;
    while (count-- > 0) {
        pgn = pgcache_lookup(address);
        if (likely(pgn)) {
            push_to_wb_list(pgn);
        }
        address += PAGE_SIZE;
    }
    return 0;
}

// This is async flush
int vpmem_flush_pages(unsigned long address, unsigned long count) {
    struct pgcache_node *pgn = NULL;
    address &= PAGE_MASK;
    while (count-- > 0) {
        pgn = pgcache_lookup(address);
        if (likely(pgn)) {
            pop_from_lru_list(pgn);
            if (is_pgn_dirty(pgn)) push_to_wb_list(pgn);
            else push_to_evict_list(pgn);
        }
        address += PAGE_SIZE;
    }
    return 0;
}

void vpmem_invalidate_pgn(struct pgcache_node *pgn) {

    pop_from_lru_list(pgn);
    pop_from_wb_list(pgn);
    pop_from_evict_list(pgn);

	smp_mb();
}

void vpmem_clear_pgn(struct pgcache_node *pgn, int index, unsigned long flags) {    

    if (unlikely(!pgn)) {
        nova_info("Error in pgcache_remove 1\n");
        return;
    }
    // index = vpmem_get_pgn_index(pgn);
    
    // if (unlikely(!list_empty(&pgn->lru_node))) {
    //     nova_info("Error in pgcache_remove 2 %lx\n", (unsigned long)&vsbi->vpmem_lru_list[index]);
    // }    

    if (unlikely(RB_EMPTY_NODE(&pgn->rb_node))) {
        nova_info("Error in pgcache_remove 2 %lx\n", pgn->address);
        mutex_unlock(&vsbi->vpmem_rb_mutex[index]);
        goto clear;
    }
    // if (!mutex_trylock(&pgn->lock)) {
    //     nova_info("Warning in pgcache_remove 1 %lx", pgn->address);
    //     schedule();
    //     mutex_lock(&pgn->lock);
    //     nova_info("Warning in pgcache_remove 2 %lx", pgn->address);
    // }
    // mutex_unlock(&pgn->lock); 
    rb_erase(&pgn->rb_node, &vsbi->vpmem_rb_tree[index]);
    mutex_unlock(&vsbi->vpmem_rb_mutex[index]);

clear:
    vpmem_invalidate_pgn(pgn);
    local_irq_restore(flags);
    // nl_send("ev %20lu %16lu %2d", pgn->address, 0, 0);

    #ifdef VPMEM_DEBUG
        atomic_inc_return(&evicts);
    #endif
    
    if (atomic_read(&vsbi->pgcache_size[index])==0) nova_info("ERROR in pgcache_size\n");
    atomic_dec_return(&vsbi->pgcache_size[index]);

    kmem_cache_free(nova_vpmem_pgnp, pgn);
}

// Currently, only pages which are freed/migrated will be invalidated.
// Allocating new data blocks will not call this function.
int vpmem_invalidate_pages(unsigned long address, unsigned long count) {
    struct pgcache_node *pgn = NULL;
    address &= PAGE_MASK;
    while (count-- > 0) {
        dif_mm4++;
        pgn = pgcache_lookup(address);
        if (pgn && pgn->page) {
            pop_from_lru_list(pgn);
            pop_from_wb_list(pgn);
            set_pgn_clean(pgn);
            push_to_evict_list(pgn);
            #ifdef VPMEM_DEBUG
                invalidate++;
            #endif
        }
        address += PAGE_SIZE;
    }

    return 0;
}

int vpmem_renew_pages(void *addr, unsigned long address, unsigned long count) {
    struct pgcache_node *pgn = NULL;
    
    address &= PAGE_MASK;
    while (count-- > 0) {
        pgn = pgcache_lookup(address);
        if (pgn && pgn->page) {
            memcpy_mcsafe(page_address(pgn->page), addr, PAGE_SIZE);
            set_pgn_clean(pgn);
            pgcache_lru_refer(pgn);
            #ifdef VPMEM_DEBUG
                renew++;
            #endif
        }
        addr += PAGE_SIZE;
        address += PAGE_SIZE;
    }
    return 0;
}

unsigned long vpmem_cached(unsigned long address, unsigned long count) {
    unsigned long cnt=0;
    struct pgcache_node *pgn = NULL;
    address &= PAGE_MASK;
    while (count-- > 0) {
        pgn = pgcache_lookup(address);
        if (likely(pgn)) cnt++;
        address += PAGE_SIZE;
    }
    return cnt;
}

// Not being used
int vpmem_pin_pages(unsigned long address, unsigned long count) {
    struct pgcache_node *pgn = NULL;
    address &= PAGE_MASK;
    while (count-- > 0) {
        pgn = pgcache_lookup(address);
        address += PAGE_SIZE;
    }
    return 0;
}

struct fpage {
    struct page *p;
    unsigned long address;
};
struct fpage pgs[8];
int pgsh=0,pgst=0;

bool vpmem_load_block(unsigned long address, struct page *p, int count)
{
    int ret = vpmem_read_from_bdev(address, count, p);
    // set_pgn_clean_addr(address);  

    if (unlikely(ret)) {
        printk("vpmem:\033[1;33m could not read from bdev %d %lu\033[0m\n", ret, ++dif_mm2);
        return false;
    } else {
        #ifdef VPMEM_DEBUG
            atomic_inc_return(&bdev_read);
        #endif
        return true;
    }
}

bool vpmem_load_block_range(unsigned long address, struct page **p, int count)
{
    int ret = vpmem_read_from_bdev_range(address, count, p);
    // int i;

    // for (i=0;i<count;++i) {
    //     set_pgn_clean_addr(address);       
    //     address += PAGE_SIZE;
    // }

    if (unlikely(ret)) {
        printk("vpmem:\033[1;33m could not read from bdev range %d %lu\033[0m\n", ret, ++dif_mm2);
        return false;
    } else {
        #ifdef VPMEM_DEBUG
            atomic_add_return(count, &bdev_read);
        #endif
        return true;
    }
}

// This function should only be called by the wb_thread.
bool clear_evict_list(int index, bool clear)
{
    struct pgcache_node *pgn;
    // struct page *p;
    pte_t *pte = NULL;
	unsigned long flags;

again:
    mutex_lock(&vsbi->vpmem_evict_mutex[index]);
    if (list_empty(&vsbi->vpmem_evict_list[index])) {
        mutex_unlock(&vsbi->vpmem_evict_mutex[index]);
        return false;
    }
    pgn = container_of(vsbi->vpmem_evict_list[index].next, struct pgcache_node, evict_node);
    if (unlikely(!pgn)) {
        printk(KERN_INFO "vpmem: pgcache_node error in clear_evict_list().\n");
        mutex_unlock(&vsbi->vpmem_evict_mutex[index]);
        return false;
    }
    wait_until_pgn_is_valid(pgn);
    if (unlikely(vpmem_get_pgn_index(pgn) != index)) {
        nova_info("Error in clear_evict_list addr %lx, virt %lu, index %d\n", 
            pgn->address, virt_to_blockoff(pgn->address), index);
    }
    if (vpmem_get_index(pgn->address) != index) {
        list_del_init(&pgn->evict_node);
        mutex_unlock(&vsbi->vpmem_evict_mutex[index]);
        push_to_lru_list(pgn);
    }

    local_irq_save(flags);
    if (pgn->page) {
        if (!clear && is_pgn_dirty(pgn)) {
            local_irq_restore(flags);
            list_del_init(&pgn->evict_node);
            mutex_unlock(&vsbi->vpmem_evict_mutex[index]);
            push_to_lru_list(pgn);
            push_to_wb_list(pgn);
            goto again;
        }
        if (!clear && is_pgn_young_reset(pgn)) {
            local_irq_restore(flags);
            list_del_init(&pgn->evict_node);
            mutex_unlock(&vsbi->vpmem_evict_mutex[index]);
            push_to_lru_list(pgn);
            goto again;
        }
    }  

    mutex_unlock(&vsbi->vpmem_evict_mutex[index]);
    mutex_lock(&vsbi->vpmem_rb_mutex[index]);
    pte = vpmem_get_pte(pgn);
    if (pte) {
        pte_clear(current_mm, pgn->address, pte);
    }
    __flush_tlb_one(pgn->address);
    pgn->pte = NULL;

    unlock_page(pgn->page);
    __free_page(pgn->page);
    pgn->page = NULL;

    vpmem_clear_pgn(pgn, index, flags);
    goto again;

    return true;
}

// This function should only be called by the wb_thread.
bool push_victim_to_wb_list(int index, bool all, bool del_lru)
{
    struct pgcache_node *pgn;
    struct list_head *tmp_lru = &vsbi->vpmem_lru_list[index];
    unsigned long counter = 0;   
    if (!all && is_pgcache_very_small(index)) return true;
    if (!del_lru) mutex_lock(&vsbi->vpmem_lru_mutex[index]);
again:
    // nova_info("wb %d %d \n",index,i);
    if (del_lru) {
        mutex_lock(&vsbi->vpmem_lru_mutex[index]);
        if (list_empty(&vsbi->vpmem_lru_list[index])) {
            mutex_unlock(&vsbi->vpmem_lru_mutex[index]);
            return false;
        }
        pgn = container_of(vsbi->vpmem_lru_list[index].next, struct pgcache_node, lru_node);
    }
    else {
        tmp_lru = tmp_lru->next;
        if (tmp_lru == &vsbi->vpmem_lru_list[index]) {
            mutex_unlock(&vsbi->vpmem_lru_mutex[index]);
            return false;
        }
        pgn = container_of(tmp_lru, struct pgcache_node, lru_node);
    }
    if (unlikely(!pgn)) {
        nova_info("vpmem: pgcache_node error in push_victim_to_wb_list().\n");
        mutex_unlock(&vsbi->vpmem_lru_mutex[index]);
        return false;
    }
    wait_until_pgn_is_valid(pgn);
    if (!pgn->page) {
        list_del_init(&pgn->lru_node);
        push_to_evict_list(pgn);
        mutex_unlock(&vsbi->vpmem_lru_mutex[index]);
        return true;
    }
    dif_mm3++;
    if (!all && is_pgn_young_reset(pgn) && counter<VPMEM_MAX_PAGES_QTR) {
        counter++;
        // This pgn is spared for now
        list_move_tail(&pgn->lru_node, &vsbi->vpmem_lru_list[index]);
        mutex_unlock(&vsbi->vpmem_lru_mutex[index]);
        goto again;
    }
    if (del_lru) list_del_init(&pgn->lru_node);

    if (is_pgn_dirty(pgn)) {
        push_to_wb_list(pgn);
    }
    else if (del_lru) push_to_evict_list(pgn);

    if (!all && is_pgcache_very_small(index)) {
        mutex_unlock(&vsbi->vpmem_lru_mutex[index]);
        return true;
    }

    if (del_lru) mutex_unlock(&vsbi->vpmem_lru_mutex[index]);
    goto again;

    return true;
}

int get_fault_smart_range(struct pgcache_node *pgn) {
    struct pgcache_node *tpgn;
    struct rb_node *rbn= NULL;
    int index;
	struct bdev_free_list *bfl;
    unsigned long address, blockoff, begin, end, bflbegin, bflend;
    unsigned int osb;
    int count1 = 0; // Unmapped pages in the right: [pgn, tpgn)
    int count2 = 0; // Mapped pages in the left: [tpgn, pgn)

    if (!MODE_SR_FAULT) return 1;

    if (!pgn) return 1;
    address = pgn->address;
    blockoff = virt_to_blockoff(address);
    osb = vsbi->bdev_list[get_tier(vsbi, blockoff)-TIER_BDEV_LOW].opt_size_bit + PAGE_SHIFT;
    begin = (address >> osb) << osb;
    end = ((address >> osb) + 1) << osb;

    index = get_bfl_index(vsbi, blockoff);
    bfl = nova_get_bdev_free_list_flat(vsbi,index);
    bflbegin = blockoff_to_virt(bfl->block_start);
    bflend = blockoff_to_virt(bfl->block_end + 1);
    if (begin < bflbegin) begin = bflbegin;
    if (end > bflend) end = bflend;

    /* Count 1: address -> next */
    mutex_lock(&vsbi->vpmem_rb_mutex[index]);
    rbn = rb_next(&pgn->rb_node);
    mutex_unlock(&vsbi->vpmem_rb_mutex[index]);
    if (rbn) {
        tpgn = container_of(rbn, struct pgcache_node, rb_node);
        if (tpgn) {
            if (tpgn->address > pgn->address && tpgn->address < end) end = tpgn->address;
        }
    }
    count1 = (end - address) >> PAGE_SHIFT;
    
    /* Count 2: valid <- address */
    tpgn = pgn;
    while (tpgn->address == address && tpgn->address > begin) {
        count2++;
        address -= PAGE_SIZE;
        mutex_lock(&vsbi->vpmem_rb_mutex[index]);
        rbn = rb_prev(&tpgn->rb_node);
        mutex_unlock(&vsbi->vpmem_rb_mutex[index]);
        if (!rbn) break;
        tpgn = container_of(rbn, struct pgcache_node, rb_node);
        if (!tpgn) break;
        // if (mutex_trylock(&tpgn->lock)) mutex_unlock(&tpgn->lock);
        // else break;
    }

    if (count2 == 0) return 1;
    
    if (unlikely(count1<1||count2<1)) {
        nova_info("Error in get_fault_smart_range count1 %d count2 %d\n", count1, count2);
        return 1;
    }

    return count1<count2?count1:count2;
}

/* 
 * Procedure of handling page fault
 * Step 1. Check rb tree
 *    1.1. Exist - refer the page
 *    1.2. Not exist - Allocate pgn(locked), put it in rb tree
 * Step 2. Get smart range
 * Step 3. Allocate pgns(locked) within the smart range
 * Step 4. Range read
 * Step 5. Insert page table entries and set pgn clean
 * Step 6. (*)Unlock the pages
 * Step 7. Refer the pages
 */
bool vpmem_do_page_fault(struct pt_regs *regs, unsigned long error_code, unsigned long address)
{
    struct pgcache_node *pgn;
    int i, sr;
    bool ret = true;
    struct pgcache_node **pgn_array;
    struct page **page_array;
    unsigned long curr_address;
    struct page *p = NULL;
    bool new = false;   
    /* Make sure we are in reserved area: */
    if (!vpmem_valid_address(address)) {
        nova_info("Error in vpmem_do_page_fault %lu\n", address);
    }
    #ifdef VPMEM_DEBUG
        atomic_inc_return(&faults);
    #endif
    address &= PAGE_MASK;
 
    pgn = pgcache_insert(address, current_mm, &new);
    if (unlikely(!new)) return true;

    p = pgn->page;
    if (unlikely(!p)) {
        nova_info("Error #1 in vpmem_do_page_fault\n");
    }

    if (unlikely(!ret)) nova_info("Error #2 in vpmem_do_page_fault\n");
    if (likely(pgn)) sr = get_fault_smart_range(pgn);
    else sr = 1;
    // nova_info("vpmem_do_page_fault address %lx sr %d\n", address, sr);
    if (unlikely(sr<1)) nova_info("Error #3 in vpmem_do_page_fault sr %d\n",sr);
    pgn_array = kcalloc(sr, sizeof(struct pgcache_node *), GFP_KERNEL);
    page_array = kcalloc(sr, sizeof(struct page *), GFP_KERNEL);
    pgn_array[0] = pgn;
    page_array[0] = p; 
    curr_address = address;
    for (i=1; i<sr; ++i) {
        curr_address += PAGE_SIZE;
        pgn = pgcache_insert(curr_address, current_mm, &new);
        pgn_array[i] = pgn;
        page_array[i] = pgn->page;
        if (!new) {
            nova_info("Warning in vpmem_do_page_fault %lx\n", curr_address);
            break;
        }
    }
    sr = i;
    vpmem_load_block_range(address, page_array, sr);
    for (i=0; i<sr; ++i) {
        insert_tlb(pgn_array[i]);
        // mutex_unlock(&pgn_array[i]->lock);
    }
    pgcache_lru_refer_range(address, sr);
    // nova_info("[Unlock] address %lx sr %d\n", address, sr);

    kfree(pgn_array);
    kfree(page_array);
    return true;
}

bool vpmem_do_page_fault_range(unsigned long address, unsigned long address_end, unsigned long entry_end) {
    struct pgcache_node *pgn;
    int i, sr = 0;
    int minr, maxr;
    struct pgcache_node **pgn_array;
    struct page **page_array;
    unsigned long curr_address;
    struct page *p = NULL;
    bool new = false;
    /* Make sure we are in reserved area: */
    if (!vpmem_valid_address(address)) {
        nova_info("Error #1 in vpmem_do_page_fault_range %lu\n", address);
    }
    
    address &= PAGE_MASK;
    address_end &= PAGE_MASK;

next:
    if (address > address_end) return true;

    minr = ((address_end-address)>>PAGE_SHIFT) + 1;
    maxr = (int)entry_end;
    
    pgn = pgcache_lookup(address);
    if (pgn) {
        address += PAGE_SIZE;
        entry_end--;
        // nova_info("In vpmem_do_page_fault_range address %lx sr %d minr %d maxr %d\n", 
        //     address, sr, minr, (int)entry_end);
        goto next;
    }

    #ifdef VPMEM_DEBUG
        range++;
    #endif

    pgn = pgcache_insert(address, current_mm, &new);
    if (!new) {
        address += PAGE_SIZE;
        entry_end--;
        // nova_info("In vpmem_do_page_fault_range address %lx sr %d minr %d maxr %d\n", 
        //     address, sr, minr, (int)entry_end);
        goto next;
    }

    p = pgn->page;
    if (unlikely(!p)) {
        nova_info("Error #1 in vpmem_do_page_fault\n");
    }

    // No need to allocate array in this case
    if (entry_end==1) {
        vpmem_load_block(pgn->address, pgn->page, 1);
        insert_tlb(pgn);
        pgcache_lru_refer(pgn);
        return true;
    }

    if (likely(pgn)) sr = get_fault_smart_range(pgn);
    else sr = 1;
    // nova_info("vpmem_do_page_fault_range address %lx sr %d minr %d maxr %d\n", address, sr, minr, maxr);
    if (sr<minr) sr = minr;
    if (sr>maxr) sr = maxr;
    if (unlikely(sr<1)) nova_info("Error #2 in vpmem_do_page_fault_range sr %d\n",sr);
    pgn_array = kcalloc(sr, sizeof(struct pgcache_node *), GFP_KERNEL);
    page_array = kcalloc(sr, sizeof(struct page *), GFP_KERNEL);
    pgn_array[0] = pgn;
    page_array[0] = p; 
    curr_address = address;
    for (i=1; i<sr; ++i) {
        curr_address += PAGE_SIZE;
        pgn = pgcache_insert(curr_address, current_mm, &new);
        pgn_array[i] = pgn;
        page_array[i] = pgn->page;
        if (!new) {
            // nova_info("Warning in vpmem_do_page_fault %d %lx\n", i, curr_address);
            break;
        }
    }
    sr = i;
    vpmem_load_block_range(address, page_array, sr);
    for (i=0; i<sr; ++i) {
        insert_tlb(pgn_array[i]);
    }
    pgcache_lru_refer_range(address, sr);

    kfree(pgn_array);
    kfree(page_array);
    return true;
}

bool vpmem_do_page_fault_lite(void *address_from, void *address_to)
{
    struct pgcache_node *pgn;
    bool new = false;   
    if (unlikely(!vpmem_valid_address((unsigned long)address_to))) {
        nova_info("Error in vpmem_do_page_fault_lite %p\n", address_to);
    }
    pgn = pgcache_lookup((unsigned long)address_to);
    if (pgn) return false;
    pgn = pgcache_insert((unsigned long)address_to, current_mm, &new);
    if (!new) {
        nova_info("Warning in vpmem_do_page_fault_lite\n");
        return false;
    }
    #ifdef VPMEM_DEBUG
        lite++;
    #endif
    memcpy_mcsafe(page_address(pgn->page), address_from, PAGE_SIZE);
    insert_tlb(pgn);
    // mutex_unlock(&pgn->lock);
    pgcache_lru_refer(pgn);
    return true;
}

static DEFINE_MUTEX(checkout_lock);
bool vpmem_checkout(unsigned long address)
{
    return true;
    nova_info("vpmem_checkout is called %lu\n", address);
    LOCK(checkout_lock);
    if(pgsh!=pgst) {
        struct fpage *p=&pgs[(pgsh++)%8];
        vpmem_load_block(p->address, p->p, 1);
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
    return 0;
}

void vpmem_init_counters(void) {
	atomic_set(&bdev_write, 0);
	atomic_set(&bdev_read, 0);
	atomic_set(&faults, 0);
	atomic_set(&writes, 0);
	atomic_set(&evicts, 0);
}

int vpmem_init_lists(struct nova_sb_info *sbi) {
    int i;
    int count = TIER_BDEV_HIGH*sbi->cpus;
    sbi->vpmem_lru_list = kcalloc(count, sizeof(struct list_head), GFP_KERNEL);
    sbi->vpmem_lru_mutex = kcalloc(count, sizeof(struct mutex), GFP_KERNEL);
	if (unlikely(!sbi->vpmem_lru_list))
		return -ENOMEM;
	if (unlikely(!sbi->vpmem_lru_mutex))
		return -ENOMEM;
    for (i=0;i<count;++i) {
	    INIT_LIST_HEAD(&sbi->vpmem_lru_list[i]);
	    mutex_init(&sbi->vpmem_lru_mutex[i]);
    }
    sbi->vpmem_wb_list = kcalloc(count, sizeof(struct list_head), GFP_KERNEL);
    sbi->vpmem_wb_mutex = kcalloc(count, sizeof(struct mutex), GFP_KERNEL);
	if (unlikely(!sbi->vpmem_wb_list))
		return -ENOMEM;
	if (unlikely(!sbi->vpmem_wb_mutex))
		return -ENOMEM;
    for (i=0;i<count;++i) {
	    INIT_LIST_HEAD(&sbi->vpmem_wb_list[i]);
	    mutex_init(&sbi->vpmem_wb_mutex[i]);
    }
    sbi->vpmem_evict_list = kcalloc(count, sizeof(struct list_head), GFP_KERNEL);
    sbi->vpmem_evict_mutex = kcalloc(count, sizeof(struct mutex), GFP_KERNEL);
	if (unlikely(!sbi->vpmem_evict_list))
		return -ENOMEM;
	if (unlikely(!sbi->vpmem_evict_mutex))
		return -ENOMEM;
    for (i=0;i<count;++i) {
	    INIT_LIST_HEAD(&sbi->vpmem_evict_list[i]);
	    mutex_init(&sbi->vpmem_evict_mutex[i]);
    }
    sbi->vpmem_rb_tree = kcalloc(count, sizeof(struct rb_root), GFP_KERNEL);
    sbi->vpmem_rb_mutex = kcalloc(count, sizeof(struct mutex), GFP_KERNEL);
	if (unlikely(!sbi->vpmem_rb_tree))
		return -ENOMEM;
	if (unlikely(!sbi->vpmem_rb_mutex))
		return -ENOMEM;
    for (i=0;i<count;++i) {
        sbi->vpmem_rb_tree[i] = RB_ROOT;
	    mutex_init(&sbi->vpmem_rb_mutex[i]);
    }
    return 0;
}

void vpmem_free_lists(void) {
    kfree(vsbi->vpmem_lru_list);
    kfree(vsbi->vpmem_lru_mutex);
    kfree(vsbi->vpmem_wb_list);
    kfree(vsbi->vpmem_wb_mutex);
    kfree(vsbi->vpmem_evict_list);
    kfree(vsbi->vpmem_evict_mutex);
    kfree(vsbi->vpmem_rb_tree);
    kfree(vsbi->vpmem_rb_mutex);
}

void vpmem_free_cache(void) {
    struct pgcache_node *pgn;
    struct rb_node *rbn = NULL;
    int i, count = 0;
    for (i=0; i<TIER_BDEV_HIGH*vsbi->cpus; ++i) {
        count = 0;
        rbn = vsbi->vpmem_rb_tree[i].rb_node;
        while (rbn) {
            pgn = container_of(rbn, struct pgcache_node, rb_node);
	        kmem_cache_free(nova_vpmem_pgnp, pgn);
            rbn = rb_next(rbn);
            count++;
        }
        nova_info("Index %d count %d\n", i, count);
    }
}

static void init_once_pgn(void *foo)
{
	memset(foo, 0, sizeof(struct pgcache_node));
}

int vpmem_get(struct nova_sb_info *sbi, unsigned long offset)
{
    int i, ret;
    unsigned long size=0;

    vpmem_init_counters();

    ret = vpmem_init_lists(sbi);
    if (unlikely(ret)) nova_info("Error in vpmem_init_lists\n");

    vsbi = sbi;

    nova_vpmem_pgnp = kmem_cache_create("nova_vpmem_pgn",
					       sizeof(struct pgcache_node),
					       0, SLAB_RECLAIM_ACCOUNT, init_once_pgn);
	if (nova_vpmem_pgnp == NULL)
		return -ENOMEM;

    wb_empty = kcalloc(TIER_BDEV_HIGH*sbi->cpus, sizeof(int), GFP_KERNEL);
    if (unlikely(!wb_empty))
		return -ENOMEM;

    flush_tlb_all();
    vpmem_start = VPMEM_START + (offset << 30);

    vpmem_operations.do_page_fault = vpmem_do_page_fault;
    vpmem_operations.do_checkout = vpmem_checkout;

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

    printk(KERN_INFO "vpmem: vpmem starts at %016lx, ends at %016lx\n",
        vpmem_start,
        vpmem_start + (size << 12));
        
    sbi->vpmem_num_blocks = size;
    
    sbi->pgcache_size = kcalloc(TIER_BDEV_HIGH*sbi->cpus, sizeof(atomic_t), GFP_KERNEL);

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

    wb_thread_init(sbi);

    printk(KERN_INFO "vpmem: vpmem_get finished (size = %lu MB)\n", size >> 20);

    return 0;
}

void vpmem_put(void)
{
    vpmem_print_status();
    printk(KERN_INFO "vpmem: [Before cleanup] pgcache_size = %d\n", pgc_total_size());
    wb_thread_cleanup();
    smp_mb();
    printk(KERN_INFO "vpmem: [After cleanup] pgcache_size = %d\n", pgc_total_size());
    vpmem_print_status();
    
    vpmem_operations.do_page_fault = 0;
    vpmem_operations.do_checkout = 0;

    flush_tlb_all();   
        
	kmem_cache_destroy(nova_vpmem_pgnp); 
    vpmem_free_lists();
    
    kfree(wb_empty);

    printk(KERN_INFO "vpmem: faults = %d bdev_reads = %d writes = %d bdev_writes = %d pte_not_present=%lu pte_not_found=%lu pgcache_full=%lu\n",
                atomic_read(&faults), atomic_read(&bdev_read), atomic_read(&writes), atomic_read(&bdev_write), pte_not_present, pte_not_found, pgcache_full);
    printk(KERN_INFO "vpmem: lru_refers = %lu evicts = %d dif_mm = %lu already_cached = %lu dif_mm2 = %lu leaked = %lu\n",
                lru_refers, atomic_read(&evicts), dif_mm, already_cached, dif_mm2, leaked);
    printk(KERN_INFO "vpmem: dif_mm3 = %lu dif_mm4 = %lu\n",
                dif_mm3, dif_mm4);
    printk(KERN_INFO "vpmem: hit = %lu miss1 = %lu miss2 = %lu size_of_pgn = %lu\n",
                hit, miss1, miss2, sizeof(struct pgcache_node));
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
    vpmem_end = 0;
    for(i=0; i<BDEV_COUNT_MAX; i++) {
        map_valid[i] = false;
        map_page[i] = 0;
    }
}
