#ifndef _MUTEX_CST_H_
#define _MUTEX_CST_H_

/**
 * Timestamp + cpu and numa node info that we can get with rdtscp()
 */
struct nid_clock_info {
        uint32_t nid;
        uint64_t timestamp;
};

#define INIT_ATOMIC_LIST_HEAD(ptr)                                             \
        do {                                                                   \
                (ptr)->next = (ptr);                                           \
        } while(0)


/**
 * mutex structure
 */
/* associated spin time during the traversal */
#define DEFAULT_SPIN_TIME          (1 << 15) /* max cost to put back to rq */
#define DEFAULT_HOLDER_SPIN_TIME   (DEFAULT_SPIN_TIME)
#define DEFAULT_WAITER_SPIN_TIME   (DEFAULT_SPIN_TIME)
#define DEFAULT_WAITER_WAKEUP_TIME (DEFAULT_SPIN_TIME)
/* This is an approximation */
#define CYCLES_TO_COUNTERS(v)      (v / (1U << 4))

#define NUMA_GID_BITS               (4)  /* even = empty, odd = not empty */
#define NUMA_GID_SHIFT(_n)          ((_n) * NUMA_GID_BITS)
#define NUMA_MAX_DOMAINS            (64 / NUMA_GEN_ID_BITS)
#define NUMA_NID_MASK(_n)           ((0xF) << NUMA_GID_SHIFT(_n))
#define NUMA_GID_MASK(_n, _g)       (((_g) & (0xF)) << NUMA_GID_SHIFT(_n))
#define numa_gid_inc(_gid)          (((_gid) & ~0x1) + 2)
#define numa_gid_not_empty(_gid)    ((_gid) & 0x1)

#define NUMA_BATCH_SIZE             (128) /* per numa throughput */
#define NUMA_WAITING_SPINNERS       (4) /* spinners in the waiter spin phase */

/* lock status */
#define STATE_PARKED (0)
#define STATE_LOCKED (1)

/* this will be around 8 milliseconds which is huge!!! */
#define MAX_SPIN_THRESHOLD          (1U << 20)
/* this is the cost of a getpriority syscall. */
#define MIN_SPIN_THRESHOLD          (1U << 7)

#define smp_swap(ptr, v)        xchg((ptr), (v))
#define smp_faa(ptr, inc)       xadd((ptr), (inc))
#define smp_cas(ptr, old, new)  (cmpxchg((ptr), (old), (new)) == (old))


#endif /* _MUTEX_CST_H_ */
