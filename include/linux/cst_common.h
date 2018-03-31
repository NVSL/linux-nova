#ifndef __LINUX_CST_COMMON_H
#define __LINUX_CST_COMMON_H

struct atomic_list_head {
        struct atomic_list_head *next;
};

/**
 * linux-like circular list manipulation
 */
struct qnode {
	struct qnode *next;

	uint64_t status ____cacheline_aligned_in_smp;
	struct task_struct *task;
	struct list_head wait_node;
} ____cacheline_aligned_in_smp;

struct numa_head {
	struct atomic_list_head head;
};

DECLARE_PER_CPU_ALIGNED(u64, snode_alloc_count);

/*
 * Used by the spinlock
 */
#define NUMA_BATCH_SIZE             (128) /* per numa throughput */
#define PARKING_BITS    32
#define COHORT_START    1
#define FIRST_ELEM 	1
#define ACQUIRE_PARENT  ((1ULL << (PARKING_BITS)) - 4)
#define CST_WAIT        (ACQUIRE_PARENT + 2)
#define REQUEUE         (ACQUIRE_PARENT + 3)

#define UNPARKED        0ULL
#define PARKED          1ULL
#define RESET_UNPARKED  2ULL
#define VERY_NEXT       3ULL

#define PARKING_STATE(n)        ((n) >> (PARKING_BITS))
#define LOCKING_STATE(n)        ((n) & (0xffffffff))
#define PARKING_STATE_MASK(n)   ((n) << (PARKING_BITS))
#define UNPARKED_WAITER_STATE   ((PARKING_STATE_MASK(UNPARKED)) | (CST_WAIT))
#define PARKED_WAITER_STATE     ((PARKING_STATE_MASK(PARKED)) | (CST_WAIT))
#define VNEXT_WAITER_STATE      ((PARKING_STATE_MASK(VERY_NEXT)) | (CST_WAIT))
#define REQUEUE_WAITER_STATE    ((PARKING_STATE_MASK(RESET_UNPARKED)) | (CST_WAIT))
#define qnode_lock_state(q)     LOCKING_STATE(((q)->status))
#define qnode_park_state(q)     PARKING_STATE(((q)->status))

#define QNODE_UNPARKED          0
#define QNODE_REQUEUE           1
#define QNODE_LOCK_ACQUIRD      2

#define CST_MAX_NODES 4
#define get_numa_id()	((numa_node_id()) + 1)
#define snode_id(_n)	(((_n) - 1) * (CST_MAX_NODES) + idx)
#define get_idx_acq()	(qnode->count++)
#define get_idx_rel()	((qnode->count) - 1)

struct __cstmcs_lock {
	union {
		atomic_t val;
		u8 gtail[4];
	};
};

struct cst_qnode {
	struct cst_qnode *next;
	int status;
	int count;
} ____cacheline_aligned;

#endif /* __LINUX_CST_COMMON_H */
