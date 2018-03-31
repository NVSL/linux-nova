/*
 * rwsem_cst.h: R/W semaphores, public interface
 */

#ifndef _LINUX_RWSEM_CST_H
#define _LINUX_RWSEM_CST_H

#include <linux/linkage.h>

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/err.h>
//#include <linux/lfswait.h>

#include <linux/cst_common.h>

struct rw_snode {
	/*
	 * ONE CACHELINE
	 */
	struct qnode *qnext;
	struct qnode *qtail;
	/* batch count */
	int32_t num_proc; /* #batched processes */
	/* current lock holder task */
	struct task_struct *holder;

	/*
	 * ANOTHER CACHELINE
	 * Maintain the readers info
	 */
	int32_t active_readers ____cacheline_aligned;

	/*
	 * ANOTHER CACHELINE
	 * tail management
	 */
	/* MCS tail to know who is the next waiter */
	struct rw_snode *gnext ____cacheline_aligned;
	/* status update of the waiter */
	int32_t status;

	/*
	 * ANOTHER CACHELINE
	 * snode bookeeping for various uses
	 */
	/* list node like Linux list */
	struct atomic_list_head numa_node;
	/* node id */
	int32_t nid; /* alive: > 0 | zombie: < 0 */
	/* wait queue */
	raw_spinlock_t wait_lock;
	struct list_head wwait_list;
	struct list_head rwait_list;
} ____cacheline_aligned;

struct rwcst_semaphore {
	/* snode which holds the hold */
	struct rw_snode *serving_socket;
	/* tail for the MCS style */
	/*
	 * IMO: there is no way to remove the READ_ONCE
	 * from any call for gtail. The reason is that this one
	 * introduces a window of vulnerability in almost
	 * every case (I can come up with almost every case
	 * where it can fail).
	 */
	struct rw_snode *gtail;
	/* Fancy way to allocate the snode */
	uint64_t ngid_vec;

	/* Maintain the snode list that tells how many sockets are active */
	struct numa_head numa_list;
};

#define for_each_snode(pos, head) \
	for (pos = (head)->next; \
	     pos != head; \
	     pos = (pos)->next)

#define for_each_snode_safe(pos, tmp, head) \
	for (pos = (head)->next, \
	     tmp = (pos)->next; \
	     pos != head; \
	     pos = tmp, tmp = (pos)->next)

extern struct rwcst_semaphore *rwsem_cst_down_read_cst_failed(struct rwcst_semaphore *sem);
extern struct rwcst_semaphore *rwsem_cst_down_write_cst_failed(struct rwcst_semaphore *sem);
extern struct rwcst_semaphore *rwsem_cst_down_write_cst_failed_killable(struct rwcst_semaphore *sem);
extern struct rwcst_semaphore *rwsem_cst_wake(struct rwcst_semaphore *);
extern struct rwcst_semaphore *rwsem_cst_downgrade_wake(struct rwcst_semaphore *sem);

/* In all implementations count != 0 means locked */
static inline int rwsem_cst_is_locked(struct rwcst_semaphore *sem)
{
	struct rw_snode *snode = NULL;
	struct atomic_list_head *pos;

	if (sem->gtail != NULL)
		return 1;

	for_each_snode(pos, &sem->numa_list.head) {
		if (READ_ONCE(snode->active_readers))
			return 1;
	}
	return 0;
}

/* Common initializer macros and functions */

#define __RWSEM_CST_INITIALIZER(lockname)			\
	{ .serving_socket = NULL \
	, .gtail = NULL \
	, .ngid_vec = 0 \
	, .numa_list.head.next = &(lockname).numa_list.head \
	}

#define DECLARE_RWSEM_CST(name) \
	struct rwcst_semaphore name = __RWSEM_CST_INITIALIZER(name)

extern void __init_rwsem_cst(struct rwcst_semaphore *sem, const char *name,
			 struct lock_class_key *key);

#define init_rwsem_cst(sem)					\
do {								\
	static struct lock_class_key __key;			\
								\
	__init_rwsem_cst((sem), #sem, &__key);			\
} while (0)

/*
 * This is the same regardless of which rwsem_cst implementation that is being used.
 * It is just a heuristic meant to be called by somebody alreadying holding the
 * rwsem_cst to see if somebody from an incompatible type is wanting access to the
 * lock.
 */
static inline int rwsem_cst_is_contended(struct rwcst_semaphore *sem)
{
	return (sem->gtail != NULL);
}

/*
 * lock for reading
 */
extern void down_read_cst(struct rwcst_semaphore *sem);

/*
 * trylock for reading -- returns 1 if successful, 0 if contention
 */
extern int down_read_cst_trylock(struct rwcst_semaphore *sem);

/*
 * lock for writing
 */
extern void down_write_cst(struct rwcst_semaphore *sem);
extern int __must_check down_write_cst_killable(struct rwcst_semaphore *sem);

/*
 * trylock for writing -- returns 1 if successful, 0 if contention
 */
extern int down_write_cst_trylock(struct rwcst_semaphore *sem);

/*
 * release a read lock
 */
extern void up_read_cst(struct rwcst_semaphore *sem);

/*
 * release a write lock
 */
extern void up_write_cst(struct rwcst_semaphore *sem);

/*
 * downgrade write lock to read lock
 */
extern void downgrade_write_cst(struct rwcst_semaphore *sem);

/*
 * with our lock design, we need to have a destroy mechanism as well
 */
extern void __deinit_rwsem_cst(struct rwcst_semaphore *sem); 

# define down_read_cst_nested(sem, subclass)		down_read_cst(sem)
# define down_write_cst_nest_lock(sem, nest_lock)	down_write_cst(sem)
# define down_write_cst_nested(sem, subclass)	down_write_cst(sem)
# define down_write_cst_killable_nested(sem, subclass)	down_write_cst_killable(sem)
# define down_read_cst_non_owner(sem)		down_read_cst(sem)
# define up_read_cst_non_owner(sem)			up_read_cst(sem)

#endif /* _LINUX_RWSEM_CST_H */
