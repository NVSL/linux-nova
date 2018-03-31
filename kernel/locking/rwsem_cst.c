/*
 * kernel/rwsem_cst.c: R/W semaphores, public implementation
 *
 * Developed by Sanidhya & Changwoo
 *
 * Copyright (C) 2016   Sanidhya Kashyap    <sanidhya@gatech.edu>,
 *                      Changwoo Min        <changwoo@gatech.edu>
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/sched/wake_q.h>
#include <linux/sched/stat.h>
#include <linux/export.h>
#include <linux/rwsem_cst.h>
#include <linux/atomic.h>
#include <linux/slab.h>

#include "rwsem_cst.h"

#define cpu_relax_lowlatency()	cpu_relax()

/*
 * Nice levels are multiplicative, with a gentle 10% change for every
 * nice level changed. I.e. when a CPU-bound task goes from nice 0 to
 * nice 1, it will get ~10% less CPU time than another CPU-bound task
 * that remained on nice 0.
 *
 * The "10% effect" is relative and cumulative: from _any_ nice level,
 * if you go up 1 level, it's -10% CPU usage, if you go down 1 level
 * it's +10% CPU usage. (to achieve that we use a multiplier of 1.25.
 * If a task goes up by ~10% and another task goes down by ~10% then
 * the relative distance between them is ~25%.)
 *
 * We will use this table to set the value of
 * task->se.upgrade_sched_policy_quota as the difference of two nice
 * values and will allow the schedule code to directly handle it.
 */
const int sched_prio_to_sched_count[40] = {
 /* -20 */     1,     1,     1,     1,     2,
 /* -15 */     2,     2,     3,     3,     4,
 /* -10 */     4,     5,     6,     7,     8,
 /*  -5 */     9,     10,    11,    12,    13,
 /*   0 */     14,    15,    17,    19,    21,
 /*   5 */     23,    25,    28,    31,    34,
 /*  10 */     37,    41,    45,    50,    55,
 /*  15 */     61,    67,    74,    81,    90,
};

/*
 * Declarations
 */
static inline uint16_t numa_get_gid(uint64_t ngid_vec, uint16_t nid);

static inline struct rw_snode *get_snode(struct rwcst_semaphore *lock, uint16_t nid);
static inline struct rw_snode *find_snode(struct rwcst_semaphore *lock, uint16_t nid);
static inline struct rw_snode *add_snode(struct rwcst_semaphore *lock, uint16_t nid,
					 uint16_t gid);
static inline struct rw_snode *alloc_snode(struct rwcst_semaphore *lock, int32_t nid);

static inline void *malloc_at_numa_node(size_t size, int32_t nid);

static inline void cst_write_local_unlock(struct rwcst_semaphore *lock,
					  struct rw_snode *snode);

static void revert_task_schedule(struct task_struct *task)
{
        if (atomic_read(&task->no_cs_mig) == 0)
                return;

        atomic_dec(&task->no_cs_mig);
        if (atomic_read(&task->no_cs_mig) == 0) {
                set_cpus_allowed_ptr(task, &task->old_cpumask);
        }
}

static void update_task_schedule(struct task_struct *task)
{
        if (task->nr_cpus_allowed == 1)
                return;

        atomic_inc(&task->no_cs_mig);
        if (atomic_read(&task->no_cs_mig) == 1) {
                cpumask_clear(&task->old_cpumask);
                cpumask_clear(&task->temp_cpumask);

                cpumask_copy(&task->old_cpumask, &task->cpus_allowed);
                cpumask_set_cpu(smp_processor_id(), &task->temp_cpumask);

                set_cpus_allowed_ptr(task, &task->temp_cpumask);
        }
}

static void __always_inline numa_get_nid(struct nid_clock_info *v)
{
	const static uint32_t NUMA_ID_BASE = 1;
	v->nid = numa_node_id() + NUMA_ID_BASE;
}

static inline void list_add_unsafe(struct atomic_list_head *new,
				   struct atomic_list_head *head)
{
	struct atomic_list_head *old;

	/* there can be concurrent enqueuers */
	new->next = head->next;
	old = smp_swap(&head->next, new);
	new->next = old;
	smp_wmb();
}

static inline int try_acquire_global(struct rwcst_semaphore *lock,
				     struct rw_snode *snode)
{
	snode->gnext = NULL;
	snode->status = STATE_PARKED;

	if (likely(cmpxchg(&lock->gtail, NULL, snode) == NULL)) {
		smp_store_release(&snode->status, STATE_LOCKED);
		return 1;
	}

	return 0;
}

static inline int try_acquire_local(struct rw_snode *snode)
{
	if (likely(cmpxchg(&snode->qtail, NULL, (void *)&snode->qnext) == NULL))
		return 1;
	return 0;
}

static inline int cst_write_trylock(struct rwcst_semaphore* lock)
{
	struct rw_snode *snode;
	int32_t nid;
	struct nid_clock_info info;
	int ret = 0;

	preempt_disable();

	numa_get_nid(&info);
	nid = info.nid;
	snode = find_snode(lock, nid);
	if (snode == NULL)
		goto out;

	ret = try_acquire_local(snode);
	if (!ret)
		goto out;

	/* Till here, it is successful, now trying to grab the global lock */
	ret = try_acquire_global(lock, snode);
	if (ret) {
                struct task_struct *task = current;
		increase_task_pin_count();
                update_task_schedule(task);
		goto out;
	}

	cst_write_local_unlock(lock, snode);

     out:
	preempt_enable();
	return ret;
}

static inline void acquire_global(struct rwcst_semaphore *lock,
				  struct rw_snode *snode)
{
	struct rw_snode *old_snode;
	snode->gnext = NULL;
	snode->status = STATE_PARKED;

	old_snode = xchg(&lock->gtail, snode);
	if (likely(!old_snode)) {
		smp_store_release(&snode->status, STATE_LOCKED);
		return;
	}

	WRITE_ONCE(old_snode->gnext, snode);
	while(smp_load_acquire(&snode->status) == STATE_PARKED) {
		if (need_resched())
			schedule_preempt_disabled();
		cpu_relax_lowlatency();
	}
}

static inline int update_qnode_state_park(struct qnode *qnode)
{
	return (qnode->status == UNPARKED_WAITER_STATE &&
		(cmpxchg(&qnode->status, UNPARKED_WAITER_STATE,
			 PARKED_WAITER_STATE) == UNPARKED_WAITER_STATE));
}

static inline int park_write_qnode(struct rwcst_semaphore *lock,
				   struct rw_snode *snode,
				   struct qnode *qnode, int state)
{
	set_task_state(qnode->task, state);
	if (raw_spin_trylock_irq(&snode->wait_lock)) {
		if (!update_qnode_state_park(qnode)) {
			goto unlock_out;
		}
		list_add_tail(&qnode->wait_node, &snode->wwait_list);
		raw_spin_unlock(&snode->wait_lock);
		schedule_preempt_disabled();
		set_task_state(qnode->task, TASK_RUNNING);
		return QNODE_REQUEUE;
	}
	set_task_state(qnode->task, TASK_RUNNING);
	return QNODE_UNPARKED;
     unlock_out:
	raw_spin_unlock(&snode->wait_lock);
	set_task_state(qnode->task, TASK_RUNNING);
	return QNODE_UNPARKED;
}

#define START_SCHEDOUT_COUNT 	4

static inline int acquire_local(struct rwcst_semaphore *lock,
				struct rw_snode *snode, int state,
				struct task_struct *task)
{
	struct qnode *old_qnode, *next_qnode;
	struct qnode cur_qnode;
	int allow_local_acquire = 0;
	int schedout_count = 0;
	int handle_sched;
	int nr_tasks = 0;

	cur_qnode.task = task;
     requeue:
	cur_qnode.status = UNPARKED_WAITER_STATE;
	cur_qnode.next = NULL;
	handle_sched = START_SCHEDOUT_COUNT;

	old_qnode = smp_swap(&snode->qtail, &cur_qnode);
	if (old_qnode) {

		WRITE_ONCE(old_qnode->next, &cur_qnode);

		for (;;) {
			if (LOCKING_STATE(READ_ONCE(cur_qnode.status)) != CST_WAIT)
				break;

			if (need_resched()) {
				nr_tasks = nr_running_tasks_current_rq();
				if (nr_tasks > 1) {
                                        int ret;
					if (++schedout_count < handle_sched) {
						handle_sched -= nr_tasks;
						schedule_preempt_disabled();
						continue;
					}
					ret = park_write_qnode(lock, snode,
								   &cur_qnode, state);
					if (ret == QNODE_UNPARKED) {
						schedule_preempt_disabled();
						continue;
					} else {
						if (LOCKING_STATE(READ_ONCE(cur_qnode.status) ==
								  ACQUIRE_PARENT))
							break;
						else if (LOCKING_STATE(READ_ONCE(cur_qnode.status) ==
								       REQUEUE))
							goto requeue;
					}
				} else {
					++handle_sched;
					schedule_preempt_disabled();
				}
			}
			cpu_relax_lowlatency();
		}
		if (LOCKING_STATE(cur_qnode.status) < ACQUIRE_PARENT)
			allow_local_acquire = 1;
	}

	next_qnode = READ_ONCE(cur_qnode.next);

	if (likely(!next_qnode)) {
		WRITE_ONCE(snode->qnext, NULL);
		if (cmpxchg_release(&snode->qtail, &cur_qnode,
			    (void *)&snode->qnext) != &cur_qnode) {

			while(!READ_ONCE(cur_qnode.next))
				cpu_relax_lowlatency();
			WRITE_ONCE(snode->qnext, cur_qnode.next);
		}
	} else
		WRITE_ONCE(snode->qnext, next_qnode);

	if (allow_local_acquire)
		goto out;

	acquire_global(lock, snode);
	WRITE_ONCE(lock->serving_socket, snode);

     out:
	return 0;
}

static inline int cstlock_acquire(struct rwcst_semaphore* lock, int state)
{
	struct nid_clock_info info;
	struct rw_snode *snode;
	struct task_struct *task;
	int32_t nid;
	int flag = false;

	preempt_disable();
	numa_get_nid(&info);
	nid = info.nid;
	task = current;
        update_task_schedule(task);

	if (READ_ONCE(task->rwlock) == lock &&
	    READ_ONCE(task->snode_nid) == nid)
		snode = task->snode;
	else {
		snode = get_snode(lock, nid);
		flag = true;
	}

	/* currently, need to get the ticket */
	increase_task_pin_count();
	acquire_local(lock, snode, state, task);

	preempt_enable();
	if (flag) {
		task->rwlock = lock;
		task->snode_nid = info.nid;
		task->snode = snode;
                smp_wmb();
	}
	return 0;
}


static inline void cst_write_global_unlock(struct rwcst_semaphore *lock, struct rw_snode *snode)
{
	struct rw_snode *next_snode = READ_ONCE(snode->gnext);

	if (likely(!next_snode)) {
		if (likely(cmpxchg_release(&lock->gtail, snode, NULL) == snode))
			return;

		while(!(next_snode = READ_ONCE(snode->gnext)))
			cpu_relax_lowlatency();
	}
	smp_store_release(&next_snode->status, STATE_LOCKED);
}

static inline void update_state_park_to_unpark(struct qnode *qnode, uint64_t count)
{
	if (cmpxchg(&qnode->status, PARKED_WAITER_STATE,
	     ((PARKING_STATE_MASK(UNPARKED)) | count)) != PARKED_WAITER_STATE)
		BUG();
}

static inline void wake_up_waiters_snode(struct rw_snode *snode)
{
	DEFINE_WAKE_Q(wake_q);

	raw_spin_lock(&snode->wait_lock);
	if (!list_empty(&snode->wwait_list)) {
		struct qnode *pos, *tmp;
		list_for_each_entry_safe(pos, tmp, &snode->wwait_list,
					 wait_node) {
			update_state_park_to_unpark(pos, REQUEUE);
			list_del(&pos->wait_node);
			wake_q_add(&wake_q, pos->task);
			//wake_up_process(pos->task);
		}
	}
	raw_spin_unlock(&snode->wait_lock);
	wake_up_q(&wake_q);
}

static inline void wake_up_waiter(struct rw_snode *snode)
{
	struct qnode *qnode = NULL;

	if (list_empty(&snode->wwait_list))
		return;

	if (raw_spin_trylock(&snode->wait_lock)) {
		if (!list_empty(&snode->wwait_list)) {
			qnode = list_entry(snode->wwait_list.next,
					   struct qnode, wait_node);
			list_del(&qnode->wait_node);
			update_state_park_to_unpark(qnode, REQUEUE);
		}
	}
	raw_spin_unlock(&snode->wait_lock);
	if (qnode)
		wake_up_process(qnode->task);
}


static inline int update_qnode_state_release(struct qnode *qnode, uint64_t count)
{
	uint64_t new_status = (PARKING_STATE_MASK(UNPARKED)) | count;
	return ((READ_ONCE(qnode->status) == UNPARKED_WAITER_STATE) &&
		(cmpxchg(&qnode->status, UNPARKED_WAITER_STATE, new_status) ==
		 UNPARKED_WAITER_STATE));
}

static inline int wake_or_update_wwait_list(struct rw_snode *snode, struct qnode *qnode,
					   uint64_t count)
{
	struct qnode *tmp = qnode;
	for (;;) {
		if (update_qnode_state_release(tmp, count))
			return true;
		if (!READ_ONCE(tmp->next)) {
			if (READ_ONCE(snode->qtail) != tmp) {
				while (!READ_ONCE(tmp->next))
					cpu_relax_lowlatency();
			} else
				break;
		} else
			tmp = READ_ONCE(tmp->next);
	}
	return false;
}

static inline void cst_write_local_unlock(struct rwcst_semaphore *lock,
					  struct rw_snode *snode)
{
	struct qnode *next_qnode = READ_ONCE(snode->qnext);

	if (likely(!next_qnode)) {
		if (likely(cmpxchg_release(&snode->qtail, (void *)&snode->qnext, NULL) ==
		    (void *)&snode->qnext)) {
			wake_up_waiters_snode(snode);
			return;
		}

		while(!(next_qnode = READ_ONCE(snode->qnext)))
			cpu_relax_lowlatency();
	}
	if (!update_qnode_state_release(next_qnode, ACQUIRE_PARENT)) {
		if (!wake_or_update_wwait_list(snode, next_qnode, ACQUIRE_PARENT)) {
			raw_spin_lock(&snode->wait_lock);
			update_state_park_to_unpark(next_qnode, ACQUIRE_PARENT);
			list_del(&next_qnode->wait_node);
			raw_spin_unlock(&snode->wait_lock);
			wake_up_process(next_qnode->task);
		}
	}
}

static inline void cstlock_release(struct rwcst_semaphore *lock, bool dec_cnt)
{
	struct rw_snode *snode;
	struct qnode *next_qnode;
	uint64_t cur_count;

	preempt_disable();
	/* does not require any barrier since this should be the same core
	 * that is going to handle the lock release (hopefully) */
	snode = READ_ONCE(lock->serving_socket);

	cur_count = ++snode->num_proc;
	if(cur_count == NUMA_BATCH_SIZE) {
		cst_write_global_unlock(lock, snode);
		//if (!list_empty(&snode->wwait_list))
		//	wake_up_waiters_snode(snode);
		cst_write_local_unlock(lock, snode);
		snode->num_proc = 0;
		goto out;
	}

	next_qnode = READ_ONCE(snode->qnext);
	if (likely(next_qnode)) {
		if (!update_qnode_state_release(next_qnode, cur_count)) {
			if (!wake_or_update_wwait_list(snode, next_qnode,
						      cur_count))
				goto unlock_out;
		}
		//wake_up_waiter(snode);
		goto out;
	}
     unlock_out:
	cst_write_global_unlock(lock, snode);
	cst_write_local_unlock(lock, snode);

     out:
	decrease_task_pin_count(dec_cnt);
        revert_task_schedule(current);
	preempt_enable();
}

static inline void check_reader_count(struct rwcst_semaphore *sem,
				      struct rw_snode *snode, int reader_count)
{
	struct atomic_list_head *pos;

	if (reader_count > 0)
		return;

	/* since, we did a wrong count, therefore, we should increase it back */
	smp_faa(&snode->active_readers, 1);

	/*
	 * Now, this is the tricky part.
	 * What has happened is that the task was misplaced by the stupid CFS
	 * and now, we have to find the right snode where we can decrease the
	 * value and someone else will take care for us eventually
	 */
     retry:
	for_each_snode(pos, &sem->numa_list.head) {
		snode = container_of(pos, struct rw_snode, numa_node);
		reader_count = READ_ONCE(snode->active_readers);
		if (reader_count > 0 &&
		    smp_cas(&snode->active_readers,
			    reader_count, reader_count - 1))
			return;
		if (need_resched())
			schedule_preempt_disabled();
	}
	goto retry;
}

static inline int park_readsnode(struct rwcst_semaphore *lock,
				 struct rw_snode *snode)
{
#if 0
	cpumask_t cur_cpumask, old_cpumask;

	old_cpumask  = current->cpus_allowed;
	cpumask_set_cpu(smp_processor_id(), &cur_cpumask);
	set_cpus_allowed_ptr(current, &cur_cpumask);


	preempt_enable();
	wait_event(snode->read_wqueue, lock->gtail);
	preempt_disable();

	if (cmpxchg(&snode->read_parked_leader, 0, 1) == 0) {
		smp_faa(&snode->active_readers, 1);
		wake_up_all(&snode->read_wqueue);
		snode->read_parked_leader = 0;
		set_cpus_allowed_ptr(current, &old_cpumask);
		return 0;
	}
	set_cpus_allowed_ptr(current, &old_cpumask);
#endif
	return 1;
}

/*
 * lock for reading
 */
static inline void down_read_cst_snode(struct rwcst_semaphore *sem,
				       struct rw_snode *snode)
{
	int reader_count;
	int ret = 1;
	while(true) {
		while (READ_ONCE(sem->gtail)) {
			if (need_resched()) {
				if (nr_running_tasks_current_rq() > 1) {
					ret = park_readsnode(sem, snode);
				}
				schedule_preempt_disabled();
			}
			cpu_relax_lowlatency();
		}
		if (ret)
			smp_faa(&snode->active_readers, 1);
		if (READ_ONCE(sem->gtail)) {
			reader_count = smp_faa(&snode->active_readers, -1);
			check_reader_count(sem, snode, reader_count);
			if (need_resched())
				schedule_preempt_disabled();
			continue;
		}
		break;
	}
}

void __sched down_read_cst(struct rwcst_semaphore *sem)
{
	struct rw_snode *snode;
	struct nid_clock_info info;
	struct task_struct *task;
	int flag = false;

	might_sleep();

	preempt_disable();
	numa_get_nid(&info);

	increase_task_pin_count();
	task = current;
        update_task_schedule(task);

	if (task->rwlock == sem &&
	    task->snode_nid == info.nid)
		snode = task->snode;
	else {
		snode = get_snode(sem, info.nid);
		flag = true;
	}
	down_read_cst_snode(sem, snode);
	preempt_enable();
	if (flag) {
		task->rwlock = sem;
		task->snode_nid = info.nid;
		task->snode = snode;
	}

}
EXPORT_SYMBOL(down_read_cst);

/*
 * trylock for reading -- returns 1 if successful, 0 if contention
 */
int down_read_cst_trylock(struct rwcst_semaphore *sem)
{
	struct rw_snode *snode;
	struct nid_clock_info info;
	int reader_count;
        struct task_struct *task;

	/* Here I can remove the READ_ONCE, but what it will
	 * do is that it go ahead thereby wasting time.
	 * I don't know how much does it really affect if I remove
	 * this one.
	 * Still going to take the chance :-).
	 */
	/* if (READ_ONCE(sem->gtail) != NULL) */
	if (sem->gtail != NULL)
		goto out;

	preempt_disable();
	numa_get_nid(&info);
        task = current;

	snode = find_snode(sem, info.nid);
	if (snode == NULL)
		goto preempt_out;

	smp_faa(&snode->active_readers, 1);
	/*
	 * This one is SUPER CRITICAL.
	 */
	if (READ_ONCE(sem->gtail) != NULL) {
		reader_count = smp_faa(&snode->active_readers, -1);
		check_reader_count(sem, snode, reader_count);
		goto preempt_out;
	}

	increase_task_pin_count();
        update_task_schedule(task);
	preempt_enable();
	return 1;

     preempt_out:
	preempt_enable();
     out:
	return 0;
}
EXPORT_SYMBOL(down_read_cst_trylock);

static inline void check_active_readers(struct rwcst_semaphore *lock)
{
	struct atomic_list_head *pos;
	struct rw_snode *snode = NULL;

	preempt_disable();
	for_each_snode(pos, &lock->numa_list.head) {
		snode = container_of(pos, struct rw_snode, numa_node);
		while (READ_ONCE(snode->active_readers)) {
			if (need_resched())
				schedule_preempt_disabled();
			cpu_relax_lowlatency();
		}
	}
	preempt_enable();
}

/*
 * lock for writing
 */
void __sched down_write_cst(struct rwcst_semaphore *sem)
{
	might_sleep();
	cstlock_acquire(sem, TASK_UNINTERRUPTIBLE);
	check_active_readers(sem);
}
EXPORT_SYMBOL(down_write_cst);

/*
 * lock for writing
 */
int __sched down_write_cst_killable(struct rwcst_semaphore *sem)
{
	might_sleep();
	cstlock_acquire(sem, TASK_KILLABLE);
	check_active_readers(sem);
	return 0;
}
EXPORT_SYMBOL(down_write_cst_killable);

/*
 * trylock for writing -- returns 1 if successful, 0 if contention
 */
int down_write_cst_trylock(struct rwcst_semaphore *sem)
{
	struct rw_snode *snode = NULL;
	struct atomic_list_head *pos;
	int ret;

	ret = cst_write_trylock(sem);
	if (!ret)
		goto out;

	for_each_snode(pos, &sem->numa_list.head) {
		snode = container_of(pos, struct rw_snode, numa_node);
		if (READ_ONCE(snode->active_readers) != 0) {
			cstlock_release(sem, true);
			return 0;
		}
	}
     out:
	return ret;
}
EXPORT_SYMBOL(down_write_cst_trylock);

/*
 * release a read lock
 */
void up_read_cst(struct rwcst_semaphore *sem)
{
	struct rw_snode *snode;
	struct nid_clock_info info;
	int reader_count;
	struct task_struct *task;

	numa_get_nid(&info);
	task = current;
	if (task->rwlock == sem &&
	    task->snode_nid == info.nid)
		snode = task->snode;
	else
		snode = get_snode(sem, info.nid);
	reader_count = smp_faa(&snode->active_readers, -1);
	check_reader_count(sem, snode, reader_count);
	decrease_task_pin_count(true);
        revert_task_schedule(task);

}
EXPORT_SYMBOL(up_read_cst);

/*
 * release a write lock
 */
void up_write_cst(struct rwcst_semaphore *sem)
{
	//struct atomic_list_head *pos;
	//struct rw_snode *snode = NULL;
	//int nid = numa_node_id() + 1;

	cstlock_release(sem, true);
#if 0
	if (sem->gtail == NULL) {
		for_each_snode(pos, &sem->numa_list.head) {
			struct rw_snode *s = container_of(pos,
							  struct rw_snode,
							  numa_node);
			if (s->nid == nid) {
				snode = s;
				continue;
			}
			wake_up(&s->read_wqueue);
		}
		wake_up(&snode->read_wqueue);
	}
#endif
}
EXPORT_SYMBOL(up_write_cst);

/*
 * downgrade write lock to read lock
 */
void downgrade_write_cst(struct rwcst_semaphore *sem)
{
	/* Same reason here since this is the same core that
	 * is trying to downgrade the write to reader */
        struct task_struct *task = current;
	struct rw_snode *snode = READ_ONCE(sem->serving_socket);
	cstlock_release(sem, false);
        update_task_schedule(task);
	down_read_cst_snode(sem, snode);
}
EXPORT_SYMBOL(downgrade_write_cst);

void __init_rwsem_cst(struct rwcst_semaphore *sem, const char *name,
		      struct lock_class_key *key)
{
	sem->serving_socket = NULL;
	sem->gtail = NULL;
	sem->ngid_vec = 0;
	sem->numa_list.head.next = &sem->numa_list.head;
	smp_wmb();
}
EXPORT_SYMBOL(__init_rwsem_cst);

void __deinit_rwsem_cst(struct rwcst_semaphore *sem)
{
	struct rw_snode *snode;
	struct atomic_list_head *pos, *tmp;

	for_each_snode_safe(pos, tmp, &sem->numa_list.head) {
		snode = container_of(pos, struct rw_snode, numa_node);
		kfree(snode);
	}
	sem->numa_list.head.next = &sem->numa_list.head;
}
EXPORT_SYMBOL(__deinit_rwsem_cst);

/* All the dark magic will be down the drain */
static inline struct rw_snode *get_snode(struct rwcst_semaphore *lock, uint16_t nid)
{
	struct rw_snode *snode, *tmp_snode;
	uint16_t gid;

     retry_snode:
	/* short cut for serving_socket */
	tmp_snode = READ_ONCE(lock->serving_socket);
	if (tmp_snode && tmp_snode->nid == nid) {
		return tmp_snode;
	}

	/* get snode */
	gid = numa_get_gid(READ_ONCE(lock->ngid_vec), nid);
	/* This is where the read CS begins */
	/* check whether the list is in use or not */
	if (numa_gid_not_empty(gid)) {
		/* snode may be already existing, let's get it */
		snode = find_snode(lock, nid);
	} else {
		snode = add_snode(lock, nid, gid);
	}
	/*
	 * even though gid was existing, but snode has not been created,
	 * someone else is doing it for us
	 */
	if (!snode) {
		goto retry_snode;
	}
	return snode;
}

static inline uint16_t numa_get_gid(uint64_t ngid_vec, uint16_t nid)
{
	uint64_t nid_mask = NUMA_NID_MASK(nid);
	uint16_t gid_value = (ngid_vec & nid_mask) >> NUMA_GID_SHIFT(nid);
	return gid_value;
}

static inline uint64_t  numa_set_gid(uint64_t ngid_vec,
				     uint16_t nid, uint16_t gid)
{
	uint64_t nid_mask = NUMA_NID_MASK(nid);
	uint64_t gid_mask = NUMA_GID_MASK(nid, gid);
	return (ngid_vec & ~nid_mask) | gid_mask;
}

/**
 * init of snode
 */
static inline struct rw_snode *find_snode(struct rwcst_semaphore *lock, uint16_t nid)
{
	struct rw_snode *snode;
	struct atomic_list_head *numa_entry;

	/* check whether it belongs to the serving snode */
	/* this is usually the fast path */
	snode = READ_ONCE(lock->serving_socket);
	if (snode && snode->nid == nid) {
		return snode;
	}

	numa_entry = lock->numa_list.head.next;
	while (numa_entry && numa_entry != &lock->numa_list.head) {
		snode = container_of(numa_entry, struct rw_snode, numa_node);
		if (snode->nid == nid) {
			return snode;
		}
		numa_entry = READ_ONCE(numa_entry->next);
	}
	return NULL;
}

static inline struct rw_snode *add_snode(struct rwcst_semaphore *lock, uint16_t nid,
					 uint16_t gid)
{
	uint64_t old_ngid_vec;
	uint64_t new_ngid_vec;
	uint16_t new_gid;
	struct rw_snode *snode = NULL;

	/*
	 * XXX: I can simplify this one to have 64 bit vector to get the snode.
	 * BUT, I will keep it if we go for the cst global memory allocator
	 * for the kernel. If we don't then can be easily changed.
	 */

	new_gid = numa_gid_inc(gid) | 0x1;
	do {
		/* prepare new_ngid_vec */
		old_ngid_vec = READ_ONCE(lock->ngid_vec);
		new_ngid_vec = numa_set_gid(old_ngid_vec, nid, new_gid);

		/*
		 * do another check again since, it is possible that somehow
		 * someone might have obtained the same gid
		 */
		if (old_ngid_vec == new_ngid_vec) {
			return find_snode(lock, nid);
		}

		/* try to atomically update ngid_vec using cas */
		if (lock->ngid_vec == old_ngid_vec &&
		    smp_cas(&lock->ngid_vec, old_ngid_vec, new_ngid_vec)) {
			/* succeeded in updating ngid_vec
			 * meaning that this thread is a winner
			 * even if there was contention on updating ngid_vec */
			break;
		} else  {
			/*
			 * this thread is a looser in updating ngid_vec
			 * there are two cases:
			 */

			/**
			 * 1) if snode for nid is added by other thread,
			 *    go back to the beginning of the lock code
			 */
			if (numa_gid_not_empty(numa_get_gid(READ_ONCE(lock->ngid_vec), nid))) {
				return find_snode(lock, nid);
			}

			/**
			 * 2) otherwise snode for other nid is added,
			 *    retry to add_snode() for this nid
			 */
		}
                cpu_relax_lowlatency();
	} while (1);

	/*
	 * This thread succeeded in updating gid for nid.
	 * The gid for this nid is marked as not-empty.
	 * This thread has the responsibility of actually allocating
	 * snode and inserting it into the numa_list. Until it is done,
	 * all other threads for the same nid will be raw_spinning
	 * in the retry loop of mutex_lock().
	 */
	snode = alloc_snode(lock, (int32_t)nid);
	snode->nid = nid;

	/* add the new snode to the list */
	list_add_unsafe(&snode->numa_node, &lock->numa_list.head);
	return snode;
}

static inline struct rw_snode *alloc_snode(struct rwcst_semaphore *lock,
					   int32_t nid)
{
	struct rw_snode *snode;

	snode = malloc_at_numa_node(sizeof(*snode), nid);
	snode->gnext = NULL;
	snode->numa_node.next = NULL;
	snode->status = STATE_PARKED;
	snode->qnext = NULL;
	snode->qtail = NULL;
	snode->num_proc = 0;
	snode->active_readers = 0;
	raw_spin_lock_init(&snode->wait_lock);
	INIT_LIST_HEAD(&snode->wwait_list);
	INIT_LIST_HEAD(&snode->rwait_list);
	return snode;
}

/**
 * allocation / deallocation of snode
 */
static inline void *malloc_at_numa_node(size_t size, int32_t nid)
{
	void *node;

	node = kmalloc_node(size, GFP_ATOMIC, nid - 1);
	return node;
}
