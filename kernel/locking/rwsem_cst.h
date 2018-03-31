#ifndef _RWSEM_CST_H_
#define _RWSEM_CST_H_
#include "mutex_cstmcsvar.h"

#ifdef CONFIG_NO_MIGRATION_IN_CS
#define increase_task_pin_count() 					\
	do {								\
		++current->se.task_pin_count; 				\
	} while (0)
#define decrease_task_pin_count(_f) 					\
	do {								\
		if (_f)							\
			--current->se.task_pin_count; 			\
	} while (0)
#define update_sched_priority(__max, task)				\
	do {								\
		task->se.upgrade_sched_policy_quota = 			\
		sched_prio_to_sched_count[task_nice(task) + 20] - 	\
		sched_prio_to_sched_count[__max + 20];			\
	} while (0)
#define reset_sched_priority(task) 					\
	do {								\
		task->se.upgrade_sched_policy_quota = 0;		\
	} while (0)
#else
#define increase_task_pin_count() do { } while (0)
#define decrease_task_pin_count(_f) do { } while (0)
#define update_sched_priority(__max, task) do { } while (0)
#define reset_sched_priority(task) do { } while (0)
#endif

#endif /* _RWSEM_CST_H_ */
