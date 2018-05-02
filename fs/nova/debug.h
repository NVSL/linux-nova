/*
 * Debug parameters
 * 1: Print nova_info
 * 0: Block nova_info
 * Too many debug messages will lead to a crash!
 */

/* Mode */
#define MODE_USE_MEMCPY 1
#define MODE_USE_GROUP 1
#define MODE_KEEP_STAT 0
#define MODE_KEEP_STAT_VPMEM

#define MODE_FORE_ALLOC 0
#define MODE_FORE_PMEM 0
#define MODE_FORE_BAL 0
#define MODE_BACK_MIG 0

/* Configure */
#define BDEV_OPT_SIZE_BIT 6
#define MIGRATION_DOWN_PMEM_PERC 6
#define MIGRATION_DOWN_BDEV_PERC 20
#define MIGRATION_FORCE_PERC 90

/* Debug */
#define DEBUG_XFSTESTS 0

#define DEBUG_INIT 0
#define DEBUG_STARTUP_TEST 0

#define DEBUG_BDEV_RW 0
#define DEBUG_BFL_INFO 0
#define DEBUG_WRITE_ENTRY 0
#define DEBUG_KTHREAD 0

#define DEBUG_FORE_ALLOC 0
#define DEBUG_FORE_FILE 0

#define DEBUG_PROF_SYNC 0
#define DEBUG_PROF_SEQ 0
#define DEBUG_PROF_HOT 0

#define DEBUG_DO_MIGRATION 0
#define DEBUG_MIGRATION 0

#define DEBUG_MIGRATION_CHECK 0
#define DEBUG_MIGRATION_ALLOC 0
#define DEBUG_MIGRATION_COPY 0
#define DEBUG_MIGRATION_FREE 0
#define DEBUG_MIGRATION_CLONE 0

#define DEBUG_MIGRATION_ENTRY 0
#define DEBUG_MIGRATION_SPLIT 0
#define DEBUG_MIGRATION_MERGE 0

#define DEBUG_GET_NVMM 0
#define DEBUG_MB_LOCK 0
#define DEBUG_BUFFERING 0