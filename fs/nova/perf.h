/*
 * BRIEF DESCRIPTION
 *
 * Performance test
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 *
 * This program is free software; you can redistribute it and/or modify it
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include <linux/zutil.h>
#include <linux/libnvdimm.h>
#include <linux/raid/xor.h>
#include "nova.h"

#define	reset_perf_timer()	__this_cpu_write(Timingstats_percpu[perf_t], 0)
#define	read_perf_timer()	__this_cpu_read(Timingstats_percpu[perf_t])

#define	mb_per_sec(size, nsec)	(nsec == 0 ? 0 : \
				(size * (1000000000 / 1024 / 1024) / nsec))

enum memcpy_call_id {
	memcpy_read_id = 0,
	memcpy_write_id,
	memcpy_bidir_id,
	NUM_MEMCPY_CALLS
};

enum from_pmem_call_id {
	memcpy_mcsafe_id = 0,
	NUM_FROM_PMEM_CALLS
};

enum to_pmem_call_id {
	memcpy_to_pmem_nocache_id = 0,
	flush_buffer_id,
	memcpy_to_pmem_flush_id,
	NUM_TO_PMEM_CALLS
};

enum checksum_call_id {
	zlib_adler32_id = 0,
	nd_fletcher64_id,
	libcrc32c_id,
	nova_crc32c_id,
	plain_xor64_id,
	NUM_CHECKSUM_CALLS
};

enum raid5_call_id {
	nova_block_parity_id = 0,
	nova_block_csum_parity_id,
//	xor_blocks_id,
	NUM_RAID5_CALLS
};

#define	NUM_PERF_CALLS	\
	 (NUM_MEMCPY_CALLS + NUM_FROM_PMEM_CALLS + NUM_TO_PMEM_CALLS + \
	  NUM_CHECKSUM_CALLS + NUM_RAID5_CALLS)

enum call_group_id {
	memcpy_gid = 0,
	from_pmem_gid,
	to_pmem_gid,
	checksum_gid,
	raid5_gid
};

typedef struct {
	const char *name;                              /* name of this call */
//	int (*valid)(void);            /* might need for availability check */
	int (*call)(char *, char *, size_t, size_t); /* dst, src, off, size */
} memcpy_call_t;

typedef struct {
	const char *name;                              /* name of this call */
//	int (*valid)(void);            /* might need for availability check */
	u64 (*call)(u64, char *, size_t);               /* init, data, size */
} checksum_call_t;

typedef struct {
	const char *name;                              /* name of this call */
//	int (*valid)(void);            /* might need for availability check */
	u64 (*call)(char **, char *,                        /* data, parity */
			size_t, int);          /* per-disk-size, data disks */
} raid5_call_t;
