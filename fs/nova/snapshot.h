/*
 * BRIEF DESCRIPTION
 *
 * Snapshot header
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


/*
 * DRAM log of updates to a snapshot.
 */
struct snapshot_list {
	struct mutex list_mutex;
	unsigned long num_pages;
	unsigned long head;
	unsigned long tail;
};


/*
 * DRAM info about a snapshop.
 */
struct snapshot_info {
	u64	epoch_id;
	u64	timestamp;
	unsigned long snapshot_entry; /* PMEM pointer to the struct
				       * snapshot_info_entry for this
				       * snapshot
				       */

	struct snapshot_list *lists;	/* Per-CPU snapshot list */
};


enum nova_snapshot_entry_type {
	SS_INODE = 1,
	SS_FILE_WRITE,
};

/*
 * Snapshot log entry for recording an inode operation in a snapshot log.
 *
 * Todo: add checksum
 */
struct snapshot_inode_entry {
	u8	type;
	u8	deleted;
	u8	padding[6];
	u64	padding64;
	u64	nova_ino;          // inode number that was deleted.
	u64	delete_epoch_id;   // Deleted when?
} __attribute((__packed__));

/*
 * Snapshot log entry for recording a write operation in a snapshot log
 *
 * Todo: add checksum.
 */
struct snapshot_file_write_entry {
	u8	type;
	u8	deleted;
	u8	padding[6];
	u64	nvmm;
	u64	num_pages;
	u64	delete_epoch_id;
} __attribute((__packed__));

/*
 * PMEM structure pointing to a log comprised of snapshot_inode_entry and
 * snapshot_file_write_entry objects.
 *
 * TODO: add checksum
 */
struct snapshot_nvmm_list {
	__le64 padding;
	__le64 num_pages;
	__le64 head;
	__le64 tail;
} __attribute((__packed__));

/* Support up to 128 CPUs */
struct snapshot_nvmm_page {
	struct snapshot_nvmm_list lists[128];
};

