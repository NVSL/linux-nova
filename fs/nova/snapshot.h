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

struct nova_snapshot_info_entry {
	u8	type;
	u8	deleted;
	u8	paddings[6];
	__le64	epoch_id;
	__le64	timestamp;
	__le64	nvmm_page_addr;
	__le32	csumpadding;
	__le32	csum;
} __attribute((__packed__));

#define SNENTRY(entry)	((struct nova_snapshot_info_entry *) entry)

struct snapshot_list {
	struct mutex list_mutex;
	unsigned long num_pages;
	unsigned long head;
	unsigned long tail;
};

struct snapshot_info {
	u64	epoch_id;
	u64	timestamp;
	unsigned long snapshot_entry;

	/* Per-CPU snapshot list */
	struct snapshot_list *lists;
};

enum nova_snapshot_entry_type {
	SS_INODE = 1,
	SS_FILE_WRITE,
};

struct snapshot_inode_entry {
	u8	type;
	u8	deleted;
	u8	padding[6];
	u64	padding64;
	u64	nova_ino;
	u64	delete_epoch_id;
} __attribute((__packed__));

struct snapshot_file_write_entry {
	u8	type;
	u8	deleted;
	u8	padding[6];
	u64	nvmm;
	u64	num_pages;
	u64	delete_epoch_id;
} __attribute((__packed__));

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

