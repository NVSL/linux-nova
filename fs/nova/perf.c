/*
 * BRIEF DESCRIPTION
 *
 * Performance test routines
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

#include "perf.h"

/* normal memcpy functions */
static int memcpy_read_call(char *dst, char *src, size_t off, size_t size)
{
	/* pin dst address to cache most writes, if size fits */
	memcpy(dst, src + off, size);
	return 0;
}

static int memcpy_write_call(char *dst, char *src, size_t off, size_t size)
{
	/* pin src address to cache most reads, if size fits */
	memcpy(dst + off, src, size);
	return 0;
}

static int memcpy_bidir_call(char *dst, char *src, size_t off, size_t size)
{
	/* minimize caching by forwarding both src and dst */
	memcpy(dst + off, src + off, size);
	return 0;
}

static const memcpy_call_t memcpy_calls[] = {
	/* order should match enum memcpy_call_id */
	{ "memcpy (mostly read)",  memcpy_read_call },
	{ "memcpy (mostly write)", memcpy_write_call },
	{ "memcpy (read write)",   memcpy_bidir_call }
};

/* copy from pmem functions */
static int from_pmem_call(char *dst, char *src, size_t off, size_t size)
{
	/* pin dst address to cache most writes, if size fits */
	/* src address should point to pmem */
	return memcpy_mcsafe(dst, src + off, size);
}

static const memcpy_call_t from_pmem_calls[] = {
	/* order should match enum from_pmem_call_id */
	{ "memcpy_mcsafe", from_pmem_call }
};

/* copy to pmem functions */
static int to_pmem_nocache_call(char *dst, char *src, size_t off, size_t size)
{
	/* pin src address to cache most reads, if size fits */
	/* dst address should point to pmem */
	memcpy_to_pmem_nocache(dst + off, src, size);
	return 0;
}

static int to_flush_call(char *dst, char *src, size_t off, size_t size)
{
	/* pin src address to cache most reads, if size fits */
	/* dst address should point to pmem */
	nova_flush_buffer(dst + off, size, 0);
	return 0;
}

static int to_pmem_flush_call(char *dst, char *src, size_t off, size_t size)
{
	/* pin src address to cache most reads, if size fits */
	/* dst address should point to pmem */
	memcpy(dst + off, src, size);
	nova_flush_buffer(dst + off, size, 0);
	return 0;
}

static const memcpy_call_t to_pmem_calls[] = {
	/* order should match enum to_pmem_call_id */
	{ "memcpy_to_pmem_nocache", to_pmem_nocache_call },
	{ "flush buffer",	    to_flush_call },
	{ "memcpy + flush buffer",  to_pmem_flush_call }
};

/* checksum functions */
static u64 zlib_adler32_call(u64 init, char *data, size_t size)
{
	u64 csum;

	/* include/linux/zutil.h */
	csum = zlib_adler32(init, data, size);
	return csum;
}

static u64 nd_fletcher64_call(u64 init, char *data, size_t size)
{
	u64 csum;

	/* drivers/nvdimm/core.c */
	csum = nd_fletcher64(data, size, 1);
	return csum;
}

static u64 libcrc32c_call(u64 init, char *data, size_t size)
{
	u32 crc = (u32) init;

	crc = crc32c(crc, data, size);
	return (u64) crc;
}

static u64 nova_crc32c_call(u64 init, char *data, size_t size)
{
	u32 crc = (u32) init;

	crc = nova_crc32c(crc, data, size);
	return (u64) crc;
}

static u64 plain_xor64_call(u64 init, char *data, size_t size)
{
	u64 csum = init;
	u64 *word = (u64 *) data;

	while (size > 8) {
		csum ^= *word;
		word += 1;
		size -= 8;
	}

	/* for perf testing ignore trailing bytes, if any */

	return csum;
}

static const checksum_call_t checksum_calls[] = {
	/* order should match enum checksum_call_id */
	{ "zlib_adler32",  zlib_adler32_call },
	{ "nd_fletcher64", nd_fletcher64_call },
	{ "libcrc32c",     libcrc32c_call },
	{ "nova_crc32c",   nova_crc32c_call },
	{ "plain_xor64",   plain_xor64_call }
};

/* raid5 functions */
static u64 nova_block_parity_call(char **data, char *parity,
	size_t size, int disks)
{
	int i, j, strp, num_strps = disks;
	size_t strp_size = size;
	char *block = *data;
	u64 xor;

	/* FIXME: using same code as in parity.c; need a way to reuse that */

	if (static_cpu_has(X86_FEATURE_XMM2)) { // sse2 128b
		for (i = 0; i < strp_size; i += 16) {
			asm volatile("movdqa %0, %%xmm0" : : "m" (block[i]));
			for (strp = 1; strp < num_strps; strp++) {
				j = strp * strp_size + i;
				asm volatile(
					"movdqa     %0, %%xmm1\n"
					"pxor   %%xmm1, %%xmm0\n"
					: : "m" (block[j])
				);
			}
			asm volatile("movntdq %%xmm0, %0" : "=m" (parity[i]));
		}
	} else { // common 64b
		for (i = 0; i < strp_size; i += 8) {
			xor = *((u64 *) &block[i]);
			for (strp = 1; strp < num_strps; strp++) {
				j = strp * strp_size + i;
				xor ^= *((u64 *) &block[j]);
			}
			*((u64 *) &parity[i]) = xor;
		}
	}

	return *((u64 *) parity);
}

static u64 nova_block_csum_parity_call(char **data, char *parity,
	size_t size, int disks)
{
	int i;
	size_t strp_size = size;
	char *block = *data;
	u32 volatile crc[8]; // avoid results being optimized out
	u64 qwd[8];
	u64 acc[8] = {0, 0, 0, 0, 0, 0, 0, 0};

	/* FIXME: using same code as in parity.c; need a way to reuse that */

	for (i = 0; i < strp_size / 8; i++) {
		qwd[0] = *((u64 *) (block));
		qwd[1] = *((u64 *) (block + 1 * strp_size));
		qwd[2] = *((u64 *) (block + 2 * strp_size));
		qwd[3] = *((u64 *) (block + 3 * strp_size));
		qwd[4] = *((u64 *) (block + 4 * strp_size));
		qwd[5] = *((u64 *) (block + 5 * strp_size));
		qwd[6] = *((u64 *) (block + 6 * strp_size));
		qwd[7] = *((u64 *) (block + 7 * strp_size));

		// if (data_csum > 0 && unroll_csum) {
			nova_crc32c_qword(qwd[0], acc[0]);
			nova_crc32c_qword(qwd[1], acc[1]);
			nova_crc32c_qword(qwd[2], acc[2]);
			nova_crc32c_qword(qwd[3], acc[3]);
			nova_crc32c_qword(qwd[4], acc[4]);
			nova_crc32c_qword(qwd[5], acc[5]);
			nova_crc32c_qword(qwd[6], acc[6]);
			nova_crc32c_qword(qwd[7], acc[7]);
		// }

		// if (data_parity > 0) {
			parity[i] = qwd[0] ^ qwd[1] ^ qwd[2] ^ qwd[3] ^
					qwd[4] ^ qwd[5] ^ qwd[6] ^ qwd[7];
		// }

		block += 8;
	}
	// if (data_csum > 0 && unroll_csum) {
		crc[0] = cpu_to_le32((u32) acc[0]);
		crc[1] = cpu_to_le32((u32) acc[1]);
		crc[2] = cpu_to_le32((u32) acc[2]);
		crc[3] = cpu_to_le32((u32) acc[3]);
		crc[4] = cpu_to_le32((u32) acc[4]);
		crc[5] = cpu_to_le32((u32) acc[5]);
		crc[6] = cpu_to_le32((u32) acc[6]);
		crc[7] = cpu_to_le32((u32) acc[7]);
	// }

	return *((u64 *) parity);
}

#if 0 // some test machines do not have this function (need CONFIG_MD_RAID456)
static u64 xor_blocks_call(char **data, char *parity,
	size_t size, int disks)
{
	int xor_cnt, disk_id;

	memcpy(parity, data[0], size); /* init parity with the first disk */
	disks--;
	disk_id = 1;
	while (disks > 0) {
		/* each xor_blocks call can do at most MAX_XOR_BLOCKS (4) */
		xor_cnt = min(disks, MAX_XOR_BLOCKS);
		/* crypto/xor.c, used in lib/raid6 and fs/btrfs */
		xor_blocks(xor_cnt, size, parity, (void **)(data + disk_id));

		disks -= xor_cnt;
		disk_id += xor_cnt;
	}

	return *((u64 *) parity);
}
#endif

static const raid5_call_t raid5_calls[] = {
	/* order should match enum raid5_call_id */
	{ "nova_block_parity", nova_block_parity_call },
	{ "nova_block_csum_parity", nova_block_csum_parity_call },
//	{ "xor_blocks", xor_blocks_call },
};

/* memory pools for perf testing */
static void *nova_alloc_vmem_pool(size_t poolsize)
{
	void *pool = vmalloc(poolsize);

	if (pool == NULL)
		return NULL;

	/* init pool to verify some checksum results */
	// memset(pool, 0xAC, poolsize);

	/* to have a clean start, flush the data cache for the given virtual
	 * address range in the vmap area
	 */
	flush_kernel_vmap_range(pool, poolsize);

	return pool;
}

static void nova_free_vmem_pool(void *pool)
{
	if (pool != NULL)
		vfree(pool);
}

static void *nova_alloc_pmem_pool(struct super_block *sb,
	struct nova_inode_info_header *sih, int cpu, size_t poolsize,
	unsigned long *blocknr, int *allocated)
{
	int num;
	void *pool;
	size_t blocksize, blockoff;
	u8 blocktype = NOVA_BLOCK_TYPE_4K;

	blocksize = blk_type_to_size[blocktype];
	num = poolsize / blocksize;
	if (poolsize % blocksize)
		num++;

	sih->ino = NOVA_TEST_PERF_INO;
	sih->i_blk_type = blocktype;
	sih->log_head = 0;
	sih->log_tail = 0;

	*allocated = nova_new_data_blocks(sb, sih, blocknr, 0, num,
					  ALLOC_NO_INIT, cpu, ALLOC_FROM_HEAD);
	if (*allocated < num) {
		nova_dbg("%s: allocated pmem blocks %d < requested blocks %d\n",
						__func__, *allocated, num);
		if (*allocated > 0)
			nova_free_data_blocks(sb, sih, *blocknr, *allocated);

		return NULL;
	}

	blockoff = nova_get_block_off(sb, *blocknr, blocktype);
	pool = nova_get_block(sb, blockoff);

	return pool;
}

static void nova_free_pmem_pool(struct super_block *sb,
	struct nova_inode_info_header *sih, char **pmem,
	unsigned long blocknr, int num)
{
	if (num > 0)
		nova_free_data_blocks(sb, sih, blocknr, num);
	*pmem = NULL;
}

static int nova_test_func_perf(struct super_block *sb, unsigned int func_id,
	size_t poolsize, size_t size, unsigned int disks)
{
	u64 csum = 12345, xor = 0;

	u64 volatile result; // avoid results being optimized out
	const char *fname = NULL;
	char *src = NULL, *dst = NULL, *pmem = NULL;
	char **data = NULL, *parity;
	size_t off = 0;
	int cpu, i, j, reps, err = 0, allocated = 0;
	unsigned int call_id = 0, call_gid = 0;
	unsigned long blocknr = 0, nsec, lat, thru;
	struct nova_inode_info_header perf_sih;
	const memcpy_call_t *fmemcpy = NULL;
	const checksum_call_t *fchecksum = NULL;
	const raid5_call_t *fraid5 = NULL;
	unsigned long irq_flags = 0;
	INIT_TIMING(perf_time);

	cpu = get_cpu(); /* get cpu id and disable preemption */
	reps = poolsize / size; /* raid calls will adjust this number */
	call_id = func_id - 1; /* individual function id starting from 1 */

	/* normal memcpy */
	if (call_id < NUM_MEMCPY_CALLS) {
		src = nova_alloc_vmem_pool(poolsize);
		dst = nova_alloc_vmem_pool(poolsize);
		if (src == NULL || dst == NULL) {
			err = -ENOMEM;
			goto out;
		}

		fmemcpy = &memcpy_calls[call_id];
		fname = fmemcpy->name;
		call_gid = memcpy_gid;

		goto test;
	}
	call_id -= NUM_MEMCPY_CALLS;

	/* memcpy from pmem */
	if (call_id < NUM_FROM_PMEM_CALLS) {
		pmem = nova_alloc_pmem_pool(sb, &perf_sih, cpu, poolsize,
							&blocknr, &allocated);
		dst = nova_alloc_vmem_pool(poolsize);
		if (pmem == NULL || dst == NULL) {
			err = -ENOMEM;
			goto out;
		}

		fmemcpy = &from_pmem_calls[call_id];
		fname = fmemcpy->name;
		call_gid = from_pmem_gid;

		goto test;
	}
	call_id -= NUM_FROM_PMEM_CALLS;

	/* memcpy to pmem */
	if (call_id < NUM_TO_PMEM_CALLS) {
		src = nova_alloc_vmem_pool(poolsize);
		pmem = nova_alloc_pmem_pool(sb, &perf_sih, cpu, poolsize,
							&blocknr, &allocated);
		if (src == NULL || pmem == NULL) {
			err = -ENOMEM;
			goto out;
		}

		fmemcpy = &to_pmem_calls[call_id];
		fname = fmemcpy->name;
		call_gid = to_pmem_gid;

		goto test;
	}
	call_id -= NUM_TO_PMEM_CALLS;

	/* checksum */
	if (call_id < NUM_CHECKSUM_CALLS) {
		src = nova_alloc_vmem_pool(poolsize);

		fchecksum = &checksum_calls[call_id];
		fname = fchecksum->name;
		call_gid = checksum_gid;

		goto test;
	}
	call_id -= NUM_CHECKSUM_CALLS;

	/* raid5 */
	if (call_id < NUM_RAID5_CALLS) {
		src = nova_alloc_vmem_pool(poolsize);
		data = kcalloc(disks, sizeof(char *), GFP_NOFS);
		if (data == NULL) {
			err = -ENOMEM;
			goto out;
		}

		reps = poolsize / ((disks + 1) * size); /* +1 for parity */

		fraid5 = &raid5_calls[call_id];
		fname = fraid5->name;
		call_gid = raid5_gid;

		if (call_id == nova_block_csum_parity_id && disks != 8) {
			nova_dbg("%s only for 8 disks, skip testing\n", fname);
			goto out;
		}

		goto test;
	}
	call_id -= NUM_RAID5_CALLS;

	/* continue with the next call group */

test:
	if (fmemcpy == NULL && fchecksum == NULL && fraid5 == NULL) {
		nova_dbg("%s: function struct error\n", __func__);
		err = -EFAULT;
		goto out;
	}

	reset_perf_timer();
	NOVA_START_TIMING(perf_t, perf_time);

	switch (call_gid) {
	case memcpy_gid:
		for (i = 0; i < reps; i++, off += size)
			err = fmemcpy->call(dst, src, off, size);
		break;
	case from_pmem_gid:
		for (i = 0; i < reps; i++, off += size)
			err = fmemcpy->call(dst, pmem, off, size);
		break;
	case to_pmem_gid:
		nova_memunlock_range(sb, pmem, poolsize, &irq_flags);
		for (i = 0; i < reps; i++, off += size)
			err = fmemcpy->call(pmem, src, off, size);
		nova_memlock_range(sb, pmem, poolsize, &irq_flags);
		break;
	case checksum_gid:
		for (i = 0; i < reps; i++, off += size)
			/* checksum calls are memory-read intensive */
			csum = fchecksum->call(csum, src + off, size);
		result = csum;
		break;
	case raid5_gid:
		for (i = 0; i < reps; i++, off += (disks + 1) * size) {
			for (j = 0; j < disks; j++)
				data[j] = &src[off + j * size];
			parity = src + off + disks * size;
			xor = fraid5->call(data, parity, size, disks);
		}
		result = xor;
		break;
	default:
		nova_dbg("%s: invalid function group %d\n", __func__, call_gid);
		break;
	}

	NOVA_END_TIMING(perf_t, perf_time);
	nsec = read_perf_timer();

	// nova_info("checksum value: 0x%016llx\n", csum);

	lat  = (err) ? 0 : nsec / reps;
	if (call_gid == raid5_gid)
		thru = (err) ? 0 : mb_per_sec(reps * disks * size, nsec);
	else
		thru = (err) ? 0 : mb_per_sec(reps * size, nsec);

	if (cpu != smp_processor_id()) /* scheduling shouldn't happen */
		nova_dbg("cpu was %d, now %d\n", cpu, smp_processor_id());

	nova_info("%4u %25s %4u %8lu %8lu\n", func_id, fname, cpu, lat, thru);

out:
	nova_free_vmem_pool(src);
	nova_free_vmem_pool(dst);
	nova_free_pmem_pool(sb, &perf_sih, &pmem, blocknr, allocated);

	if (data != NULL)
		kfree(data);

	put_cpu(); /* enable preemption */

	if (err)
		nova_dbg("%s: performance test aborted\n", __func__);
	return err;
}

int nova_test_perf(struct super_block *sb, unsigned int func_id,
	unsigned int poolmb, size_t size, unsigned int disks)
{
	int id, ret = 0;
	size_t poolsize = poolmb * 1024 * 1024;

	if (!measure_timing) {
		nova_dbg("%s: measure_timing not set!\n", __func__);
		ret = -EFAULT;
		goto out;
	}
	if (func_id > NUM_PERF_CALLS) {
		nova_dbg("%s: invalid function id %d!\n", __func__, func_id);
		ret = -EFAULT;
		goto out;
	}
	if (poolmb < 1 || 1024 < poolmb) { /* limit pool size to 1GB */
		nova_dbg("%s: invalid pool size %u MB!\n", __func__, poolmb);
		ret = -EFAULT;
		goto out;
	}
	if (size < 64 || poolsize < size || (size % 64)) {
		nova_dbg("%s: invalid data size %zu!\n", __func__, size);
		ret = -EFAULT;
		goto out;
	}
	if (disks < 1 || 32 < disks) { /* limit number of disks */
		nova_dbg("%s: invalid disk count %u!\n", __func__, disks);
		ret = -EFAULT;
		goto out;
	}

	nova_info("test function performance\n");
	nova_info("pool size %u MB, work size %zu, disks %u\n",
					poolmb, size, disks);

	nova_info("%4s %25s %4s %8s %8s\n", "id", "name", "cpu", "ns", "MB/s");
	nova_info("-------------------------------------------------------\n");
	if (func_id == 0) {
		/* individual function id starting from 1 */
		for (id = 1; id <= NUM_PERF_CALLS; id++) {
			ret = nova_test_func_perf(sb, id, poolsize,
							size, disks);
			if (ret < 0)
				goto out;
		}
	} else {
		ret = nova_test_func_perf(sb, func_id, poolsize, size, disks);
	}
	nova_info("-------------------------------------------------------\n");

out:
	return ret;
}
