/*
 * BRIEF DESCRIPTION
 *
 * Checksum related methods.
 *
 * Copyright 2015-2016 Regents of the University of California,
 * UCSD Non-Volatile Systems Lab, Andiry Xu <jix024@cs.ucsd.edu>
 * Copyright 2012-2013 Intel Corporation
 * Copyright 2009-2011 Marco Stornelli <marco.stornelli@gmail.com>
 * Copyright 2003 Sony Corporation
 * Copyright 2003 Matsushita Electric Industrial Co., Ltd.
 * 2003-2004 (c) MontaVista Software, Inc. , Steve Longerbeam
 * This file is licensed under the terms of the GNU General Public
 * License version 2. This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#include "nova.h"
#include "inode.h"

static int nova_get_entry_copy(struct super_block *sb, void *entry,
	u32 *entry_csum, size_t *entry_size, void *entry_copy)
{
	u8 type;
	struct nova_dentry *dentry;
	int ret = 0;

	ret = memcpy_mcsafe(&type, entry, sizeof(u8));
	if (ret < 0)
		return ret;

	switch (type) {
	case DIR_LOG:
		dentry = DENTRY(entry_copy);
		ret = memcpy_mcsafe(dentry, entry, NOVA_DENTRY_HEADER_LEN);
		if (ret < 0 || dentry->de_len > NOVA_MAX_ENTRY_LEN)
			break;
		*entry_size = dentry->de_len;
		ret = memcpy_mcsafe((u8 *) dentry + NOVA_DENTRY_HEADER_LEN,
					(u8 *) entry + NOVA_DENTRY_HEADER_LEN,
					*entry_size - NOVA_DENTRY_HEADER_LEN);
		if (ret < 0)
			break;
		*entry_csum = dentry->csum;
		break;
	case FILE_WRITE:
		*entry_size = sizeof(struct nova_file_write_entry);
		ret = memcpy_mcsafe(entry_copy, entry, *entry_size);
		if (ret < 0)
			break;
		*entry_csum = WENTRY(entry_copy)->csum;
		break;
	case SET_ATTR:
		*entry_size = sizeof(struct nova_setattr_logentry);
		ret = memcpy_mcsafe(entry_copy, entry, *entry_size);
		if (ret < 0)
			break;
		*entry_csum = SENTRY(entry_copy)->csum;
		break;
	case LINK_CHANGE:
		*entry_size = sizeof(struct nova_link_change_entry);
		ret = memcpy_mcsafe(entry_copy, entry, *entry_size);
		if (ret < 0)
			break;
		*entry_csum = LCENTRY(entry_copy)->csum;
		break;
	case MMAP_WRITE:
		*entry_size = sizeof(struct nova_mmap_entry);
		ret = memcpy_mcsafe(entry_copy, entry, *entry_size);
		if (ret < 0)
			break;
		*entry_csum = MMENTRY(entry_copy)->csum;
		break;
	case SNAPSHOT_INFO:
		*entry_size = sizeof(struct nova_snapshot_info_entry);
		ret = memcpy_mcsafe(entry_copy, entry, *entry_size);
		if (ret < 0)
			break;
		*entry_csum = SNENTRY(entry_copy)->csum;
		break;
	default:
		*entry_csum = 0;
		*entry_size = 0;
		nova_dbg("%s: unknown or unsupported entry type (%d) for checksum, 0x%llx\n",
			 __func__, type, (u64)entry);
		ret = -EINVAL;
		dump_stack();
		break;
	}

	return ret;
}

/* Calculate the entry checksum. */
static u32 nova_calc_entry_csum(void *entry)
{
	u8 type;
	u32 csum = 0;
	size_t entry_len, check_len;
	void *csum_addr, *remain;
	INIT_TIMING(calc_time);

	NOVA_START_TIMING(calc_entry_csum_t, calc_time);

	/* Entry is checksummed excluding its csum field. */
	type = nova_get_entry_type(entry);
	switch (type) {
	/* nova_dentry has variable length due to its name. */
	case DIR_LOG:
		entry_len =  DENTRY(entry)->de_len;
		csum_addr = &DENTRY(entry)->csum;
		break;
	case FILE_WRITE:
		entry_len = sizeof(struct nova_file_write_entry);
		csum_addr = &WENTRY(entry)->csum;
		break;
	case SET_ATTR:
		entry_len = sizeof(struct nova_setattr_logentry);
		csum_addr = &SENTRY(entry)->csum;
		break;
	case LINK_CHANGE:
		entry_len = sizeof(struct nova_link_change_entry);
		csum_addr = &LCENTRY(entry)->csum;
		break;
	case MMAP_WRITE:
		entry_len = sizeof(struct nova_mmap_entry);
		csum_addr = &MMENTRY(entry)->csum;
		break;
	case SNAPSHOT_INFO:
		entry_len = sizeof(struct nova_snapshot_info_entry);
		csum_addr = &SNENTRY(entry)->csum;
		break;
	default:
		entry_len = 0;
		csum_addr = NULL;
		nova_dbg("%s: unknown or unsupported entry type (%d) for checksum, 0x%llx\n",
			 __func__, type, (u64) entry);
		break;
	}

	if (entry_len > 0) {
		check_len = ((u8 *) csum_addr) - ((u8 *) entry);
		csum = nova_crc32c(NOVA_INIT_CSUM, entry, check_len);
		check_len = entry_len - (check_len + NOVA_META_CSUM_LEN);
		if (check_len > 0) {
			remain = ((u8 *) csum_addr) + NOVA_META_CSUM_LEN;
			csum = nova_crc32c(csum, remain, check_len);
		}

		if (check_len < 0) {
			nova_dbg("%s: checksum run-length error %ld < 0",
				__func__, check_len);
		}
	}

	NOVA_END_TIMING(calc_entry_csum_t, calc_time);
	return csum;
}

/* Update the log entry checksum. */
void nova_update_entry_csum(void *entry)
{
	u8  type;
	u32 csum;
	size_t entry_len = CACHELINE_SIZE;

	if (metadata_csum == 0)
		goto flush;

	type = nova_get_entry_type(entry);
	csum = nova_calc_entry_csum(entry);

	switch (type) {
	case DIR_LOG:
		DENTRY(entry)->csum = cpu_to_le32(csum);
		entry_len = DENTRY(entry)->de_len;
		break;
	case FILE_WRITE:
		WENTRY(entry)->csum = cpu_to_le32(csum);
		entry_len = sizeof(struct nova_file_write_entry);
		break;
	case SET_ATTR:
		SENTRY(entry)->csum = cpu_to_le32(csum);
		entry_len = sizeof(struct nova_setattr_logentry);
		break;
	case LINK_CHANGE:
		LCENTRY(entry)->csum = cpu_to_le32(csum);
		entry_len = sizeof(struct nova_link_change_entry);
		break;
	case MMAP_WRITE:
		MMENTRY(entry)->csum = cpu_to_le32(csum);
		entry_len = sizeof(struct nova_mmap_entry);
		break;
	case SNAPSHOT_INFO:
		SNENTRY(entry)->csum = cpu_to_le32(csum);
		entry_len = sizeof(struct nova_snapshot_info_entry);
		break;
	default:
		entry_len = 0;
		nova_dbg("%s: unknown or unsupported entry type (%d), 0x%llx\n",
			__func__, type, (u64) entry);
		break;
	}

flush:
	if (entry_len > 0)
		nova_flush_buffer(entry, entry_len, 0);

}

int nova_update_alter_entry(struct super_block *sb, void *entry)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	void *alter_entry;
	u64 curr, alter_curr;
	u32 entry_csum;
	size_t size;
	char entry_copy[NOVA_MAX_ENTRY_LEN];
	int ret;

	if (metadata_csum == 0)
		return 0;

	curr = nova_get_addr_off(sbi, entry);
	alter_curr = alter_log_entry(sb, curr);
	if (alter_curr == 0) {
		nova_err(sb, "%s: log page tail error detected\n", __func__);
		return -EIO;
	}
	alter_entry = (void *)nova_get_block(sb, alter_curr);

	ret = nova_get_entry_copy(sb, entry, &entry_csum, &size, entry_copy);
	if (ret)
		return ret;

	ret = memcpy_to_pmem_nocache(alter_entry, entry_copy, size);
	return ret;
}

/* media error: repair the poison radius that the entry belongs to */
static int nova_repair_entry_pr(struct super_block *sb, void *entry)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret;
	u64 entry_off, alter_off;
	void *entry_pr, *alter_pr;

	entry_off = nova_get_addr_off(sbi, entry);
	alter_off = alter_log_entry(sb, entry_off);
	if (alter_off == 0) {
		nova_err(sb, "%s: log page tail error detected\n", __func__);
		goto fail;
	}

	entry_pr = (void *) nova_get_block(sb, entry_off & POISON_MASK);
	alter_pr = (void *) nova_get_block(sb, alter_off & POISON_MASK);

	if (entry_pr == NULL || alter_pr == NULL)
		BUG();

	nova_memunlock_range(sb, entry_pr, POISON_RADIUS);
	ret = memcpy_mcsafe(entry_pr, alter_pr, POISON_RADIUS);
	nova_memlock_range(sb, entry_pr, POISON_RADIUS);
	nova_flush_buffer(entry_pr, POISON_RADIUS, 0);

	/* alter_entry shows media error during memcpy */
	if (ret < 0)
		goto fail;

	nova_dbg("%s: entry media error repaired\n", __func__);
	return 0;

fail:
	nova_err(sb, "%s: unrecoverable media error detected\n", __func__);
	return -1;
}

static int nova_repair_entry(struct super_block *sb, void *bad, void *good,
	size_t entry_size)
{
	int ret;

	nova_memunlock_range(sb, bad, entry_size);
	ret = memcpy_to_pmem_nocache(bad, good, entry_size);
	nova_memlock_range(sb, bad, entry_size);

	if (ret == 0)
		nova_dbg("%s: entry error repaired\n", __func__);

	return ret;
}

/* Verify the log entry checksum and get a copy in DRAM. */
bool nova_verify_entry_csum(struct super_block *sb, void *entry, void *entryc)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	int ret = 0;
	u64 entry_off, alter_off;
	void *alter;
	size_t entry_size, alter_size;
	u32 entry_csum, alter_csum;
	u32 entry_csum_calc, alter_csum_calc;
	char entry_copy[NOVA_MAX_ENTRY_LEN];
	char alter_copy[NOVA_MAX_ENTRY_LEN];
	INIT_TIMING(verify_time);

	if (metadata_csum == 0)
		return true;

	NOVA_START_TIMING(verify_entry_csum_t, verify_time);

	ret = nova_get_entry_copy(sb, entry, &entry_csum, &entry_size,
				  entry_copy);
	if (ret < 0) { /* media error */
		ret = nova_repair_entry_pr(sb, entry);
		if (ret < 0)
			goto fail;
		/* try again */
		ret = nova_get_entry_copy(sb, entry, &entry_csum, &entry_size,
						entry_copy);
		if (ret < 0)
			goto fail;
	}

	entry_off = nova_get_addr_off(sbi, entry);
	alter_off = alter_log_entry(sb, entry_off);
	if (alter_off == 0) {
		nova_err(sb, "%s: log page tail error detected\n", __func__);
		goto fail;
	}

	alter = (void *) nova_get_block(sb, alter_off);
	ret = nova_get_entry_copy(sb, alter, &alter_csum, &alter_size,
					alter_copy);
	if (ret < 0) { /* media error */
		ret = nova_repair_entry_pr(sb, alter);
		if (ret < 0)
			goto fail;
		/* try again */
		ret = nova_get_entry_copy(sb, alter, &alter_csum, &alter_size,
						alter_copy);
		if (ret < 0)
			goto fail;
	}

	/* no media errors, now verify the checksums */
	entry_csum = le32_to_cpu(entry_csum);
	alter_csum = le32_to_cpu(alter_csum);
	entry_csum_calc = nova_calc_entry_csum(entry_copy);
	alter_csum_calc = nova_calc_entry_csum(alter_copy);

	if (entry_csum != entry_csum_calc && alter_csum != alter_csum_calc) {
		nova_err(sb, "%s: both entry and its replica fail checksum verification\n",
			 __func__);
		goto fail;
	} else if (entry_csum != entry_csum_calc) {
		nova_dbg("%s: entry %p checksum error, trying to repair using the replica\n",
			 __func__, entry);
		ret = nova_repair_entry(sb, entry, alter_copy, alter_size);
		if (ret != 0)
			goto fail;

		memcpy(entryc, alter_copy, alter_size);
	} else if (alter_csum != alter_csum_calc) {
		nova_dbg("%s: entry replica %p checksum error, trying to repair using the primary\n",
			 __func__, alter);
		ret = nova_repair_entry(sb, alter, entry_copy, entry_size);
		if (ret != 0)
			goto fail;

		memcpy(entryc, entry_copy, entry_size);
	} else {
		/* now both entries pass checksum verification and the primary
		 * is trusted if their buffers don't match
		 */
		if (memcmp(entry_copy, alter_copy, entry_size)) {
			nova_dbg("%s: entry replica %p error, trying to repair using the primary\n",
				 __func__, alter);
			ret = nova_repair_entry(sb, alter, entry_copy,
						entry_size);
			if (ret != 0)
				goto fail;
		}

		memcpy(entryc, entry_copy, entry_size);
	}

	NOVA_END_TIMING(verify_entry_csum_t, verify_time);
	return true;

fail:
	nova_err(sb, "%s: unable to repair entry errors\n", __func__);

	NOVA_END_TIMING(verify_entry_csum_t, verify_time);
	return false;
}

/* media error: repair the poison radius that the inode belongs to */
static int nova_repair_inode_pr(struct super_block *sb,
	struct nova_inode *bad_pi, struct nova_inode *good_pi)
{
	int ret;
	void *bad_pr, *good_pr;

	bad_pr = (void *)((u64) bad_pi & POISON_MASK);
	good_pr = (void *)((u64) good_pi & POISON_MASK);

	if (bad_pr == NULL || good_pr == NULL)
		BUG();

	nova_memunlock_range(sb, bad_pr, POISON_RADIUS);
	ret = memcpy_mcsafe(bad_pr, good_pr, POISON_RADIUS);
	nova_memlock_range(sb, bad_pr, POISON_RADIUS);
	nova_flush_buffer(bad_pr, POISON_RADIUS, 0);

	/* good_pi shows media error during memcpy */
	if (ret < 0)
		goto fail;

	nova_dbg("%s: inode media error repaired\n", __func__);
	return 0;

fail:
	nova_err(sb, "%s: unrecoverable media error detected\n", __func__);
	return -1;
}

static int nova_repair_inode(struct super_block *sb, struct nova_inode *bad_pi,
	struct nova_inode *good_copy)
{
	int ret;

	nova_memunlock_inode(sb, bad_pi);
	ret = memcpy_to_pmem_nocache(bad_pi, good_copy,
					sizeof(struct nova_inode));
	nova_memlock_inode(sb, bad_pi);

	if (ret == 0)
		nova_dbg("%s: inode %llu error repaired\n", __func__,
					good_copy->nova_ino);

	return ret;
}

/*
 * Check nova_inode and get a copy in DRAM.
 * If we are going to update (write) the inode, we don't need to check the
 * alter inode if the major inode checks ok. If we are going to read or rebuild
 * the inode, also check the alter even if the major inode checks ok.
 */
int nova_check_inode_integrity(struct super_block *sb, u64 ino, u64 pi_addr,
	u64 alter_pi_addr, struct nova_inode *pic, int check_replica)
{
	struct nova_inode *pi, *alter_pi, alter_copy, *alter_pic;
	int inode_bad, alter_bad;
	int ret;

	pi = (struct nova_inode *)nova_get_block(sb, pi_addr);

	ret = memcpy_mcsafe(pic, pi, sizeof(struct nova_inode));

	if (metadata_csum == 0)
		return ret;

	alter_pi = (struct nova_inode *)nova_get_block(sb, alter_pi_addr);

	if (ret < 0) { /* media error */
		ret = nova_repair_inode_pr(sb, pi, alter_pi);
		if (ret < 0)
			goto fail;
		/* try again */
		ret = memcpy_mcsafe(pic, pi, sizeof(struct nova_inode));
		if (ret < 0)
			goto fail;
	}

	inode_bad = nova_check_inode_checksum(pic);

	if (!inode_bad && !check_replica)
		return 0;

	alter_pic = &alter_copy;
	ret = memcpy_mcsafe(alter_pic, alter_pi, sizeof(struct nova_inode));
	if (ret < 0) { /* media error */
		if (inode_bad)
			goto fail;
		ret = nova_repair_inode_pr(sb, alter_pi, pi);
		if (ret < 0)
			goto fail;
		/* try again */
		ret = memcpy_mcsafe(alter_pic, alter_pi,
					sizeof(struct nova_inode));
		if (ret < 0)
			goto fail;
	}

	alter_bad = nova_check_inode_checksum(alter_pic);

	if (inode_bad && alter_bad) {
		nova_err(sb, "%s: both inode and its replica fail checksum verification\n",
			 __func__);
		goto fail;
	} else if (inode_bad) {
		nova_dbg("%s: inode %llu checksum error, trying to repair using the replica\n",
			 __func__, ino);
		nova_print_inode(pi);
		nova_print_inode(alter_pi);
		ret = nova_repair_inode(sb, pi, alter_pic);
		if (ret != 0)
			goto fail;

		memcpy(pic, alter_pic, sizeof(struct nova_inode));
	} else if (alter_bad) {
		nova_dbg("%s: inode replica %llu checksum error, trying to repair using the primary\n",
			 __func__, ino);
		ret = nova_repair_inode(sb, alter_pi, pic);
		if (ret != 0)
			goto fail;
	} else if (memcmp(pic, alter_pic, sizeof(struct nova_inode))) {
		nova_dbg("%s: inode replica %llu is stale, trying to repair using the primary\n",
			 __func__, ino);
		ret = nova_repair_inode(sb, alter_pi, pic);
		if (ret != 0)
			goto fail;
	}

	return 0;

fail:
	nova_err(sb, "%s: unable to repair inode errors\n", __func__);

	return -EIO;
}

static int nova_update_stripe_csum(struct super_block *sb, unsigned long strps,
	unsigned long strp_nr, u8 *strp_ptr, int zero)
{
	struct nova_sb_info *sbi = NOVA_SB(sb);
	size_t strp_size = NOVA_STRIPE_SIZE;
	unsigned long strp;
	u32 csum;
	u32 crc[8];
	void *csum_addr, *csum_addr1;
	void *src_addr;

	while (strps >= 8) {
		if (zero) {
			src_addr = sbi->zero_csum;
			goto copy;
		}

		crc[0] = cpu_to_le32(nova_crc32c(NOVA_INIT_CSUM,
				strp_ptr, strp_size));
		crc[1] = cpu_to_le32(nova_crc32c(NOVA_INIT_CSUM,
				strp_ptr + strp_size, strp_size));
		crc[2] = cpu_to_le32(nova_crc32c(NOVA_INIT_CSUM,
				strp_ptr + strp_size * 2, strp_size));
		crc[3] = cpu_to_le32(nova_crc32c(NOVA_INIT_CSUM,
				strp_ptr + strp_size * 3, strp_size));
		crc[4] = cpu_to_le32(nova_crc32c(NOVA_INIT_CSUM,
				strp_ptr + strp_size * 4, strp_size));
		crc[5] = cpu_to_le32(nova_crc32c(NOVA_INIT_CSUM,
				strp_ptr + strp_size * 5, strp_size));
		crc[6] = cpu_to_le32(nova_crc32c(NOVA_INIT_CSUM,
				strp_ptr + strp_size * 6, strp_size));
		crc[7] = cpu_to_le32(nova_crc32c(NOVA_INIT_CSUM,
				strp_ptr + strp_size * 7, strp_size));

		src_addr = crc;
copy:
		csum_addr = nova_get_data_csum_addr(sb, strp_nr, 0);
		csum_addr1 = nova_get_data_csum_addr(sb, strp_nr, 1);

		nova_memunlock_range(sb, csum_addr, NOVA_DATA_CSUM_LEN * 8);
		if (support_clwb) {
			memcpy(csum_addr, src_addr, NOVA_DATA_CSUM_LEN * 8);
			memcpy(csum_addr1, src_addr, NOVA_DATA_CSUM_LEN * 8);
		} else {
			memcpy_to_pmem_nocache(csum_addr, src_addr,
						NOVA_DATA_CSUM_LEN * 8);
			memcpy_to_pmem_nocache(csum_addr1, src_addr,
						NOVA_DATA_CSUM_LEN * 8);
		}
		nova_memlock_range(sb, csum_addr, NOVA_DATA_CSUM_LEN * 8);
		if (support_clwb) {
			nova_flush_buffer(csum_addr,
					  NOVA_DATA_CSUM_LEN * 8, 0);
			nova_flush_buffer(csum_addr1,
					  NOVA_DATA_CSUM_LEN * 8, 0);
		}

		strp_nr += 8;
		strps -= 8;
		if (!zero)
			strp_ptr += strp_size * 8;
	}

	for (strp = 0; strp < strps; strp++) {
		if (zero)
			csum = sbi->zero_csum[0];
		else
			csum = nova_crc32c(NOVA_INIT_CSUM, strp_ptr, strp_size);

		csum = cpu_to_le32(csum);
		csum_addr = nova_get_data_csum_addr(sb, strp_nr, 0);
		csum_addr1 = nova_get_data_csum_addr(sb, strp_nr, 1);

		nova_memunlock_range(sb, csum_addr, NOVA_DATA_CSUM_LEN);
		memcpy_to_pmem_nocache(csum_addr, &csum, NOVA_DATA_CSUM_LEN);
		memcpy_to_pmem_nocache(csum_addr1, &csum, NOVA_DATA_CSUM_LEN);
		nova_memlock_range(sb, csum_addr, NOVA_DATA_CSUM_LEN);

		strp_nr += 1;
		if (!zero)
			strp_ptr += strp_size;
	}

	return 0;
}

/* Checksums a sequence of contiguous file write data stripes within one block
 * and writes the checksum values to nvmm.
 *
 * The block buffer to compute checksums should reside in dram (more trusted),
 * not in nvmm (less trusted).
 *
 * Checksum is calculated over a whole stripe.
 *
 * block:   block buffer with user data and possibly partial head-tail block
 *          - should be in kernel memory (dram) to avoid page faults
 * blocknr: destination nvmm block number where the block is written to
 *          - used to derive checksum value addresses
 * offset:  byte offset of user data in the block buffer
 * bytes:   number of user data bytes in the block buffer
 * zero:    if the user data is all zero
 */
int nova_update_block_csum(struct super_block *sb,
	struct nova_inode_info_header *sih, u8 *block, unsigned long blocknr,
	size_t offset, size_t bytes, int zero)
{
	u8 *strp_ptr;
	size_t blockoff;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	unsigned int strp_index, strp_offset;
	unsigned long strps, strp_nr;
	INIT_TIMING(block_csum_time);

	NOVA_START_TIMING(block_csum_t, block_csum_time);
	blockoff = nova_get_block_off(sb, blocknr, sih->i_blk_type);

	/* strp_index: stripe index within the block buffer
	 * strp_offset: stripe offset within the block buffer
	 *
	 * strps: number of stripes touched by user data (need new checksums)
	 * strp_nr: global stripe number converted from blocknr and offset
	 * strp_ptr: pointer to stripes in the block buffer
	 */
	strp_index = offset >> strp_shift;
	strp_offset = offset - (strp_index << strp_shift);

	strps = ((strp_offset + bytes - 1) >> strp_shift) + 1;
	strp_nr = (blockoff + offset) >> strp_shift;
	strp_ptr = block + (strp_index << strp_shift);

	nova_update_stripe_csum(sb, strps, strp_nr, strp_ptr, zero);

	NOVA_END_TIMING(block_csum_t, block_csum_time);

	return 0;
}

int nova_update_pgoff_csum(struct super_block *sb,
	struct nova_inode_info_header *sih, struct nova_file_write_entry *entry,
	unsigned long pgoff, int zero)
{
	void *dax_mem = NULL;
	u64 blockoff;
	size_t strp_size = NOVA_STRIPE_SIZE;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	unsigned long strp_nr;
	int count;

	count = blk_type_to_size[sih->i_blk_type] / strp_size;

	blockoff = nova_find_nvmm_block(sb, sih, entry, pgoff);

	/* Truncated? */
	if (blockoff == 0)
		return 0;

	dax_mem = nova_get_block(sb, blockoff);

	strp_nr = blockoff >> strp_shift;

	nova_update_stripe_csum(sb, count, strp_nr, dax_mem, zero);

	// reclaim_get_nvmm(sb, blockoff >> PAGE_SHIFT, entry, pgoff);

	return 0;
}

/* Verify checksums of requested data bytes starting from offset of blocknr.
 *
 * Only a whole stripe can be checksum verified.
 *
 * blocknr: container blocknr for the first stripe to be verified
 * offset:  byte offset within the block associated with blocknr
 * bytes:   number of contiguous bytes to be verified starting from offset
 *
 * return: true or false
 */
bool nova_verify_data_csum(struct super_block *sb,
	struct nova_inode_info_header *sih, unsigned long blocknr,
	size_t offset, size_t bytes)
{
	void *blockptr, *strp_ptr;
	size_t blockoff, blocksize = nova_inode_blk_size(sih);
	size_t strp_size = NOVA_STRIPE_SIZE;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	unsigned int strp_index;
	unsigned long strp, strps, strp_nr;
	void *strip = NULL;
	u32 csum_calc, csum_nvmm0, csum_nvmm1;
	u32 *csum_addr0, *csum_addr1;
	int error;
	bool match;
	INIT_TIMING(verify_time);

	NOVA_START_TIMING(verify_data_csum_t, verify_time);

	/* Only a whole stripe can be checksum verified.
	 * strps: # of stripes to be checked since offset.
	 */
	strps = ((offset + bytes - 1) >> strp_shift)
		- (offset >> strp_shift) + 1;

	blockoff = nova_get_block_off(sb, blocknr, sih->i_blk_type);
	blockptr = nova_get_block(sb, blockoff);

	/* strp_nr: global stripe number converted from blocknr and offset
	 * strp_ptr: virtual address of the 1st stripe
	 * strp_index: stripe index within a block
	 */
	strp_nr = (blockoff + offset) >> strp_shift;
	strp_index = offset >> strp_shift;
	strp_ptr = blockptr + (strp_index << strp_shift);

	strip = kmalloc(strp_size, GFP_KERNEL);
	if (strip == NULL)
		return false;

	match = true;
	for (strp = 0; strp < strps; strp++) {
		csum_addr0 = nova_get_data_csum_addr(sb, strp_nr, 0);
		csum_nvmm0 = le32_to_cpu(*csum_addr0);

		csum_addr1 = nova_get_data_csum_addr(sb, strp_nr, 1);
		csum_nvmm1 = le32_to_cpu(*csum_addr1);

		error = memcpy_mcsafe(strip, strp_ptr, strp_size);
		if (error < 0) {
			nova_dbg("%s: media error in data strip detected!\n",
				__func__);
			match = false;
		} else {
			csum_calc = nova_crc32c(NOVA_INIT_CSUM, strip,
						strp_size);
			match = (csum_calc == csum_nvmm0) ||
				(csum_calc == csum_nvmm1);
		}

		if (!match) {
			/* Getting here, data is considered corrupted.
			 *
			 * if: csum_nvmm0 == csum_nvmm1
			 *     both csums good, run data recovery
			 * if: csum_nvmm0 != csum_nvmm1
			 *     at least one csum is corrupted, also need to run
			 *     data recovery to see if one csum is still good
			 */
			nova_dbg("%s: nova data corruption detected! inode %lu, strp %lu of %lu, block offset %lu, stripe nr %lu, csum calc 0x%08x, csum nvmm 0x%08x, csum nvmm replica 0x%08x\n",
				__func__, sih->ino, strp, strps, blockoff,
				strp_nr, csum_calc, csum_nvmm0, csum_nvmm1);

			if (data_parity == 0) {
				nova_dbg("%s: no data redundancy available, can not repair data corruption!\n",
					 __func__);
				break;
			}

			nova_dbg("%s: nova data recovery begins\n", __func__);

			error = nova_restore_data(sb, blocknr, strp_index,
					strip, error, csum_nvmm0, csum_nvmm1,
					&csum_calc);
			if (error) {
				nova_dbg("%s: nova data recovery fails!\n",
						__func__);
				dump_stack();
				break;
			}

			/* Getting here, data corruption is repaired and the
			 * good checksum is stored in csum_calc.
			 */
			nova_dbg("%s: nova data recovery success!\n", __func__);
			match = true;
		}

		/* Getting here, match must be true, otherwise already breaking
		 * out the for loop. Data is known good, either it's good in
		 * nvmm, or good after recovery.
		 */
		if (csum_nvmm0 != csum_nvmm1) {
			/* Getting here, data is known good but one checksum is
			 * considered corrupted.
			 */
			nova_dbg("%s: nova checksum corruption detected! inode %lu, strp %lu of %lu, block offset %lu, stripe nr %lu, csum calc 0x%08x, csum nvmm 0x%08x, csum nvmm replica 0x%08x\n",
				__func__, sih->ino, strp, strps, blockoff,
				strp_nr, csum_calc, csum_nvmm0, csum_nvmm1);

			nova_memunlock_range(sb, csum_addr0,
							NOVA_DATA_CSUM_LEN);
			if (csum_nvmm0 != csum_calc) {
				csum_nvmm0 = cpu_to_le32(csum_calc);
				memcpy_to_pmem_nocache(csum_addr0, &csum_nvmm0,
							NOVA_DATA_CSUM_LEN);
			}

			if (csum_nvmm1 != csum_calc) {
				csum_nvmm1 = cpu_to_le32(csum_calc);
				memcpy_to_pmem_nocache(csum_addr1, &csum_nvmm1,
							NOVA_DATA_CSUM_LEN);
			}
			nova_memlock_range(sb, csum_addr0, NOVA_DATA_CSUM_LEN);

			nova_dbg("%s: nova checksum corruption repaired!\n",
								__func__);
		}

		/* Getting here, the data stripe and both checksum copies are
		 * known good. Continue to the next stripe.
		 */
		strp_nr    += 1;
		strp_index += 1;
		strp_ptr   += strp_size;
		if (strp_index == (blocksize >> strp_shift)) {
			blocknr += 1;
			blockoff += blocksize;
			strp_index = 0;
		}

	}

	if (strip != NULL)
		kfree(strip);

	NOVA_END_TIMING(verify_data_csum_t, verify_time);

	return match;
}

int nova_update_truncated_block_csum(struct super_block *sb,
	struct inode *inode, loff_t newsize) {

	struct nova_inode_info *si = NOVA_I(inode);
	struct nova_inode_info_header *sih = &si->header;
	unsigned long offset = newsize & (sb->s_blocksize - 1);
	unsigned long pgoff, length;
	u64 nvmm;
	char *nvmm_addr, *strp_addr, *tail_strp = NULL;
	unsigned int strp_size = NOVA_STRIPE_SIZE;
	unsigned int strp_shift = NOVA_STRIPE_SHIFT;
	unsigned int strp_index, strp_offset;
	unsigned long strps, strp_nr;

	length = sb->s_blocksize - offset;
	pgoff = newsize >> sb->s_blocksize_bits;

	nvmm = nova_find_nvmm_block(sb, sih, NULL, pgoff);
	if (nvmm == 0)
		return -EFAULT;

	nvmm_addr = (char *)nova_get_block(sb, nvmm);

	strp_index = offset >> strp_shift;
	strp_offset = offset - (strp_index << strp_shift);

	strps = ((strp_offset + length - 1) >> strp_shift) + 1;
	strp_nr = (nvmm + offset) >> strp_shift;
	strp_addr = nvmm_addr + (strp_index << strp_shift);

	if (strp_offset > 0) {
		/* Copy to DRAM to catch MCE. */
		tail_strp = kzalloc(strp_size, GFP_KERNEL);
		if (tail_strp == NULL)
			return -ENOMEM;

		if (memcpy_mcsafe(tail_strp, strp_addr, strp_offset) < 0)
			return -EIO;

		nova_update_stripe_csum(sb, 1, strp_nr, tail_strp, 0);

		strps--;
		strp_nr++;
	}

	// reclaim_get_nvmm(sb, nvmm >> PAGE_SHIFT, NULL, pgoff);

	if (strps > 0)
		nova_update_stripe_csum(sb, strps, strp_nr, NULL, 1);

	if (tail_strp != NULL)
		kfree(tail_strp);

	return 0;
}

