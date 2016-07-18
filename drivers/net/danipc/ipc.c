/*
 *	All files except if stated otherwise in the beginning of the file
 *	are under the ISC license:
 *	----------------------------------------------------------------------
 *	Copyright (c) 2015-2016, The Linux Foundation. All rights reserved.
 *	Copyright (c) 2010-2012 Design Art Networks Ltd.
 *
 *	Permission to use, copy, modify, and/or distribute this software for any
 *	purpose with or without fee is hereby granted, provided that the above
 *	copyright notice and this permission notice appear in all copies.
 *
 *	THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *	WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *	MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *	ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *	WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *	ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *	OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/cache.h>
#include <linux/slab.h>
#include <linux/err.h>

#include "ipc_reg.h"
#include "ipc_api.h"

#include "danipc_lowlevel.h"

/* -----------------------------------------------------------
 * MACRO (define) section
 * -----------------------------------------------------------
 */
/* max. number of local agents per one Node */
#define MAX_LOCAL_ID     (MAX_LOCAL_AGENT-1)

uint8_t	ipc_req_sn;	/* Maintain node related sequence number */

/* ===========================================================================
 * ipc_appl_init
 * ===========================================================================
 * Description:	This function initializes software/HW during startup
 *
 * Parameters:		def_trns_funcs	- pointer to default transport layer
 *					  function vector
 *
 * Returns: n/a
 *
 */
static inline void ipc_appl_init(uint8_t local_cpuid,
				 struct ipc_trns_func const *def_trns_funcs,
				 uint8_t ifidx, uint8_t fifos_initialized)
{
	ipc_agent_table_clean(local_cpuid);

	if (fifos_initialized == 0)
		ipc_trns_fifo_buf_init(local_cpuid, ifidx);
	else
		ipc_trns_fifo_move_m_to_b(local_cpuid);

	/* Initialize IPC routing table (of CPU#) */
	ipc_route_table_init(local_cpuid, def_trns_funcs);
}

unsigned ipc_init(uint8_t local_cpuid, uint8_t ifidx, uint8_t fifos_initialized)
{
	ipc_appl_init(local_cpuid, &ipc_fifo_utils, ifidx, fifos_initialized);
	return 0;
}

unsigned ipc_cleanup(uint8_t local_cpuid)
{
	ipc_agent_table_clean(local_cpuid);

	return 0;
}

/* ===========================================================================
 * ipc_buf_alloc
 * ===========================================================================
 * Description:	buffer allocation API, should be called before building
 *		new message
 *
 * Parameters:		dest_aid	- Message destination AgentId
 *			prio		- Transport priority level
 *
 *
 * Returns: Pointer to a 128 Byte buffer
 *
*/
char *ipc_buf_alloc(uint8_t dest_aid, enum ipc_trns_prio prio)
{
	char			*ptr = NULL;
	struct ipc_trns_func const *trns_funcs;
	ipc_trns_alloc_t	alloc_func;
	const uint8_t		cpuid = ipc_get_node(dest_aid);

	/* Allocate buffer of 128 Bytes using the allocation function */
	/* associated with the given destination agentId */
	trns_funcs = (void *)get_trns_funcs(cpuid);
	if (likely(trns_funcs)) {
		alloc_func = trns_funcs->trns_alloc;
		if (likely(alloc_func)) {
			ptr = alloc_func(cpuid, prio);

			/* Clear the 'Next buffer' field. */
			if (likely(ptr))
				((struct ipc_buf_hdr *)ptr)->next = 0;
		}
	}

	return ptr;
}

/* ===========================================================================
 * ipc_buf_free
 * ===========================================================================
 * Description:  Free the buffer, could be called on IPC message receiving node
 *		or on sending node when need to free previously allocated
 *		buffers
 *
 * Parameters:	cpuid		- index for remote processor
 *		buf_first	- Pointer to first message buffer
 *		prio		- Transport priority level
 *
 *
 * Returns: Result code
 *
 */
int32_t ipc_buf_free(char *buf_first, uint8_t cpuid, enum ipc_trns_prio prio)
{
	struct ipc_buf_hdr		*cur_buf;
	struct ipc_trns_func const	*trns_funcs;
	ipc_trns_free_t			free_func;
	int32_t				res = IPC_GENERIC_ERROR;

	if (likely(buf_first)) {
		cur_buf = (struct ipc_buf_hdr *)buf_first;
		trns_funcs = get_trns_funcs(cpuid);
		if (likely(trns_funcs)) {
			free_func = trns_funcs->trns_free;
			if (likely(free_func)) {
				free_func(
				IPC_NEXT_PTR_PART(cur_buf), cpuid,
				prio);

				res = IPC_SUCCESS;
			}
		}
	}
	return res;
}

/* ===========================================================================
 * ipc_buf_link
 * ===========================================================================
 * Description:	Link two buffers, should be called when message does not fit
 *		the single buffer
 *
 * Parameters:		buf_prev	- Pointer to a message buffer
 *			buf_next	- Pointer to the next message buffer
 *					  (to be linked to)
 *
 * Returns: Result code
 *
 */
static int32_t ipc_buf_link(char *buf_prev, char *buf_next)
{
	if (buf_prev == NULL || buf_next == NULL)
		return IPC_GENERIC_ERROR;

	/* Set the next buffer pointer in place */
	*(uint32_t *)buf_prev |= (uint32_t)buf_next & ~IPC_BUF_TYPE_BITS;
	/* Set the LSB of the prev buffer to signal there are more to come */
	*(uint32_t *)buf_prev |= IPC_BUF_TYPE_MTC;
	/* Mark the next buffer as the last one */
	*(uint32_t *)buf_next |= IPC_BUF_TYPE_END;
	return IPC_SUCCESS;
}

/* ===========================================================================
 * ipc_msg_set_len
 * ===========================================================================
 * Description:	sets message length, first buffer of the message
 *		should be provided
 *
 * Parameters:		buf_first	- Pointer to the first message buffer
 *			len		- Message length (bytes)
 *
 *
 * Returns: Result code
 *
 */
static int32_t ipc_msg_set_len(char *buf_first, size_t len)
{
	if (buf_first == NULL)
		return IPC_GENERIC_ERROR;
	(((struct ipc_first_buf *)buf_first)->msg_hdr).msg_len = len;
	return IPC_SUCCESS;
}

/* ===========================================================================
 * ipc_msg_set_type
 * ===========================================================================
 * Description:  sets message type, first buffer of the message
 *		should be provided
 *
 * Parameters:		buf_first	- Pointer to the first message buffer
 *			type		- Message type
 *
 *
 * Returns: Result code
 *
 */
static int32_t ipc_msg_set_type(char *buf_first, uint8_t type)
{
	if (buf_first == NULL)
		return IPC_GENERIC_ERROR;
	(((struct ipc_first_buf *)buf_first)->msg_hdr).msg_type = type;
	return IPC_SUCCESS;
}

/* ===========================================================================
 * ipc_msg_set_reply_ptr
 * ===========================================================================
 * Description:  sets message reply buffer pointer
 *
 * Parameters:		buf_first	- Pointer to the first message buffer
 *			buf_rep		- Pointer to the expected replay message
 *
 *
 * Returns: Result code
 *
 */
static int32_t ipc_msg_set_reply_ptr(
	char			*buf_first,
	char			*buf_rep
)
{
	if (buf_first == NULL)
		return IPC_GENERIC_ERROR;
	(((struct ipc_first_buf *)buf_first)->msg_hdr).reply = buf_rep;
	return IPC_SUCCESS;
}

static inline int ipc_buf_copy(
	char		*dst,
	const char	*src,
	size_t		size,
	bool		user_space)
{
	if (!user_space) {
		memcpy(dst, src, size);
		return 0;
	}
	if (copy_from_user(dst, src, size))
		return -EFAULT;
	return 0;
}

/* ===========================================================================
 * ipc_msg_alloc
 * ===========================================================================
 * Description:  Allocate message buffer[s] and set the type and length.
 *		Copy message data into allocated buffers.
 *
 *
 * Parameters:		src_aid	- Message source AgentId
 *			dest_aid	- Message destination AgentId
 *			msg		- Pointer to message data
 *			msg_len		- Message length
 *			msg_type	- Message type
 *			prio		- Transport priority level
 *			from_user_space	- Message from user space
 *
 *
 * Returns: Pointer to the message first buffer
 *
 */
char *ipc_msg_alloc(
	uint8_t			src_aid,
	uint8_t			dest_aid,
	const char		*msg,
	size_t			msg_len,
	uint8_t			msg_type,
	enum ipc_trns_prio	prio,
	bool			from_user_space
)
{
	char			*first_buf = NULL;
	char			*prev_buf = NULL;
	char			*next_buf = NULL;
	unsigned		buf;
	unsigned		next_bufs_num = 0;
	size_t			tmp_size, reminder;
	const char		*last_data;
	int			ret = 0;

	if ((msg_len > IPC_MAX_MESSAGE_SIZE) || (msg_len == 0))
		return NULL;

	/* Calculate number of 'next' buffers required */
	/* (i.e. buffers additional to the first buffer) */
	if (msg_len > IPC_FIRST_BUF_DATA_SIZE_MAX) {
		next_bufs_num = (msg_len - IPC_FIRST_BUF_DATA_SIZE_MAX) /
					IPC_NEXT_BUF_DATA_SIZE_MAX;
		if ((msg_len - IPC_FIRST_BUF_DATA_SIZE_MAX) %
					IPC_NEXT_BUF_DATA_SIZE_MAX)
			next_bufs_num++;
	}

	first_buf = ipc_buf_alloc(dest_aid, prio);
	prev_buf = first_buf;
	for (buf = 0; buf < next_bufs_num; buf++) {
		if (prev_buf == NULL)
			break;
		next_buf = ipc_buf_alloc(dest_aid, prio);
		if (next_buf != NULL)
			ipc_buf_link(prev_buf, next_buf);
		prev_buf = next_buf;
	}

	/* If buffer allocation failed free the entire buffers */
	if ((prev_buf == NULL) && (first_buf != NULL)) {
		ipc_buf_free(first_buf, ipc_get_node(dest_aid), prio);
		first_buf = NULL;
	} else if (first_buf) {
		ipc_msg_set_type(first_buf, msg_type);
		ipc_msg_set_len(first_buf, msg_len);
		ipc_msg_set_reply_ptr(first_buf, NULL);
		((struct ipc_msg_hdr *)first_buf)->dest_aid = dest_aid;
		((struct ipc_msg_hdr *)first_buf)->src_aid = src_aid;
		((struct ipc_msg_hdr *)first_buf)->request_num = ipc_req_sn;
		((struct ipc_msg_hdr *)first_buf)->next  = NULL;
		ipc_req_sn++;

		if (msg) {
			last_data = msg + msg_len;

			/* Now copy the Data */
			reminder = msg_len;
			tmp_size = min_t(size_t, reminder,
					 IPC_FIRST_BUF_DATA_SIZE_MAX);

			ret = ipc_buf_copy(
				((struct ipc_first_buf *)first_buf)->body,
				last_data - reminder,
				tmp_size,
				from_user_space);
			if (ret)
				goto err;

			reminder -= tmp_size;
			prev_buf = first_buf;

			while (reminder > 0) {
				next_buf = IPC_NEXT_PTR_PART(
					((struct ipc_msg_hdr *)prev_buf)->next);
				tmp_size = min_t(size_t, reminder,
						 IPC_NEXT_BUF_DATA_SIZE_MAX);

				ret = ipc_buf_copy(
					((struct ipc_next_buf *)next_buf)->body,
					last_data - reminder,
					tmp_size,
					from_user_space);
				if (ret)
					goto err;

				reminder -= tmp_size;
				prev_buf = next_buf;
			}
		}
	}

	return first_buf;
err:
	ipc_buf_free(first_buf, ipc_get_node(dest_aid), prio);
	return NULL;
}

/* ===========================================================================
 * ipc_msg_send
 * ===========================================================================
 * Description:  Message send, first buffer of the message should be provided,
 *
 * Parameters:		buf_first	- Pointer to the first message buffer
 *			prio		- Transport priority level
 *
 *
 * Returns: Result code
 *
 */
int32_t ipc_msg_send(char *buf_first, enum ipc_trns_prio prio)
{
	struct ipc_next_buf		*buf;
	struct ipc_trns_func const	*trns_funcs;
	ipc_trns_send_t			send_func;
	uint8_t				dest_aid;
	uint8_t				cpuid;
	int32_t				res = IPC_GENERIC_ERROR;

	if (likely(buf_first)) {
		dest_aid	= (((struct ipc_first_buf *)buf_first)->
							msg_hdr).dest_aid;
		cpuid		= ipc_get_node(dest_aid);
		buf		= (struct ipc_next_buf *)buf_first;
		trns_funcs	= get_trns_funcs(cpuid);
		if (likely(trns_funcs)) {
			send_func = trns_funcs->trns_send;
			if (send_func)
				res = send_func((char *)buf, cpuid, prio);
		}
	}
	return res;
}

#define MAX_SHM_REGION_NUM	4

#define CACHELINE_ALIGNED(a)	(!((a) & (cache_line_size() - 1)))
#define ALIGN_BUF(a, s)		((a) - (a)%(s))

struct shm_region_tbl {
	struct shm_region	*region[MAX_SHM_REGION_NUM];
	uint32_t		num_region;
};

static struct shm_region_tbl region_tbl;

static inline struct shm_buf *buf_in_region(struct shm_region *region)
{
	return (struct shm_buf *)(region+1);
}

static inline void __shm_bufpool_del_buf(struct shm_bufpool *pool,
					 struct shm_buf *buf)
{
	list_del_init(&buf->list);
	buf->head = NULL;
	pool->count--;
}

static inline void __shm_bufpool_add_buf(struct shm_bufpool *pool,
					 struct shm_buf *buf)
{
	list_add_tail(&buf->list, &pool->head);
	buf->head = &pool->head;
	pool->count++;
}

static inline struct shm_buf *find_dir_map_buf_by_offset(
	struct shm_region *region,
	uint32_t offset)
{
	uint32_t index = offset/region->real_buf_sz;

	if (index < region->buf_num)
		return buf_in_region(region)+index;
	return NULL;
}

struct shm_buf *shm_region_find_buf_by_pa(
	struct shm_region *region,
	phys_addr_t phy_addr)
{
	if (!region->dir_buf_map)
		return NULL;

	return find_dir_map_buf_by_offset(region, phy_addr - region->start);
}

struct shm_buf *shm_find_buf_by_pa(phys_addr_t phy_addr)
{
	struct shm_buf *buf = NULL;
	int i;
	int n = 0;

	for (i = 0; i < MAX_SHM_REGION_NUM && n < region_tbl.num_region; i++) {
		if (!region_tbl.region[i])
			continue;
		if (address_in_range(phy_addr,
				     region_tbl.region[i]->start,
				     region_tbl.region[i]->end)) {
			buf = shm_region_find_buf_by_pa(region_tbl.region[i],
							phy_addr);
			break;
		}
		n++;
	}
	return buf;
}

struct shm_region *shm_region_create(
	phys_addr_t	start,
	void		*vaddr,
	resource_size_t	size,
	uint32_t	buf_sz,
	uint32_t	buf_headroom,
	uint32_t	buf_num)
{
	struct shm_region_tbl *tbl = &region_tbl;
	struct shm_region *region;
	struct shm_buf *buf;
	phys_addr_t end = start+size;
	uint32_t real_buf_sz = buf_sz + buf_headroom;
	uint32_t n;
	int i, idx;
	bool dir_map = true;

	if (unlikely(!size || !buf_num || !buf_sz))
		return NULL;

	if (!CACHELINE_ALIGNED(start) || !CACHELINE_ALIGNED(real_buf_sz)) {
		pr_err("%s: %x/%u not cacheline aligned\n",
		       __func__, start, real_buf_sz);
		return NULL;
	}

	if (tbl->num_region >= MAX_SHM_REGION_NUM) {
		pr_err("%s: number of shm_region exceeds the limit\n",
		       __func__);
		return NULL;
	}

	for (i = 0, idx = -1; i < MAX_SHM_REGION_NUM; i++) {
		region = tbl->region[i];
		if (region == NULL) {
			if (idx < 0)
				idx = i;
			continue;
		}
		if (address_in_range(start, region->start, region->end) ||
		    address_in_range(end, region->start, region->end)) {
			pr_err("%s: region(%x/%x) overlay with %x/%x",
			       __func__, start, end,
			       region->start, region->end);
			return NULL;
		}
	}

	if (idx < 0)
		return NULL;

	n = size/real_buf_sz;
	if (buf_num < n) {
		n = buf_num;
		dir_map = false;
	}

	region = kzalloc((sizeof(struct shm_region) +
			  sizeof(struct shm_buf) * n),
			 GFP_KERNEL);
	if (IS_ERR(region)) {
		pr_err("%s: failed to alloc the region data\n", __func__);
		return NULL;
	}

	region->start = start;
	region->vaddr = vaddr;
	region->end = end;
	region->buf_sz = buf_sz;
	region->buf_num = n;
	region->buf_headroom_sz = buf_headroom;
	region->real_buf_sz = real_buf_sz;
	region->dir_buf_map = dir_map;

	buf = (struct shm_buf *)(region + 1);
	for (i = 0; i < region->buf_num; i++, buf++) {
		buf->region = region;
		buf->head = NULL;
		INIT_LIST_HEAD(&buf->list);

		if (dir_map)
			buf->offset = i * real_buf_sz + buf_headroom;
	}

	tbl->region[idx] = region;
	tbl->num_region++;
	return region;
}

void shm_region_release(struct shm_region *region)
{
	struct shm_region_tbl *tbl = &region_tbl;
	int i;

	if (unlikely(!region))
		return;

	for (i = 0; i < MAX_SHM_REGION_NUM; i++) {
		if (tbl->region[i] == region) {
			kfree(region);
			tbl->region[i] = NULL;
			tbl->num_region--;
			break;
		}
	}
}

void shm_region_release_all(void)
{
	struct shm_region_tbl *tbl = &region_tbl;
	int i;

	for (i = 0; i < MAX_SHM_REGION_NUM; i++) {
		kfree(tbl->region[i]);
		tbl->region[i] = NULL;
	}
	tbl->num_region = 0;
}

int shm_bufpool_acquire_region(
	struct shm_bufpool	*pool,
	struct shm_region	*region,
	uint32_t		offset,
	uint32_t		size)
{
	struct shm_buf *buf;
	phys_addr_t start, end;
	uint32_t nbuf;
	int i;

	if (unlikely(!pool || !region || !region->buf_num))
		return -EINVAL;

	if (!region->dir_buf_map)
		return -EPERM;

	start = region->start + ALIGN_BUF((offset + region->real_buf_sz - 1),
					  region->real_buf_sz);

	if (!address_in_range(start, region->start, region->end)) {
		pr_err("%s: invalid offset(0x%x)\n", __func__, offset);
		return -EINVAL;
	}

	end = region->start + ALIGN_BUF((offset + size), region->real_buf_sz);
	if (end > region->end) {
		pr_err("%s: size(%u) is too big\n", __func__, size);
		return -EINVAL;
	}

	nbuf = (end - start)/region->real_buf_sz;
	if (!nbuf) {
		pr_err("%s: size(%u) is too small\n", __func__, size);
		return -EINVAL;
	}

	buf = shm_region_find_buf_by_pa(region, start);
	BUG_ON(buf == NULL);

	for (i = 0; i < nbuf; i++) {
		if (buf[i].head != NULL) {
			pr_err("%s: can't claim the buffer at 0x%x\n",
			       __func__, buf_paddr(buf+i));
			return -EINVAL;
		}
	}

	for (i = 0; i < nbuf; i++, buf++)
		__shm_bufpool_add_buf(pool, buf);

	return 0;
}

int shm_bufpool_acquire_whole_region(
	struct shm_bufpool *pool,
	struct shm_region *region)
{
	struct shm_buf *buf;
	int i;

	if (unlikely(!pool || !region))
		return -EINVAL;

	buf = buf_in_region(region);
	for (i = 0; i < region->buf_num; i++) {
		if (buf[i].head != NULL) {
			pr_err("%s: can't claim the buffer, buffer_idx=%d\n",
			       __func__, i);
			return -EINVAL;
		}
	}

	for (i = 0; i < region->buf_num; i++, buf++)
		__shm_bufpool_add_buf(pool, buf);

	return 0;
}

void shm_bufpool_release(struct shm_bufpool *pool)
{
	struct shm_buf *buf, *p;

	if (unlikely(pool == NULL))
		return;

	list_for_each_entry_safe(buf, p, &pool->head, list)
		__shm_bufpool_del_buf(pool, buf);
}

struct shm_buf *shm_bufpool_get_buf(struct shm_bufpool *pool)
{
	struct shm_buf *buf;

	if (unlikely(!pool))
		return NULL;

	buf = list_first_entry_or_null(&pool->head, struct shm_buf, list);
	if (buf) {
		__shm_bufpool_del_buf(pool, buf);
		pr_debug("%s: get buf %p from pool %p, pool_count=%u\n",
			 __func__, buf, pool, pool->count);
	}
	return buf;
}

void shm_bufpool_put_buf(struct shm_bufpool *pool, struct shm_buf *buf)
{
	if (unlikely(!pool || !buf))
		return;

	__shm_bufpool_add_buf(pool, buf);
	pr_debug("%s: put buf %p into pool %p, pool_count=%u\n",
		 __func__, buf, pool, pool->count);
}

int shm_bufpool_del_buf(struct shm_bufpool *pool, struct shm_buf *buf)
{
	if (unlikely(!pool || !buf))
		return -EINVAL;

	if (unlikely(buf->head != &pool->head)) {
		pr_debug("%s: unable to del buf, pool(%p) head %p\n",
			 __func__, pool, buf->head);
		return -EINVAL;
	}
	__shm_bufpool_del_buf(pool, buf);
	return 0;
}

struct shm_buf *shm_bufpool_find_buf_in_region(struct shm_bufpool *pool,
					       struct shm_region *region,
					       phys_addr_t phy_addr)
{
	struct shm_buf *buf;
	uint32_t offset;

	if (unlikely(!pool || !region))
		return NULL;

	offset = phy_addr - region->start;
	if (region->dir_buf_map) {
		buf = find_dir_map_buf_by_offset(region, offset);
		if (buf && buf->head != &pool->head)
			buf = NULL;
		return buf;
	}

	list_for_each_entry(buf, &pool->head, list) {
		if (buf->region != region)
			continue;
		if (address_in_range(offset, buf->offset,
				     buf->offset+buf->region->real_buf_sz))
			return buf;
	}
	return NULL;
}

struct shm_buf *shm_bufpool_find_buf_overlap(struct shm_bufpool *pool,
					     struct shm_region *region,
					     phys_addr_t phy_addr)
{
	struct shm_buf *buf;
	uint32_t offset;

	if (unlikely(!pool || !region))
		return NULL;

	offset = phy_addr - region->start;
	if (region->dir_buf_map) {
		buf = find_dir_map_buf_by_offset(region, offset);
		if (buf && buf->head != &pool->head)
			buf = NULL;
		return buf;
	}

	list_for_each_entry(buf, &pool->head, list) {
		if (buf->region != region)
			continue;
		if (address_space_overlap(offset,
					  region->real_buf_sz,
					  buf->offset,
					  region->real_buf_sz))
			return buf;
	}
	return NULL;
}
