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

#ifndef __DANIPC_H__
#define __DANIPC_H__

#include <linux/netdevice.h>
#include <linux/ioctl.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>
#include <linux/bitmap.h>

#include <linux/danipc_ioctl.h>
#include <ipc_api.h>

enum danipc_resources {
	IPC_BUFS_RES = 0,
	AGENT_TABLE_RES,
	KRAIT_IPC_MUX_RES,
	RESOURCE_NUM
};

#define DANIPC_PROTOCOL_MATCH(p) (((p) & htons(0xf000)) == htons(COOKIE_BASE))
#define DANIPC_AGENT_DISCOVERED(aid, list) \
	(((uint8_t *)(list))[(aid) >> 3] |= 1 << ((aid)&(BITS_PER_BYTE - 1)))
#define DANIPC_IS_AGENT_DISCOVERED(aid, list) \
	(((uint8_t *)(list))[(aid) >> 3] & (1 << ((aid)&(BITS_PER_BYTE - 1))))

struct delayed_skb {
	struct list_head	 list;
	struct sk_buff		*skb;
};

/* Rx task type */
union rx_work {
	struct tasklet_struct	rx_task;
	struct work_struct	rx_work;
	struct timer_list	timer;
};

/* Return index into the histogram array as long as
 * size of packet is < 2Kb, for all other sizes returns
 * index 0.
 */
#define	PACKT_HISTO_IDX(sz)	(-(sz && ((sz) < 2048)) \
					 & (((sz) + (64 - 1))>>6))

/* Packet sizes multiple of 64bytes. First entry reserved
 * for packets > 2Kb size.
 */
#define	MAX_PACKET_SIZES	((2048 >> 6) + 1)

struct danipc_pkt_histo {
	struct net_device_stats *stats;
	unsigned long		rx_pool_used;
	unsigned long		tx_delayed;
	unsigned long		rx_err_dest_aid;
	unsigned long		rx_err_chained_buf;
	unsigned long		rx_err_len;
	unsigned long		rx_histo[MAX_PACKET_SIZES];
	unsigned long		tx_histo[MAX_PACKET_SIZES];

	/* + 1 to account for having IPC_FIFO_BUF_NUM_HIGH packets in
	 * a burst
	 */
	unsigned long		rx_pkt_burst[IPC_FIFO_BUF_NUM_HIGH + 1];
};

/* TX/RX packet processign routine info */
struct packet_proc_info {
	struct danipc_if		*intf;
	uint32_t		intstatus;
	uint32_t		intmask;

	/* Rx work information */
	union rx_work		rx_work;

	/* RX packet processing ops */
	uint8_t			rxproc_type;
	uint8_t			rxbound;
	uint8_t			pending;
	/* Histogram of TX/RX packets */
	struct danipc_pkt_histo	pkt_hist;
};

/* Packet queue */
struct danipc_pktq {
	struct sk_buff_head	q;
	unsigned long		used;
	uint8_t			refill;
	uint16_t		max_size;
};

/* debugfs handler info */
struct dbgfs_hdlr {
	void (*display)(struct seq_file *);
	ssize_t (*write)(struct file *, const char __user*, size_t, loff_t *);
	void *data;
};

/* debugfs info */
struct danipc_dbgfs {
	const char *fname;
	umode_t mode;
	struct dbgfs_hdlr dbghdlr;
};

#define DBGFS_NODE(n, m, read_op, write_op) {	\
	.fname = n,				\
	.mode = m,				\
	{					\
		.display = read_op,		\
		.write = write_op,		\
	},					\
}

#define DBGFS_NODE_LAST	{	\
	.fname = NULL,		\
}

struct danipc_probe_info {
	const char	*res_name;
	const char	*ifname;
	const uint16_t	poolsz;
};

#define DANIPC_MAX_LFIFO	2
#define DANIPC_FIFO_F_INIT	1
#define DANIPC_FIFO_F_INUSE	2

#define DANIPC_FIFO_OWNER_TYPE_NETDEV	0
#define DANIPC_FIFO_OWNER_TYPE_CDEV	1

struct danipc_fifo {
	struct mutex			lock;	/* lock for fifo */
	struct ipc_to_virt_map		*map;
	struct danipc_probe_info	*probe_info;
	void				*owner;
	uint32_t			irq;
	uint8_t				node_id;
	uint8_t				idx;
	uint8_t				owner_type;
	uint32_t			flag;
};

/* Danipc interface specific info */
struct danipc_if {
	struct danipc_drvr	*drvr;
	struct net_device	*dev;
	struct danipc_fifo	*fifo;
	struct mutex		lock;

	/* Packet processing information for
	 * both high and low priority fifos.
	 */
	struct packet_proc_info	pproc[max_ipc_prio];

	/* packet pool for rx packets */
	struct danipc_pktq			rx_pkt_pool;

	uint32_t		irq;
	uint8_t		ifidx;
	uint8_t			rx_fifo_idx;

	/* Yield in favour of high-prio FIFO */
	uint8_t			rx_fifo_prio;

	/* Interrupt affinity */
	uint8_t			affinity;

	/* Debug fs node */
	struct dentry		*dirent;
	struct danipc_dbgfs	*dbgfs;
};

/* RX packet processing types */
enum pkt_rx_proc_type {
	rx_proc_default,
	rx_proc_parallel,
	rx_proc_concurrent,
	rx_proc_concurrent_delay,
	rx_proc_timer,
	rx_max_proc,
};

typedef void (*pktproc_fn)(unsigned long);
typedef void (*pktproc_work)(struct work_struct *work);
typedef void (*pktproc_init)(struct packet_proc_info *);
typedef void (*pktproc_sched)(union rx_work *task);

union pktproc_type {
	pktproc_fn	fn;
	pktproc_work	work;
};

struct packet_proc {
	pktproc_init	init;
	pktproc_sched	schedule_work;
	union pktproc_type	proc_pkt;
	pktproc_init	stop;
};

#define DANIPC_MAX_IF		DANIPC_MAX_LFIFO

/* Character device interface */
#define DANIPC_MAJOR		100
#define DANIPC_CDEV_NAME	"danipc"
#define DANIPC_MAX_CDEV		1

struct rx_queue_status {
	uint32_t	kmem_recvq_hi;
	uint32_t	kmem_freeq_lo;
	uint32_t	recvq_hi;
	uint32_t	freeq_lo;
	uint32_t	bq_lo;
};

struct rx_queue {
	struct shm_bufpool	kmem_recvq;
	struct shm_bufpool	kmem_freeq;
	struct shm_bufpool	recvq;
	struct shm_bufpool	freeq;
	struct shm_bufpool	bq;
	struct shm_bufpool	mmapq;
	struct rx_queue_status	status;
};

struct tx_queue {
	struct shm_bufpool	mmapq;
	struct shm_bufpool	mmap_bufcacheq;
};

struct danipc_cdev_status {
	uint32_t	rx;
	uint32_t	rx_bytes;
	uint32_t	rx_drop;
	uint32_t	rx_no_buf;
	uint32_t	rx_error;
	uint32_t	rx_zlen_msg;
	uint32_t	rx_oversize_msg;
	uint32_t	rx_inval_msg;
	uint32_t	rx_chained_msg;

	uint32_t	mmap_rx;
	uint32_t	mmap_rx_done;
	uint32_t	mmap_rx_error;

	uint32_t	tx;
	uint32_t	tx_bytes;
	uint32_t	tx_drop;
	uint32_t	tx_error;
	uint32_t	tx_no_buf;

	uint32_t	mmap_tx;
	uint32_t	mmap_tx_reqbuf;
	uint32_t	mmap_tx_reqbuf_error;
	uint32_t	mmap_tx_nobuf;
	uint32_t	mmap_tx_error;
	uint32_t	mmap_tx_bad_buf;
};

struct rx_kmem_region {
	void			*kmem;
	uint32_t		kmem_sz;
	struct shm_region	*region;
};

struct danipc_cdev {
	struct danipc_drvr	*drvr;
	struct device		*dev;
	struct danipc_fifo	*fifo;

	struct rx_kmem_region	rx_kmem_region;
	struct shm_region	*rx_region;
	struct vm_area_struct	*rx_vma;
	atomic_t		rx_vma_ref;
	struct rx_queue		rx_queue[max_ipc_prio];
	struct tasklet_struct	rx_work;
	spinlock_t		rx_lock;	/* sync access to HW FIFO */
	wait_queue_head_t	rx_wq;

	struct shm_region	*tx_region;
	struct vm_area_struct	*tx_vma;
	atomic_t		tx_vma_ref;
	struct tx_queue		tx_queue;

	int			minor;

	/* Debug fs node */
	struct dentry		*dirent;
	struct danipc_dbgfs	*dbgfs;

	struct danipc_cdev_status	status;
};

/* Network device private data */
struct danipc_drvr {
	resource_size_t		res_start[RESOURCE_NUM];
	resource_size_t		res_len[RESOURCE_NUM];

	/* Interface list */
	struct danipc_if		*if_list[DANIPC_MAX_IF];

	/* Packet Rx processign ops */
	struct packet_proc		proc_rx[rx_max_proc];

	/* Valid Dest-aid map */
	uint8_t			dst_aid[MAX_AGENTS/BITS_PER_BYTE];

	/* Number of devices found during probe */
	uint8_t			ndev;

	/* Number of devices active */
	uint8_t			ndev_active;

	/* driver debug fs information */
	struct dentry		*dirent;

	bool			support_mem_map;
	uint32_t		mem_map_version;

	/* char device driver interface */
	struct danipc_cdev	cdev[DANIPC_MAX_CDEV];

	/* local FIFO */
	struct danipc_fifo	lfifo[DANIPC_MAX_LFIFO];
	uint8_t			num_lfifo;
};

/* Connection information. */
struct danipc_pair {
	unsigned		prio;
	danipc_addr_t		dst;
	danipc_addr_t		src;
};

#define HADDR_CB_OFFSET		40

#define COOKIE_BASE		0xE000		/* EtherType */

#define PRIO_SHIFT			4
#define PRIO_MASK			(((1 <<  PRIO_SHIFT)) - 1)

#define COOKIE_TO_AGENTID(cookie)	((cookie - COOKIE_BASE) >> PRIO_SHIFT)
#define COOKIE_TO_PRIO(cookie)		((cookie - COOKIE_BASE) & PRIO_MASK)
#define AGENTID_TO_COOKIE(agentid, pri)	(COOKIE_BASE +			\
					  ((agentid) << PRIO_SHIFT) +	\
					  (pri))

/* Describes an IPC buffer region, either ours or an extern one */
struct ipc_buf_desc {
	uint32_t phy_addr;
	uint32_t sz;
};

void danipc_ll_init(struct danipc_drvr *drv);
void danipc_ll_cleanup(struct danipc_drvr *drv);
int danipc_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd);
int danipc_hard_start_xmit(struct sk_buff *skb, struct net_device *dev);

void danipc_init_irq(struct danipc_fifo *fifo);
void danipc_disable_irq(struct danipc_fifo *fifo);
irqreturn_t danipc_interrupt(int irq, void *data);
irqreturn_t danipc_cdev_interrupt(int irq, void *data);

int	send_pkt(struct sk_buff *skb);

extern struct list_head	delayed_skbs;
extern spinlock_t	skbs_lock;
extern struct work_struct delayed_skbs_work;

extern struct net_device	*danipc_dev;
extern struct danipc_drvr	danipc_driver;

int danipc_change_mtu(struct net_device *dev, int new_mtu);

void danipc_default_rcv_init(struct packet_proc_info *prio);
void danipc_default_work_sched(union rx_work *task);
void danipc_default_rcv(unsigned long);
void danipc_default_stop(struct packet_proc_info *pproc);

void danipc_tasklet_init(struct packet_proc_info *pproc);
void danipc_tasklet_sched(union rx_work *task);
void danipc_conc_tasklet_sched(union rx_work *task);
void danipc_tasklet_stop(struct packet_proc_info *pproc);

void danipc_proc_parallel_rcv(unsigned long data);
void danipc_proc_concurrent_rcv(unsigned long data);

void danipc_wq_init(struct packet_proc_info *pproc);
void danipc_wq_sched(union rx_work *task);
void danipc_proc_wq_rcv(struct work_struct *work);
void danipc_wq_stop(struct packet_proc_info *pproc);

void danipc_timer_init(struct packet_proc_info *pproc);
void danipc_timer_sched(union rx_work *task);
void danipc_rcv_timer(unsigned long data);
void danipc_timer_stop(struct packet_proc_info *pproc);

void alloc_pool_buffers(struct danipc_if *intf);

int init_own_ipc_to_virt_map(struct danipc_fifo *fifo);

long danipc_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int danipc_cdev_tx(struct danipc_cdev *cdev,
		   struct danipc_cdev_msghdr *hdr,
		   const char __user *buf,
		   size_t count);

int danipc_cdev_mmsg_rx(struct danipc_cdev *cdev,
			struct danipc_cdev_mmsg *mmsg);

void danipc_cdev_refill_rx_b_fifo(struct danipc_cdev *cdev,
				  enum ipc_trns_prio pri);

void danipc_cdev_init_rx_work(struct danipc_cdev *cdev);
void danipc_cdev_stop_rx_work(struct danipc_cdev *cdev);

int danipc_cdev_mapped_recv(struct danipc_cdev *cdev,
			    struct vm_area_struct *vma,
			    struct danipc_bufs *bufs);

int danipc_cdev_mapped_recv_done(struct danipc_cdev *cdev,
				 struct vm_area_struct *vma,
				 struct danipc_bufs *bufs);

int danipc_cdev_mapped_tx(struct danipc_cdev *cdev,
			  struct danipc_bufs *bufs);

int danipc_cdev_mapped_tx_get_buf(struct danipc_cdev *cdev,
				  struct danipc_bufs *bufs);

int danipc_cdev_mapped_tx_put_buf(struct danipc_cdev *cdev,
				  struct danipc_bufs *bufs);

int danipc_cdev_enqueue_kmem_recvq(struct danipc_cdev *cdev,
				   enum ipc_trns_prio pri);

int ipc_msg_copy(void *dst, const void *src, size_t size, bool adj_offset);

static inline bool local_fifo_owner(struct danipc_fifo *fifo, void *owner)
{
	return ((fifo->flag & DANIPC_FIFO_F_INUSE) && (fifo->owner == owner));
}

struct dentry *danipc_dbgfs_create_dir(struct dentry *parent_dent,
				       const char *dir_name,
				       struct danipc_dbgfs *nodes,
				       void *private_data);

int danipc_dbgfs_netdev_init(void);
void danipc_dbgfs_netdev_remove(void);
int danipc_dbgfs_cdev_init(void);
void danipc_dbgfs_cdev_remove(void);

#endif /* __DANIPC_H__ */
