/*
 *	All files except if stated otherwise in the beginning of the file
 *	are under the ISC license:
 *	----------------------------------------------------------------------
 *	Copyright (c) 2015, The Linux Foundation. All rights reserved.
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

#define RESOURCE_NUM		3
#define IPC_BUFS_RES		0
#define AGENT_TABLE_RES		1
#define KRAIT_IPC_MUX_RES	2

#define DANIPC_PROTOCOL_MATCH(p) (((p) & htons(0xf000)) == htons(COOKIE_BASE))
#define DANIPC_AGENT_DISCOVERED(aid, list) \
	(((uint8_t *)(list))[(aid) >> 3] |= 1 << ((aid)&(BITS_PER_BYTE - 1)))
#define DANIPC_IS_AGENT_DISCOVERED(aid, list) \
	(((uint8_t *)(list))[(aid) >> 3] & (1 << ((aid)&(BITS_PER_BYTE - 1))))

#define DANIPC_DBGDRV_ENTRY_MAX 23

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
	unsigned long		rx_histo[MAX_PACKET_SIZES];
	unsigned long		tx_histo[MAX_PACKET_SIZES];
	unsigned long		rx_pkt_burst[IPC_FIFO_BUF_NUM_HIGH];
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
	struct dentry *ent;
	const char fname[50];
	umode_t mode;
	struct dbgfs_hdlr dbghdlr;
};

/* Danipc interface specific info */
struct danipc_if {
	struct danipc_drvr		*drvr;
	struct net_device	*dev;
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

	/* index to select interrupt mask that maps
	 * interrupts from CDU to APPS IRQ.
	 */
	uint16_t			mux_mask;
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

#define DANIPC_MAX_IF		2

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
	struct danipc_dbgfs		dbgfsinf[DANIPC_DBGDRV_ENTRY_MAX];
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

void danipc_ll_init(struct danipc_if *intf);
void danipc_ll_cleanup(struct danipc_if *intf);
int danipc_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd);
int danipc_hard_start_xmit(struct sk_buff *skb, struct net_device *dev);

void danipc_init_irq(struct danipc_if *intf);
void danipc_disable_irq(struct danipc_if *intf);
irqreturn_t danipc_interrupt(int irq, void *data);

int	send_pkt(struct sk_buff *skb);

extern struct list_head	delayed_skbs;
extern spinlock_t	skbs_lock;
extern struct work_struct delayed_skbs_work;

extern struct net_device	*danipc_dev;
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

int init_own_ipc_to_virt_map(struct danipc_if *intf);

#endif /* __DANIPC_H__ */
