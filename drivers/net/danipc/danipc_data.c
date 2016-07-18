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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/debugfs.h>

#include "ipc_api.h"

#include "danipc_k.h"
#include "danipc_lowlevel.h"

#define TIMER_INTERVAL		1

DEFINE_PER_CPU(atomic_t, danipc_rx_sched_state);

int send_pkt(struct sk_buff *skb)
{
	struct danipc_pair	*pair =
		(struct danipc_pair *)&skb->cb[HADDR_CB_OFFSET];
	char			*msg;
	struct danipc_if	*intf  =
		(struct danipc_if *)netdev_priv(skb->dev);
	struct danipc_pkt_histo *histo = &intf->pproc[pair->prio].pkt_hist;
	int			 rc    = NETDEV_TX_OK;

	netdev_dbg(skb->dev, "%s: pair={dst=0x%x src=0x%x}\n", __func__,
		   pair->dst, pair->src);

	if (DANIPC_IS_AGENT_DISCOVERED(pair->dst, intf->drvr->dst_aid)) {
		msg = ipc_msg_alloc(pair->src,
				    pair->dst,
				    skb->data,
				    skb->len,
				    0x12,
				    pair->prio,
				    false
			);

		if (likely(msg)) {
			ipc_msg_send(msg, pair->prio);
			histo->stats->tx_packets++;
			histo->stats->tx_bytes += skb->len;
			histo->tx_histo[PACKT_HISTO_IDX(skb->len)]++;
		} else {
			netdev_dbg(skb->dev, "%s: ipc_msg_alloc failed!",
				   __func__);
			histo->stats->tx_dropped++;
			histo->stats->tx_fifo_errors++;

			/* If we are busy, qdisc will retry later with the same
			 * skb, so return without freeing skb.
			 */
			return NETDEV_TX_BUSY;
		}
	} else {
		netdev_dbg(skb->dev, "%s: Packet for un-identified agent",
			   __func__);
		histo->stats->tx_dropped++;
		histo->stats->tx_heartbeat_errors++;
	}

	/* This is only called if the device is NOT busy. */
	dev_kfree_skb(skb);

	return rc;
}

static int delay_skb(struct sk_buff *skb, struct ipc_to_virt_map *map)
{
	int			 rc;
	struct danipc_pair	*pair  =
		(struct danipc_pair *)&skb->cb[HADDR_CB_OFFSET];
	struct delayed_skb	*dskb  = kmalloc(sizeof(*dskb), GFP_ATOMIC);
	struct danipc_if	*intf  =
		(struct danipc_if *)netdev_priv(skb->dev);
	struct danipc_pkt_histo *histo = &intf->pproc[pair->prio].pkt_hist;

	if (dskb) {
		unsigned long	flags;

		dskb->skb = skb;
		INIT_LIST_HEAD(&dskb->list);

		spin_lock_irqsave(&skbs_lock, flags);
		list_add_tail(&dskb->list, &delayed_skbs);
		atomic_inc(&map->pending_skbs);
		spin_unlock_irqrestore(&skbs_lock, flags);

		schedule_work(&delayed_skbs_work);
		histo->tx_delayed++;
		rc = NETDEV_TX_OK;
	} else {
		netdev_err(skb->dev, "cannot allocate struct delayed_skb\n");
		rc = NETDEV_TX_BUSY;	/* Try again sometime */
		histo->stats->tx_dropped++;
		histo->stats->tx_aborted_errors++;
	}
	return rc;
}

int danipc_hard_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct danipc_pair	*pair  =
		(struct danipc_pair *)&skb->cb[HADDR_CB_OFFSET];
	struct ipc_to_virt_map	*map   =
		&ipc_to_virt_map[ipc_get_node(pair->dst)][pair->prio];
	struct danipc_if	*intf  =
		(struct danipc_if *)netdev_priv(skb->dev);
	struct danipc_pkt_histo *histo = &intf->pproc[pair->prio].pkt_hist;
	int			 rc    = NETDEV_TX_OK;

	/* DANIPC is a network device, however it does not support regular IP
	 * packets. All packets not identified by DANIPC protocol (marked with
	 * COOKIE_BASE bits) are discarded.
	 */
	if (DANIPC_PROTOCOL_MATCH(skb->protocol)) {
		if (map->paddr && atomic_read(&map->pending_skbs) == 0)
			rc = send_pkt(skb);
		else
			rc = delay_skb(skb, map);
	} else {
		histo->stats->tx_dropped++;
		histo->stats->tx_carrier_errors++;
		netdev_dbg(dev, "%s() discard packet with protocol=0x%x\n",
			   __func__, ntohs(skb->protocol));
		dev_kfree_skb(skb);
	}
	return rc;
}

static void
read_ipc_message(char *const packet, char *buf,
			struct ipc_msg_hdr *const first_hdr, const unsigned len,
			u8 cpuid, enum ipc_trns_prio prio)
{
	unsigned		data_len = IPC_FIRST_BUF_DATA_SIZE_MAX;
	unsigned		rest_len = len;
	uint8_t			*data_ptr = (uint8_t *)(first_hdr) +
						sizeof(struct ipc_msg_hdr);

	data_len = min(rest_len, data_len);
	memcpy(buf, data_ptr, data_len);

	ipc_buf_free(packet, cpuid, prio);
}

void drop_ipc_message(char *const packet, enum ipc_trns_prio prio, u8 cpuid)
{
	ipc_buf_free(packet, cpuid, prio);
}

void
handle_incoming_packet(struct packet_proc_info *pproc, char *const packet)
{
	struct danipc_if	*intf = pproc->intf;
	struct danipc_pktq	*rx_pool = &intf->rx_pkt_pool;
	struct ipc_msg_hdr *const first_hdr = (struct ipc_msg_hdr *)packet;
	const unsigned		msg_len = first_hdr->msg_len;
	struct net_device	*dev = intf->dev;
	struct sk_buff		*skb = netdev_alloc_skb(dev, msg_len);
	uint8_t			prio = pproc - intf->pproc;
	struct danipc_pkt_histo	*histo = &pproc->pkt_hist;

	/* for high-priority fifo, try from pre-allocated pool */
	if (!skb && (prio == ipc_trns_prio_1)) {
		netdev_dbg(dev, "%s: using skb from rx_pool\n", __func__);
		skb = __skb_dequeue(&rx_pool->q);
		if (skb) {
			histo->rx_pool_used++;
			rx_pool->used++;
			rx_pool->refill = 1;
		}
	}

	if (skb) {
		struct danipc_pair	*pair =
			(struct danipc_pair *)&skb->cb[HADDR_CB_OFFSET];

		pair->dst = first_hdr->dest_aid;
		pair->src = first_hdr->src_aid;

		read_ipc_message(packet, skb->data, first_hdr, msg_len,
				 intf->rx_fifo_idx, prio);

		netdev_dbg(dev, "%s() pair={dst=0x%x src=0x%x}\n",
			   __func__, pair->dst, pair->src);

		skb_put(skb, msg_len);
		skb_reset_mac_header(skb);

		skb->protocol = cpu_to_be16(AGENTID_TO_COOKIE(pair->dst, prio));

		if (NET_RX_SUCCESS != netif_rx(skb))
			netdev_dbg(dev, "%s: netif_rx send failed\n", __func__);

		histo->stats->rx_packets++;
		histo->stats->rx_bytes += skb->len;
		histo->rx_histo[PACKT_HISTO_IDX(skb->len)]++;
	} else {
		netdev_warn(dev, "%s: skb alloc failed dropping message\n",
			    __func__);
		drop_ipc_message(packet, prio, intf->rx_fifo_idx);
		histo->stats->rx_dropped++;
		histo->stats->rx_missed_errors++;
	}
}

int danipc_change_mtu(struct net_device *dev, int new_mtu)
{
	if ((new_mtu < 68) || (new_mtu > IPC_BUF_SIZE_MAX))
		return -EINVAL;
	dev->mtu = new_mtu;
	return 0;
}

static inline void set_rxstate_schedule(uint8_t prio)
{
	set_bit(prio, (unsigned long *)this_cpu_ptr(&danipc_rx_sched_state));
}

static inline void set_rxstate_complete(uint8_t prio)
{
	clear_bit(prio, (unsigned long *)this_cpu_ptr(&danipc_rx_sched_state));
}

static inline unsigned long get_rxsched_state(void)
{
	return (unsigned long)atomic_read(
		(atomic_t *)this_cpu_ptr(&danipc_rx_sched_state));
}

/* Returns true if there are errors */
static inline int check_errors(struct packet_proc_info *pproc, char *packet)
{
	struct ipc_msg_hdr *const first_hdr = (struct ipc_msg_hdr *)packet;

	if (first_hdr->msg_len > IPC_FIRST_BUF_DATA_SIZE_MAX ||
	    !first_hdr->msg_len) {
		pproc->pkt_hist.stats->rx_dropped++;
		pproc->pkt_hist.stats->rx_errors++;
		pproc->pkt_hist.rx_err_len++;

		return 1;
	}

	/* Destination AID should for a CPU ID/FIFO index we know about */
	if (ipc_get_node(first_hdr->dest_aid) != pproc->intf->rx_fifo_idx) {
		pproc->pkt_hist.stats->rx_dropped++;
		pproc->pkt_hist.stats->rx_errors++;
		pproc->pkt_hist.rx_err_dest_aid++;

		return 1;
	}

	if (first_hdr->next != NULL) {
		pproc->pkt_hist.stats->rx_dropped++;
		pproc->pkt_hist.stats->rx_errors++;
		pproc->pkt_hist.rx_err_chained_buf++;

		return 1;
	}

	return 0;
}

/* -----------------------------------------------------------
 * Function:    danipc_recv
 * Description: Processing IPC messages
 * Input:               pproc - Interface specific packet processign info.
 * Output:              number of processed messages
 * -----------------------------------------------------------
 */
uint32_t danipc_recv(struct packet_proc_info *pproc)
{
	struct danipc_if	*intf = pproc->intf;
	unsigned	ix;
	uint8_t	prio = pproc - intf->pproc;
	char		*ipc_data;

	for (ix = 0; ix < pproc->rxbound; ix++) {
		ipc_data = ipc_trns_fifo_buf_read(prio, intf->rx_fifo_idx);

		if (ipc_data) {
			if (check_errors(pproc, ipc_data)) {
				drop_ipc_message(
					ipc_data, prio,
					intf->rx_fifo_idx);
			} else {
				/* IPC_msg_handler(ipc_data); */
				handle_incoming_packet(pproc, ipc_data);
			}
		} else {
			break; /* no more messages, queue empty */
		}
	}

	/* If required refill skb pool */
	if (intf->rx_pkt_pool.refill)
		alloc_pool_buffers(intf);

	return ix;
}

/* -----------------------------------------------------------
 * Function:    danipc_recv_concurrent
 * Description: Processing ipc messages only if fifo within
 *		current interface is highest priority.
 * Input:               pproc - Interface specific packet processign info.
 * Output:              number of processed messages
 * -----------------------------------------------------------
 */
uint32_t danipc_recv_concurrent(struct packet_proc_info *pproc)
{
/* Priority decreases from LSbit towards MSbit.
 * DANIPC_IF_MYPRIO -1 gives all high priority
 * fifo status.
 * NOTE: danipc_recv_concurrent on behalf of high priority
 * does not care to check if there are low-prioity
 * rx jobs pending.
 */
#define DANIPC_IF_MYPRIO(p)	(1<<(p))
#define IS_HIGHPRIO_FIFO(p)	\
	(!((p) && ((DANIPC_IF_MYPRIO(p) - 1) & get_rxsched_state())))
	struct danipc_if	*intf = pproc->intf;
	unsigned	ix;
	uint8_t	prio = pproc - intf->pproc;
	char		*ipc_data;

	for (ix = 0; (ix < pproc->rxbound) &&
	     IS_HIGHPRIO_FIFO(intf->rx_fifo_prio); ix++) {
		ipc_data = ipc_trns_fifo_buf_read(prio, intf->rx_fifo_idx);

		if (ipc_data) {
			/* IPC_msg_handler(ipc_data); */
			handle_incoming_packet(pproc, ipc_data);
		} else {
			break; /* no more messages, queue empty */
		}
	}
	return ix;
}

void danipc_default_rcv_init(struct packet_proc_info *prio)
{
	pr_info("WARNING!!! default Danipc work init\n");
}

void danipc_default_work_sched(union rx_work *task)
{
	pr_info("WARNING!!! default Danipc work scheduled\n");
}

void danipc_default_rcv(unsigned long data)
{
	pr_info("WARNING!!! default Danipc rcv:%p\n", (void *)data);
}

void danipc_default_stop(struct packet_proc_info *pproc)
{
	pr_info("WARNING!!! default Danipc wrok rcv\n");
}

void danipc_tasklet_init(struct packet_proc_info *pproc)
{
	struct danipc_if		*intf = pproc->intf;
	struct danipc_drvr	*drvr = intf->drvr;
	pktproc_fn		fn =
		 drvr->proc_rx[pproc->rxproc_type].proc_pkt.fn;
	struct tasklet_struct   *task = &pproc->rx_work.rx_task;

	tasklet_init(task, fn, (unsigned long)pproc);
}

void danipc_tasklet_stop(struct packet_proc_info *pproc)
{
	tasklet_kill(&pproc->rx_work.rx_task);
}

void danipc_tasklet_sched(union rx_work *task)
{
	tasklet_schedule(&task->rx_task);
}

void danipc_conc_tasklet_sched(union rx_work *task)
{
	struct packet_proc_info *pproc =
		container_of(task, struct packet_proc_info, rx_work);

	set_rxstate_schedule(pproc->intf->rx_fifo_prio);
	tasklet_schedule(&task->rx_task);
}

void danipc_proc_parallel_rcv(unsigned long data)
{
	struct packet_proc_info *pproc = (struct packet_proc_info *)data;
	struct danipc_if	*intf = pproc->intf;
	uint8_t cnt;

	/* Process all messages. */
	cnt = danipc_recv(pproc);
	pproc->pending = (cnt == pproc->rxbound);
	pproc->pkt_hist.rx_pkt_burst[cnt]++;

	/* Skip interrupt enable if more packets to process */
	if (pproc->pending) {
		danipc_tasklet_sched(&pproc->rx_work);
	} else {
		/* Clear interrupt source. */
		danipc_clear_interrupt(intf->rx_fifo_idx);
		/* Unmask IPC AF interrupt again. */
		danipc_unmask_interrupt(intf->rx_fifo_idx);
	}
}

void danipc_proc_concurrent_rcv(unsigned long data)
{
	struct packet_proc_info *pproc = (struct packet_proc_info *)data;
	struct danipc_if	*intf = pproc->intf;
	uint8_t cnt;

	/* Process all messages. */
	cnt = danipc_recv_concurrent(pproc);
	pproc->pending = (cnt == pproc->rxbound);
	pproc->pkt_hist.rx_pkt_burst[cnt]++;

	set_rxstate_complete(intf->rx_fifo_prio);

	/* Skip interrupt enable if more packets to process */
	if (pproc->pending) {
		danipc_conc_tasklet_sched(&pproc->rx_work);
	} else {
		/* Clear interrupt source. */
		danipc_clear_interrupt(intf->rx_fifo_idx);
		/* Unmask IPC AF interrupt again. */
		danipc_unmask_interrupt(intf->rx_fifo_idx);
	}
}

void danipc_wq_init(struct packet_proc_info *pproc)
{
	struct danipc_if		*intf = pproc->intf;
	struct danipc_drvr		*drvr = intf->drvr;
	pktproc_work		fn =
		drvr->proc_rx[pproc->rxproc_type].proc_pkt.work;
	struct work_struct	*work = &pproc->rx_work.rx_work;

	INIT_WORK(work, fn);
}

void danipc_wq_stop(struct packet_proc_info *pproc)
{
	cancel_work_sync(&pproc->rx_work.rx_work);
}

void danipc_wq_sched(union rx_work *task)
{
	schedule_work(&task->rx_work);
}

void danipc_proc_wq_rcv(struct work_struct *work)
{
	struct packet_proc_info *pproc = container_of((union rx_work *)work,
						      struct packet_proc_info,
						      rx_work);
	struct danipc_if	*intf = pproc->intf;
	uint8_t cnt;

	/* Process all messages. */
	cnt = danipc_recv(pproc);
	pproc->pending = (cnt == pproc->rxbound);
	pproc->pkt_hist.rx_pkt_burst[cnt]++;

	/* Skip interrupt enable if more packets to process */
	if (pproc->pending) {
		danipc_wq_sched(&pproc->rx_work);
	} else {
		/* Clear interrupt source. */
		danipc_clear_interrupt(intf->rx_fifo_idx);
		/* Unmask IPC AF interrupt again. */
		danipc_unmask_interrupt(intf->rx_fifo_idx);
	}
}

void danipc_timer_init(struct packet_proc_info *pproc)
{
	struct danipc_if	*intf  = pproc->intf;
	struct danipc_drvr	*drvr  = intf->drvr;
	pktproc_fn		fn     =
		drvr->proc_rx[pproc->rxproc_type].proc_pkt.fn;
	struct timer_list	*timer = &pproc->rx_work.timer;

	setup_timer(timer, fn, (unsigned long)pproc);
	mod_timer(timer, jiffies +  TIMER_INTERVAL);
}

void danipc_timer_stop(struct packet_proc_info *pproc)
{
	del_timer_sync(&pproc->rx_work.timer);
}

void danipc_timer_sched(union rx_work *task)
{
	add_timer(&task->timer);
}

void danipc_rcv_timer(unsigned long data)
{
	struct packet_proc_info	*pproc = (struct packet_proc_info *)data;
	struct timer_list	*timer = &pproc->rx_work.timer;
	uint8_t cnt;

	cnt = danipc_recv(pproc);
	pproc->pkt_hist.rx_pkt_burst[cnt]++;

	mod_timer(timer, jiffies + TIMER_INTERVAL);
}

/* DANIPC netdev debugfs interface */
static void danipc_dump_fifo_info(struct seq_file *s)
{
	struct dbgfs_hdlr       *hdlr    = (struct dbgfs_hdlr *)s->private;
	struct danipc_if        *intf   = (struct danipc_if *)hdlr->data;
	struct danipc_pktq             *rx_pool = &intf->rx_pkt_pool;
	struct packet_proc_info *pproc   = intf->pproc;
	static const char  *format  = "%-20s: %-d\n";

	seq_puts(s, "\n\nDanipc driver fifo info:\n\n");
	seq_printf(s, format, "Irq", intf->irq);
	seq_printf(s, format, "If Index", intf->ifidx);
	seq_printf(s, format, "HW fifo Index", intf->rx_fifo_idx);
	seq_printf(s, format, "Inter fifo prio", intf->rx_fifo_prio);
	seq_printf(s, format, "Interrupt affinity", intf->affinity);
	seq_printf(s, format, "Hiprio rxbound",
		   pproc[ipc_trns_prio_1].rxbound);
	seq_printf(s, format, "Lowprio rxbound",
		   pproc[ipc_trns_prio_0].rxbound);
	seq_printf(s, format, "Rxpool maxsize", rx_pool->max_size);
	seq_printf(s, format, "Rxpool cursize", skb_queue_len(&rx_pool->q));
	seq_printf(s, "%-20s: %-lu\n", "Rxpool usage", rx_pool->used);
}

static void danipc_dump_pkt_hist(struct seq_file *s, unsigned long *pkt_histo,
				 unsigned long totpkts)
{
	uint32_t i;

	if (totpkts) {
		char buf[50];

		for (i = 0; i < MAX_PACKET_SIZES; i++) {
			if ((i%4) == 0)
				seq_puts(s, "\n");
			snprintf(buf, sizeof(buf), "<=%-6d:%-lu(%%%-lu)",
				 (i == 0) ? 2048 : i*64, pkt_histo[i],
			(pkt_histo[i] * 100)/totpkts);
			seq_printf(s, "%-25s", buf);
		}
		seq_puts(s, "\n\n");
	}
}

static void danipc_dump_fifo_hist(struct seq_file *s,
				  struct danipc_pkt_histo *histo)
{
	struct net_device_stats *stats = histo->stats;
	static const char *fmt_lu = "%-25s: %-lu\n";

	seq_printf(s, fmt_lu, "Tx packets", stats->tx_packets);
	seq_printf(s, fmt_lu, "Tx delayed packets", histo->tx_delayed);
	seq_printf(s, fmt_lu, "Tx bytes", stats->tx_bytes);
	seq_printf(s, fmt_lu, "Tx errors", stats->tx_errors);
	seq_printf(s, fmt_lu, "Tx dropped", stats->tx_dropped);
	seq_printf(s, fmt_lu, "Tx Remote bfifo empty",
		   stats->tx_fifo_errors);
	seq_printf(s, fmt_lu, "Tx no dst agent",
		   stats->tx_heartbeat_errors);
	seq_printf(s, fmt_lu, "Tx not danipc packet",
		   stats->tx_carrier_errors);
	seq_printf(s, fmt_lu, "Tx dskb alloc failed",
		   stats->tx_aborted_errors);
	seq_printf(s, fmt_lu, "Tx unknown drops",
		   stats->tx_dropped -
		   (stats->tx_fifo_errors +
		    stats->tx_heartbeat_errors +
		    stats->tx_carrier_errors +
		    stats->tx_aborted_errors));
	seq_printf(s, fmt_lu, "Rx pool used", histo->rx_pool_used);
	seq_printf(s, fmt_lu, "Rx packets", stats->rx_packets);
	seq_printf(s, fmt_lu, "Rx bytes", stats->rx_bytes);
	seq_printf(s, fmt_lu, "Rx errors", stats->rx_errors);
	seq_printf(s, fmt_lu, "Rx dropped", stats->rx_dropped);
	seq_printf(s, fmt_lu, "Rx nobuf", stats->rx_missed_errors);
	seq_printf(
		s, fmt_lu, "Rx invalid dest aid",
		histo->rx_err_dest_aid);
	seq_printf(s, fmt_lu, "Rx chained_buffers", histo->rx_err_chained_buf);
	seq_printf(s, fmt_lu, "Rx invalid length", histo->rx_err_len);
	seq_printf(s, fmt_lu, "Rx unknown drops", stats->rx_dropped -
		(stats->rx_missed_errors + histo->rx_err_dest_aid
		+ histo->rx_err_chained_buf + histo->rx_err_len));
}

static void danipc_dump_pkt_burst(struct seq_file *s, unsigned long *pkt_bust)
{
	uint32_t i;
	char buf[50];

	for (i = 0; i <= IPC_BUF_COUNT_MAX; i++) {
		if ((i%4) == 0)
			seq_puts(s, "\n");
		snprintf(buf, sizeof(buf), "%-5d:%-lu", i, pkt_bust[i]);
		seq_printf(s, "%-25s", buf);
	}
	seq_puts(s, "\n");
}

static void danipc_dump_fifo_stats(struct seq_file *s)
{
	struct dbgfs_hdlr *hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_if *intf = (struct danipc_if *)hdlr->data;
	struct packet_proc_info *pproc = intf->pproc;
	struct danipc_pkt_histo *histo_hi = &pproc[ipc_trns_prio_1].pkt_hist;
	struct danipc_pkt_histo *histo_lo = &pproc[ipc_trns_prio_0].pkt_hist;
	struct net_device_stats *stats_hi = histo_hi->stats;
	struct net_device_stats *stats_lo = histo_lo->stats;

	if (!netif_running(intf->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}

	seq_puts(s, "\n\nfifo TX/RX stats:\n\n");
	danipc_dump_fifo_hist(s, histo_hi);
	seq_puts(s, "\n\nTx HI packet histogram(<=pkt-size:count):\n\n");
	danipc_dump_pkt_hist(s, histo_hi->tx_histo, stats_hi->tx_packets);
	seq_puts(s, "\n\nRx HI packet histogram(<=pkt-size:count):\n\n");
	danipc_dump_pkt_hist(s, histo_hi->rx_histo, stats_hi->rx_packets);
	seq_puts(s, "\n\nTx LO packet histogram(<=pkt-size:count):\n\n");
	danipc_dump_pkt_hist(s, histo_lo->tx_histo, stats_lo->tx_packets);
	seq_puts(s, "\n\nRx LO packet histogram(<=pkt-size:count):\n\n");
	danipc_dump_pkt_hist(s, histo_lo->rx_histo, stats_lo->rx_packets);
	seq_puts(s, "\n\nRx HI packet burst:\n");
	danipc_dump_pkt_burst(s, histo_hi->rx_pkt_burst);
	seq_puts(s, "\n\nRx LO packet burst:\n");
	danipc_dump_pkt_burst(s, histo_lo->rx_pkt_burst);
}

struct fifo_threshold {
	uint32_t fifo_0: 7;
	uint32_t reserved_0: 1;
	uint32_t fifo_1: 7;
	uint32_t reserved_1: 1;
	uint32_t fifo_2: 7;
	uint32_t reserved_2: 1;
	uint32_t fifo_3: 7;
	uint32_t reserved_3: 1;
};

static void danipc_dump_af_threshold(struct seq_file *s)
{
	struct dbgfs_hdlr	*hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_if	*intf = (struct danipc_if *)hdlr->data;
	uint32_t	thr;
	struct fifo_threshold *thr_s;

	if (!netif_running(intf->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}

	thr = danipc_read_af_threshold(intf->rx_fifo_idx);
	thr_s = (struct fifo_threshold *)(&thr);

	seq_printf(s, "%#06x:\nfifo0=%d\nfifo1=%d\nfifo2=%d\nfifo3=%d\n", thr,
		   thr_s->fifo_0,
		   thr_s->fifo_1,
		   thr_s->fifo_2,
		   thr_s->fifo_3);
	seq_puts(s, "# to change threshold write line following format\n");
	seq_puts(s, "# fifo<n>=<thr>\n");
	seq_puts(s, "# where:\n");
	seq_puts(s, "# - n is fifo number 0-3\n");
	seq_puts(s, "# - thr is new threshold 0-127\n");
}

static void danipc_dump_ae_threshold(struct seq_file *s)
{
	struct dbgfs_hdlr	*hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_if	*intf = (struct danipc_if *)hdlr->data;
	uint32_t	thr;
	struct fifo_threshold *thr_s;

	if (!netif_running(intf->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}
	thr = danipc_read_ae_threshold(intf->rx_fifo_idx);
	thr_s = (struct fifo_threshold *)(&thr);

	seq_printf(s, "%#06x:\nfifo0=%d\nfifo1=%d\nfifo2=%d\nfifo3=%d\n", thr,
		   thr_s->fifo_0,
		   thr_s->fifo_1,
		   thr_s->fifo_2,
		   thr_s->fifo_3);
	seq_puts(s, "# to change threshold write line following format\n");
	seq_puts(s, "# fifo<n>=<thr>\n");
	seq_puts(s, "# where:\n");
	seq_puts(s, "# - n is fifo number 0-3\n");
	seq_puts(s, "# - thr is new threshold 0-127\n");
}

#define STATUS_IS_EMPTY(s) (s & 1)
#define STATUS_IS_AEMPTY(s) (s & (1 << 1))
#define STATUS_IS_HALFULL(s) (s & (1 << 2))
#define STATUS_IS_AFULL(s) (s & (1 << 3))
#define STATUS_IS_FULL(s) (s & (1 << 4))
#define STATUS_IS_ERR(s) (s & (1 << 5))

static void danipc_dump_fifo_n_stat(struct seq_file *s, uint32_t stat)
{
	seq_printf(s, "REGISTER: %#06x (", stat);
	if (STATUS_IS_EMPTY(stat))
		seq_puts(s, " empty");
	if (STATUS_IS_AEMPTY(stat))
		seq_puts(s, " aempty");
	if (STATUS_IS_HALFULL(stat))
		seq_puts(s, " halfull");
	if (STATUS_IS_AFULL(stat))
		seq_puts(s, " afull");
	if (STATUS_IS_FULL(stat))
		seq_puts(s, " full");
	if (STATUS_IS_ERR(stat))
		seq_puts(s, " err");
	seq_puts(s, " )\n");
}

static void danipc_dump_fifo_counters(struct seq_file *s)
{
	struct dbgfs_hdlr	*hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_if	*intf = (struct danipc_if *)hdlr->data;
	uint32_t	status;
	int		i;

	if (!netif_running(intf->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}

	for (i = 0 ; i < 4 ; i++) {
		status = danipc_read_fifo_counter(intf->rx_fifo_idx, i);
		seq_printf(s, "\n\nFIFO %d Counter: %d\n", i, status);
	}
}

static void danipc_dump_fifo_status(struct seq_file *s)
{
	struct dbgfs_hdlr	*hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_if	*intf = (struct danipc_if *)hdlr->data;
	uint32_t	status;
	int		i;

	if (!netif_running(intf->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}

	for (i = 0 ; i < 4 ; i++) {
		seq_printf(s, "\n\nFIFO %d STATUS:\n", i);
		status = danipc_read_fifo_status(intf->rx_fifo_idx, i);
		danipc_dump_fifo_n_stat(s, status);
	}
}

#define FIFO_N_IRQ_STAT(s, n) ((uint8_t)((s >> (n*8)) & 0xFF))
#define IS_EMPTY_IRQ(s, n) (FIFO_N_IRQ_STAT(s, n) & (1<<2))
#define IS_AEMPTY_IRQ(s, n) (FIFO_N_IRQ_STAT(s, n) & (1<<3))
#define IS_HALFULL_IRQ(s, n) (FIFO_N_IRQ_STAT(s, n) & (1<<4))
#define IS_AFULL_IRQ(s, n) (FIFO_N_IRQ_STAT(s, n) & (1<<5))
#define IS_FULL_IRQ(s, n) (FIFO_N_IRQ_STAT(s, n) & (1<<6))
#define IS_ERR_IRQ(s, n) (FIFO_N_IRQ_STAT(s, n) & (1<<7))

static void danipc_dump_fifo_n_status(struct seq_file *s, uint8_t n,
				      uint32_t stat)
{
	seq_printf(s, "fifo %d %#02x (", n, FIFO_N_IRQ_STAT(stat, n));
	if (IS_EMPTY_IRQ(stat, n))
		seq_puts(s, " empty");
	if (IS_AEMPTY_IRQ(stat, n))
		seq_puts(s, " aempty");
	if (IS_HALFULL_IRQ(stat, n))
		seq_puts(s, " halfull");
	if (IS_AFULL_IRQ(stat, n))
		seq_puts(s, " afull");
	if (IS_FULL_IRQ(stat, n))
		seq_puts(s, " full");
	if (IS_ERR_IRQ(stat, n))
		seq_puts(s, " err");
	seq_puts(s, " )\n");
}

static void danipc_dump_irq_raw_status(struct seq_file *s)
{
	struct dbgfs_hdlr	*hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_if	*intf = (struct danipc_if *)hdlr->data;
	uint32_t	status;
	int		i;

	if (!netif_running(intf->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}

	status = danipc_read_fifo_irq_status_raw(intf->rx_fifo_idx);
	seq_printf(s, "# %#06x\n", status);
	for (i = 0 ; i < 4 ; i++)
		danipc_dump_fifo_n_status(s, i, status);
}

static void danipc_dump_irq_status(struct seq_file *s)
{
	struct dbgfs_hdlr	 *hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_if	*intf = (struct danipc_if *)hdlr->data;
	uint32_t	  status;
	int		  i;

	if (!netif_running(intf->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}

	status = danipc_read_fifo_irq_status(intf->rx_fifo_idx);
	seq_printf(s, "# %#06x\n", status);
	for (i = 0 ; i < 4 ; i++)
		danipc_dump_fifo_n_status(s, i, status);
}

static void danipc_dump_irq_enable(struct seq_file *s)
{
	struct dbgfs_hdlr	*hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_if	*intf = (struct danipc_if *)hdlr->data;
	uint32_t	enable;
	int		i;

	if (!netif_running(intf->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}

	enable = danipc_read_fifo_irq_enable(intf->rx_fifo_idx);
	seq_printf(s, "%#06x\n", enable);
	for (i = 0 ; i < 4 ; i++)
		danipc_dump_fifo_n_status(s, i, enable);
}

static void danipc_dump_irq_mask(struct seq_file *s)
{
	struct dbgfs_hdlr	*hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_if	*intf = (struct danipc_if *)hdlr->data;
	uint32_t	mask;
	int		i;

	if (!netif_running(intf->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}

	mask = danipc_read_fifo_irq_mask(intf->rx_fifo_idx);
	for (i = 0 ; i < 4 ; i++)
		danipc_dump_fifo_n_status(s, i, mask);
}

static int danipc_parse_fifo_threshold(struct net_device *dev,
				       const char *buf, size_t len,
				       u8 *fifo, u8 *threshold)
{
	char int_buf[20];
	char *ibuf;
	size_t skip;
	int ret = 0;

	ibuf = strnstr(buf, "fifo", len);
	if (ibuf == 0)
		return -EINVAL;
	ibuf += 4;

	/* look for fifo number */
	skip = strspn(ibuf, " \t");
	ibuf += skip;
	skip = strcspn(ibuf, " \t=");
	if (skip > sizeof(int_buf)) {
		netdev_warn(dev, "%s: Fifo number too long %s\n",
			    __func__, ibuf);
		return -EINVAL;
	}
	strlcpy(int_buf, ibuf, skip+1);
	ibuf += skip;
	ret = kstrtou8(int_buf, 0, fifo);
	if (ret != 0) {
		netdev_warn(dev, "%s: Error(%d) parsing fifo number \"%s\"\n",
			    __func__, ret, int_buf);
		return ret;
	}
	if (*fifo > 3) {
		netdev_warn(dev, "%s: fifo number(%d) out of range (0-3)\n",
			    __func__, *fifo);
		return -EINVAL;
	}

	/* look for threshold value */
	skip = strspn(ibuf, " \t=");
	ibuf += skip;
	skip = strspn(ibuf, "0123456789ABCDEFabcdefXx");
	if (skip > sizeof(int_buf)) {
		netdev_warn(dev, "%s: Threshold too long %s\n", __func__, ibuf);
		return -EINVAL;
	}
	strlcpy(int_buf, ibuf, skip+1);
	ret = kstrtou8(int_buf, 0, threshold);
	if (ret != 0) {
		netdev_warn(dev, "%s: Error(%d) parsing threshold \"%s\"\n",
			    __func__, ret, int_buf);
		return ret;
	}
	if (*threshold > 127) {
		netdev_warn(dev, "%s: threshold(%d) out of range (0-127)\n",
			    __func__, *threshold);
		return -EINVAL;
	}
	return ret;
}

static ssize_t
danipc_write_af_threshold(struct file *filp, const char __user *ubuf,
			  size_t cnt, loff_t *ppos)
{
	struct seq_file *m = filp->private_data;
	struct dbgfs_hdlr *dbgfshdlr = (struct dbgfs_hdlr *)m->private;
	struct danipc_if *intf = (struct danipc_if *)dbgfshdlr->data;
	struct net_device *dev = intf->dev;
	char buf[64];
	int buf_size;
	int ret;
	u8 fifo;
	u8 thr;

	if (*ppos)
		return -EINVAL;

	buf_size = min(cnt, (sizeof(buf) - 1));
	memset(buf, '\0', sizeof(buf));
	if (strncpy_from_user(buf, ubuf, buf_size) < 0)
		return -EFAULT;

	ret = danipc_parse_fifo_threshold(dev, buf, buf_size, &fifo, &thr);
	if (ret)
		return ret;

	danipc_set_af_threshold(intf->rx_fifo_idx, fifo, thr);
	return cnt;
}

static ssize_t
danipc_write_ae_threshold(struct file *filp, const char __user *ubuf,
			  size_t cnt, loff_t *ppos)
{
	struct seq_file *m = filp->private_data;
	struct dbgfs_hdlr *dbgfshdlr = (struct dbgfs_hdlr *)m->private;
	struct danipc_if *intf = (struct danipc_if *)dbgfshdlr->data;
	struct net_device *dev = intf->dev;
	char buf[64];
	int buf_size;
	int ret;
	u8 fifo;
	u8 thr;

	if (*ppos)
		return -EINVAL;

	buf_size = min(cnt, (sizeof(buf) - 1));
	memset(buf, '\0', sizeof(buf));
	if (strncpy_from_user(buf, ubuf, buf_size) < 0)
		return -EFAULT;

	ret = danipc_parse_fifo_threshold(dev, buf, buf_size, &fifo, &thr);
	if (ret)
		return ret;

	danipc_set_ae_threshold(intf->rx_fifo_idx, fifo, thr);
	return cnt;
}

static struct danipc_dbgfs netdev_dbgfs[] = {
	DBGFS_NODE("fifo_info", 0444, danipc_dump_fifo_info, NULL),
	DBGFS_NODE("fifo_stats", 0444, danipc_dump_fifo_stats, NULL),
	DBGFS_NODE("af_threshold", 0644, danipc_dump_af_threshold,
		   danipc_write_af_threshold),
	DBGFS_NODE("ae_threshold", 0644, danipc_dump_ae_threshold,
		   danipc_write_ae_threshold),
	DBGFS_NODE("fifo_status", 0444, danipc_dump_fifo_status, NULL),
	DBGFS_NODE("fifo_counters", 0444, danipc_dump_fifo_counters, NULL),
	DBGFS_NODE("raw_irq_status", 0444, danipc_dump_irq_raw_status, NULL),
	DBGFS_NODE("irq_enable", 0444, danipc_dump_irq_enable, NULL),
	DBGFS_NODE("irq_mask", 0444, danipc_dump_irq_mask, NULL),
	DBGFS_NODE("data_irq_status", 0444, danipc_dump_irq_status, NULL),

	DBGFS_NODE_LAST
};

int danipc_dbgfs_netdev_init(void)
{
	struct danipc_drvr *drvr = &danipc_driver;
	struct dentry *dent;
	int ret = 0;
	int i;

	dent = debugfs_create_dir("intf_netdev", drvr->dirent);
	if (IS_ERR(dent)) {
		pr_err("%s: failed to create intf directory\n", __func__);
		return PTR_ERR(dent);
	}

	for (i = 0; i < drvr->ndev; i++) {
		struct danipc_if *intf = drvr->if_list[i];

		intf->dbgfs = kzalloc(sizeof(netdev_dbgfs), GFP_KERNEL);
		if (intf->dbgfs == NULL) {
			ret = -ENOMEM;
			pr_err("%s: failed to allocate dbgfs\n", __func__);
			break;
		}
		memcpy(intf->dbgfs, &netdev_dbgfs[0], sizeof(netdev_dbgfs));
		intf->dirent = danipc_dbgfs_create_dir(dent,
						       intf->dev->name,
						       intf->dbgfs,
						       intf);
		if (intf->dirent == NULL) {
			kfree(intf->dbgfs);
			intf->dbgfs = NULL;
			ret = PTR_ERR(intf->dirent);
			break;
		}
	}

	return ret;
}

void danipc_dbgfs_netdev_remove(void)
{
	struct danipc_drvr *drvr = &danipc_driver;
	int i;

	for (i = 0; i < drvr->ndev; i++) {
		struct danipc_if *intf = drvr->if_list[i];

		debugfs_remove_recursive(intf->dirent);
		intf->dirent = NULL;

		kfree(intf->dbgfs);
		intf->dbgfs = NULL;
	}
}
