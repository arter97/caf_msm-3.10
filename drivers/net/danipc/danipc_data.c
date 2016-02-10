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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>

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
				    pair->prio
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

		return NETDEV_TX_BUSY;
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

static void
drop_ipc_message(char *const packet, enum ipc_trns_prio prio, u8 cpuid)
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

	if (first_hdr->msg_len > IPC_FIRST_BUF_DATA_SIZE_MAX) {
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
