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

#include <linux/debugfs.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/etherdevice.h>
#include <linux/platform_device.h>
#include <linux/interrupt.h>
#include <linux/ioctl.h>
#include <linux/cpumask.h>
#include <linux/poll.h>
#include <linux/vmalloc.h>
#include <net/arp.h>

#include "danipc_k.h"
#include "ipc_api.h"
#include "danipc_lowlevel.h"

#define DANIPC_VERSION		"v1.0"

#define TX_MMAP_REGION_BUF_NUM	512

struct shm_msg {
	struct ipc_msg_hdr	*hdr;
	struct shm_buf		*shmbuf;
	uint8_t			prio;
};

struct danipc_drvr danipc_driver = {
	.proc_rx = {
			{
				danipc_default_rcv_init,
				danipc_default_work_sched,
				.proc_pkt.fn = danipc_default_rcv,
				danipc_default_stop
			},
			{
				danipc_tasklet_init,
				danipc_tasklet_sched,
				.proc_pkt.fn = danipc_proc_parallel_rcv,
				danipc_tasklet_stop
			},
			{
				danipc_tasklet_init,
				danipc_tasklet_sched,
				.proc_pkt.fn = danipc_proc_concurrent_rcv,
				danipc_tasklet_stop
			},
			{
				danipc_wq_init,
				danipc_wq_sched,
				.proc_pkt.work = danipc_proc_wq_rcv,
				danipc_wq_stop
			},
			{
				danipc_timer_init,
				danipc_timer_sched,
				.proc_pkt.fn = danipc_rcv_timer,
				danipc_timer_stop
			},
	},
};

const struct ipc_buf_desc *ext_bufs = NULL;
uint32_t num_ext_bufs = 0;

void alloc_pool_buffers(struct danipc_if *intf)
{
	struct net_device	*dev = intf->dev;
	struct danipc_pktq	*rx_pool = &intf->rx_pkt_pool;

	/* Pre-allocate or refill skb for selected interfaces */
	if (intf->drvr->ndev > 1) {
		uint16_t	fillsz = rx_pool->max_size -
					 skb_queue_len(&rx_pool->q);

		while (fillsz) {
			struct sk_buff *nskb =
			 netdev_alloc_skb(dev, IPC_BUF_SIZE_MAX);

			if (nskb == NULL) {
				pr_info("Failed alloc, rx packet pool\n");
				/* TBD: Add counter for failure */
				break;
			}

			__skb_queue_tail(&rx_pool->q, nskb);

			fillsz--;
		}

		rx_pool->refill = (fillsz != 0);
	}
}

void free_pool_buffers(struct danipc_if *intf)
{
	struct danipc_pktq          *rx_pool = &intf->rx_pkt_pool;

	while (!skb_queue_empty(&rx_pool->q))
		dev_kfree_skb(__skb_dequeue(&rx_pool->q));
}

static int init_local_fifo(struct platform_device *pdev,
			   uint8_t nodeid,
			   struct danipc_probe_info *info)
{
	struct device_node *node = pdev->dev.of_node;
	struct danipc_drvr *pdrv = &danipc_driver;
	struct danipc_fifo *fifo = &pdrv->lfifo[pdrv->num_lfifo];
	int ret = 0;

	if (pdrv->num_lfifo >= DANIPC_MAX_LFIFO)
		return -EINVAL;

	fifo->irq = irq_of_parse_and_map(node, pdrv->num_lfifo);
	if (!(fifo->irq) || (fifo->irq == NO_IRQ)) {
		pr_err("cannot get IRQ from DT\n");
		return -EINVAL;
	}

	mutex_init(&fifo->lock);
	fifo->map = &ipc_to_virt_map[nodeid][0];
	fifo->probe_info = info;
	fifo->node_id = nodeid;
	fifo->owner = NULL;
	fifo->flag = 0;
	fifo->idx = pdrv->num_lfifo;
	ret = init_own_ipc_to_virt_map(fifo);
	if (ret)
		goto out;
	pdrv->num_lfifo++;

out:
	return ret;
}

static int acquire_local_fifo(struct danipc_fifo *fifo,
			      void *owner,
			      uint8_t owner_type)
{
	int ret = 0;

	mutex_lock(&fifo->lock);
	if (fifo->flag & DANIPC_FIFO_F_INUSE) {
		ret = -EBUSY;
		goto out;
	}

	ret = ipc_init(fifo->node_id, fifo->idx,
		       (fifo->flag & DANIPC_FIFO_F_INIT));
	if (ret)
		goto out;
	fifo->flag |= DANIPC_FIFO_F_INIT;

	fifo->owner = owner;
	fifo->owner_type = owner_type;
	fifo->flag |= DANIPC_FIFO_F_INUSE;

out:
	mutex_unlock(&fifo->lock);
	return ret;
}

static int release_local_fifo(struct danipc_fifo *fifo, void *owner)
{
	int ret = 0;

	mutex_lock(&fifo->lock);
	if (!local_fifo_owner(fifo, owner)) {
		ret = -EPERM;
		goto out;
	}
	fifo->owner = NULL;
	fifo->flag &= ~DANIPC_FIFO_F_INUSE;
out:
	mutex_unlock(&fifo->lock);
	return ret;
}

static void clear_stats(struct danipc_pkt_histo *histo)
{
	uint32_t packet_size;

	histo->stats->rx_packets = 0;
	histo->stats->rx_bytes = 0;

	histo->stats->tx_packets = 0;
	histo->stats->tx_bytes = 0;

	for (packet_size = 0; packet_size < MAX_PACKET_SIZES; packet_size++) {
		histo->rx_histo[packet_size] = 0;
		histo->tx_histo[packet_size] = 0;
	}

	for (packet_size = 0; packet_size < IPC_FIFO_BUF_NUM_HIGH;
		packet_size++)
		histo->rx_pkt_burst[packet_size] = 0;

	histo->stats->rx_dropped = 0;
	histo->stats->rx_missed_errors = 0;

	histo->stats->tx_dropped = 0;

	histo->rx_pool_used = 0;
	histo->tx_delayed = 0;
}

static void
danipc_if_cleanup(struct danipc_if *intf)
{
	/* Clear counters */
	clear_stats(&intf->pproc[ipc_trns_prio_1].pkt_hist);
	clear_stats(&intf->pproc[ipc_trns_prio_0].pkt_hist);

	/* Clean agent table entries and Flush B-FIFO buffers */
	ipc_cleanup(intf->rx_fifo_idx);

	mutex_destroy(&intf->lock);

	/* Free rx pool buffers */
	free_pool_buffers(intf);
}

static int danipc_open(struct net_device *dev)
{
	struct danipc_if	*intf = netdev_priv(dev);
	struct danipc_drvr	*drv = intf->drvr;
	struct danipc_fifo	*fifo = intf->fifo;
	struct packet_proc_info *pproc_hi = &intf->pproc[ipc_trns_prio_1];
	struct packet_proc_info *pproc_lo = &intf->pproc[ipc_trns_prio_0];
	uint8_t		rxptype_hi = pproc_hi->rxproc_type;
	uint8_t		rxptype_lo = pproc_lo->rxproc_type;
	int			rc;

	if (rxptype_hi >= rx_max_proc || rxptype_lo >= rx_max_proc) {
		pr_err("Invalid rxtype. hi: %u, lo: %u\n",
		       rxptype_hi, rxptype_lo);
		BUG();
		return -EINVAL;
	}

	rc = acquire_local_fifo(fifo, intf, DANIPC_FIFO_OWNER_TYPE_NETDEV);
	if (rc) {
		netdev_err(dev, "local fifo(%s) is in used\n",
			   intf->fifo->probe_info->res_name);
		return rc;
	}

	if (rc == 0) {
		alloc_pool_buffers(intf);

		if (pproc_hi->rxproc_type == rx_proc_timer) {
			(drv->proc_rx[rxptype_hi].init)(pproc_hi);
			(drv->proc_rx[rxptype_lo].init)(pproc_lo);

			netif_start_queue(dev);
			drv->ndev_active++;

			rc = 0;
		} else {
			rc = request_irq(dev->irq, danipc_interrupt, 0,
					 dev->name, pproc_lo);

			if (rc == 0) {
				irq_set_affinity(dev->irq,
						 cpumask_of(intf->affinity));

				(drv->proc_rx[rxptype_hi].init)(pproc_hi);
				(drv->proc_rx[rxptype_lo].init)(pproc_lo);

				danipc_init_irq(fifo);

				netif_start_queue(dev);
				drv->ndev_active++;
			}
		}
	}

	return rc;
}

static int danipc_close(struct net_device *dev)
{
	struct danipc_if		*intf = netdev_priv(dev);
	struct danipc_drvr		*drv = intf->drvr;
	struct packet_proc_info	*pproc_hi =
		 &intf->pproc[ipc_trns_prio_1];
	struct packet_proc_info	*pproc_lo =
		 &intf->pproc[ipc_trns_prio_0];
	uint8_t			rxptype_hi = pproc_hi->rxproc_type;
	uint8_t			rxptype_lo = pproc_lo->rxproc_type;

	if (rxptype_hi >= rx_max_proc || rxptype_lo >= rx_max_proc) {
		pr_err("Invalid rxtype. hi: %u, lo: %u\n",
		       rxptype_hi, rxptype_lo);
		BUG();
		return -EINVAL;
	}

	netif_stop_queue(dev);

	if (pproc_hi->rxproc_type == rx_proc_timer) {
		(drv->proc_rx[rxptype_hi].stop)(pproc_hi);
		(drv->proc_rx[rxptype_lo].stop)(pproc_lo);
	} else {
		danipc_disable_irq(intf->fifo);
		(drv->proc_rx[rxptype_hi].stop)(pproc_hi);
		(drv->proc_rx[rxptype_lo].stop)(pproc_lo);
		free_irq(dev->irq, pproc_lo);
	}

	danipc_if_cleanup(intf);

	release_local_fifo(intf->fifo, intf);

	drv->ndev_active--;

	return 0;
}

static int danipc_set_mac_addr(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (!(dev->priv_flags & IFF_LIVE_ADDR_CHANGE) && netif_running(dev))
		return -EBUSY;

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	return 0;
}

static const struct net_device_ops danipc_netdev_ops = {
	.ndo_open		= danipc_open,
	.ndo_stop		= danipc_close,
	.ndo_start_xmit	= danipc_hard_start_xmit,
	.ndo_do_ioctl		= danipc_ioctl,
	.ndo_change_mtu	= danipc_change_mtu,
	.ndo_set_mac_address	= danipc_set_mac_addr,
};

static void danipc_setup(struct net_device *dev)
{
	dev->netdev_ops         = &danipc_netdev_ops;

	dev->type		= ARPHRD_VOID;
	dev->hard_header_len    = sizeof(struct ipc_msg_hdr);
	dev->addr_len           = sizeof(danipc_addr_t);
	dev->tx_queue_len       = 1000;

	/* New-style flags. */
	dev->flags              = IFF_NOARP;
}

/* Our vision of L2 header: it is of type struct danipc_pair
 * it is stored at address skb->cb[HADDR_CB_OFFSET].
 */

static int danipc_header_parse(const struct sk_buff *skb, unsigned char *haddr)
{
	struct danipc_pair *pair =
		(struct danipc_pair *)&skb->cb[HADDR_CB_OFFSET];
	memcpy(haddr, &pair->src, sizeof(danipc_addr_t));
	return sizeof(danipc_addr_t);
}

int danipc_header(struct sk_buff *skb, struct net_device *dev,
		  unsigned short type, const void *daddr,
		  const void *saddr, unsigned len)
{
	struct danipc_pair *pair =
		(struct danipc_pair *)&skb->cb[HADDR_CB_OFFSET];
	const uint8_t	*addr = daddr;

	pair->src = COOKIE_TO_AGENTID(type);
	pair->prio = COOKIE_TO_PRIO(type);
	if (addr)
		pair->dst = *addr;
	return 0;
}

static const struct header_ops danipc_header_ops ____cacheline_aligned = {
	.create		= danipc_header,
	.parse		= danipc_header_parse,
};

static int parse_resources(struct platform_device *pdev, const char *regs[],
			   const char *resource[], const char *shm_names[])
{
	struct device_node	*node = pdev->dev.of_node;
	bool			parse_err = false;
	int			rc = -ENODEV;
	bool			has_ipc_bufs = false;

	if (node) {
		struct resource	*res;
		int		shm_size = 0;
		int		r;

		for (r = 0; r < RESOURCE_NUM && !parse_err; r++) {
			res = platform_get_resource_byname(pdev,
							   IORESOURCE_MEM,
							   resource[r]);
			if (res) {
				danipc_driver.res_start[r] = res->start;
				danipc_driver.res_len[r] = resource_size(res);

				if (strcmp(resource[r], "ipc_bufs") == 0)
					has_ipc_bufs = true;
			} else {
				if (strcmp(resource[r], "ipc_bufs") == 0) {
					has_ipc_bufs = false;
				} else {
					pr_err("cannot get resource %s\n",
					       resource[r]);
					parse_err = true;
				}
			}
		}

		if (!has_ipc_bufs) {
			const struct ipc_buf_desc *buf_desc;
			uint32_t len;

			buf_desc = of_get_property(node, "ul-bufs", &len);

			if (buf_desc == NULL) {
				pr_err("could not find ul-bufs property\n");
				parse_err = true;
			} else {
				danipc_driver.res_start[IPC_BUFS_RES] =
					buf_desc->phy_addr;
				danipc_driver.res_len[IPC_BUFS_RES] =
					buf_desc->sz;
			}

			ext_bufs = of_get_property(node, "dl-bufs", &len);

			if (ext_bufs == NULL) {
				pr_err("could not find dl-bufs property\n");
				parse_err = true;
			}

			danipc_driver.support_mem_map = true;
			num_ext_bufs = len/sizeof(struct ipc_buf_desc);
		}

		for (r = 0; r < PLATFORM_MAX_NUM_OF_NODES && !parse_err; r++) {
			if (!regs[r])
				continue;
			res = platform_get_resource_byname(pdev,
							   IORESOURCE_MEM,
							   regs[r]);
			if (res) {
				ipc_regs_phys[r] = res->start;
				ipc_regs_len[r] = resource_size(res);
			}

			/* Don't look at shared memory regions if we support
			 * flexible memory map
			 */
			if (!danipc_driver.support_mem_map &&
			    (!shm_names[r] ||
			    (of_property_read_u32(node,
						  shm_names[r], &shm_size))))
				ipc_shared_mem_sizes[r] = 0;
			else
				ipc_shared_mem_sizes[r] = shm_size;
		}

		rc = (!parse_err) ? 0 : -ENOMEM;
	}

	return rc;
}

static void danipc_if_remove(struct danipc_drvr *pdrv, uint8_t ifidx)
{
	struct danipc_if *intf = pdrv->if_list[ifidx];
	struct net_device *netdev = (intf) ? intf->dev : NULL;

	if (netdev == NULL)
		return;

	if (netdev->reg_state == NETREG_REGISTERED)
		unregister_netdev(netdev);

	free_netdev(netdev);

	netdev_info(netdev,
		    "Unregister DANIPC Network Interface(%s).\n",
		    netdev->name);

	pdrv->if_list[ifidx] = NULL;
	pdrv->ndev--;
}

static int danipc_if_init(struct platform_device *pdev,
			  struct danipc_fifo *fifo,
			  uint8_t ifidx)
{
	struct danipc_probe_info *probe_list = fifo->probe_info;
	struct net_device	*dev;
	int			rc = -ENOMEM;

	dev = alloc_netdev(sizeof(struct danipc_if),
			   probe_list->ifname, danipc_setup);
	if (dev) {
		int ncpus = num_online_cpus();

		struct danipc_if	*intf = netdev_priv(dev);
		struct packet_proc_info *pproc = intf->pproc;
		struct danipc_pktq	*pktq = &intf->rx_pkt_pool;

		intf->drvr = &danipc_driver;
		intf->dev = dev;
		intf->ifidx = danipc_driver.ndev;
		intf->affinity = (danipc_driver.ndev + 1)%ncpus;
		intf->fifo = fifo;
		intf->rx_fifo_idx = fifo->node_id;
		intf->rx_fifo_prio = danipc_driver.ndev;

		mutex_init(&intf->lock);

		 __skb_queue_head_init(&pktq->q);

		intf->irq = fifo->irq;

		pktq->max_size = probe_list->poolsz;

		pproc[ipc_trns_prio_0].intf = intf;
		pproc[ipc_trns_prio_1].intf = intf;
		pproc[ipc_trns_prio_0].pkt_hist.stats = &dev->stats;
		pproc[ipc_trns_prio_1].pkt_hist.stats = &dev->stats;

		if (strcmp(dev->name, "danipc") == 0) {
			pproc[ipc_trns_prio_0].rxproc_type = rx_proc_timer;
			pproc[ipc_trns_prio_1].rxproc_type = rx_proc_parallel;
		} else {
			/* danipc-pcap */
			pproc[ipc_trns_prio_0].rxproc_type = rx_proc_timer;
			pproc[ipc_trns_prio_1].rxproc_type = rx_proc_parallel;
		}

		pproc[ipc_trns_prio_0].rxbound = IPC_FIFO_BUF_NUM_HIGH;
		pproc[ipc_trns_prio_1].rxbound = IPC_FIFO_BUF_NUM_HIGH;

		strlcpy(dev->name, probe_list->ifname, sizeof(dev->name));
		dev->header_ops = &danipc_header_ops;
		dev->irq = intf->irq;
		dev->dev_addr[0] = intf->rx_fifo_idx;

		rc = register_netdev(dev);
		if (rc) {
			netdev_err(dev, "%s: register_netdev failed\n",
				   __func__);
			mutex_destroy(&intf->lock);
			goto danipc_iferr;
		}

		danipc_driver.if_list[ifidx] = intf;
		danipc_driver.ndev++;
	}
danipc_iferr:
	if (rc && dev)
		free_netdev(dev);
	return rc;
}

static int danipc_netdev_init(struct platform_device *pdev)
{
	struct danipc_drvr *pdrv = &danipc_driver;
	uint8_t ifidx;
	int ret = 0;

	for (ifidx = 0; ifidx < pdrv->num_lfifo && !ret; ifidx++)
		ret = danipc_if_init(pdev, &pdrv->lfifo[ifidx], ifidx);

	return ret;
}

static int danipc_netdev_cleanup(struct platform_device *pdev)
{
	struct danipc_drvr *pdrv = &danipc_driver;
	uint8_t	ifidx = 0;
	(void)pdev;

	for (ifidx = 0; ifidx < DANIPC_MAX_IF; ifidx++)
		danipc_if_remove(pdrv, ifidx);

	pr_info("DANIPC Network driver " DANIPC_VERSION " unregistered.\n");
	return 0;
}

static int probe_local_fifo(struct platform_device *pdev,
			    struct danipc_probe_info *probe_list,
			    const char *regs[])
{
	uint8_t nodeid;
	int	rc = ENODEV;

	for (nodeid = 0; nodeid < PLATFORM_MAX_NUM_OF_NODES; nodeid++) {
		if (ipc_regs_len[nodeid] &&
		    (!strcmp(probe_list->res_name, regs[nodeid]))) {
			rc = init_local_fifo(pdev, nodeid, probe_list);
			break;
		}
	}

	pr_info("FIFO %s %s!\n", probe_list->res_name,
		(rc == ENODEV) ? "NOT FOUND" : "FOUND");
	return rc;
}

static struct danipc_probe_info danipc_probe_list[DANIPC_MAX_LFIFO] = {
	{"apps_ipc_data", "danipc", 256},
	{"apps_ipc_pcap", "danipc-pcap", 0},
};

static int danipc_probe_lfifo(struct platform_device *pdev, const char *regs[])
{
	uint8_t		idx;
	int		rc = 0;

	/* Probe for local fifos */
	for (idx = 0; idx < DANIPC_MAX_LFIFO && !rc; idx++)
		rc = probe_local_fifo(pdev, &danipc_probe_list[idx], regs);

	return rc;
}

/* Character device interface */
static inline void __shm_msg_free(struct danipc_cdev *cdev, struct shm_msg *msg)
{
	shm_bufpool_put_buf(&cdev->rx_queue[msg->prio].kmem_freeq, msg->shmbuf);
}

static void shm_msg_free(struct danipc_cdev *cdev, struct shm_msg *msg)
{
	unsigned long flags;

	spin_lock_irqsave(&cdev->rx_lock, flags);
	__shm_msg_free(cdev, msg);
	spin_unlock_irqrestore(&cdev->rx_lock, flags);
}

static int __shm_msg_get(struct danipc_cdev *cdev, struct shm_msg *msg)
{
	struct shm_buf *buf;
	int prio;
	int ret = -EAGAIN;

	for (prio = ipc_trns_prio_1; prio >= 0; prio--) {
		buf = shm_bufpool_get_buf(&cdev->rx_queue[prio].kmem_recvq);
		if (buf) {
			msg->prio = prio;
			msg->shmbuf = buf;
			msg->hdr = buf_vaddr(buf);

			dev_dbg(cdev->dev, "get message at %p\n", msg->hdr);
			ret = 0;
			break;
		}
	}
	return ret;
}

static ssize_t ipc_msg_copy_to_user(void *msg, enum ipc_trns_prio prio,
				    char __user *buf, size_t count)
{
	struct ipc_msg_hdr *hdr = msg;
	struct danipc_cdev_msghdr cdev_hdr;
	ssize_t size = count-sizeof(cdev_hdr);
	ssize_t n = 0;

	if (size <= 0)
		return -EINVAL;

	if (size > hdr->msg_len)
		size = hdr->msg_len;

	cdev_hdr.dst = hdr->dest_aid;
	cdev_hdr.src = hdr->src_aid;
	cdev_hdr.prio = prio;

	if (copy_to_user(buf, &cdev_hdr, sizeof(cdev_hdr)))
		return -EFAULT;
	n += sizeof(cdev_hdr);
	if (copy_to_user(buf+n, hdr+1, size))
		return -EFAULT;
	n += size;
	return n;
}

static void reset_rx_queue_status(struct rx_queue *rxque)
{
	rxque->status.bq_lo = rxque->bq.count;
	rxque->status.freeq_lo = rxque->freeq.count;
	rxque->status.recvq_hi = rxque->recvq.count;
	rxque->status.kmem_freeq_lo = rxque->kmem_freeq.count;
	rxque->status.kmem_recvq_hi = rxque->kmem_recvq.count;
}

static int danipc_cdev_rx_buf_init(struct danipc_cdev *cdev)
{
	struct danipc_fifo *fifo = cdev->fifo;

	danipc_fifo_drain(fifo->node_id, ipc_trns_prio_1);
	danipc_fifo_drain(fifo->node_id, ipc_trns_prio_0);
	danipc_cdev_refill_rx_b_fifo(cdev, ipc_trns_prio_1);
	danipc_cdev_refill_rx_b_fifo(cdev, ipc_trns_prio_0);

	return 0;
}

static int danipc_cdev_rx_buf_release(struct danipc_cdev *cdev)
{
	struct danipc_fifo *fifo = cdev->fifo;
	enum ipc_trns_prio pri;

	for (pri = ipc_trns_prio_0; pri < max_ipc_prio; pri++)
		danipc_fifo_drain(fifo->node_id, pri);
	ipc_trns_fifo_buf_init(fifo->node_id, fifo->idx);

	return 0;
}

void danipc_cdev_refill_rx_b_fifo(struct danipc_cdev *cdev,
				  enum ipc_trns_prio pri)
{
	struct danipc_fifo *fifo = cdev->fifo;
	struct rx_queue *rxq = &cdev->rx_queue[pri];
	struct shm_bufpool *bq = &rxq->bq;
	struct shm_bufpool *freeq = &rxq->freeq;
	uint32_t n = 0;

	while (bq->count < IPC_BUF_COUNT_MAX) {
		struct shm_buf *buf;

		buf = shm_bufpool_get_buf(freeq);

		if (buf == NULL)
			break;

		danipc_b_fifo_push(buf_paddr(buf), fifo->node_id, pri);
		shm_bufpool_put_buf(bq, buf);
		n++;
	}
	if (freeq->count < rxq->status.freeq_lo)
		rxq->status.freeq_lo = freeq->count;
	if (bq->count < rxq->status.bq_lo)
		rxq->status.bq_lo = bq->count;
	if (n)
		pr_debug("%s: fill fifo(%u/%u) with %d buffers\n",
			 __func__, fifo->idx, pri, n);
}

static int danipc_cdev_rx_kmem_region_init(struct danipc_cdev *cdev,
					   uint32_t size,
					   uint32_t buf_sz,
					   uint32_t buf_headroom)
{
	struct rx_kmem_region *kmem_region = &cdev->rx_kmem_region;
	uint32_t freeq_sz, offset = 0;
	int ret = 0, i;

	kmem_region->kmem = vmalloc(size);
	if (kmem_region->kmem == NULL)
		return -ENOMEM;

	kmem_region->region = __shm_region_create(size,
						  buf_sz,
						  buf_headroom,
						  size/(buf_sz+buf_headroom));
	if (kmem_region->region == NULL) {
		dev_err(cdev->dev, "%s: failed to create region\n",
			__func__);
		ret = -ENOMEM;
		goto err;
	}

	kmem_region->kmem_sz = size;
	kmem_region->region->start = (phys_addr_t)kmem_region->kmem;
	kmem_region->region->end = (phys_addr_t)kmem_region->kmem + size;
	kmem_region->region->vaddr = kmem_region->kmem;

	freeq_sz = IPC_BUF_COUNT_MAX * (buf_sz+buf_headroom);
	for (i = 0; i < ARRAY_SIZE(cdev->rx_queue); i++) {
		ret = shm_bufpool_acquire_region(&cdev->rx_queue[i].kmem_freeq,
						 kmem_region->region,
						 offset,
						 freeq_sz);
		if (ret)
			goto err_release;
		offset += freeq_sz;
		freeq_sz = size - freeq_sz;
	}

	return 0;

err_release:
	for (i = 0; i < ARRAY_SIZE(cdev->rx_queue); i++)
		shm_bufpool_release(&cdev->rx_queue[i].kmem_freeq);
	__shm_region_release(kmem_region->region);

err:
	vfree(kmem_region->kmem);
	memset(kmem_region, 0, sizeof(*kmem_region));
	return ret;
}

static void danipc_cdev_rx_kmem_region_release(struct danipc_cdev *cdev)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(cdev->rx_queue); i++) {
		shm_bufpool_release(&cdev->rx_queue[i].kmem_freeq);
		shm_bufpool_release(&cdev->rx_queue[i].kmem_recvq);
	}
	__shm_region_release(cdev->rx_kmem_region.region);
	vfree(cdev->rx_kmem_region.kmem);
	memset(&cdev->rx_kmem_region, 0, sizeof(cdev->rx_kmem_region));
}

static int danipc_cdev_init_tx_region(struct danipc_cdev *cdev,
				      uint8_t cpuid,
				      enum ipc_trns_prio pri)
{
	uint32_t size = SZ_256K;
	phys_addr_t addr;
	phys_addr_t start;

	if (!valid_cpu_id(cpuid) || pri != ipc_trns_prio_1)
		return -EINVAL;

	addr = danipc_b_fifo_pop(cpuid, pri);
	if (!addr)
		return -EAGAIN;

	danipc_b_fifo_push(addr, cpuid, pri);

	if (ipc_to_virt(cpuid, pri, addr) == NULL)
		return -EAGAIN;

	start = ipc_to_virt_map[cpuid][pri].paddr;
	size = ipc_to_virt_map[cpuid][pri].size;

	dev_dbg(cdev->dev,
		"%s: b_fifo(%u) start: 0x%x size: 0x%x\n",
		__func__, cpuid, start, size);

	cdev->tx_region = shm_region_create(start,
					    ipc_to_virt_map[cpuid][pri].vaddr,
					    size,
					    IPC_BUF_SIZE_MAX,
					    DANIPC_MMAP_TX_BUF_HEADROOM,
					    TX_MMAP_REGION_BUF_NUM);
	if (cdev->tx_region == NULL)
		return -EPERM;

	shm_bufpool_acquire_whole_region(&cdev->tx_queue.mmap_bufcacheq,
					 cdev->tx_region);
	return 0;
}

static ssize_t danipc_cdev_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	DECLARE_WAITQUEUE(wait, current);
	struct danipc_cdev *cdev = file->private_data;
	unsigned int minor = iminor(file_inode(file));
	struct shm_msg msg;
	unsigned long flags;
	ssize_t ret = 0;

	dev_dbg(cdev->dev, "%s: minor %u\n", __func__, minor);

	if (count <= sizeof(struct danipc_cdev_msghdr)) {
		cdev->status.rx_error++;
		return -EINVAL;
	}

	add_wait_queue(&cdev->rx_wq, &wait);
	while (1) {
		spin_lock_irqsave(&cdev->rx_lock, flags);
		ret = __shm_msg_get(cdev, &msg);
		spin_unlock_irqrestore(&cdev->rx_lock, flags);

		if (!ret)
			break;

		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto out;
		}

		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
		if (signal_pending(current)) {
			cdev->status.rx_error++;
			ret = -ERESTARTSYS;
			goto out;
		}
	}

	ret = ipc_msg_copy_to_user(msg.hdr, msg.prio, buf, count);
	if (ret < 0)
		cdev->status.rx_error++;

	shm_msg_free(cdev, &msg);

out:
	 __set_current_state(TASK_RUNNING);
	remove_wait_queue(&cdev->rx_wq, &wait);
	return ret;
}

int danipc_cdev_mmsg_rx(struct danipc_cdev *cdev,
			struct danipc_cdev_mmsg *mmsg)
{
	struct rx_queue *rx_queue;
	struct shm_bufpool msgs;
	struct shm_buf *buf, *p;
	unsigned long flags;
	int n = 0;

	if (unlikely(!cdev || !mmsg))
		return -EINVAL;
	if (mmsg->msgs.num_entry > DANIPC_BUFS_MAX_NUM_BUF ||
	    !mmsg->msgs.num_entry)
		return -EINVAL;
	if (!valid_ipc_prio(mmsg->hdr.prio))
		return -EINVAL;

	rx_queue = &cdev->rx_queue[mmsg->hdr.prio];
	shm_bufpool_init(&msgs);

	spin_lock_irqsave(&cdev->rx_lock, flags);
	list_for_each_entry_safe(buf, p, &rx_queue->kmem_recvq.head, list) {
		struct ipc_msg_hdr *hdr = buf_vaddr(buf);

		if (hdr->dest_aid == mmsg->hdr.dst &&
		    hdr->src_aid == mmsg->hdr.src &&
		    hdr->msg_len <= mmsg->msgs.entry[msgs.count].data_len) {
			shm_bufpool_del_buf(&rx_queue->kmem_recvq, buf);
			shm_bufpool_put_buf(&msgs, buf);
			if (msgs.count == mmsg->msgs.num_entry)
				break;
		}
	}
	spin_unlock_irqrestore(&cdev->rx_lock, flags);

	if (!msgs.count)
		return 0;

	list_for_each_entry(buf, &msgs.head, list) {
		struct ipc_msg_hdr *hdr = buf_vaddr(buf);

		if (copy_to_user(mmsg->msgs.entry[n].data,
				 hdr+1,
				 hdr->msg_len)) {
			cdev->status.rx_error++;
			n = -EFAULT;
			break;
		}
		mmsg->msgs.entry[n++].data_len = hdr->msg_len;
		cdev->status.rx++;
		cdev->status.rx_bytes += hdr->msg_len;
	}

	spin_lock_irqsave(&cdev->rx_lock, flags);
	while ((buf = shm_bufpool_get_buf(&msgs)))
		shm_bufpool_put_buf(&rx_queue->kmem_freeq, buf);
	spin_unlock_irqrestore(&cdev->rx_lock, flags);

	return n;
}

int danipc_cdev_tx(struct danipc_cdev *cdev,
		   struct danipc_cdev_msghdr *hdr,
		   const char __user *buf,
		   size_t count)
{
	struct danipc_drvr *pdrv;
	char *msg;

	if (unlikely(cdev == NULL || hdr == NULL))
		return -EINVAL;

	if (count < 0)
		return -EINVAL;

	pdrv = cdev->drvr;

	dev_dbg(cdev->dev, "%s: request to send %d bytes to %u:%u\n",
		__func__, count, hdr->dst, hdr->src);

	if (!valid_ipc_prio(hdr->prio)) {
		cdev->status.tx_drop++;
		dev_dbg(cdev->dev, "%s: invalid priorioty %u\n",
			__func__, hdr->prio);
		return -EINVAL;
	}

	if (!DANIPC_IS_AGENT_DISCOVERED(hdr->dst, pdrv->dst_aid)) {
		cdev->status.tx_drop++;
		return -EAGAIN;
	}

	msg = ipc_msg_alloc(hdr->src, hdr->dst, buf,
			    count, 0x12, hdr->prio, true);

	if (msg == NULL) {
		cdev->status.tx_no_buf++;
		dev_dbg(cdev->dev, "%s: failed to alloc %d bytes from fifo\n",
			__func__, count);
		return -EBUSY;
	}

	if (ipc_msg_send(msg, hdr->prio) != IPC_SUCCESS) {
		cdev->status.tx_error++;
		dev_warn(cdev->dev, "%s: failed to send %d bytes\n",
			 __func__, count);
		return -ENOMEM;
	}

	cdev->status.tx++;
	cdev->status.tx_bytes += count;
	return 0;
}

static ssize_t danipc_cdev_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct danipc_cdev *cdev = file->private_data;
	unsigned int minor = iminor(file_inode(file));
	struct danipc_cdev_msghdr hdr;
	int ret;

	dev_dbg(cdev->dev, "%s: minor %u, byte %d\n", __func__, minor, count);

	if (copy_from_user(&hdr, buf, sizeof(hdr)))
		return -EFAULT;

	ret = danipc_cdev_tx(cdev, &hdr, buf+sizeof(hdr), count - sizeof(hdr));
	if (ret)
		return ret;

	return count;
}

static inline bool danipc_fifo_is_empty(struct danipc_fifo *fifo)
{
	if (!danipc_m_fifo_is_empty(fifo->node_id, ipc_trns_prio_0) ||
	    !danipc_m_fifo_is_empty(fifo->node_id, ipc_trns_prio_1))
		return false;
	return true;
}

static unsigned int danipc_cdev_poll(struct file *file,
				     struct poll_table_struct *wait)
{
	struct danipc_cdev *cdev = file->private_data;
	unsigned long flags;
	unsigned int ret = 0;

	dev_dbg(cdev->dev, "%s\n", __func__);

	poll_wait(file, &cdev->rx_wq, wait);
	spin_lock_irqsave(&cdev->rx_lock, flags);
	if (!list_empty(&cdev->rx_queue[ipc_trns_prio_1].kmem_recvq.head) ||
	    !list_empty(&cdev->rx_queue[ipc_trns_prio_0].kmem_recvq.head))
		ret = POLLIN | POLLRDNORM;
	spin_unlock_irqrestore(&cdev->rx_lock, flags);

	return ret;
}

static inline void *buf_vma_vaddr(struct shm_buf *buf,
				  struct vm_area_struct *vma)
{
	phys_addr_t vm_size = vma->vm_end - vma->vm_start;
	phys_addr_t offset_s = buf->offset + (buf->region->start & ~PAGE_MASK);
	phys_addr_t offset_e = offset_s + buf->region->buf_sz;

	if (!address_in_range(offset_e, 0, vm_size))
		return NULL;
	return (void *)(vma->vm_start + offset_s);
}

static inline phys_addr_t vma_paddr(struct vm_area_struct *vma,
				    struct shm_region *region,
				    void *addr)
{
	unsigned long offset;

	if (unlikely(vma == NULL || region == NULL))
		return 0;

	if (!address_in_range((phys_addr_t)addr, vma->vm_start, vma->vm_end))
		return 0;

	offset = (unsigned long)(addr) - vma->vm_start;

	return ((region->start & PAGE_MASK)+offset);
}

static inline void *to_ipc_data(void *msg)
{
	struct ipc_msg_hdr *hdr = (struct ipc_msg_hdr *)msg;

	return (void *)(hdr+1);
}

static inline uint8_t vma_get_aid(struct vm_area_struct *vma)
{
	unsigned offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned aid = (offset >> DANIPC_MMAP_AID_SHIFT) & 0xFF;

	return (uint8_t)aid;
}

static inline uint8_t vma_get_lid(struct vm_area_struct *vma)
{
	unsigned offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned lid = (offset >> DANIPC_MMAP_LID_SHIFT) & 0xFF;

	return (uint8_t)lid;
}

static inline int vma_get_node(struct vm_area_struct *vma)
{
	int node_id;

	node_id = ipc_get_node(vma_get_aid(vma)) & 0xFF;
	if (node_id >= PLATFORM_MAX_NUM_OF_NODES)
		return -EINVAL;

	return node_id;
}

static bool vma_in_region(struct vm_area_struct *vma, struct shm_region *region)
{
	unsigned long vma_size = vma->vm_end - vma->vm_start;
	unsigned long region_size = region->end - region->start;
	unsigned long size;

	size = region_size + (region->start & ~PAGE_MASK);

	return (size > vma_size) ? true : false;
}

int danipc_cdev_mapped_recv(struct danipc_cdev *cdev,
			    struct vm_area_struct *vma,
			    struct danipc_bufs *bufs)
{
	struct shm_buf *buf, *p;
	int n = 0, num;
	int i;
	unsigned long flags;

	if (unlikely(!cdev || !vma || !bufs))
		return -EINVAL;

	if (!cdev->rx_vma) {
		dev_err(cdev->dev, "%s: the region is not mmaped\n",
			__func__);
		return -EIO;
	}

	num = bufs->num_entry;
	if (!num || num > DANIPC_BUFS_MAX_NUM_BUF)
		return -EINVAL;

	spin_lock_irqsave(&cdev->rx_lock, flags);

	for (i = ipc_trns_prio_1; (i >= ipc_trns_prio_0) && (n < num); i--) {
		struct shm_bufpool *pq = &cdev->rx_queue[i].kmem_recvq;
		struct shm_bufpool *mmapq = &cdev->rx_queue[i].mmapq;

		list_for_each_entry_safe(buf, p, &pq->head, list) {
			void *vma_addr = buf_vma_vaddr(buf, cdev->rx_vma);
			void *vaddr = buf_vaddr(buf);

			if (vma_addr && vaddr) {
				struct ipc_msg_hdr *ipchdr =
					(struct ipc_msg_hdr *)vma_addr;

				dev_dbg(cdev->dev,
					"%s: put %p(%p) in mmapq, prio=%d\n",
					__func__, buf, vma_addr, i);

				shm_bufpool_del_buf(pq, buf);
				shm_bufpool_put_buf(mmapq, buf);
				bufs->entry[n].data = ipchdr+1;
				bufs->entry[n].data_len =
					((struct ipc_msg_hdr *)vaddr)->msg_len;
				cdev->status.mmap_rx++;
				n++;
				if (n >= num)
					break;
			}
		}
	}

	spin_unlock_irqrestore(&cdev->rx_lock, flags);
	bufs->num_entry = n;
	return n;
}

int danipc_cdev_mapped_recv_done(struct danipc_cdev *cdev,
				 struct vm_area_struct *vma,
				 struct danipc_bufs *bufs)
{
	unsigned long flags;
	int i;

	if (unlikely(!bufs || !vma || !cdev))
		return -EINVAL;

	if (bufs->num_entry > DANIPC_BUFS_MAX_NUM_BUF || !bufs->num_entry)
		return -EINVAL;

	spin_lock_irqsave(&cdev->rx_lock, flags);

	for (i = 0; i < bufs->num_entry; i++) {
		phys_addr_t paddr = vma_paddr(cdev->rx_vma,
					      cdev->rx_kmem_region.region,
					      bufs->entry[i].data);
		struct shm_buf *buf;
		int pri;
		bool found;

		if (!paddr) {
			cdev->status.mmap_rx_error++;
			dev_warn(cdev->dev,
				 "%s: address %x not in mmap area\n",
				 __func__, paddr);
			continue;
		}

		buf = shm_region_find_buf_by_pa(cdev->rx_kmem_region.region,
						paddr);
		if (!buf) {
			cdev->status.mmap_rx_error++;
			dev_warn(cdev->dev,
				 "%s: no buffer at phy_addr %x\n",
				 __func__, paddr);
			continue;
		}

		for (pri = ipc_trns_prio_1, found = false; pri >= 0; pri--) {
			struct rx_queue *pq = &cdev->rx_queue[pri];

			if (buf->head == &pq->mmapq.head) {
				dev_dbg(cdev->dev,
					"%s: put mapped buf %p to freeq\n",
					__func__, buf);
				shm_bufpool_del_buf(&pq->mmapq, buf);
				shm_bufpool_put_buf(&pq->kmem_freeq, buf);
				cdev->status.mmap_rx_done++;
				found = true;
				break;
			}
		}
		if (!found) {
			cdev->status.mmap_rx_error++;
			dev_warn(cdev->dev,
				 "%s: vaddr %p not in mmapq\n",
				 __func__, bufs->entry[i].data);
		}
	}

	spin_unlock_irqrestore(&cdev->rx_lock, flags);

	return 0;
}

static void danipc_cdev_rx_vma_open(struct vm_area_struct *vma)
{
	struct danipc_cdev *cdev = vma->vm_private_data;

	dev_dbg(cdev->dev, "%s: vma %p\n", __func__, vma);

	if (atomic_add_return(1, &cdev->rx_vma_ref) == 1)
		cdev->rx_vma = vma;
}

static void danipc_cdev_rx_vma_close(struct vm_area_struct *vma)
{
	struct danipc_cdev *cdev = vma->vm_private_data;
	unsigned long flags;
	int i;

	dev_dbg(cdev->dev, "%s: vma %p\n", __func__, vma);

	if (!atomic_dec_and_test(&cdev->rx_vma_ref))
		return;

	spin_lock_irqsave(&cdev->rx_lock, flags);
	for (i = 0; i < max_ipc_prio; i++) {
		struct rx_queue *pq = &cdev->rx_queue[i];
		struct shm_buf *buf;

		while ((buf = shm_bufpool_get_buf(&pq->mmapq)))
			shm_bufpool_put_buf(&pq->kmem_freeq,  buf);
		danipc_cdev_refill_rx_b_fifo(cdev, i);
	}

	spin_unlock_irqrestore(&cdev->rx_lock, flags);

	cdev->rx_vma = NULL;
}

static int danipc_cdev_rx_vma_fault(struct vm_area_struct *vma,
				    struct vm_fault *vmf)
{
	struct danipc_cdev *cdev = vma->vm_private_data;
	struct page *page;
	unsigned long offset;

	offset = (unsigned long)vmf->virtual_address - vma->vm_start;

	dev_dbg(cdev->dev, "%s: vma %p, offset %lu\n", __func__, vma, offset);

	page = vmalloc_to_page((char *)cdev->rx_kmem_region.kmem+offset);
	if (page == NULL)
		return VM_FAULT_SIGBUS;

	get_page(page);
	vmf->page = page;

	return 0;
}

static struct vm_operations_struct danipc_cdev_rx_vma_ops = {
	.open	= danipc_cdev_rx_vma_open,
	.close	= danipc_cdev_rx_vma_close,
	.fault	= danipc_cdev_rx_vma_fault,
};

static int danipc_rx_mmap(struct danipc_cdev *cdev, struct vm_area_struct *vma)
{
	struct shm_region *region = cdev->rx_kmem_region.region;

	if (cdev->rx_vma) {
		dev_warn(cdev->dev, "%s: rx is already mmaped\n",
			 __func__);
		return -EBUSY;
	}

	if (vma_in_region(vma, region)) {
		dev_dbg(cdev->dev,
			"%s: vma area is too small, start=%lx end=%lx\n",
			__func__, vma->vm_start, vma->vm_end);
		return -EINVAL;
	}

	vma->vm_private_data = cdev;
	vma->vm_ops = &danipc_cdev_rx_vma_ops;
	danipc_cdev_rx_vma_open(vma);
	return 0;
}

static struct shm_buf *tx_mmap_bufcacheq_get_buf(struct danipc_cdev *cdev,
						 phys_addr_t phy_addr)
{
	struct shm_bufpool *pq = &cdev->tx_queue.mmap_bufcacheq;
	struct shm_buf *buf = NULL;

	if (cdev->tx_region->dir_buf_map) {
		buf = shm_bufpool_find_buf_in_region(pq,
						     cdev->tx_region,
						     phy_addr);
	} else {
		buf = shm_bufpool_get_buf(pq);
		if (buf)
			buf->offset = phy_addr - buf->region->start;
	}
	return buf;
}

static inline void tx_mmap_bufcacheq_put_buf(struct danipc_cdev *cdev,
					     struct shm_buf *buf)
{
	struct shm_bufpool *pq = &cdev->tx_queue.mmap_bufcacheq;

	shm_bufpool_put_buf(pq, buf);
}

int danipc_cdev_mapped_tx(struct danipc_cdev *cdev, struct danipc_bufs *bufs)
{
	struct shm_region *region;
	struct shm_buf *buf;
	struct ipc_msg_hdr *ipchdr;
	phys_addr_t paddr, paddr_buf, offset;
	int i, num_tx;
	uint8_t aid, lid, node;

	if (unlikely(!bufs || !cdev))
		return -EINVAL;

	region = cdev->tx_region;
	if (!region || !cdev->tx_vma) {
		dev_warn(cdev->dev, "%s: tx is no mmaped\n", __func__);
		return -EPERM;
	}

	if (bufs->num_entry > DANIPC_BUFS_MAX_NUM_BUF || !bufs->num_entry)
		return -EINVAL;

	aid = vma_get_aid(cdev->tx_vma);
	lid = vma_get_lid(cdev->tx_vma);
	node = ipc_get_node(aid);

	for (i = 0, num_tx = 0; i < bufs->num_entry; i++) {
		paddr = vma_paddr(cdev->tx_vma, region, bufs->entry[i].data);

		buf = shm_bufpool_find_buf_in_region(&cdev->tx_queue.mmapq,
						     region,
						     paddr);
		if (buf == NULL) {
			dev_warn(cdev->dev,
				 "%s: buffer at phy address %x not in mmapq\n",
				 __func__, paddr);
			cdev->status.tx_error++;
			cdev->status.mmap_tx_error++;
			continue;
		}

		if (shm_bufpool_del_buf(&cdev->tx_queue.mmapq, buf)) {
			dev_warn(cdev->dev,
				 "%s: vaddr %p not in mmapq\n",
				 __func__, bufs->entry[i].data);
			cdev->status.tx_error++;
			cdev->status.mmap_tx_error++;
			continue;
		}

		paddr_buf = buf_paddr(buf);
		offset = paddr - paddr_buf;

		dev_dbg(cdev->dev, "%s: buf(%p) is returned, paddr=%x\n",
			__func__, buf, paddr_buf);

		/* For now, the user must pass the same address it got
		 * from ioctl
		 */
		if (offset != sizeof(*ipchdr)) {
			dev_warn(cdev->dev,
				 "%s: message offset(%p/%x) not expected.\n",
				 __func__, bufs->entry[i].data, offset);
			goto err;
		}
		if ((offset + bufs->entry[i].data_len > region->buf_sz) ||
		    (offset < sizeof(*ipchdr))) {
			dev_warn(cdev->dev,
				 "%s: message(%p) cross the buffer boundary\n",
				 __func__, bufs->entry[i].data);
			goto err;
		}

		offset -= sizeof(*ipchdr);
		ipchdr = (struct ipc_msg_hdr *)bufs->entry[i].data - 1;
		ipchdr->msg_type = 0x12;
		ipchdr->msg_len = bufs->entry[i].data_len;
		ipchdr->reply = NULL;
		ipchdr->dest_aid = aid;
		ipchdr->src_aid = lid;
		ipchdr->request_num = ipc_req_sn++;
		ipchdr->next = NULL;

		dev_dbg(cdev->dev,
			"%s: send %u bytes to %u, lid=%u paddr=%08x\n",
			__func__, ipchdr->msg_len, ipchdr->dest_aid,
			ipchdr->src_aid, paddr_buf+offset);

		danipc_m_fifo_push(paddr_buf+offset,
				   node,
				   ipc_trns_prio_1);

		cdev->status.mmap_tx++;
		cdev->status.tx++;
		cdev->status.tx_bytes += bufs->entry[i].data_len;
		num_tx++;

		tx_mmap_bufcacheq_put_buf(cdev, buf);
		continue;
err:
		tx_mmap_bufcacheq_put_buf(cdev, buf);
		cdev->status.tx_drop++;
		cdev->status.mmap_tx_error++;
		danipc_b_fifo_push(paddr_buf, node, ipc_trns_prio_1);
	}

	return num_tx;
}

int danipc_cdev_mapped_tx_get_buf(struct danipc_cdev *cdev,
				  struct danipc_bufs *bufs)
{
	struct shm_buf *buf;
	phys_addr_t paddr;
	void *vaddr;
	int ret = 0, node, i = 0;

	if (unlikely(!bufs || !cdev))
		return -EINVAL;

	if (bufs->num_entry > DANIPC_BUFS_MAX_NUM_BUF || !bufs->num_entry)
		return -EINVAL;

	if (!cdev->tx_vma) {
		dev_warn(cdev->dev, "%s: tx is not mmaped.\n", __func__);
		return -EPERM;
	}

	node = vma_get_node(cdev->tx_vma);
	if (node < 0) {
		dev_warn(cdev->dev, "%s: invalid node from tx_vma\n", __func__);
		return -EINVAL;
	}

	while (i < bufs->num_entry) {
		paddr = danipc_b_fifo_pop(node, ipc_trns_prio_1);
		if (!paddr)
			break;

		if (!address_in_range(paddr,
				      cdev->tx_region->start,
				      cdev->tx_region->end)) {
			cdev->status.mmap_tx_bad_buf++;
			dev_warn(cdev->dev,
				 "%s: phy_addr %x is out of region range\n",
				 __func__, paddr);
			continue;
		}

		buf = shm_bufpool_find_buf_overlap(&cdev->tx_queue.mmapq,
						   cdev->tx_region,
						   paddr);
		if (buf) {
			cdev->status.mmap_tx_bad_buf++;
			dev_warn(cdev->dev,
				 "%s: addr %x is used by mmap buf(%p/%x)\n",
				 __func__, paddr, buf, buf->offset);
			continue;
		}

		buf = tx_mmap_bufcacheq_get_buf(cdev, paddr);
		if (!buf) {
			cdev->status.mmap_tx_reqbuf_error++;
			dev_warn(cdev->dev,
				 "%s: can't get buf from cache, phy_addr %x\n",
				 __func__, paddr);
			goto err;
		}
		shm_bufpool_put_buf(&cdev->tx_queue.mmapq, buf);
		vaddr = buf_vma_vaddr(buf, cdev->tx_vma);
		BUG_ON(!vaddr);

		dev_dbg(cdev->dev,
			"%s: give buf to user space, phys=%x vaddr=%p\n",
			__func__, paddr, vaddr);

		bufs->entry[i].data = (struct ipc_msg_hdr *)(vaddr) + 1;
		bufs->entry[i].data_len = buf->region->buf_sz -
			sizeof(struct ipc_msg_hdr);
		cdev->status.mmap_tx_reqbuf++;
		i++;
	}

	if (i == 0) {
		cdev->status.mmap_tx_nobuf++;
		ret = -ENOBUFS;
	} else {
		bufs->num_entry = i;
	}

	return ret;
err:
	danipc_b_fifo_push(paddr, node, ipc_trns_prio_1);
	return ret;
}

int danipc_cdev_mapped_tx_put_buf(struct danipc_cdev *cdev,
				  struct danipc_bufs *bufs)
{
	struct shm_region *region;
	struct shm_buf *buf;
	phys_addr_t paddr, paddr_buf;
	int i, node, ret = 0;

	if (unlikely(!bufs || !cdev))
		return -EINVAL;

	if (bufs->num_entry > DANIPC_BUFS_MAX_NUM_BUF || !bufs->num_entry)
		return -EINVAL;

	if (!cdev->tx_vma) {
		dev_warn(cdev->dev, "%s: tx is not mmaped.\n", __func__);
		return -EPERM;
	}

	node = vma_get_node(cdev->tx_vma);
	if (node < 0) {
		dev_warn(cdev->dev, "%s: invalid node from tx_vma\n", __func__);
		return -EINVAL;
	}

	region = cdev->tx_region;
	for (i = 0; i < bufs->num_entry; i++) {
		paddr = vma_paddr(cdev->tx_vma, region, bufs->entry[i].data);

		buf = shm_bufpool_find_buf_in_region(&cdev->tx_queue.mmapq,
						     region,
						     paddr);
		if (buf == NULL) {
			dev_warn(cdev->dev,
				 "%s: buffer at phy address %x not in mmapq\n",
				 __func__, paddr);
			ret = -EINVAL;
			continue;
		}

		if (shm_bufpool_del_buf(&cdev->tx_queue.mmapq, buf)) {
			dev_warn(cdev->dev,
				 "%s: vaddr %p not in mmapq\n",
				 __func__, bufs->entry[i].data);
			ret = -EINVAL;
			continue;
		}

		paddr_buf = buf_paddr(buf);

		dev_dbg(cdev->dev, "%s: buf(%p) is returned, paddr=%x\n",
			__func__, buf, paddr_buf);

		danipc_b_fifo_push(paddr_buf, node, ipc_trns_prio_1);

		tx_mmap_bufcacheq_put_buf(cdev, buf);
	}

	return ret;
}

static void danipc_cdev_tx_vma_open(struct vm_area_struct *vma)
{
	struct danipc_cdev *cdev = vma->vm_private_data;

	dev_dbg(cdev->dev, "%s: vma %p\n", __func__, vma);

	if (atomic_add_return(1, &cdev->tx_vma_ref) == 1)
		cdev->tx_vma = vma;
}

static void danipc_cdev_tx_vma_close(struct vm_area_struct *vma)
{
	struct danipc_cdev *cdev = vma->vm_private_data;
	struct tx_queue *pq = &cdev->tx_queue;
	struct shm_buf *buf;
	int node;

	dev_dbg(cdev->dev, "%s: vma %p\n", __func__, vma);

	if (!atomic_dec_and_test(&cdev->tx_vma_ref))
		return;

	node = vma_get_node(cdev->tx_vma);
	while ((buf = shm_bufpool_get_buf(&pq->mmapq))) {
		danipc_b_fifo_push(buf_paddr(buf),
				   node,
				   ipc_trns_prio_1);
		tx_mmap_bufcacheq_put_buf(cdev, buf);
	}

	cdev->tx_vma = NULL;
}

static struct vm_operations_struct danipc_cdev_tx_vma_ops = {
	.open	= danipc_cdev_tx_vma_open,
	.close	= danipc_cdev_tx_vma_close,
};

static int danipc_tx_mmap(struct danipc_cdev *cdev, struct vm_area_struct *vma)
{
	struct shm_region *region;
	unsigned long size = vma->vm_end - vma->vm_start;

	if (cdev->tx_vma) {
		dev_warn(cdev->dev, "%s: tx is already mmaped\n",
			 __func__);
		return -EBUSY;
	}

	if (cdev->tx_region == NULL)
		danipc_cdev_init_tx_region(cdev,
					   vma_get_node(vma),
					   ipc_trns_prio_1);

	region = cdev->tx_region;
	if (region == NULL)
		return -EPERM;

	if (vma_in_region(vma, region)) {
		dev_dbg(cdev->dev,
			"%s: vma area is too small, start=%lx end=%lx\n",
			__func__, vma->vm_start, vma->vm_end);
		return -EINVAL;
	}

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	if (remap_pfn_range(vma,
			    vma->vm_start,
			    region->start >> PAGE_SHIFT,
			    size,
			    vma->vm_page_prot)) {
		dev_warn(cdev->dev,
			 "%s: remap_pfn_range(%lx/%lx/%lx) failed\n",
			 __func__, vma->vm_start, size, vma->vm_pgoff);
		return -EAGAIN;
	}

	vma->vm_private_data = cdev;
	vma->vm_ops = &danipc_cdev_tx_vma_ops;
	danipc_cdev_tx_vma_open(vma);
	return 0;
}

static int danipc_cdev_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned int minor = iminor(file_inode(file));
	struct danipc_cdev *cdev;
	int node_id;
	int ret;

	if (minor >= DANIPC_MAX_CDEV)
		return -ENODEV;

	cdev = &danipc_driver.cdev[minor];

	dev_dbg(cdev->dev, "%s\n", __func__);

	if (!vma->vm_pgoff)
		node_id = cdev->fifo->node_id;
	else
		node_id = vma_get_node(vma);

	if (node_id < 0) {
		dev_dbg(cdev->dev, "%s: invalid offset 0x%lx\n",
			__func__, vma->vm_pgoff);
		return -EINVAL;
	}

	if (node_id == cdev->fifo->node_id)
		ret = danipc_rx_mmap(cdev, vma);
	else
		ret = danipc_tx_mmap(cdev, vma);

	return ret;
}

static int danipc_cdev_open(struct inode *inode, struct file *file)
{
	unsigned int minor = iminor(file_inode(file));
	struct danipc_cdev *cdev;
	struct danipc_fifo *fifo;
	struct device *dev;
	struct ipc_to_virt_map *map;
	int i;
	int ret = 0;
	uint32_t off_netdev, off_cdev, sz_netdev, sz_cdev;

	if (minor >= DANIPC_MAX_CDEV)
		return -ENODEV;

	cdev = &danipc_driver.cdev[minor];
	fifo = cdev->fifo;
	dev = cdev->dev;
	map = &ipc_to_virt_map[fifo->node_id][ipc_trns_prio_1];

	dev_dbg(cdev->dev, "%s\n", __func__);

	ret = acquire_local_fifo(fifo, cdev, DANIPC_FIFO_OWNER_TYPE_CDEV);
	if (ret) {
		dev_warn(cdev->dev, "%s: fifo(%s) is busy\n",
			 __func__, fifo->probe_info->res_name);
		goto out;
	}

	cdev->rx_region = shm_region_create(map->paddr,
					    map->vaddr,
					    map->size,
					    IPC_BUF_SIZE_MAX,
					    0,
					    map->size/IPC_BUF_SIZE_MAX);
	if (cdev->rx_region == NULL) {
		ret = -ENOBUFS;
		goto err;
	}

	for (i = 0; i < ARRAY_SIZE(cdev->rx_queue); i++) {
		shm_bufpool_init(&cdev->rx_queue[i].kmem_freeq);
		shm_bufpool_init(&cdev->rx_queue[i].kmem_recvq);
		shm_bufpool_init(&cdev->rx_queue[i].freeq);
		shm_bufpool_init(&cdev->rx_queue[i].recvq);
		shm_bufpool_init(&cdev->rx_queue[i].bq);
		shm_bufpool_init(&cdev->rx_queue[i].mmapq);
	}

	/* The netdev interface use 128 buffer for each priority fifo.
	 * The cdev interface will use these buffers. The remaining
	 * share memory space will be equally divided among the
	 * cdev interface for high priority fifo
	 */
	off_netdev = IPC_BUF_SIZE * fifo->idx;
	off_cdev = IPC_BUF_SIZE * DANIPC_MAX_IF;
	sz_cdev = (map->size - off_cdev)/DANIPC_MAX_CDEV;
	off_cdev += sz_cdev * minor;
	sz_netdev = IPC_BUF_SIZE/ARRAY_SIZE(cdev->rx_queue);

	for (i = 0; i < ARRAY_SIZE(cdev->rx_queue); i++) {
		ret = shm_bufpool_acquire_region(&cdev->rx_queue[i].freeq,
						 cdev->rx_region,
						 off_netdev,
						 sz_netdev);
		if (ret)
			goto err_release_region;
		off_netdev += sz_netdev;

		if (i != ipc_trns_prio_1)
			continue;

		ret = shm_bufpool_acquire_region(&cdev->rx_queue[i].freeq,
						 cdev->rx_region,
						 off_cdev,
						 sz_cdev);
		if (ret)
			goto err_release_region;
		off_cdev += sz_cdev;
	}

	danipc_cdev_rx_buf_init(cdev);

	ret = danipc_cdev_rx_kmem_region_init(cdev,
					      SZ_16M,
					      IPC_BUF_SIZE_MAX,
					      DANIPC_MMAP_RX_BUF_HEADROOM);
	if (ret) {
		dev_err(cdev->dev,
			"%s: init rx kmem region failed\n",
			__func__);
		goto err_release_ul_buf;
	}

	reset_rx_queue_status(&cdev->rx_queue[ipc_trns_prio_1]);
	reset_rx_queue_status(&cdev->rx_queue[ipc_trns_prio_0]);

	init_waitqueue_head(&cdev->rx_wq);

	danipc_cdev_init_rx_work(cdev);

	shm_bufpool_init(&cdev->tx_queue.mmapq);
	shm_bufpool_init(&cdev->tx_queue.mmap_bufcacheq);

	ret = request_irq(fifo->irq, danipc_cdev_interrupt, 0,
			  dev->kobj.name, cdev);
	if (ret) {
		dev_err(cdev->dev, "%s: request irq(%d) failed, fifo(%s)\n",
			__func__, fifo->irq, fifo->probe_info->res_name);
		goto err_release_rx_kmem;
	}

	danipc_init_irq(fifo);

	file->private_data = cdev;

	atomic_set(&cdev->rx_vma_ref, 0);
	atomic_set(&cdev->tx_vma_ref, 0);
out:
	return ret;

err_release_rx_kmem:
	danipc_cdev_rx_kmem_region_release(cdev);
err_release_ul_buf:
	danipc_cdev_rx_buf_release(cdev);
	for (i = 0; i < ARRAY_SIZE(cdev->rx_queue); i++)
		shm_bufpool_release(&cdev->rx_queue[i].freeq);
err_release_region:
	shm_region_release(cdev->rx_region);
err:
	release_local_fifo(fifo, cdev);
	return ret;

}

static int danipc_cdev_release(struct inode *inode, struct file *file)
{
	unsigned int minor = iminor(file_inode(file));
	struct danipc_cdev *cdev;
	struct danipc_fifo *fifo;
	int ret = 0;
	int i;

	if (minor >= DANIPC_MAX_CDEV)
		return -ENODEV;

	cdev = &danipc_driver.cdev[minor];
	fifo = cdev->fifo;

	dev_dbg(cdev->dev, "%s\n", __func__);

	danipc_disable_irq(fifo);
	free_irq(fifo->irq, cdev);
	danipc_cdev_stop_rx_work(cdev);

	for (i = 0; i < ARRAY_SIZE(cdev->rx_queue); i++) {
		shm_bufpool_release(&cdev->rx_queue[i].freeq);
		shm_bufpool_release(&cdev->rx_queue[i].recvq);
	}
	shm_region_release(cdev->rx_region);
	shm_region_release(cdev->tx_region);
	cdev->rx_region = NULL;
	cdev->tx_region = NULL;

	danipc_cdev_rx_kmem_region_release(cdev);
	release_local_fifo(cdev->fifo, cdev);
	file->private_data = NULL;
	return ret;
}

static const struct file_operations danipc_cdevs_fops = {
	.read		= danipc_cdev_read,
	.write		= danipc_cdev_write,
	.poll		= danipc_cdev_poll,
	.unlocked_ioctl = danipc_cdev_ioctl,
	.mmap		= danipc_cdev_mmap,
	.open		= danipc_cdev_open,
	.release	= danipc_cdev_release,
};

static struct class *danipc_class;

static int cdev_create(struct danipc_cdev *cdev,
		       struct danipc_fifo *fifo,
		       int minor)
{
	cdev->dev = device_create(danipc_class, NULL,
				  MKDEV(DANIPC_MAJOR, minor),
				  NULL, DANIPC_CDEV_NAME "%d", minor);
	if (cdev->dev == NULL) {
		pr_err("%s: failed to create the device %s%d\n",
		       __func__, DANIPC_CDEV_NAME, minor);
		return -ENOMEM;
	}

	cdev->drvr = &danipc_driver;
	cdev->fifo = fifo;
	cdev->minor = minor;
	spin_lock_init(&cdev->rx_lock);

	return 0;
}

static void cdev_remove(struct danipc_cdev *cdev)
{
	struct device *dev = (cdev) ? cdev->dev : NULL;

	if (dev == NULL)
		return;

	device_destroy(danipc_class, MKDEV(DANIPC_MAJOR, cdev->minor));
	cdev->dev = NULL;
}

static int danipc_cdev_init(void)
{
	struct danipc_drvr *pdrv = &danipc_driver;
	struct danipc_cdev *cdev = pdrv->cdev;
	int minor = 0;
	int ret = 0;

	if (register_chrdev(DANIPC_MAJOR, DANIPC_CDEV_NAME,
			    &danipc_cdevs_fops)) {
		pr_err("%s: register_chrdev failed\n", __func__);
		return -ENODEV;
	}

	danipc_class = class_create(THIS_MODULE, DANIPC_CDEV_NAME);
	if (IS_ERR(danipc_class)) {
		pr_err("%s: failed to create the class\n", __func__);
		unregister_chrdev(DANIPC_MAJOR, DANIPC_CDEV_NAME);
		return PTR_ERR(danipc_class);
	}

	for (minor = 0; minor < DANIPC_MAX_CDEV && !ret; minor++, cdev++)
		ret = cdev_create(cdev, &pdrv->lfifo[minor], minor);

	return ret;
}

static void danipc_cdev_cleanup(void)
{
	int minor = 0;

	for (minor = 0; minor < DANIPC_MAX_CDEV; minor++)
		cdev_remove(&danipc_driver.cdev[minor]);
	class_destroy(danipc_class);
	unregister_chrdev(DANIPC_MAJOR, DANIPC_CDEV_NAME);
}

/* DANIPC DEBUGFS for character device interface */
static void danipc_cdev_show_status(struct seq_file *s)
{
	struct dbgfs_hdlr *hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_cdev *cdev = (struct danipc_cdev *)hdlr->data;
	struct danipc_cdev_status *stats = &cdev->status;

	seq_printf(s, "%-25s: %u\n", "rx", stats->rx);
	seq_printf(s, "%-25s: %u\n", "rx_bytes", stats->rx_bytes);
	seq_printf(s, "%-25s: %u\n", "rx_drop", stats->rx_drop);
	seq_printf(s, "%-25s: %u\n", "rx_no_buf", stats->rx_no_buf);
	seq_printf(s, "%-25s: %u\n", "rx_error", stats->rx_error);
	seq_printf(s, "%-25s: %u\n", "rx_zero_len_msg", stats->rx_zlen_msg);
	seq_printf(s, "%-25s: %u\n", "rx_oversize_msg", stats->rx_oversize_msg);
	seq_printf(s, "%-25s: %u\n", "rx_invalid_aid_msg", stats->rx_inval_msg);
	seq_printf(s, "%-25s: %u\n", "rx_chained_msg", stats->rx_chained_msg);

	seq_printf(s, "%-25s: %u\n", "mmap_rx", stats->mmap_rx);
	seq_printf(s, "%-25s: %u\n", "mmap_rx_done", stats->mmap_rx_done);
	seq_printf(s, "%-25s: %u\n", "mmap_rx_error", stats->mmap_rx_error);

	seq_printf(s, "%-25s: %u\n", "tx", stats->tx);
	seq_printf(s, "%-25s: %u\n", "tx_bytes", stats->tx_bytes);
	seq_printf(s, "%-25s: %u\n", "tx_drop", stats->tx_drop);
	seq_printf(s, "%-25s: %u\n", "tx_error", stats->tx_error);
	seq_printf(s, "%-25s: %u\n", "tx_no_buf", stats->tx_no_buf);

	seq_printf(s, "%-25s: %u\n", "mmap_tx", stats->mmap_tx);
	seq_printf(s, "%-25s: %u\n", "mmap_tx_reqbuf", stats->mmap_tx_reqbuf);
	seq_printf(s, "%-25s: %u\n", "mmap_tx_reqbuf_error",
		   stats->mmap_tx_reqbuf_error);
	seq_printf(s, "%-25s: %u\n", "mmap_tx_nobuf", stats->mmap_tx_nobuf);
	seq_printf(s, "%-25s: %u\n", "mmap_tx_error", stats->mmap_tx_error);

	seq_printf(s, "%-25s: %u\n", "mmap_tx_bad_buf", stats->mmap_tx_bad_buf);
}

static void danipc_cdev_show_queue_info(struct seq_file *s)
{
	struct dbgfs_hdlr *hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_cdev *cdev = (struct danipc_cdev *)hdlr->data;
	int i;

	seq_puts(s, "\nReceiving:\n");
	for (i = 0; i < max_ipc_prio; i++) {
		seq_printf(s, "%s\n",
			   (i == ipc_trns_prio_1) ? "HIGH_PRIO" : "LOW_PRIO");

		seq_printf(s, "%-25s: %u\n",
			   "kmem_recv_queue",
			   cdev->rx_queue[i].kmem_recvq.count);
		seq_printf(s, "%-25s: %u\n",
			   "kmem_recv_queue_hi",
			   cdev->rx_queue[i].status.kmem_recvq_hi);
		seq_printf(s, "%-25s: %u\n",
			   "recv_queue", cdev->rx_queue[i].recvq.count);
		seq_printf(s, "%-25s: %u\n",
			   "recv_queue_hi", cdev->rx_queue[i].status.recvq_hi);
		seq_printf(s, "%-25s: %u\n",
			   "fifo_b_queue", cdev->rx_queue[i].bq.count);
		seq_printf(s, "%-25s: %u\n",
			   "fifo_b_queue_lo", cdev->rx_queue[i].status.bq_lo);
		seq_printf(s, "%-25s: %u\n",
			   "kmem_free_queue",
			   cdev->rx_queue[i].kmem_freeq.count);
		seq_printf(s, "%-25s: %u\n",
			   "kmem_free_queue_lo",
			   cdev->rx_queue[i].status.kmem_freeq_lo);
		seq_printf(s, "%-25s: %u\n",
			   "free_queue", cdev->rx_queue[i].freeq.count);
		seq_printf(s, "%-25s: %u\n",
			   "free_queue_lo", cdev->rx_queue[i].status.freeq_lo);
		seq_printf(s, "%-25s: %u\n",
			   "mmap_queue", cdev->rx_queue[i].mmapq.count);
	}
	seq_puts(s, "\nSending:\n");
	seq_printf(s, "%-25s: %u\n",
		   "mmap_queue", cdev->tx_queue.mmapq.count);
	seq_printf(s, "%-25s: %u\n",
		   "mmap_bufcache_queue", cdev->tx_queue.mmap_bufcacheq.count);
}

static ssize_t danipc_cdev_reset_queue_info(struct file *filep,
					    const char __user *ubuf,
					    size_t cnt,
					    loff_t *ppos)
{
	struct seq_file *m = filep->private_data;
	struct dbgfs_hdlr *hdlr = (struct dbgfs_hdlr *)m->private;
	struct danipc_cdev *cdev = (struct danipc_cdev *)hdlr->data;
	unsigned long flags;

	spin_lock_irqsave(&cdev->rx_lock, flags);
	reset_rx_queue_status(&cdev->rx_queue[ipc_trns_prio_1]);
	reset_rx_queue_status(&cdev->rx_queue[ipc_trns_prio_0]);
	spin_unlock_irqrestore(&cdev->rx_lock, flags);

	return cnt;
}

static void danipc_cdev_show_vma(struct seq_file *s,
				 struct vm_area_struct *vma)
{
	seq_printf(s, "%-25s: %lx\n", "vma_start", vma->vm_start);
	seq_printf(s, "%-25s: %lx\n", "vma_end", vma->vm_end);
}

static void danipc_cdev_show_region(struct seq_file *s,
				    struct shm_region *region)
{
	seq_printf(s, "%-25s: %x\n", "phy_start", region->start);
	seq_printf(s, "%-25s: %x\n", "phy_end", region->end);
	seq_printf(s, "%-25s: %u\n", "num_buf", region->buf_num);
	seq_printf(s, "%-25s: %u\n", "buf_sz", region->buf_sz);
	seq_printf(s, "%-25s: %u\n", "buf_headroom", region->buf_headroom_sz);
	seq_printf(s, "%-25s: %u\n", "real_buf_sz", region->real_buf_sz);
	seq_printf(s, "%-25s: %s\n", "direct_buf_mapping",
		   (region->dir_buf_map) ? "true" : "false");
}

static void danipc_cdev_show_mmap_mapping(struct seq_file *s)
{
	struct dbgfs_hdlr *hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_cdev *cdev = (struct danipc_cdev *)hdlr->data;

	if (cdev->rx_vma) {
		seq_puts(s, "\nRX_MMAP:\n");
		danipc_cdev_show_vma(s, cdev->rx_vma);
		danipc_cdev_show_region(s, cdev->rx_region);
	}
	if (cdev->tx_vma) {
		seq_puts(s, "\nTX_MMAP:\n");
		danipc_cdev_show_vma(s, cdev->tx_vma);
		danipc_cdev_show_region(s, cdev->tx_region);
	}
}

static struct danipc_dbgfs cdev_dbgfs[] = {
	DBGFS_NODE("status", 0444, danipc_cdev_show_status, NULL),
	DBGFS_NODE("queue", 0666, danipc_cdev_show_queue_info,
		   danipc_cdev_reset_queue_info),
	DBGFS_NODE("mmap-mapping", 0444, danipc_cdev_show_mmap_mapping, NULL),
	DBGFS_NODE_LAST
};

int danipc_dbgfs_cdev_init(void)
{
	struct danipc_drvr *drvr = &danipc_driver;
	struct dentry *dent;
	int ret = 0;
	int i;

	dent = debugfs_create_dir("intf_cdev", drvr->dirent);
	if (IS_ERR(dent)) {
		pr_err("%s: failed to create cdev directory\n", __func__);
		return PTR_ERR(dent);
	}

	for (i = 0; i < DANIPC_MAX_CDEV; i++) {
		struct danipc_cdev *cdev = &drvr->cdev[i];

		cdev->dbgfs = kzalloc(sizeof(cdev_dbgfs), GFP_KERNEL);
		if (cdev->dbgfs == NULL) {
			ret = -ENOMEM;
			pr_err("%s: failed to allocate dbgfs\n", __func__);
			break;
		}
		memcpy(cdev->dbgfs, &cdev_dbgfs[0], sizeof(cdev_dbgfs));
		cdev->dirent = danipc_dbgfs_create_dir(dent,
						       cdev->dev->kobj.name,
						       cdev->dbgfs,
						       cdev);
		if (cdev->dirent == NULL) {
			kfree(cdev->dbgfs);
			cdev->dbgfs = NULL;
			ret = PTR_ERR(cdev->dirent);
			break;
		}
	}

	return ret;
}

void danipc_dbgfs_cdev_remove(void)
{
	struct danipc_drvr *drvr = &danipc_driver;
	int i;

	for (i = 0; i < DANIPC_MAX_CDEV; i++) {
		struct danipc_cdev *cdev = &drvr->cdev[i];

		debugfs_remove_recursive(cdev->dirent);
		cdev->dirent = NULL;

		kfree(cdev->dbgfs);
		cdev->dbgfs = NULL;
	}
}

/* DANIPC DEBUGFS ROOT interface */
static void danipc_dump_fifo_mmap(struct seq_file *s)
{
	struct dbgfs_hdlr *hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_drvr *drvr = (struct danipc_drvr *)hdlr->data;
	int i;

	if (drvr->ndev_active == 0) {
		seq_puts(s, "\n\nNo active device!\n\n");
		return;
	}

	seq_puts(s, "\n\nCPU Fifo memory map:\n\n");
	seq_puts(s, " -------------------------------------------------\n");
	seq_puts(s, "| CPU ID | HW Address | Virtual Address | Size    |\n");
	seq_puts(s, " -------------------------------------------------\n");
	for (i = 0; (i < PLATFORM_MAX_NUM_OF_NODES); i++) {
		if (ipc_regs_len[i]) {
			seq_printf(s, "| %-6d | 0x%-8p | 0x%-12p | %-8d |\n", i,
				   (void *)ipc_regs_phys[i],
				   (void *)ipc_regs[i],
				   ipc_regs_len[i]);
		}
	}
}

static void danipc_dump_resource_map(struct seq_file *s)
{
	struct dbgfs_hdlr *hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_drvr *drvr = (struct danipc_drvr *)hdlr->data;
	resource_size_t *res_addr = drvr->res_start;
	resource_size_t *res_len = drvr->res_len;
	static const char *format = "| %-11s | 0x%-11p | 0x%-14p | %-6d |\n";

	if (drvr->ndev_active == 0) {
		seq_puts(s, "\n\nNo active device!\n\n");
		return;
	}

	seq_puts(s, "\n\nResource map:\n\n");
	seq_puts(s, " --------------------------------------------------------\n");
	seq_puts(s, "| Name        | Phys Address  | Virtual Address | Size    |\n");
	seq_puts(s, " --------------------------------------------------------\n");

	seq_printf(s, format, "q6ul_ipcbuf", res_addr[IPC_BUFS_RES],
		   ipc_buffers, res_len[IPC_BUFS_RES]);
	seq_printf(s, format, "Agnt_tbl", res_addr[AGENT_TABLE_RES],
		   agent_table, res_len[AGENT_TABLE_RES]);
	seq_printf(s, format, "Intren_map", res_addr[KRAIT_IPC_MUX_RES],
		   apps_ipc_mux, res_len[KRAIT_IPC_MUX_RES]);
}

static void danipc_dump_local_agents(struct seq_file *s, uint8_t cpuid)
{
	int i;
	char (*table)[MAX_AGENT_NAME_LEN] =
	 (char (*)[MAX_AGENT_NAME_LEN])(&agent_table[cpuid*MAX_LOCAL_AGENT]);

	for (i = 0; i < MAX_LOCAL_AGENT; i++) {
		if (table[i][0] != '\0')
			seq_printf(s, "| %-2d | %-35.32s |\n",
				   (cpuid * MAX_LOCAL_AGENT) + i, table[i]);
	}
}

static void danipc_dump_drvr_info(struct seq_file *s)
{
	struct dbgfs_hdlr *hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_drvr *drvr = (struct danipc_drvr *)hdlr->data;
	char (*table)[MAX_AGENT_NAME_LEN] =
		(char (*)[MAX_AGENT_NAME_LEN])agent_table;
	int i;

	seq_puts(s, "\n\nDanipc driver status:\n\n");
	seq_printf(s, "%-20s: %-2d\n", "Devices found", drvr->ndev);
	seq_printf(s, "%-20s: %-2d\n", "Devices active", drvr->ndev_active);

	if (drvr->ndev_active == 0)
		return;

	seq_puts(s, "\n\nActive remote agents:\n");
	seq_puts(s, " -------------------------------------------\n");
	seq_puts(s, "| AID | Agent name                          |\n");
	seq_puts(s, " -------------------------------------------\n");

	for (i = 0; i < MAX_AGENTS; i++) {
		if (DANIPC_IS_AGENT_DISCOVERED(i, drvr->dst_aid))
			seq_printf(s, "| %-2d | %-35.32s |\n", i, table[i]);
	}

	seq_printf(s, "\n\nActive danipc interface local agents cpuid(%d):\n",
		   drvr->if_list[0]->rx_fifo_idx);
	seq_puts(s, " -------------------------------------------\n");
	seq_puts(s, "| AID | Agent name                          |\n");
	seq_puts(s, " -------------------------------------------\n");
	danipc_dump_local_agents(s, drvr->if_list[0]->rx_fifo_idx);
	seq_puts(s, "\n\n");
	seq_printf(s, "Active danipc-pcap interface local agents cpuid(%d):\n",
		   drvr->if_list[1]->rx_fifo_idx);
	seq_puts(s, " -------------------------------------------\n");
	seq_puts(s, "| AID | Agent name                          |\n");
	seq_puts(s, " -------------------------------------------\n");
	danipc_dump_local_agents(s, drvr->if_list[1]->rx_fifo_idx);
}

static struct danipc_dbgfs drvr_dbgfs[] = {
	DBGFS_NODE("fifo_mem_map", 0444, danipc_dump_fifo_mmap, NULL),
	DBGFS_NODE("resource_map", 0444, danipc_dump_resource_map, NULL),
	DBGFS_NODE("driver_info", 0444, danipc_dump_drvr_info, NULL),
	DBGFS_NODE_LAST
};

static int danipc_dbgfs_root_init(void)
{
	struct danipc_drvr *drvr = &danipc_driver;

	drvr->dirent = danipc_dbgfs_create_dir(NULL,
					       "danipc",
					       drvr_dbgfs,
					       drvr);
	if (IS_ERR(drvr->dirent)) {
		pr_err("%s: Failed to create danipc debugfs\n", __func__);
		return PTR_ERR(drvr->dirent);
	}
	return 0;
}

static void danipc_dbgfs_root_remove(void)
{
	struct danipc_drvr *drvr = &danipc_driver;

	debugfs_remove_recursive(drvr->dirent);
	drvr->dirent = NULL;
}

/* DANIPC DEBUGFS */
static int danipc_dbgfs_show(struct seq_file *s, void *data)
{
	struct dbgfs_hdlr *dbgfshdlr = (struct dbgfs_hdlr *)s->private;

	dbgfshdlr->display(s);

	return 0;
}

static ssize_t danipc_dbgfs_write(struct file *filp, const char __user *ubuf,
				  size_t cnt, loff_t *ppos)
{
	struct seq_file *m = filp->private_data;
	struct dbgfs_hdlr *dbgfshdlr = (struct dbgfs_hdlr *)m->private;

	if (dbgfshdlr->write)
		return dbgfshdlr->write(filp, ubuf, cnt, ppos);

	return -EINVAL;
}

static int danipc_dbgfs_open(struct inode *inode, struct file *file)
{
	return single_open(file, danipc_dbgfs_show, inode->i_private);
}

static const struct file_operations danipc_dbgfs_ops = {
	.open = danipc_dbgfs_open,
	.release = single_release,
	.read = seq_read,
	.write = danipc_dbgfs_write,
	.llseek = seq_lseek,
};

struct dentry *danipc_dbgfs_create_dir(struct dentry *parent_dent,
				       const char *dir_name,
				       struct danipc_dbgfs *nodes,
				       void *private_data)
{
	struct dentry *dent, *ent;

	if (!dir_name || !nodes) {
		pr_err("%s: invalid argument\n", __func__);
		return NULL;
	}

	dent = debugfs_create_dir(dir_name, parent_dent);
	if (IS_ERR(dent)) {
		pr_err("%s: failed to create directory node(%s)\n",
		       __func__, dir_name);
		return NULL;
	}

	while (nodes->fname) {
		ent = debugfs_create_file(nodes->fname,
					  nodes->mode,
					  dent,
					  &nodes->dbghdlr,
					  &danipc_dbgfs_ops);
		if (ent == NULL) {
			pr_err("%s: failed to create node(%s)\n",
			       __func__, nodes->fname);
			return NULL;
		}
		nodes->dbghdlr.data = private_data;
		nodes++;
	}

	return dent;
}

static void __init danipc_dbgfs_init(void)
{
	if (danipc_dbgfs_root_init()) {
		pr_err("%s: Failed to create root debugfs node\n", __func__);
		goto done;
	}
	if (danipc_dbgfs_netdev_init()) {
		pr_err("%s: Failed to create netdev debugfs\n", __func__);
		goto done;
	}
	if (danipc_dbgfs_cdev_init()) {
		pr_err("%s: Failed to create netdev debugfs\n", __func__);
		goto done;
	}

done:
	return;
}

static void danipc_dbgfs_remove(void)
{
	danipc_dbgfs_netdev_remove();
	danipc_dbgfs_cdev_remove();
	danipc_dbgfs_root_remove();
}

static int danipc_probe(struct platform_device *pdev)
{
	struct danipc_drvr	*pdrv = &danipc_driver;
	int			rc = -ENOMEM;
	static const char	*regs[PLATFORM_MAX_NUM_OF_NODES] = {
		"phycpu0_ipc", "phycpu1_ipc", "phycpu2_ipc", "phycpu3_ipc",
		"phydsp0_ipc", "phydsp1_ipc", "phydsp2_ipc", NULL,
		"apps_ipc_data", "qdsp6_0_ipc", "qdsp6_1_ipc",
		"qdsp6_2_ipc", "qdsp6_3_ipc", "apps_ipc_pcap", NULL, NULL
	};
	static const char	*resource[RESOURCE_NUM] = {
		"ipc_bufs", "agent_table", "apps_ipc_intr_en"
	};
	static const char	*shm_names[PLATFORM_MAX_NUM_OF_NODES] = {
		"qcom,phycpu0-shm-size", "qcom,phycpu1-shm-size",
		"qcom,phycpu2-shm-size", "qcom,phycpu3-shm-size",
		"qcom,phydsp0-shm-size", "qcom,phydsp1-shm-size",
		"qcom,phydsp2-shm-size", NULL, "qcom,apps-shm-size",
		"qcom,qdsp6-0-shm-size", "qcom,qdsp6-1-shm-size",
		"qcom,qdsp6-2-shm-size", "qcom,qdsp6-3-shm-size",
		NULL, NULL, NULL
	};

	rc = parse_resources(pdev, regs, resource, shm_names);
	if (rc)
		goto err_probe;

	danipc_ll_init(pdrv);

	rc = danipc_probe_lfifo(pdev, regs);
	if (rc)
		goto err_ll_cleanup;

	rc = danipc_netdev_init(pdev);
	if (rc)
		goto err_netdev_cleanup;

	rc = danipc_cdev_init();
	if (rc)
		goto err_cdev_cleanup;

	danipc_dbgfs_init();

	return 0;
err_cdev_cleanup:
	danipc_cdev_cleanup();
err_netdev_cleanup:
	danipc_netdev_cleanup(pdev);
err_ll_cleanup:
	danipc_ll_cleanup(&danipc_driver);
err_probe:
	return rc;
}

int danipc_remove(struct platform_device *pdev)
{
	danipc_dbgfs_remove();
	danipc_netdev_cleanup(pdev);
	danipc_cdev_cleanup();
	danipc_ll_cleanup(&danipc_driver);
	return 0;
}

static struct of_device_id danipc_ids[] = {
	{
		.compatible = "qcom,danipc",
	},
	{}
};

static struct platform_driver danipc_platform_driver = {
	.probe   = danipc_probe,
	.remove  = danipc_remove,
	.driver = {
		.owner = THIS_MODULE,
		.name	= "danipc",
		.of_match_table = danipc_ids,
	},
};

static int __init danipc_init_module(void)
{
	return platform_driver_register(&danipc_platform_driver);
}

static void __exit danipc_exit_module(void)
{
	platform_driver_unregister(&danipc_platform_driver);
}

module_init(danipc_init_module);
module_exit(danipc_exit_module);
