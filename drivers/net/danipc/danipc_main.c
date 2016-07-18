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
#include <net/arp.h>

#include "danipc_k.h"
#include "ipc_api.h"
#include "danipc_lowlevel.h"

#define DANIPC_VERSION		"v1.0"

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

static int acquire_local_fifo(struct danipc_fifo *fifo, void *owner)
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

static void enable_irq_local_fifo(struct danipc_fifo *fifo)
{
	if (!(fifo->flag & DANIPC_FIFO_F_IRQ_EN)) {
		danipc_clear_interrupt(fifo->node_id);
		danipc_unmask_interrupt(fifo->node_id);
		fifo->flag |= DANIPC_FIFO_F_IRQ_EN;
	}
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

	rc = acquire_local_fifo(intf->fifo, intf);
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
static inline bool valid_ipc_msg_hdr(struct danipc_cdev *cdev,
				     const struct ipc_msg_hdr *hdr)
{
	if (hdr->msg_len > IPC_FIRST_BUF_DATA_SIZE_MAX) {
		dev_dbg(cdev->dev,
			"%s: receive the message with bad message len(%u)\n",
			__func__, hdr->msg_len);
		cdev->status.rx_oversize_msg++;
		return false;
	}
	if (!hdr->msg_len) {
		cdev->status.rx_zlen_msg++;
		return false;
	}
	if (ipc_get_node(hdr->dest_aid) != cdev->fifo->node_id) {
		dev_dbg(cdev->dev,
			"%s: receive the message with bad dest_aid(%u)\n",
			__func__, hdr->dest_aid);
		cdev->status.rx_inval_msg++;
		return false;
	}
	/* no buffer chain */
	if (hdr->next != NULL) {
		dev_dbg(cdev->dev,
			"%s: receive the message with next point(%p)\n",
			__func__, hdr->next);
		cdev->status.rx_chained_msg++;
		return false;
	}
	return true;
}

static inline struct ipc_msg_hdr *__ipc_msg_get(struct danipc_fifo *fifo,
						uint8_t *prio)
{
	char *data = ipc_trns_fifo_buf_read(ipc_trns_prio_1,
					    fifo->node_id);
	uint8_t priority = ipc_trns_prio_1;

	if (data == NULL) {
		data = ipc_trns_fifo_buf_read(ipc_trns_prio_0,
					      fifo->node_id);
		priority = ipc_trns_prio_0;
	}
	if (data)
		*prio = priority;

	return (struct ipc_msg_hdr *)data;
}

static struct ipc_msg_hdr *ipc_msg_get(struct danipc_cdev *cdev, uint8_t *prio)
{
	struct danipc_fifo *fifo = cdev->fifo;
	struct ipc_msg_hdr *hdr;
	uint8_t priority = 0;

	while ((hdr = __ipc_msg_get(fifo, &priority))) {
		dev_dbg(cdev->dev, "get message at %p\n", hdr);
		if (valid_ipc_msg_hdr(cdev, hdr))
			break;
		dev_dbg(cdev->dev, "drop message at %p\n", hdr);
		ipc_buf_free((char *)hdr, fifo->node_id, priority);
		cdev->status.rx_drop++;
	}
	if (hdr)
		*prio = priority;
	return hdr;
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

static ssize_t danipc_cdev_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	DECLARE_WAITQUEUE(wait, current);
	struct danipc_cdev *cdev = file->private_data;
	struct danipc_fifo *fifo = cdev->fifo;
	unsigned int minor = iminor(file_inode(file));
	struct ipc_msg_hdr *hdr;
	uint8_t prio = 0;
	unsigned long flags;
	ssize_t ret = 0;

	dev_dbg(cdev->dev, "%s: minor %u\n", __func__, minor);

	if (count <= sizeof(struct danipc_cdev_msghdr)) {
		cdev->status.rx_error++;
		return -EINVAL;
	}

	add_wait_queue(&cdev->rq, &wait);
	while (1) {
		hdr = ipc_msg_get(cdev, &prio);
		if (hdr)
			break;

		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			goto out;
		}

		set_current_state(TASK_INTERRUPTIBLE);
		spin_lock_irqsave(&cdev->lock, flags);
		enable_irq_local_fifo(fifo);
		spin_unlock_irqrestore(&cdev->lock, flags);
		schedule();
		if (signal_pending(current)) {
			cdev->status.rx_error++;
			ret = -ERESTARTSYS;
			goto out;
		}
	}

	ret = ipc_msg_copy_to_user(hdr, prio, buf, count);
	if (ret < 0) {
		cdev->status.rx_error++;
	} else {
		cdev->status.rx++;
		cdev->status.rx_bytes += hdr->msg_len;
	}

	ipc_buf_free((char *)hdr, fifo->node_id, prio);
out:
	 __set_current_state(TASK_RUNNING);
	remove_wait_queue(&cdev->rq, &wait);
	return ret;
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
		return -EIO;
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
	struct danipc_fifo *fifo = cdev->fifo;
	unsigned long flags;
	unsigned int ret = 0;

	dev_dbg(cdev->dev, "%s\n", __func__);

	poll_wait(file, &cdev->rq, wait);
	spin_lock_irqsave(&cdev->lock, flags);
	if (danipc_fifo_is_empty(fifo))
		enable_irq_local_fifo(fifo);
	else
		ret = POLLIN | POLLRDNORM;
	spin_unlock_irqrestore(&cdev->lock, flags);

	return ret;
}

static int danipc_cdev_open(struct inode *inode, struct file *file)
{
	unsigned int minor = iminor(file_inode(file));
	struct danipc_cdev *cdev;
	struct danipc_fifo *fifo;
	struct device *dev;
	int ret = 0;

	if (minor >= DANIPC_MAX_CDEV)
		return -ENODEV;

	cdev = &danipc_driver.cdev[minor];
	fifo = cdev->fifo;
	dev = cdev->dev;

	dev_dbg(cdev->dev, "%s\n", __func__);

	ret = acquire_local_fifo(fifo, cdev);
	if (ret) {
		dev_warn(cdev->dev, "%s: fifo(%s) is busy\n",
			 __func__, fifo->probe_info->res_name);
		goto out;
	}

	init_waitqueue_head(&cdev->rq);

	ret = request_irq(fifo->irq, danipc_cdev_interrupt, 0,
			  dev->kobj.name, cdev);
	if (ret) {
		dev_err(cdev->dev, "%s: request irq(%d) failed, fifo(%s)\n",
			__func__, fifo->irq, fifo->probe_info->res_name);
		release_local_fifo(fifo, cdev);
		goto out;
	}

	danipc_init_irq(fifo);

	file->private_data = cdev;

out:
	return ret;
}

static int danipc_cdev_release(struct inode *inode, struct file *file)
{
	unsigned int minor = iminor(file_inode(file));
	struct danipc_cdev *cdev;
	struct danipc_fifo *fifo;
	int ret = 0;

	if (minor >= DANIPC_MAX_CDEV)
		return -ENODEV;

	cdev = &danipc_driver.cdev[minor];
	fifo = cdev->fifo;

	dev_dbg(cdev->dev, "%s\n", __func__);

	danipc_disable_irq(fifo);
	free_irq(fifo->irq, cdev);
	release_local_fifo(cdev->fifo, cdev);
	file->private_data = NULL;
	return ret;
}

static const struct file_operations danipc_cdevs_fops = {
	.read		= danipc_cdev_read,
	.write		= danipc_cdev_write,
	.poll		= danipc_cdev_poll,
	.unlocked_ioctl = danipc_cdev_ioctl,
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
	spin_lock_init(&cdev->lock);

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

	for (minor = 0; minor < DANIPC_MAX_LFIFO && !ret; minor++, cdev++)
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
	seq_printf(s, "%-25s: %u\n", "rx_error", stats->rx_error);
	seq_printf(s, "%-25s: %u\n", "rx_zero_len_msg", stats->rx_zlen_msg);
	seq_printf(s, "%-25s: %u\n", "rx_oversize_msg", stats->rx_oversize_msg);
	seq_printf(s, "%-25s: %u\n", "rx_invalid_aid_msg", stats->rx_inval_msg);
	seq_printf(s, "%-25s: %u\n", "rx_chained_msg", stats->rx_chained_msg);

	seq_printf(s, "%-25s: %u\n", "tx", stats->tx);
	seq_printf(s, "%-25s: %u\n", "tx_bytes", stats->tx_bytes);
	seq_printf(s, "%-25s: %u\n", "tx_drop", stats->tx_drop);
	seq_printf(s, "%-25s: %u\n", "tx_error", stats->tx_error);
	seq_printf(s, "%-25s: %u\n", "tx_no_buf", stats->tx_no_buf);
}

static struct danipc_dbgfs cdev_dbgfs[] = {
	DBGFS_NODE("status", 0444, danipc_cdev_show_status, NULL),
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
