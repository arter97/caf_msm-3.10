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
#include <net/arp.h>

#include "danipc_k.h"
#include "ipc_api.h"
#include "danipc_lowlevel.h"

#define DANIPC_VERSION		"v1.0"

static void danipc_dump_fifo_mmap(struct seq_file *s);
static void danipc_dump_resource_map(struct seq_file *s);
static void danipc_dump_drvr_info(struct seq_file *s);
static void danipc_dump_fifo_info(struct seq_file *s);
static void danipc_dump_fifo_stats(struct seq_file *s);
static void danipc_dump_af_threshold(struct seq_file *s);
static ssize_t danipc_write_af_threshold(struct file *, const char __user *,
					 size_t, loff_t *);
static ssize_t danipc_write_ae_threshold(struct file *, const char __user *,
					 size_t, loff_t *);
static void danipc_dump_ae_threshold(struct seq_file *s);
static void danipc_dump_fifo_status(struct seq_file *s);
static void danipc_dump_fifo_counters(struct seq_file *s);
static void danipc_dump_irq_raw_status(struct seq_file *s);
static void danipc_dump_irq_enable(struct seq_file *s);
static void danipc_dump_irq_mask(struct seq_file *s);
static void danipc_dump_irq_status(struct seq_file *s);

struct danipc_probe_info {
	const char	*res_name;
	const char	*ifname;
	const uint16_t	poolsz;
	const enum apps_int_mux_mask mux_mask;
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
	.dbgfsinf = {
			{
				.fname = "fifo_mem_map",
				.mode = 0444,
				.dbghdlr = { .display = danipc_dump_fifo_mmap,
					     .data = &danipc_driver
					   }
			},
			{
				.fname = "resource_map",
				.mode = 0444,
				.dbghdlr = {
					.display = danipc_dump_resource_map,
					.data = &danipc_driver
				}
			},
			{
				.fname = "driver_info",
				.mode = 0444,
				.dbghdlr = { .display = danipc_dump_drvr_info,
					     .data = &danipc_driver
					   }
			},
			{
				.fname = "data_fifo_info",
				.mode = 0444,
				.dbghdlr = { .display = danipc_dump_fifo_info,
					     .data = &danipc_driver.if_list[0]
					   }
			},
			{
				.fname = "pcap_fifo_info",
				.mode = 0444,
				.dbghdlr = { .display = danipc_dump_fifo_info,
					     .data = &danipc_driver.if_list[1]
					   }
			},
			{
				.fname = "data_fifo_stats",
				.mode = 0444,
				.dbghdlr = { .display = danipc_dump_fifo_stats,
					     .data = &danipc_driver.if_list[0]
					   }
			},
			{
				.fname = "pcap_fifo_stats",
				.mode = 0444,
				.dbghdlr = { .display = danipc_dump_fifo_stats,
					     .data = &danipc_driver.if_list[1]
					   }
			},
			{
				.fname = "data_af_threshold",
				.mode = 0644,
				.dbghdlr = {
					.display = danipc_dump_af_threshold,
					.write = danipc_write_af_threshold,
					.data = &danipc_driver.if_list[0]
				}
			},
			{
				.fname = "pcap_af_threshold",
				.mode = 0644,
				.dbghdlr = {
					.display = danipc_dump_af_threshold,
					.write = danipc_write_af_threshold,
					.data = &danipc_driver.if_list[1]
				}
			},
			{
				.fname = "data_ae_threshold",
				.mode = 0644,
				.dbghdlr = {
					.display = danipc_dump_ae_threshold,
					.write = danipc_write_ae_threshold,
					.data = &danipc_driver.if_list[0]
				}
			},
			{
				.fname = "pcap_ae_threshold",
				.mode = 0644,
				.dbghdlr = {
					.display = danipc_dump_ae_threshold,
					.write = danipc_write_ae_threshold,
					.data = &danipc_driver.if_list[1]
				}
			},
			{
				.fname = "data_fifo_status",
				.mode = 0444,
				.dbghdlr = { .display = danipc_dump_fifo_status,
					     .data = &danipc_driver.if_list[0]
				}
			},
			{
				.fname = "pcap_fifo_status",
				.mode = 0444,
				.dbghdlr = { .display = danipc_dump_fifo_status,
					     .data = &danipc_driver.if_list[1]
				}
			},
			{
				.fname = "data_fifo_counters",
				.mode = 0444,
				.dbghdlr = {
					.display = danipc_dump_fifo_counters,
					.data = &danipc_driver.if_list[0]
				}
			},
			{
				.fname = "pcap_fifo_counters",
				.mode = 0444,
				.dbghdlr = {
					.display = danipc_dump_fifo_counters,
					.data = &danipc_driver.if_list[1]
				}
			},
			{
				.fname = "data_raw_irq_status",
				.mode = 0444,
				.dbghdlr = {
					.display = danipc_dump_irq_raw_status,
					.data = &danipc_driver.if_list[0]
				}
			},
			{
				.fname = "pcap_raw_irq_status",
				.mode = 0444,
				.dbghdlr = {
					.display = danipc_dump_irq_raw_status,
					.data = &danipc_driver.if_list[1]
				}
			},
			{
				.fname = "data_irq_enable",
				.mode = 0444,
				.dbghdlr = { .display = danipc_dump_irq_enable,
					     .data = &danipc_driver.if_list[0]
				}
			},
			{
				.fname = "pcap_irq_enable",
				.mode = 0444,
				.dbghdlr = { .display = danipc_dump_irq_enable,
					     .data = &danipc_driver.if_list[1]
				}
			},
			{
				.fname = "data_irq_mask",
				.mode = 0444,
				.dbghdlr = { .display = danipc_dump_irq_mask,
					     .data = &danipc_driver.if_list[0]
				}
			},
			{
				.fname = "pcap_irq_mask",
				.mode = 0444,
				.dbghdlr = { .display = danipc_dump_irq_mask,
					     .data = &danipc_driver.if_list[1]
				}
			},
			{
				.fname = "data_irq_status",
				.mode = 0444,
				.dbghdlr = { .display = danipc_dump_irq_status,
					     .data = &danipc_driver.if_list[0]
				}
			},
			{
				.fname = "pcap_irq_status",
				.mode = 0444,
				.dbghdlr = { .display = danipc_dump_irq_status,
					     .data = &danipc_driver.if_list[1]
				}
			},
	}
};

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
	struct packet_proc_info *pproc_hi = &intf->pproc[ipc_trns_prio_1];
	struct packet_proc_info *pproc_lo = &intf->pproc[ipc_trns_prio_0];
	uint8_t		rxptype_hi = pproc_hi->rxproc_type;
	uint8_t		rxptype_lo = pproc_lo->rxproc_type;
	int			rc = -ENOMEM;

	/* Low-level is initialized only for first interface */
	if (intf->drvr->ndev_active == 0)
		danipc_ll_init(intf);

	rc = init_own_ipc_to_virt_map(intf);
	if (rc == 0) {
		ipc_init(
			intf->rx_fifo_idx,
			intf->ifidx,
			intf->fifos_initialized);
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

				danipc_init_irq(intf);

				netif_start_queue(dev);
				drv->ndev_active++;
			}
		}

		intf->fifos_initialized = 1;
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
		danipc_disable_irq(intf);
		(drv->proc_rx[rxptype_hi].stop)(pproc_hi);
		(drv->proc_rx[rxptype_lo].stop)(pproc_lo);
		free_irq(dev->irq, pproc_lo);
	}

	danipc_if_cleanup(intf);

	/* Free register-map, ipc bufferes-map, agenttable-map,
	 * and fifo-reg-map.
	 */
	if (intf->drvr->ndev_active == 1)
		danipc_ll_cleanup(intf);

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

static void danipc_cleanup_dev(struct net_device *dev)
{
	if (dev) {
		netdev_info(dev, "Unregister DANIPC driver(%s).\n", dev->name);
		if (dev->reg_state == NETREG_REGISTERED)
			unregister_netdev(dev);

		free_netdev(dev);
	}
}

static int danipc_remove(struct platform_device *pdev)
{
	uint8_t	ifidx = 0;
	(void)pdev;

	while (ifidx < DANIPC_MAX_IF) {
		if (danipc_driver.if_list[ifidx])
			danipc_close(danipc_driver.if_list[ifidx]->dev);
			danipc_cleanup_dev(danipc_driver.if_list[ifidx]->dev);
		ifidx++;
	}

	pr_info("DANIPC driver " DANIPC_VERSION " unregistered.\n");
	return 0;
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
			   const char *resource[], const char *shm_sizes[])
{
	struct device_node	*node = pdev->dev.of_node;
	bool			parse_err = false;
	int			rc = -ENODEV;

	if (node) {
		struct resource	*res;
		int		shm_size;
		int		r;

		for (r = 0; r < RESOURCE_NUM && !parse_err; r++) {
			res = platform_get_resource_byname(pdev,
							   IORESOURCE_MEM,
							   resource[r]);
			if (res) {
				danipc_driver.res_start[r] = res->start;
				danipc_driver.res_len[r] = resource_size(res);
			} else {
				pr_err("cannot get resource %s\n", resource[r]);
				parse_err = true;
			}
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

			if (!shm_sizes[r] ||
			    (of_property_read_u32((&pdev->dev)->of_node,
						  shm_sizes[r], &shm_size)))
				ipc_shared_mem_sizes[r] = 0;
			else
				ipc_shared_mem_sizes[r] = shm_size;
		}

		rc = (!parse_err) ? 0 : -ENOMEM;
	}

	return rc;
}

static int danipc_if_init(struct platform_device *pdev, uint8_t nodeid,
			  struct danipc_probe_info *probe_list)
{
	struct net_device	*dev = alloc_netdev(sizeof(struct danipc_if),
					probe_list->ifname, danipc_setup);
	struct device_node	*node = pdev->dev.of_node;
	int		rc = -ENOMEM;

	if (dev) {
		int ncpus = num_online_cpus();

		struct danipc_if	*intf =
			danipc_driver.if_list[danipc_driver.ndev] =
			netdev_priv(dev);
		struct packet_proc_info *pproc = intf->pproc;
		struct danipc_pktq	*pktq = &intf->rx_pkt_pool;

		intf->drvr = &danipc_driver;
		intf->dev = dev;
		intf->ifidx = danipc_driver.ndev;
		intf->affinity = (danipc_driver.ndev + 1)%ncpus;
		intf->rx_fifo_idx = nodeid;
		intf->rx_fifo_prio = danipc_driver.ndev;
		intf->mux_mask = probe_list->mux_mask;
		intf->fifos_initialized = 0;

		mutex_init(&intf->lock);

		 __skb_queue_head_init(&pktq->q);

		intf->irq = irq_of_parse_and_map(node, intf->ifidx);
		if (!(intf->irq) || (intf->irq == NO_IRQ)) {
			netdev_err(dev, "cannot get IRQ from DT\n");
			goto danipc_iferr;
		}

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
			goto danipc_iferr;
		}
	}
danipc_iferr:
	if (rc)
		danipc_cleanup_dev(dev);
	return rc;
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
			rc = danipc_if_init(pdev, nodeid, probe_list);
			break;
		}
	}

	pr_info("Device %s %s!\n", probe_list->ifname,
		(rc == ENODEV) ? "NOT FOUND" : "FOUND");
	return rc;
}

static int danipc_probe_lfifo(struct platform_device *pdev, const char *regs[])
{
	uint8_t		ifidx;
	int		rc;
	struct danipc_probe_info danipc_probe_list[DANIPC_MAX_IF] = {
		{"apps_ipc_data", "danipc", 256, apps_ipc_data_mux_mask},
		{"apps_ipc_pcap", "danipc-pcap", 0, apps_ipc_pcap_mux_mask}
	};

	/* Probe for local fifos */
	for (ifidx = 0; ifidx < DANIPC_MAX_IF; ifidx++) {
		rc = probe_local_fifo(pdev, &danipc_probe_list[ifidx], regs);
		if (rc == 0)
			danipc_driver.ndev++;
	}

	return (danipc_driver.ndev == 0) ? -ENODEV : 0;
}

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

static void danipc_dump_fifo_info(struct seq_file *s)
{
	struct dbgfs_hdlr       *hdlr    = (struct dbgfs_hdlr *)s->private;
	struct danipc_if        **intf   = (struct danipc_if **)hdlr->data;
	struct danipc_pktq             *rx_pool = &(*intf)->rx_pkt_pool;
	struct packet_proc_info *pproc   = (*intf)->pproc;
	static const char  *format  = "%-20s: %-d\n";

	seq_puts(s, "\n\nDanipc driver fifo info:\n\n");
	seq_printf(s, format, "Irq", (*intf)->irq);
	seq_printf(s, format, "If Index", (*intf)->ifidx);
	seq_printf(s, format, "HW fifo Index", (*intf)->rx_fifo_idx);
	seq_printf(s, format, "Inter fifo prio", (*intf)->rx_fifo_prio);
	seq_printf(s, format, "Interrupt affinity", (*intf)->affinity);
	seq_printf(s, format, "Intr mux mask", (*intf)->mux_mask);
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
	struct danipc_if **intf = (struct danipc_if **)hdlr->data;
	struct packet_proc_info *pproc = (*intf)->pproc;
	struct danipc_pkt_histo *histo_hi = &pproc[ipc_trns_prio_1].pkt_hist;
	struct danipc_pkt_histo *histo_lo = &pproc[ipc_trns_prio_0].pkt_hist;
	struct net_device_stats *stats_hi = histo_hi->stats;
	struct net_device_stats *stats_lo = histo_lo->stats;

	if (!netif_running((*intf)->dev)) {
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
	struct danipc_if	**intf = (struct danipc_if **)hdlr->data;
	uint32_t	thr;
	struct fifo_threshold *thr_s;

	if (!netif_running((*intf)->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}

	thr = danipc_read_af_threshold((*intf)->rx_fifo_idx);
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
	struct danipc_if	**intf = (struct danipc_if **)hdlr->data;
	uint32_t	thr;
	struct fifo_threshold *thr_s;

	if (!netif_running((*intf)->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}
	thr = danipc_read_ae_threshold((*intf)->rx_fifo_idx);
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
	struct danipc_if	**intf = (struct danipc_if **)hdlr->data;
	uint32_t	status;
	int		i;

	if (!netif_running((*intf)->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}

	for (i = 0 ; i < 4 ; i++) {
		status = danipc_read_fifo_counter((*intf)->rx_fifo_idx, i);
		seq_printf(s, "\n\nFIFO %d Counter: %d\n", i, status);
	}
}

static void danipc_dump_fifo_status(struct seq_file *s)
{
	struct dbgfs_hdlr	*hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_if	**intf = (struct danipc_if **)hdlr->data;
	uint32_t	status;
	int		i;

	if (!netif_running((*intf)->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}

	for (i = 0 ; i < 4 ; i++) {
		seq_printf(s, "\n\nFIFO %d STATUS:\n", i);
		status = danipc_read_fifo_status((*intf)->rx_fifo_idx, i);
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
	struct danipc_if	**intf = (struct danipc_if **)hdlr->data;
	uint32_t	status;
	int		i;

	if (!netif_running((*intf)->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}

	status = danipc_read_fifo_irq_status_raw((*intf)->rx_fifo_idx);
	seq_printf(s, "# %#06x\n", status);
	for (i = 0 ; i < 4 ; i++)
		danipc_dump_fifo_n_status(s, i, status);
}

static void danipc_dump_irq_status(struct seq_file *s)
{
	struct dbgfs_hdlr	 *hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_if	**intf = (struct danipc_if **)hdlr->data;
	uint32_t	  status;
	int		  i;

	if (!netif_running((*intf)->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}

	status = danipc_read_fifo_irq_status((*intf)->rx_fifo_idx);
	seq_printf(s, "# %#06x\n", status);
	for (i = 0 ; i < 4 ; i++)
		danipc_dump_fifo_n_status(s, i, status);
}

static void danipc_dump_irq_enable(struct seq_file *s)
{
	struct dbgfs_hdlr	*hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_if	**intf = (struct danipc_if **)hdlr->data;
	uint32_t	enable;
	int		i;

	if (!netif_running((*intf)->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}

	enable = danipc_read_fifo_irq_enable((*intf)->rx_fifo_idx);
	seq_printf(s, "%#06x\n", enable);
	for (i = 0 ; i < 4 ; i++)
		danipc_dump_fifo_n_status(s, i, enable);
}

static void danipc_dump_irq_mask(struct seq_file *s)
{
	struct dbgfs_hdlr	*hdlr = (struct dbgfs_hdlr *)s->private;
	struct danipc_if	**intf = (struct danipc_if **)hdlr->data;
	uint32_t	mask;
	int		i;

	if (!netif_running((*intf)->dev)) {
		seq_puts(s, "\n\nDevice is not up!\n\n");
		return;
	}

	mask = danipc_read_fifo_irq_mask((*intf)->rx_fifo_idx);
	for (i = 0 ; i < 4 ; i++)
		danipc_dump_fifo_n_status(s, i, mask);
}

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
	struct danipc_if **intf = (struct danipc_if **)dbgfshdlr->data;
	struct net_device *dev = (*intf)->dev;
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

	danipc_set_af_threshold((*intf)->rx_fifo_idx, fifo, thr);
	return cnt;
}

static ssize_t
danipc_write_ae_threshold(struct file *filp, const char __user *ubuf,
			  size_t cnt, loff_t *ppos)
{
	struct seq_file *m = filp->private_data;
	struct dbgfs_hdlr *dbgfshdlr = (struct dbgfs_hdlr *)m->private;
	struct danipc_if **intf = (struct danipc_if **)dbgfshdlr->data;
	struct net_device *dev = (*intf)->dev;
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

	danipc_set_ae_threshold((*intf)->rx_fifo_idx, fifo, thr);
	return cnt;
}

static const struct file_operations danipc_dbgfs_ops = {
	.open = danipc_dbgfs_open,
	.release = single_release,
	.read = seq_read,
	.write = danipc_dbgfs_write,
	.llseek = seq_lseek,
};

static void __init danipc_dbgfs_init(void)
{
	struct dentry **dirent = &danipc_driver.dirent;

	*dirent = debugfs_create_dir("danipc", 0);
	if (!IS_ERR(*dirent)) {
		uint8_t		i;
		struct danipc_dbgfs	*dbgfs_ent = danipc_driver.dbgfsinf;

		for (i = 0; (i < DANIPC_DBGDRV_ENTRY_MAX) &&
		     dbgfs_ent[i].dbghdlr.display; i++) {
			dbgfs_ent[i].ent =
				debugfs_create_file(dbgfs_ent[i].fname,
						    dbgfs_ent[i].mode, *dirent,
						    &dbgfs_ent[i].dbghdlr,
						    &danipc_dbgfs_ops);
			if (!dbgfs_ent[i].ent)
				pr_err("%s: Failed to create dbgfs_ent[i].fname!\n",
				       __func__);
		}
	} else {
		pr_err("%s: Failed to create danipc debugfs\n", __func__);
	}
}

static int danipc_probe(struct platform_device *pdev)
{
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
	static const char	*shm_sizes[PLATFORM_MAX_NUM_OF_NODES] = {
		"qcom,phycpu0-shm-size", "qcom,phycpu1-shm-size",
		"qcom,phycpu2-shm-size", "qcom,phycpu3-shm-size",
		"qcom,phydsp0-shm-size", "qcom,phydsp1-shm-size",
		"qcom,phydsp2-shm-size", NULL, "qcom,apps-shm-size",
		"qcom,qdsp6-0-shm-size", "qcom,qdsp6-1-shm-size",
		"qcom,qdsp6-2-shm-size", "qcom,qdsp6-3-shm-size",
		NULL, NULL, NULL
	};

	rc = parse_resources(pdev, regs, resource, shm_sizes);
	if (rc == 0) {
		rc = danipc_probe_lfifo(pdev, regs);
		if (rc == 0)
			danipc_dbgfs_init();
	}

	return rc;
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
