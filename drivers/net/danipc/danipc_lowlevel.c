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
#include <linux/irq.h>

#include "danipc_k.h"

#include "ipc_api.h"

#include "danipc_lowlevel.h"

/* Almost Full(AF) interrupt threshold */
#define AF_THRESHOLD		0x7D
#define AF_PCAP_THRESHOLD	0x7D

/* IPC FIFO interrupt register offsets */
#define FIFO_0_COUNTER		0x6c
#define FIFO_1_COUNTER		0x70
#define FIFO_2_COUNTER		0x74
#define FIFO_3_COUNTER		0x78

#define FIFO_0_STATUS		0x24
#define FIFO_1_STATUS		0x28
#define FIFO_2_STATUS		0x2c
#define FIFO_3_STATUS		0x30
#define FIFO_THR_AF_CFG_F0	0x34
#define FIFO_THR_AE_CFG_F0	0x38
#define CDU_INT0_MASK_F0	0x44
#define CDU_INT0_ENABLE_F0	0x4c
#define CDU_INT0_STATUS_F0	0x54
#define CDU_INT0_RAW_STATUS_F0	0x5C
#define CDU_INT0_CLEAR_F0	0x64
#define FIFO_0_POP_COUNTER	0x6C
#define FIFO_POP_COUNTER_ENABLE 0x80

/* Pop counter set FIFO'd*/
#define FIFO_POP_SET_ALL_FIFOS 0x15

/* Almost Full(AF) interrupt indication bit */
#define IPC_INTR_FIFO_AF	5
#define IPC_INTR(intr)		(1 << (intr))

/* Allocation of IPC FIFOS among CPU cores is evident from
 * Platform specific dts file.
 */
#define TCSR_IPC0_CDU0_INT0_MUX	0x1
#define TCSR_IPC0_CDU0_INT1_MUX	0x2
#define TCSR_IPC3_CDU1_INT0_MUX	0x4000
#define TCSR_IPC3_CDU1_INT1_MUX	0x8000

/* Mux IPC0_CDU0 and IPC3_CDU1 interrupts to APPS.
 * As APPS receives all its messages from
 * FIFOs in TCSR_IPC0_CDU0 alone.
 */
#define APPS_IPC_DATA_FIFO_INT	(TCSR_IPC0_CDU0_INT0_MUX | \
				 TCSR_IPC0_CDU0_INT1_MUX)
#define APPS_IPC_PCAP_FIFO_INT	(TCSR_IPC3_CDU1_INT0_MUX | \
				 TCSR_IPC3_CDU1_INT1_MUX)

/* IPC and Linux coexistence.
 * IPC uses/needs physical addresses with bit 31 set while Linux obviously
 * uses virtual addresses. So when writing an address to IPC / reading from IPC
 * make sure it is converted from virtual to IPC address
 * (physical address with bit 31 set) and vice versa.
 * For every cpuid (except my own) FIFO buffers of both priorities remapped.
 * It is guaranteed (?) that FIFO buffers are in contiguous memory of 16kB long.
 * So remapping of 2*16kB is a safe way to access all possible FIFO buffers.
 * For my own CPU just take physical address.
 * Vladik, 21.08.2011
 */

#define FIFO_MAP_SIZE		SZ_256K
#define FIFO_MAP_MASK		(FIFO_MAP_SIZE - 1)

uint8_t	__iomem		*ipc_buffers;

struct ipc_to_virt_map		ipc_to_virt_map[PLATFORM_MAX_NUM_OF_NODES][2];

void __iomem		*apps_ipc_mux;

static uint32_t apps_ipc_mux_val[apps_ipc_int_mux_max] = {
	APPS_IPC_DATA_FIFO_INT,
	APPS_IPC_PCAP_FIFO_INT
};

void danipc_clear_interrupt(uint8_t fifo)
{
	const unsigned          base_addr = ipc_regs[fifo];

	__raw_writel_no_log(IPC_INTR(IPC_INTR_FIFO_AF),
			    (void *)(base_addr + CDU_INT0_CLEAR_F0));
}

void danipc_mask_interrupt(uint8_t fifo)
{
	const unsigned          base_addr = ipc_regs[fifo];

	__raw_writel_no_log(IPC_INTR(IPC_INTR_FIFO_AF),
			    (void *)(base_addr + CDU_INT0_MASK_F0));
}

void danipc_unmask_interrupt(uint8_t fifo)
{
	const unsigned          base_addr = ipc_regs[fifo];

	__raw_writel_no_log(~IPC_INTR(IPC_INTR_FIFO_AF),
			    (void *)(base_addr + CDU_INT0_MASK_F0));
}

static void *map_ipc_buffers(struct danipc_drvr *drv)
{
	resource_size_t res_start = drv->res_start[IPC_BUFS_RES];
	resource_size_t res_len = drv->res_len[IPC_BUFS_RES];

	ipc_buffers = ioremap_nocache(res_start, res_len);

	if (ipc_buffers) {
		memset(ipc_buffers, 0, res_len);
	} else {
		pr_err("%s: cannot allocate IPC buffers!\n", __func__);
		BUG();
	}

	return ipc_buffers;
}

static void free_ipc_buffers(void)
{
	if (ipc_buffers) {
		iounmap(ipc_buffers);
		ipc_buffers = NULL;
	}
}

int init_own_ipc_to_virt_map(struct danipc_if *intf)
{
	uint8_t	idx = intf->ifidx;
	int	rc = 0;
	struct ipc_to_virt_map *high_map =
		&ipc_to_virt_map[intf->rx_fifo_idx][ipc_trns_prio_1];
	struct ipc_to_virt_map *low_map =
		&ipc_to_virt_map[intf->rx_fifo_idx][ipc_trns_prio_0];
	uint8_t __iomem *buf = (ipc_buffers == NULL) ?
		map_ipc_buffers(intf->drvr) : &ipc_buffers[idx * IPC_BUF_SIZE];

	if (buf) {
		/* This prevents remapping by remap_fifo_mem() */
		high_map->vaddr = buf;
		high_map->paddr = intf->drvr->res_start[IPC_BUFS_RES] +
			(idx * IPC_BUF_SIZE);
		low_map->vaddr	= &buf[IPC_BUF_SIZE / 2];
		low_map->paddr	= high_map->paddr + (IPC_BUF_SIZE / 2);
	} else {
		rc = -1;
	}

	return rc;
}

/* Free IPC buffers for all remote FIFO's.*/
static void unmap_ipc_to_virt_map(struct danipc_if *intf)
{
	uint8_t		cpuid;
	struct danipc_drvr	*drvr = intf->drvr;
	void			*vaddr_hi;
	void			*vaddr_lo;

	for (cpuid = 0; cpuid < PLATFORM_MAX_NUM_OF_NODES; cpuid++) {
		vaddr_hi = ipc_to_virt_map[cpuid][ipc_trns_prio_1].vaddr;
		vaddr_lo = ipc_to_virt_map[cpuid][ipc_trns_prio_0].vaddr;

		/* Exclude APPS IPC buffers */
		if (((uint8_t *)vaddr_hi >= ipc_buffers) &&
		    ((uint8_t *)vaddr_hi <
		     &ipc_buffers[drvr->res_len[IPC_BUFS_RES]]))
			continue;
		if (vaddr_hi)
			iounmap(vaddr_hi);
		if (vaddr_lo != vaddr_hi)
			iounmap(vaddr_lo);
		memset(&ipc_to_virt_map[cpuid][ipc_trns_prio_1], 0,
		       sizeof(ipc_to_virt_map[cpuid][ipc_trns_prio_1]));
	}
}

static void remap_fifo_mem(const int cpuid, const unsigned prio,
			   const uint32_t paddr)
{
	struct ipc_to_virt_map *const map = ipc_to_virt_map[cpuid];
	unsigned other_prio = (prio == ipc_trns_prio_0) ?
				ipc_trns_prio_1 : ipc_trns_prio_0;
	uint32_t start_addr;
	uint32_t map_size;
	uint32_t map_mask;

	/* Use shared memory size if defined for given CPU.
	 * Since shared memory is used for both FIFO priorities, remap
	 * only once for this CPU.
	 */
	if (ipc_shared_mem_sizes[cpuid]) {
		map_size = ipc_shared_mem_sizes[cpuid];
		map_mask = map_size - 1;
		start_addr = ((paddr + map_mask) & ~map_mask) - map_size;
		map[prio].paddr = start_addr;
		map[other_prio].paddr = start_addr;
		map[prio].vaddr = ioremap_nocache(start_addr, 2 * map_size);
		map[other_prio].vaddr = map[prio].vaddr;
	} else {
		map_size = FIFO_MAP_SIZE;
		map_mask = FIFO_MAP_MASK;
		start_addr = ((paddr + map_mask) & ~map_mask) - 2 * map_size;
		map[prio].paddr = start_addr;
		map[prio].vaddr = ioremap_nocache(start_addr, 2 * map_size);
	}

	if (!map[prio].vaddr) {
		pr_err(
			"%s:%d cpuid = %d priority = %u cannot remap FIFO memory at addr. 0x%x\n",
			__func__, __LINE__, cpuid, prio, start_addr);
		BUG();
	}
}

uint32_t virt_to_ipc(const int cpuid, const unsigned prio, void *vaddr)
{
	if (likely(prio <= ipc_trns_prio_1)) {
		struct ipc_to_virt_map *map = &ipc_to_virt_map[cpuid][prio];
		int offset;

		if (unlikely(!map->paddr)) {
			pr_err("%s:%d: cpuid = %d priority = %u unmapped\n",
			       __func__, __LINE__, cpuid, prio);
			BUG();
		}
		offset = (unsigned)vaddr - (unsigned)map->vaddr;
		return map->paddr + offset;
	}

	pr_err("%s:%d: cpuid = %d illegal priority = %u\n",
	       __func__, __LINE__, cpuid, prio);
	BUG();

	return 0;
}

void *ipc_to_virt(const int cpuid, const unsigned prio, const uint32_t ipc_addr)
{
	if (likely(prio <= ipc_trns_prio_1 ||
		   cpuid < PLATFORM_MAX_NUM_OF_NODES)) {
		struct ipc_to_virt_map	*map = &ipc_to_virt_map[cpuid][prio];
		const uint32_t	paddr = ipc_addr;
		int		offset;

		if (unlikely(!map->paddr))
			remap_fifo_mem(cpuid, prio, paddr);
		offset = paddr - map->paddr;
		return (uint8_t *)map->vaddr + offset;
	}

	pr_err("%s:%d: cpuid = %d illegal priority = %u\n",
	       __func__, __LINE__, cpuid, prio);
	BUG();

	return NULL;
}

irqreturn_t danipc_interrupt(int irq, void *data)
{
	/* By default we always pass packet_proc for low-prio
	 * danipc fifo.
	 */
	struct packet_proc_info *pproc_hi =
		 &((struct packet_proc_info *)data)[ipc_trns_prio_1];
	struct danipc_if		*intf = pproc_hi->intf;
	struct packet_proc		*proc_rx =
		&intf->drvr->proc_rx[pproc_hi->rxproc_type];
	const unsigned	base_addr = ipc_regs[intf->rx_fifo_idx];

	/* Mask all IPC interrupts. */
	__raw_writel_no_log(~0, (void *)(base_addr + CDU_INT0_MASK_F0));

	(proc_rx->schedule_work)(&pproc_hi->rx_work);

	return IRQ_HANDLED;
}

void danipc_init_irq(struct danipc_if *intf)
{
	struct danipc_drvr	*drvr	   = intf->drvr;
	struct net_device	*dev	   = intf->dev;
	const unsigned		 base_addr = ipc_regs[intf->rx_fifo_idx];

	if (intf == drvr->if_list[0]) {
		netdev_dbg(dev, "%s: dev->irq = %d Threshold = %x\n", __func__,
			   dev->irq, AF_THRESHOLD);
		__raw_writel_no_log(AF_THRESHOLD,
				    (void *)(base_addr + FIFO_THR_AF_CFG_F0));
	} else if (intf == drvr->if_list[1]) {
		netdev_dbg(dev, "%s: dev->irq = %d Threshold = %x\n", __func__,
			   dev->irq, AF_PCAP_THRESHOLD);
		__raw_writel_no_log(AF_PCAP_THRESHOLD,
				    (void *)(base_addr + FIFO_THR_AF_CFG_F0));
	} else {
		netdev_err(dev, "%s: Unknown device passed %p\n",
			   __func__ , intf);
	}

	__raw_writel_no_log(FIFO_POP_SET_ALL_FIFOS,
			    (void *)(base_addr + FIFO_POP_COUNTER_ENABLE));
	__raw_writel_no_log(IPC_INTR(IPC_INTR_FIFO_AF),
			    (void *)(base_addr + CDU_INT0_CLEAR_F0));
	__raw_writel_no_log(IPC_INTR(IPC_INTR_FIFO_AF),
			    (void *)(base_addr + CDU_INT0_ENABLE_F0));
	__raw_writel_no_log(~IPC_INTR(IPC_INTR_FIFO_AF),
			    (void *)(base_addr + CDU_INT0_MASK_F0));

	/* Route interrupts from TCSR to APPS (relevant to APPS-FIFO) */
	/* TBD: makesure apps_ipc_mux is incremented by 4 bytes */
	__raw_writel_no_log(apps_ipc_mux_val[intf->mux_mask],
			    &((uint32_t *)apps_ipc_mux)[intf->ifidx]);
}

uint32_t danipc_read_af_threshold(uint8_t fifo)
{
	const unsigned	base_addr = ipc_regs[fifo];
	uint32_t	af        =
		__raw_readl((void *)(base_addr + FIFO_THR_AF_CFG_F0));
	return af;
}

uint32_t danipc_set_af_threshold(uint8_t fifo, uint8_t n, uint8_t thr)
{
	const unsigned base_addr = ipc_regs[fifo];
	uint32_t       af;

	if (thr > 127) {
		pr_err("%s: Threshold value out of valid range (0-127) %d\n",
		       __func__, n);
		return 0;
	}
	if (n > 3) {
		pr_err("%s: fifo number(%d) out of valid range (0-3)\n",
		       __func__, n);
		return 0;
	}
	af = __raw_readl((void *)(base_addr + FIFO_THR_AF_CFG_F0));
	af = ((af & ~((((uint32_t)0x7f)) << (n*8))) |
	      (((uint32_t)(thr)) << (n*8)));
	__raw_writel_no_log(af, (void *)(base_addr + FIFO_THR_AF_CFG_F0));
	af = __raw_readl((void *)(base_addr + FIFO_THR_AF_CFG_F0));
	return af;
}

uint32_t danipc_read_ae_threshold(uint8_t fifo)
{
	const unsigned	base_addr = ipc_regs[fifo];
	uint32_t	ae        =
		__raw_readl((void *)(base_addr + FIFO_THR_AE_CFG_F0));
	return ae;
}

uint32_t danipc_set_ae_threshold(uint8_t fifo, uint8_t n, uint8_t thr)
{
	const unsigned base_addr = ipc_regs[fifo];
	uint32_t       ae;

	if (thr < 0 || thr > 127) {
		pr_err("%s: Threshold value out of valid range (0-127) %d\n",
		       __func__, n);
		return 0;
	}
	if (n < 0 || n > 3) {
		pr_err("%s: Unsupported fifo number %d\n", __func__, n);
		return 0;
	}
	ae = __raw_readl((void *)(base_addr + FIFO_THR_AE_CFG_F0));
	ae = ((ae & ~((((uint32_t)0x7f)) << (n*8))) |
	      ((uint32_t)(thr) << (n*8)));
	__raw_writel_no_log(ae, (void *)(base_addr + FIFO_THR_AE_CFG_F0));
	ae = __raw_readl((void *)(base_addr + FIFO_THR_AE_CFG_F0));
	return ae;
}

uint32_t danipc_read_fifo_counter(uint8_t fifo, uint8_t n)
{
	const unsigned	base_addr = ipc_regs[fifo];
	uint32_t status_offset = FIFO_0_COUNTER;
	uint32_t status;

	switch (n) {
	case 0:
		status_offset = FIFO_0_COUNTER;
		break;
	case 1:
		status_offset = FIFO_1_COUNTER;
		break;
	case 2:
		status_offset = FIFO_2_COUNTER;
		break;
	case 3:
		status_offset = FIFO_3_COUNTER;
		break;
	default:
		pr_err("%s: Unsupported fifo number %d\n", __func__, n);
		return 0;
	}

	pr_debug("%s: reading status record %p\n", __func__,
		 (void *)(base_addr + status_offset));
	status = __raw_readl((void *)(base_addr + status_offset));
	return status;
}

uint32_t danipc_read_fifo_status(uint8_t fifo, uint8_t n)
{
	const unsigned	base_addr = ipc_regs[fifo];
	uint32_t status_offset = FIFO_0_STATUS;
	uint32_t status;

	switch (n) {
	case 0:
		status_offset = FIFO_0_STATUS;
		break;
	case 1:
		status_offset = FIFO_1_STATUS;
		break;
	case 2:
		status_offset = FIFO_2_STATUS;
		break;
	case 3:
		status_offset = FIFO_3_STATUS;
		break;
	default:
		pr_err("%s: Unsupported fifo number %d\n", __func__, n);
		return 0;
	}

	pr_debug("%s: reading status record %p\n", __func__,
		 (void *)(base_addr + status_offset));
	status = __raw_readl((void *)(base_addr + status_offset));
	return status;
}

uint32_t danipc_read_fifo_irq_status_raw(uint8_t fifo)
{
	const unsigned base_addr = ipc_regs[fifo];
	uint32_t irq_status =
		__raw_readl((void *)(base_addr + CDU_INT0_RAW_STATUS_F0));
	return irq_status;
}

uint32_t danipc_read_fifo_irq_mask(uint8_t fifo)
{
	const unsigned base_addr = ipc_regs[fifo];
	uint32_t irq_mask = __raw_readl((void *)(base_addr + CDU_INT0_MASK_F0));
	return irq_mask;
}

uint32_t danipc_read_fifo_irq_enable(uint8_t fifo)
{
	const unsigned	base_addr = ipc_regs[fifo];
	uint32_t irq_enable	  =
		__raw_readl((void *)(base_addr + CDU_INT0_ENABLE_F0));
	return irq_enable;
}

uint32_t danipc_read_fifo_irq_status(uint8_t fifo)
{
	const unsigned	base_addr = ipc_regs[fifo];
	uint32_t irq_status	  =
		__raw_readl((void *)(base_addr + CDU_INT0_STATUS_F0));
	return irq_status;
}

void danipc_disable_irq(struct danipc_if *intf)
{
	const unsigned	base_addr = ipc_regs[intf->rx_fifo_idx];

	/* Clear, disable and mask all interrupts from this CDU */
	__raw_writel_no_log(IPC_INTR(IPC_INTR_FIFO_AF),
			    (void *)(base_addr + CDU_INT0_CLEAR_F0));
	__raw_writel_no_log(0, (void *)(base_addr + CDU_INT0_ENABLE_F0));
	__raw_writel_no_log(IPC_INTR(IPC_INTR_FIFO_AF),
			    (void *)(base_addr + CDU_INT0_MASK_F0));

	/* Route interrupts from TCSR to APPS (relevant to APPS-FIFO) */
	/* TBD: makesure apps_ipc_mux is incremented by 4 bytes */
	__raw_writel_no_log(0, &((uint32_t *)apps_ipc_mux)[intf->ifidx]);
}

static void remap_agent_table(struct danipc_drvr *drv)
{
	agent_table = ioremap_nocache(drv->res_start[AGENT_TABLE_RES],
				      drv->res_len[AGENT_TABLE_RES]);
	if (!agent_table) {
		pr_err("%s: cannot remap IPC global agent table\n", __func__);
		BUG();
	}
}

static void unmap_agent_table(struct danipc_if *intf)
{
	if (agent_table) {
		iounmap(agent_table);
		agent_table = NULL;
	}
}

static void prepare_node(const int cpuid)
{
	struct ipc_to_virt_map	*map;

	ipc_regs[cpuid] = (uintptr_t)ioremap_nocache(ipc_regs_phys[cpuid],
							ipc_regs_len[cpuid]);
	map = &ipc_to_virt_map[cpuid][ipc_trns_prio_0];
	atomic_set(&map->pending_skbs, 0);

	map = &ipc_to_virt_map[cpuid][ipc_trns_prio_1];
	atomic_set(&map->pending_skbs, 0);
}

static void prepare_nodes(void)
{
	int		n;

	for (n = 0; n < PLATFORM_MAX_NUM_OF_NODES; n++)
		if (ipc_regs_len[n])
			prepare_node(n);
}

static void unmap_nodes_memory(void)
{
	int		n;

	for (n = 0; n < PLATFORM_MAX_NUM_OF_NODES; n++)
		if (ipc_regs[n]) {
			iounmap((void __iomem *)ipc_regs[n]);
			ipc_regs[n] = 0;
		}
}

static void remap_apps_ipc_mux(struct danipc_drvr *drv)
{
	apps_ipc_mux = ioremap_nocache(
				drv->res_start[KRAIT_IPC_MUX_RES],
				drv->res_len[KRAIT_IPC_MUX_RES]);
	if (!apps_ipc_mux) {
		pr_err("%s: cannot remap APPS IPC mux\n", __func__);
		BUG();
	}
}

static void unmap_apps_ipc_mux(void)
{
	if (apps_ipc_mux) {
		iounmap(apps_ipc_mux);
		apps_ipc_mux = NULL;
	}
}

void danipc_ll_init(struct danipc_if *intf)
{
	prepare_nodes();
	remap_agent_table(intf->drvr);
	remap_apps_ipc_mux(intf->drvr);
}

void danipc_ll_cleanup(struct danipc_if *intf)
{
	unmap_apps_ipc_mux();
	unmap_ipc_to_virt_map(intf);
	unmap_agent_table(intf);
	unmap_nodes_memory();
	free_ipc_buffers();
}
