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

#ifndef __DANIPC_LOWLEVEL_H__
#define __DANIPC_LOWLEVEL_H__

#include <linux/irqflags.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>

#define IPC_DUMMY_ADDR		  0
#define PLATFORM_MAX_NUM_OF_NODES 16
#define IPC_BUF_SIZE		  ((2 * IPC_BUF_COUNT_MAX) * IPC_BUF_SIZE_MAX)

#define IPC_FIFO_EMPTY	1
#define IPC_FIFO_FULL	0x10

#define TCSR_IPC_IF_FIFO_RD_ACCESS_2_OFFSET		0x18
#define TCSR_IPC_IF_FIFO_RD_ACCESS_0_OFFSET		0x8

#define TCSR_IPC_IF_FIFO_0_STATS_OFFSET		0x24
#define TCSR_IPC_IF_FIFO_1_STATS_OFFSET		0x28
#define TCSR_IPC_IF_FIFO_2_STATS_OFFSET		0x2C
#define TCSR_IPC_IF_FIFO_3_STATS_OFFSET		0x30

#define TCSR_IPC_FIFO_RD_IN_LOW_ADDR(cpuid)				\
	(ipc_regs[cpuid] + TCSR_IPC_IF_FIFO_RD_ACCESS_2_OFFSET)
#define TCSR_IPC_FIFO_RD_IN_HIGH_ADDR(cpuid)				\
	(ipc_regs[cpuid] + TCSR_IPC_IF_FIFO_RD_ACCESS_0_OFFSET)

#define TCSR_IPC_FIFO_STATUS_LOW_ADDR(cpuid)				\
	(ipc_regs[cpuid] + TCSR_IPC_IF_FIFO_2_STATS_OFFSET)
#define TCSR_IPC_FIFO_STATUS_HIGH_ADDR(cpuid)				\
	(ipc_regs[cpuid] + TCSR_IPC_IF_FIFO_0_STATS_OFFSET)

#define IPC_FIFO_ACCESS(cpuid, odd, even)		({		\
	const typeof(cpuid) __cpuid = cpuid;				\
	ipc_regs[__cpuid] + ((__cpuid & 1) ? (odd) : (even)); })

#define IPC_REMOTE_FIFO_STATUS_HIGH_ADDR(cpuid)				\
	IPC_FIFO_ACCESS(cpuid, TCSR_IPC_IF_FIFO_1_STATS_OFFSET,		\
		TCSR_IPC_IF_FIFO_1_STATS_OFFSET)

#define IPC_REMOTE_FIFO_STATUS_LOW_ADDR(cpuid)				\
	IPC_FIFO_ACCESS(cpuid, TCSR_IPC_IF_FIFO_3_STATS_OFFSET,		\
		TCSR_IPC_IF_FIFO_3_STATS_OFFSET)

#define IPC_FIFO_RD_OUT_HIGH_ADDR(cpuid)				\
	IPC_FIFO_ACCESS(cpuid, DAN_IPC_IF_FIFO_RD_5, DAN_IPC_IF_FIFO_RD_1)

#define IPC_FIFO_RD_OUT_LOW_ADDR(cpuid)				\
	IPC_FIFO_ACCESS(cpuid, DAN_IPC_IF_FIFO_RD_7, DAN_IPC_IF_FIFO_RD_3)

#define IPC_FIFO_WR_IN_HIGH_ADDR(cpuid)				\
	IPC_FIFO_ACCESS(cpuid, DAN_IPC_IF_FIFO_WR_4, DAN_IPC_IF_FIFO_WR_0)

#define IPC_FIFO_WR_OUT_HIGH_ADDR(cpuid)			\
	IPC_FIFO_ACCESS(cpuid, DAN_IPC_IF_FIFO_WR_5, DAN_IPC_IF_FIFO_WR_1)

#define IPC_FIFO_WR_IN_LOW_ADDR(cpuid)				\
	IPC_FIFO_ACCESS(cpuid, DAN_IPC_IF_FIFO_WR_6, DAN_IPC_IF_FIFO_WR_2)

#define IPC_FIFO_WR_OUT_LOW_ADDR(cpuid)				\
	IPC_FIFO_ACCESS(cpuid, DAN_IPC_IF_FIFO_WR_7, DAN_IPC_IF_FIFO_WR_3)

extern void __iomem			*apps_ipc_mux;
extern uint8_t __iomem			*ipc_buffers;
extern uint32_t			ipc_regs_phys[];
extern unsigned			ipc_regs_len[];
extern uintptr_t			ipc_regs[];
extern uint32_t			ipc_shared_mem_sizes[];
extern struct agent_entry __iomem	*agent_table;
extern const struct ipc_buf_desc	*ext_bufs;
extern uint32_t				num_ext_bufs;

struct ipc_to_virt_map {
	/* Physical address of the FIFO data buffer *without* bit 31 set. */
	uint32_t		paddr;

	/* Virtual address of the FIFO data buffer. */
	void __iomem		*vaddr;

	/* Size of the address space */
	uint32_t		size;

	/* How many skbs destined for this core are on delayed_skb list */
	atomic_t		pending_skbs;
};

uint32_t virt_to_ipc(const int cpuid, const unsigned prio, void *v_addr);
void *ipc_to_virt(const int cpuid, const unsigned prio,
		  const uint32_t raw_ipc_addr);

#define __IPC_AGENT_ID(cpuid, lid)			\
	(((cpuid&(PLATFORM_MAX_NUM_OF_NODES-1)) << 4) +	\
				(0x0f & (lid)))

void ipc_trns_fifo_move_m_to_b(uint8_t cpuid);
unsigned ipc_init(
	uint8_t local_cpuid,
	uint8_t ifidx,
	uint8_t fifos_initialized);
unsigned ipc_cleanup(uint8_t local_cpuid);
void ipc_trns_fifo_buf_init(uint8_t cpuid , uint8_t ifidx);
void ipc_trns_fifo_buf_flush(uint8_t cpuid);
void ipc_route_table_init(uint8_t local_cpuid,
			  struct ipc_trns_func const *ptr);
char *ipc_trns_fifo_buf_alloc(uint8_t dest_aid,
			      enum ipc_trns_prio pri);
void ipc_trns_fifo_buf_free(char *ptr, uint8_t dest_aid,
			    enum ipc_trns_prio pri);
int32_t ipc_trns_fifo_buf_send(char *ptr, uint8_t dest_id,
			       enum ipc_trns_prio pri);
char *ipc_trns_fifo2eth_buf_alloc(uint8_t dest_aid,
				  enum ipc_trns_prio pri);
void ipc_trns_fifo2eth_buf_free(char *ptr, uint8_t dest_aid,
				enum ipc_trns_prio pri);
int32_t ipc_trns_fifo2eth_buf_send(char *ptr, uint8_t dest_id,
				   enum ipc_trns_prio pri);
char *ipc_trns_fifo_buf_read(enum ipc_trns_prio pri, uint8_t cpuid);

void ipc_agent_table_clean(uint8_t local_cpuid);
struct ipc_trns_func const *get_trns_funcs(uint8_t cpuid);

extern struct ipc_to_virt_map	ipc_to_virt_map[PLATFORM_MAX_NUM_OF_NODES][2];

void danipc_clear_interrupt(uint8_t fifo);
void danipc_mask_interrupt(uint8_t fifo);
void danipc_unmask_interrupt(uint8_t fifo);

uint32_t danipc_read_af_threshold(uint8_t intf);
uint32_t danipc_set_af_threshold(uint8_t intf, uint8_t n, uint8_t thr);
uint32_t danipc_read_ae_threshold(uint8_t intf);
uint32_t danipc_set_ae_threshold(uint8_t intf, uint8_t n, uint8_t thr);
uint32_t danipc_read_fifo_status(uint8_t fifo, uint8_t n);
uint32_t danipc_read_fifo_counter(uint8_t fifo, uint8_t n);
uint32_t danipc_read_fifo_irq_mask(uint8_t fifo);
uint32_t danipc_read_fifo_irq_enable(uint8_t fifo);
uint32_t danipc_read_fifo_irq_status(uint8_t fifo);
uint32_t danipc_read_fifo_irq_status_raw(uint8_t fifo);

bool danipc_m_fifo_is_empty(uint8_t cpuid, enum ipc_trns_prio pri);
bool danipc_b_fifo_is_full(uint8_t cpuid, enum ipc_trns_prio pri);

void danipc_b_fifo_push(phys_addr_t paddr,
			int cpuid,
			enum ipc_trns_prio prio);

void danipc_m_fifo_push(phys_addr_t paddr,
			int cpuid,
			enum ipc_trns_prio prio);

phys_addr_t danipc_b_fifo_pop(int cpuid, enum ipc_trns_prio prio);

void danipc_fifo_drain(int cpuid, enum ipc_trns_prio prio);

static inline bool valid_cpu_id(int cpuid)
{
	if (cpuid < 0 || cpuid >= PLATFORM_MAX_NUM_OF_NODES)
		return false;
	return true;
}

#endif /* __DANIPC_LOWLEVEL_H__ */
