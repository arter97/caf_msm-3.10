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

#ifndef __DANIPC_LOWLEVEL_H__
#define __DANIPC_LOWLEVEL_H__

#include <linux/irqflags.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>

#define IPC_DUMMY_ADDR		  0
#define PLATFORM_MAX_NUM_OF_NODES 16
#define IPC_BUF_SIZE		  ((2 * IPC_BUF_COUNT_MAX) * IPC_BUF_SIZE_MAX)

extern void __iomem			*apps_ipc_mux;
extern uint8_t __iomem			*ipc_buffers;
extern uint32_t			ipc_regs_phys[];
extern unsigned			ipc_regs_len[];
extern uintptr_t			ipc_regs[];
extern uint32_t			ipc_shared_mem_sizes[];
extern struct agent_entry __iomem	*agent_table;

enum apps_int_mux_mask {
	apps_ipc_data_mux_mask,
	apps_ipc_pcap_mux_mask,
	apps_ipc_int_mux_max
};

struct ipc_to_virt_map {
	/* Physical address of the FIFO data buffer *without* bit 31 set. */
	uint32_t		paddr;

	/* Virtual address of the FIFO data buffer. */
	void __iomem		*vaddr;

	/* How many skbs destined for this core are on delayed_skb list */
	atomic_t		pending_skbs;
};

uint32_t virt_to_ipc(const int cpuid, const unsigned prio, void *v_addr);
void *ipc_to_virt(const int cpuid, const unsigned prio,
		  const uint32_t raw_ipc_addr);

#define __IPC_AGENT_ID(cpuid, lid)			\
	(((cpuid&(PLATFORM_MAX_NUM_OF_NODES-1)) << 4) +	\
				(0x0f & (lid)))

unsigned ipc_init(uint8_t local_cpuid, uint8_t ifidx);
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
uint8_t ipc_get_own_node(void);
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

#endif /* __DANIPC_LOWLEVEL_H__ */
