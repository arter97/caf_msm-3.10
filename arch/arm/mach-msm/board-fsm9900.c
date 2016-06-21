/* Copyright (c) 2013-2016, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/err.h>
#include <linux/etherdevice.h>
#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/memory.h>
#include <linux/clk/msm-clk-provider.h>
#include <linux/uio_driver.h>
#include <asm/mach/map.h>
#include <asm/mach/arch.h>
#include <mach/board.h>
#include <mach/gpiomux.h>
#include <mach/msm_iomap.h>
#include <soc/qcom/restart.h>
#include <soc/qcom/socinfo.h>
#include <soc/qcom/smd.h>
#include "board-dt.h"
#include "clock.h"
#include "platsmp.h"

#define FSM9900_MAC0_FUSE_PHYS	0xFC4B8440
#define FSM9900_MAC1_FUSE_PHYS	0xFC4B8448
#define FSM9900_MAC_FUSE_SIZE	0x10

#define FSM9900_FSM_ID_FUSE_PHYS	0xFC4BC0A0
#define FSM9900_FSM_ID_FUSE_SIZE	0x2

#define FSM_ID_MASK	0x000FFFFF
#define FSM_ID_FSM9900	0x0080f

#define FSM9900_QDSP6_0_DEBUG_DUMP_PHYS	0x19800000
#define FSM9900_QDSP6_1_DEBUG_DUMP_PHYS	0x19880000
#define FSM9900_QDSP6_2_DEBUG_DUMP_PHYS	0x19900000
#define FSM9900_QDSP6_3_DEBUG_DUMP_PHYS	0x19A80000
#define FSM9900_SCLTE_DEBUG_DUMP_PHYS	0x19780000
#define FSM9900_SCLTE_DEBUG_TRACE_PHYS	0x19700000
#define FSM9900_SCLTE_CDU_PHYS		0x18600000
#define FSM9900_SCLTE_CB_TRACE_PHYS	0x1a100000
#define FSM9900_SCLTE_RF_CAL_PHYS	0x1a100000
#define FSM9900_SCLTE_ETH_TRACE_PHYS	0x19c00000
#define FSM9900_SCLTE_DDR_PHYS		0x00100000
#define FSM9900_SCLTE_GEN_DBG_PHYS	0xf6000000

#define FSM9900_UIO_VERSION "1.0"

#define FSM9900_MEM_MAP_PHYS		0xFE803C00
#define FSM9900_MEM_MAP_SIZE		0x400

#define MEM_TAG_NONE			0x00000000
#define MEM_TAG_OEM_DEBUG		0x00000001
#define MEM_TAG_LOADABLE_HEX0		0x00000002
#define MEM_TAG_LOADABLE_HEX1		0x00000003
#define MEM_TAG_LOADABLE_HEX2		0x00000004
#define MEM_TAG_LOADABLE_HEX3		0x00000005
#define MEM_TAG_SHARED_LTEFAPI_UL	0x00000006
#define MEM_TAG_SHARED_LTEFAPI_DL	0x00000007
#define MEM_TAG_SHARED_LTEIPC		0x00000008
#define MEM_TAG_SHARED_LTEL2_DL		0x00000009
#define MEM_TAG_SHARED_LTEL2_UL		0x0000000A

#define VMID_NOACCESS			0
#define VMID_RPM			1
#define VMID_TZ				2
#define VMID_AP				3
#define VMID_HEX_0			4
#define VMID_HEX_1			5
#define VMID_HEX_2			6
#define VMID_HEX_3			7
#define VMID_CTTHRT			8
#define VMID_SCLTE			9
#define VMID_NAV			10
#define VMID_EMAC0			11
#define VMID_EMAC1			12
#define VMID_PCIE0			13
#define VMID_PCIE1			14

#define VMID_NOACCESS_BIT		(1<<VMID_NOACCESS)
#define VMID_RPM_BIT			(1<<VMID_RPM)
#define VMID_TZ_BIT			(1<<VMID_TZ)
#define VMID_AP_BIT			(1<<VMID_AP)
#define VMID_HEX_0_BIT			(1<<VMID_HEX_0)
#define VMID_HEX_1_BIT			(1<<VMID_HEX_1)
#define VMID_HEX_2_BIT			(1<<VMID_HEX_2)
#define VMID_HEX_3_BIT			(1<<VMID_HEX_3)
#define VMID_CTTHRT_BIT			(1<<VMID_CTTHRT)
#define VMID_SCLTE_BIT			(1<<VMID_SCLTE)
#define VMID_NAV_BIT			(1<<VMID_NAV)
#define VMID_EMAC0_BIT			(1<<VMID_EMAC0)
#define VMID_EMAC1_BIT			(1<<VMID_EMAC1)
#define VMID_PCIE0_BIT			(1<<VMID_PCIE0)
#define VMID_PCIE1_BIT			(1<<VMID_PCIE1)

struct mem_map_seg {
	u32 phy_addr;
	u32 sz;
	u32 rd_vmid;
	u32 wr_vmid;
	u32 tag;
} __attribute__((__packed__));

static struct of_dev_auxdata fsm9900_auxdata_lookup[] __initdata = {
	OF_DEV_AUXDATA("qcom,sdhci-msm", 0xF9824900, "msm_sdcc.1", NULL),
	OF_DEV_AUXDATA("qcom,sdhci-msm", 0xF98A4900, "msm_sdcc.2", NULL),
	{}
};

static struct uio_info fsm9900_uio_info[] = {
	{
		.name = "fsm9900-uio0",
		.version = FSM9900_UIO_VERSION,
	},
	{
		.name = "fsm9900-uio1",
		.version = FSM9900_UIO_VERSION,
	},
	{
		.name = "fsm9900-uio2",
		.version = FSM9900_UIO_VERSION,
	},
};

static struct resource fsm9900_uio0_resources[] = {
	{
		.start = FSM9900_QDSP6_0_DEBUG_DUMP_PHYS,
		.end   = FSM9900_QDSP6_0_DEBUG_DUMP_PHYS + SZ_512K - 1,
		.name  = "qdsp6_0_debug_dump",
		.flags = IORESOURCE_MEM,
	},
	{
		.start = FSM9900_QDSP6_1_DEBUG_DUMP_PHYS,
		.end   = FSM9900_QDSP6_1_DEBUG_DUMP_PHYS + SZ_512K - 1,
		.name  = "qdsp6_1_debug_dump",
		.flags = IORESOURCE_MEM,
	},
	{
		.start = FSM9900_QDSP6_2_DEBUG_DUMP_PHYS,
		.end   = FSM9900_QDSP6_2_DEBUG_DUMP_PHYS + SZ_1M + SZ_512K - 1,
		.name  = "qdsp6_2_debug_dump",
		.flags = IORESOURCE_MEM,
	},
	{
		.start = FSM9900_QDSP6_3_DEBUG_DUMP_PHYS,
		.end   = FSM9900_QDSP6_3_DEBUG_DUMP_PHYS + SZ_1M + SZ_512K - 1,
		.name  = "qdsp6_3_debug_dump",
		.flags = IORESOURCE_MEM,
	},
	{
		.start = FSM9900_SCLTE_DEBUG_DUMP_PHYS,
		.end   = FSM9900_SCLTE_DEBUG_DUMP_PHYS + SZ_512K - 1,
		.name  = "sclte_debug_dump",
		.flags = IORESOURCE_MEM,
	},
};

static struct platform_device fsm9900_uio0_device = {
	.name = "uio_pdrv",
	.id = 0,
	.dev = {
		.platform_data = &fsm9900_uio_info[0]
	},
	.num_resources = ARRAY_SIZE(fsm9900_uio0_resources),
	.resource = fsm9900_uio0_resources,
};

static struct resource fsm9900_uio1_resources[] = {
	{
		.start = FSM9900_SCLTE_DEBUG_TRACE_PHYS,
		.end   = FSM9900_SCLTE_DEBUG_TRACE_PHYS + SZ_512K - 1,
		.name  = "sclte_debug_trace",
		.flags = IORESOURCE_MEM,
	},
	{
		.start = FSM9900_SCLTE_CDU_PHYS,
		.end   = FSM9900_SCLTE_CDU_PHYS + SZ_16M - 1,
		.name  = "sclte_cdu",
		.flags = IORESOURCE_MEM,
	},
	{
		.start = FSM9900_SCLTE_CB_TRACE_PHYS,
		.end   = FSM9900_SCLTE_CB_TRACE_PHYS + SZ_8M + SZ_2M - 1,
		.name  = "sclte_cb_trace",
		.flags = IORESOURCE_MEM,
	},
	{
		.start = FSM9900_SCLTE_RF_CAL_PHYS,
		.end   = FSM9900_SCLTE_RF_CAL_PHYS + SZ_8M + SZ_2M - 1,
		.name  = "sclte_rf_cal",
		.flags = IORESOURCE_MEM,
	},
	{
		.start = FSM9900_SCLTE_ETH_TRACE_PHYS,
		.end   = FSM9900_SCLTE_ETH_TRACE_PHYS + SZ_1M - 1,
		.name  = "sclte_eth_trace",
		.flags = IORESOURCE_MEM,
	},
};

static struct platform_device fsm9900_uio1_device = {
	.name = "uio_pdrv",
	.id = 1,
	.dev = {
		.platform_data = &fsm9900_uio_info[1]
	},
	.num_resources = ARRAY_SIZE(fsm9900_uio1_resources),
	.resource = fsm9900_uio1_resources,
};

static struct resource fsm9900_uio2_resources[] = {
	{
		.start = FSM9900_SCLTE_DDR_PHYS,
		.end   = FSM9900_SCLTE_DDR_PHYS + 127 * SZ_1M - 1,
		.name  = "sclte_ddr",
		.flags = IORESOURCE_MEM,
	},
	{
		.start = FSM9900_SCLTE_GEN_DBG_PHYS,
		.end   = FSM9900_SCLTE_GEN_DBG_PHYS + SZ_32M - 1,
		.name  = "sclte_gen_dbg",
		.flags = IORESOURCE_MEM,
	},
};

static struct platform_device fsm9900_uio2_device = {
	.name = "uio_pdrv",
	.id = 2,
	.dev = {
		.platform_data = &fsm9900_uio_info[2]
	},
	.num_resources = ARRAY_SIZE(fsm9900_uio2_resources),
	.resource = fsm9900_uio2_resources,
};

static struct platform_device *fsm9900_uio_devices[] = {
	&fsm9900_uio0_device,
	&fsm9900_uio1_device,
};

static const char mac_addr_prop_name[] = "mac-address";
static const char shm_ul_bufs_prop_name[] = "ul-bufs";
static const char shm_dl_bufs_prop_name[] = "dl-bufs";

void __init fsm9900_reserve(void)
{
}

static struct mem_map_seg *find_mem_map_seg(struct mem_map_seg *tbl, u32 tag)
{
	if (tbl == NULL)
		return NULL;

	while (tbl->tag != MEM_TAG_NONE) {
		if (tbl->tag == tag)
			return tbl;

		tbl++;
	}

	return NULL;
}

static bool is_fsm9900(void)
{
	void __iomem *fuse_reg;
	u32 fsm_id;

	fuse_reg = ioremap(FSM9900_FSM_ID_FUSE_PHYS,
			   FSM9900_FSM_ID_FUSE_SIZE);
	if (!fuse_reg) {
		pr_err("failed to ioremap fuse to read fsm id");
		return false;
	}

	fsm_id = ioread16(fuse_reg) & FSM_ID_MASK;
	iounmap(fuse_reg);

	return (fsm_id == FSM_ID_FSM9900) ? true : false;
}

/*
 * Used to satisfy dependencies for devices that need to be
 * run early or in a particular order. Most likely your device doesn't fall
 * into this category, and thus the driver should not be added here. The
 * EPROBE_DEFER can satisfy most dependency problems.
 */
void __init fsm9900_add_drivers(void)
{
	msm_smd_init();
	if (of_board_is_rumi())
		msm_clock_init(&fsm9900_dummy_clock_init_data);
	else
		msm_clock_init(&fsm9900_clock_init_data);
	platform_add_devices(fsm9900_uio_devices,
			     ARRAY_SIZE(fsm9900_uio_devices));
	if (is_fsm9900())
		platform_device_register(&fsm9900_uio2_device);
}

static void __init fsm9900_map_io(void)
{
	msm_map_fsm9900_io();
}

static int emac_dt_update(int cell, phys_addr_t addr, unsigned long size)
{
	/*
	 * Use an array for the fuse. Corrected fuse data may be located
	 * at a different offsets.
	 */
	static int offset[ETH_ALEN] = { 0, 1, 2, 3, 4, 5};
	void __iomem *fuse_reg;
	struct device_node *np = NULL;
	struct property *pmac = NULL;
	struct property *pp = NULL;
	u8 buf[ETH_ALEN];
	int n;
	int retval = 0;

	fuse_reg = ioremap(addr, size);
	if (!fuse_reg) {
		pr_err("failed to ioremap efuse to read mac address");
		return -ENOMEM;
	}

	for (n = 0; n < ETH_ALEN; n++)
		buf[n] = ioread8(fuse_reg + offset[n]);

	iounmap(fuse_reg);

	if (!is_valid_ether_addr(buf)) {
		pr_err("invalid MAC address in efuse\n");
		return -ENODATA;
	}

	pmac = kzalloc(sizeof(*pmac) + ETH_ALEN, GFP_KERNEL);
	if (!pmac) {
		pr_err("failed to alloc memory for mac address\n");
		return -ENOMEM;
	}

	pmac->value = pmac + 1;
	pmac->length = ETH_ALEN;
	pmac->name = (char *)mac_addr_prop_name;
	memcpy(pmac->value, buf, ETH_ALEN);

	for_each_compatible_node(np, NULL, "qcom,emac") {
		if (of_property_read_u32(np, "cell-index", &n))
			continue;
		if (n == cell)
			break;
	}

	if (!np) {
		pr_err("failed to find dt node for emac%d", cell);
		retval = -ENODEV;
		goto out;
	}

	pp = of_find_property(np, pmac->name, NULL);
	if (pp)
		of_update_property(np, pmac);
	else
		of_add_property(np, pmac);

out:
	of_node_put(np);

	if (retval && pmac)
		kfree(pmac);

	return retval;
}

int __init fsm9900_emac_dt_update(void)
{
	emac_dt_update(0, FSM9900_MAC0_FUSE_PHYS, FSM9900_MAC_FUSE_SIZE);
	emac_dt_update(1, FSM9900_MAC1_FUSE_PHYS, FSM9900_MAC_FUSE_SIZE);
	return 0;
}

static int add_danipc_property(struct device_node *np,
			       struct mem_map_seg *region,
			       const char *name)
{
	u32 buf[2];
	struct property *pbuf = NULL;

	if (!(region->rd_vmid & VMID_AP_BIT) ||
	    !(region->wr_vmid & VMID_AP_BIT)) {
		pr_err("do not have permissions for %s\n", name);
		return -EPERM;
	}

	buf[0] = region->phy_addr;
	buf[1] = region->sz;

	pbuf = kzalloc(sizeof(*pbuf) + sizeof(buf), GFP_KERNEL);

	if (pbuf == NULL)
		return -ENOMEM;

	pbuf->value = pbuf + 1;
	pbuf->length = sizeof(buf);
	pbuf->name = (char *)name;
	memcpy(pbuf->value, buf, sizeof(buf));

	of_add_property(np, pbuf);

	return 0;
}

static int __init fsm9900_ipc_buf_region_update(void)
{
	struct device_node *np = NULL;
	int ret = -ENODEV;
	void *mem_map_region = NULL;
	struct mem_map_seg __iomem *mem_map_table;
	struct mem_map_seg *ul_region;
	struct mem_map_seg *dl_region;

	/* Once node "qcom,danipc" is found in DT, break out of loop */
	for_each_compatible_node(np, NULL, "qcom,danipc") {
		break;
	}

	if (np == NULL) {
		pr_err("failed to find dt node for qcom,danipc\n");
		return -ENODEV;
	}

	mem_map_region = ioremap(FSM9900_MEM_MAP_PHYS, FSM9900_MEM_MAP_SIZE);

	if (mem_map_region == NULL) {
		pr_err("failed to map memory map");
		ret = -ENOMEM;
		goto out;
	}

	/* Version number comes first */
	mem_map_table = mem_map_region + sizeof(u32);

	/* Find the UL and DL regions and store them in the DT */
	ul_region = find_mem_map_seg(mem_map_table, MEM_TAG_SHARED_LTEL2_UL);
	dl_region = find_mem_map_seg(mem_map_table, MEM_TAG_SHARED_LTEL2_DL);

	if (dl_region == NULL || ul_region == NULL) {
		pr_err("could not find regions: %p, %p", ul_region, dl_region);
		ret = -ENODEV;
		goto out;
	}

	ret = add_danipc_property(np, dl_region, shm_dl_bufs_prop_name);

	if (ret != 0)
		goto out;

	ret = add_danipc_property(np, ul_region, shm_ul_bufs_prop_name);

	if (ret != 0)
		goto out;

out:
	of_node_put(np);

	if (mem_map_region)
		iounmap(mem_map_region);

	return ret;
}

void __init fsm9900_init(void)
{
	struct of_dev_auxdata *adata = fsm9900_auxdata_lookup;

	/*
	 * populate devices from DT first so smem probe will get called as part
	 * of msm_smem_init.  socinfo_init needs smem support so call
	 * msm_smem_init before it.
	 */
	board_dt_populate(adata);

	msm_smem_init();

	if (socinfo_init() < 0)
		pr_err("%s: socinfo_init() failed\n", __func__);

	fsm9900_init_gpiomux();
	fsm9900_emac_dt_update();
	fsm9900_ipc_buf_region_update();

	fsm9900_add_drivers();
}

static const char *fsm9900_dt_match[] __initconst = {
	"qcom,fsm9900",
	NULL
};

DT_MACHINE_START(FSM9900_DT,
		"Qualcomm Technologies, Inc. FSM 9900 (Flattened Device Tree)")
	.map_io			= fsm9900_map_io,
	.init_machine		= fsm9900_init,
	.dt_compat		= fsm9900_dt_match,
	.reserve		= fsm9900_reserve,
	.smp			= &msm8974_smp_ops,
MACHINE_END
