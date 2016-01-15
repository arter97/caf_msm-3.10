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
 *
 */

#include <linux/gpio.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <mach/board.h>
#include <mach/gpiomux.h>

/*
 * The drive strength setting for MDIO pins
 * is different from the others
 */
#define MDIO_DRV_8MA	GPIOMUX_DRV_16MA

#ifndef CONFIG_FSM9900_GSM_NL
static struct gpiomux_setting dan_spi_func4_config = {
	.func = GPIOMUX_FUNC_4,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct gpiomux_setting dan_spi_func1_config = {
	.func = GPIOMUX_FUNC_1,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct msm_gpiomux_config fsm_dan_spi_configs[] __initdata = {
	{
		.gpio      = 12,       /* BLSP DAN0 SPI_MOSI */
		.settings = {
			[GPIOMUX_SUSPENDED] = &dan_spi_func4_config,
		},
	},
	{
		.gpio      = 13,       /* BLSP DAN0 SPI_MISO */
		.settings = {
			[GPIOMUX_SUSPENDED] = &dan_spi_func4_config,
		},
	},
	{
		.gpio      = 14,       /* BLSP DAN0 SPI_CS */
		.settings = {
			[GPIOMUX_SUSPENDED] = &dan_spi_func4_config,
		},
	},
	{
		.gpio      = 15,       /* BLSP DAN0 SPI_CLK */
		.settings = {
			[GPIOMUX_SUSPENDED] = &dan_spi_func4_config,
		},
	},
	{
		.gpio      = 16,       /* BLSP DAN1 SPI_MOSI */
		.settings = {
			[GPIOMUX_SUSPENDED] = &dan_spi_func4_config,
		},
	},
	{
		.gpio      = 17,       /* BLSP DAN1 SPI_MISO */
		.settings = {
			[GPIOMUX_SUSPENDED] = &dan_spi_func4_config,
		},
	},
	{
		.gpio      = 18,       /* BLSP DAN1 SPI_CS */
		.settings = {
			[GPIOMUX_SUSPENDED] = &dan_spi_func4_config,
		},
	},
	{
		.gpio      = 19,       /* BLSP DAN1 SPI_CLK */
		.settings = {
			[GPIOMUX_SUSPENDED] = &dan_spi_func4_config,
		},
	},
	{
		.gpio      = 81,       /* BLSP DAN1 SPI_CS0 */
		.settings = {
			[GPIOMUX_SUSPENDED] = &dan_spi_func1_config,
		},
	},
	{
		.gpio      = 82,       /* BLSP DAN1 SPI_CS1 */
		.settings = {
			[GPIOMUX_SUSPENDED] = &dan_spi_func1_config,
		},
	},
};
#endif

static struct gpiomux_setting pcie_config = {
	.func = GPIOMUX_FUNC_4,
	.drv = GPIOMUX_DRV_8MA,
	.pull = GPIOMUX_PULL_UP,
};

static struct gpiomux_setting pcie_perst_config = {
	.func = GPIOMUX_FUNC_GPIO,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_NONE,
	.dir = GPIO_CFG_OUTPUT,
};

static struct msm_gpiomux_config fsm_pcie_configs[] __initdata = {
	{
		.gpio      = 28,       /* BLSP PCIE1_CLK */
		.settings = {
			[GPIOMUX_SUSPENDED] = &pcie_config,
		},
	},
	{
		.gpio      = 32,       /* BLSP PCIE0_CLK */
		.settings = {
			[GPIOMUX_SUSPENDED] = &pcie_config,
		},
	},
	{
		.gpio      = 29,       /* PCIE1_PERST */
		.settings = {
			[GPIOMUX_SUSPENDED] = &pcie_perst_config,
		},
	},
	{
		.gpio      = 33,       /* PCIE0_PERST */
		.settings = {
			[GPIOMUX_SUSPENDED] = &pcie_perst_config,
		},
	},
};

static struct gpiomux_setting pps_out_config = {
	.func = GPIOMUX_FUNC_1,
	.drv = GPIOMUX_DRV_4MA,
	.pull = GPIOMUX_PULL_NONE,
};

static struct gpiomux_setting pps_in_config = {
	.func = GPIOMUX_FUNC_1,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
};

static struct gpiomux_setting gps_clk_in_config = {
	.func = GPIOMUX_FUNC_1,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
};

static struct gpiomux_setting gps_nav_tlmm_blank_config = {
	.func = GPIOMUX_FUNC_2,
	.drv = GPIOMUX_DRV_2MA,
	.pull = GPIOMUX_PULL_DOWN,
};
static struct msm_gpiomux_config fsm_gps_configs[] __initdata = {
	{
		.gpio      = 40,       /* GPS_PPS_OUT */
		.settings = {
			[GPIOMUX_SUSPENDED] = &pps_out_config,
		},
	},
	{
		.gpio      = 41,       /* GPS_PPS_IN */
		.settings = {
			[GPIOMUX_SUSPENDED] = &pps_in_config,
		},
	},
	{
		.gpio      = 43,       /* GPS_CLK_IN */
		.settings = {
			[GPIOMUX_SUSPENDED] = &gps_clk_in_config,
		},
	},
	{
		.gpio      = 120,      /* GPS_NAV_TLMM_BLANK */
		.settings = {
			[GPIOMUX_SUSPENDED] = &gps_nav_tlmm_blank_config,
		},
	},
};

void __init fsm9900_init_gpiomux(void)
{
	int rc;

	rc = msm_gpiomux_init_dt();
	if (rc) {
		pr_err("%s failed %d\n", __func__, rc);
		return;
	}

#ifndef CONFIG_FSM9900_GSM_NL
	msm_gpiomux_install(fsm_dan_spi_configs,
			    ARRAY_SIZE(fsm_dan_spi_configs));
#endif
	msm_gpiomux_install(fsm_pcie_configs, ARRAY_SIZE(fsm_pcie_configs));
	msm_gpiomux_install(fsm_gps_configs, ARRAY_SIZE(fsm_gps_configs));
}
