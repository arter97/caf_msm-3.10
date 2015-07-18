/* Copyright (c) 2013-2015, The Linux Foundation. All rights reserved.
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

/* Qualcomm Technologies Inc EMAC SGMII Controller driver.
 */

#include "emac.h"
#include "emac_hw.h"

/* LINK */
static int emac_sgmii_v1_init_link(struct emac_hw *hw, u32 speed,
				   bool autoneg, bool fc)
{
	u32 val;
	u32 speed_cfg = 0;

	val = emac_reg_r32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_AUTONEG_CFG2);

	if (autoneg) {
		val &= ~(FORCE_AN_RX_CFG | FORCE_AN_TX_CFG);
		val |= AN_ENABLE;
		emac_reg_w32(hw, EMAC_SGMII_PHY,
			     EMAC_SGMII_PHY_AUTONEG_CFG2, val);
	} else {
		switch (speed) {
		case EMAC_LINK_SPEED_10_HALF:
			speed_cfg = SPDMODE_10;
			break;
		case EMAC_LINK_SPEED_10_FULL:
			speed_cfg = SPDMODE_10 | DUPLEX_MODE;
			break;
		case EMAC_LINK_SPEED_100_HALF:
			speed_cfg = SPDMODE_100;
			break;
		case EMAC_LINK_SPEED_100_FULL:
			speed_cfg = SPDMODE_100 | DUPLEX_MODE;
			break;
		case EMAC_LINK_SPEED_1GB_FULL:
			speed_cfg = SPDMODE_1000 | DUPLEX_MODE;
			break;
		default:
			return -EINVAL;
		}
		val &= ~AN_ENABLE;
		emac_reg_w32(hw, EMAC_SGMII_PHY,
			     EMAC_SGMII_PHY_SPEED_CFG1, speed_cfg);
		emac_reg_w32(hw, EMAC_SGMII_PHY,
			     EMAC_SGMII_PHY_AUTONEG_CFG2, val);
	}
	/* Ensure Auto-Neg setting are written to HW before leaving */
	wmb();

	return 0;
}

int emac_hw_clear_sgmii_intr_status(struct emac_hw *hw, u32 irq_bits)
{
	u32 status;
	int i;

	emac_reg_w32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_INTERRUPT_CLEAR,
		     irq_bits);
	emac_reg_w32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_IRQ_CMD,
		     IRQ_GLOBAL_CLEAR);
	/* Ensure interrupt clear command is written to HW */
	wmb();

	/* After set the IRQ_GLOBAL_CLEAR bit, the status clearing must
	 * be confirmed before clearing the bits in other registers.
	 * It takes a few cycles for hw to clear the interrupt status.
	 */
	for (i = 0; i < SGMII_PHY_IRQ_CLR_WAIT_TIME; i++) {
		udelay(1);
		status = emac_reg_r32(hw, EMAC_SGMII_PHY,
				      EMAC_SGMII_PHY_INTERRUPT_STATUS);
		if (!(status & irq_bits))
			break;
	}
	if (status & irq_bits) {
		emac_err(emac_hw_get_adap(hw),
			 "failed to clear SGMII irq: status 0x%x bits 0x%x\n",
			 status, irq_bits);
		return -EIO;
	}

	/* Finalize clearing procedure */
	emac_reg_w32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_IRQ_CMD, 0);
	emac_reg_w32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_INTERRUPT_CLEAR, 0);
	/* Ensure that clearing procedure finalization is written to HW */
	wmb();

	return 0;
}

int emac_sgmii_v1_init(struct emac_adapter *adpt)
{
	int i;
	struct emac_hw *hw = &adpt->hw;

	emac_sgmii_v1_init_link(hw, hw->autoneg_advertised,
				hw->autoneg, !hw->disable_fc_autoneg);
	/* Physical Coding Sublayer (PCS) programming */
	emac_reg_w32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_CDR_CTRL0,
		     SGMII_CDR_MAX_CNT);
	emac_reg_w32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_POW_DWN_CTRL0, PWRDN_B);
	emac_reg_w32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_CMN_PWR_CTRL,
		     BIAS_EN | SYSCLK_EN | CLKBUF_L_EN |
		     PLL_TXCLK_EN | PLL_RXCLK_EN);
	emac_reg_w32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_TX_PWR_CTRL,
		     L0_TX_EN | L0_CLKBUF_EN | L0_TRAN_BIAS_EN);
	emac_reg_w32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_RX_PWR_CTRL,
		     L0_RX_SIGDET_EN |
		     (1 << L0_RX_TERM_MODE_SHFT) | L0_RX_I_EN);
	emac_reg_w32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_CMN_PWR_CTRL,
		     BIAS_EN | PLL_EN | SYSCLK_EN | CLKBUF_L_EN |
		     PLL_TXCLK_EN | PLL_RXCLK_EN);
	emac_reg_w32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_LANE_CTRL1,
		     L0_RX_EQ_EN | L0_RESET_TSYNC_EN | L0_DRV_LVL_BMSK);
	/* Ensure Rx/Tx lanes power configuration is written to hw before
	 * configuring the SerDes engine's clocks
	 */
	wmb();

	/* sysclk/refclk setting */
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_SYSCLK_EN_SEL,
		     SYSCLK_SEL_CMOS);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_SYS_CLK_CTRL,
		     SYSCLK_CM | SYSCLK_AC_COUPLE);

	/* PLL setting */
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_PLL_IP_SETI,
		     QSERDES_PLL_IPSETI);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_PLL_CP_SETI,
		     QSERDES_PLL_CP_SETI);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_PLL_IP_SETP,
		     QSERDES_PLL_IP_SETP);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_PLL_CP_SETP,
		     QSERDES_PLL_CP_SETP);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_PLL_CRCTRL,
		     QSERDES_PLL_CRCTRL);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_PLL_CNTRL,
		     OCP_EN | PLL_DIV_FFEN | PLL_DIV_ORD);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_DEC_START1,
		     DEC_START1_MUX | QSERDES_PLL_DEC);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_DEC_START2,
		     DEC_START2_MUX | DEC_START2);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_DIV_FRAC_START1,
		     DIV_FRAC_START1_MUX | QSERDES_PLL_DIV_FRAC_START1);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_DIV_FRAC_START2,
		     DIV_FRAC_START2_MUX | QSERDES_PLL_DIV_FRAC_START2);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_DIV_FRAC_START3,
		     DIV_FRAC_START3_MUX | QSERDES_PLL_DIV_FRAC_START3);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_PLLLOCK_CMP1,
		     QSERDES_PLL_LOCK_CMP1);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_PLLLOCK_CMP2,
		     QSERDES_PLL_LOCK_CMP2);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_PLLLOCK_CMP3,
		     QSERDES_PLL_LOCK_CMP3);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_PLLLOCK_CMP_EN,
		     PLLLOCK_CMP_EN);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_RESETSM_CNTRL,
		     FRQ_TUNE_MODE);

	/* CDR setting */
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_RX_CDR_CONTROL,
		     SECONDORDERENABLE |
		     (QSERDES_RX_CDR_CTRL1_THRESH << FIRSTORDER_THRESH_SHFT) |
		     (QSERDES_RX_CDR_CTRL1_GAIN << SECONDORDERGAIN_SHFT));
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_RX_CDR_CONTROL2,
		     SECONDORDERENABLE |
		     (QSERDES_RX_CDR_CTRL2_THRESH << FIRSTORDER_THRESH_SHFT) |
		     (QSERDES_RX_CDR_CTRL2_GAIN << SECONDORDERGAIN_SHFT));

	/* TX/RX setting */
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_TX_BIST_MODE_LANENO,
		     QSERDES_TX_BIST_MODE_LANENO);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_TX_TX_DRV_LVL,
		     TX_DRV_LVL_MUX | (QSERDES_TX_DRV_LVL << TX_DRV_LVL_SHFT));
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_TX_TRAN_DRVR_EMP_EN,
		     EMP_EN_MUX | EMP_EN);
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_TX_TX_EMP_POST1_LVL,
		     TX_EMP_POST1_LVL_MUX |
		     (QSERDES_TX_EMP_POST1_LVL << TX_EMP_POST1_LVL_SHFT));
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_RX_RX_EQ_GAIN12,
		     (QSERDES_RX_EQ_GAIN2 << RX_EQ_GAIN2_SHFT) |
		     (QSERDES_RX_EQ_GAIN1 << RX_EQ_GAIN1_SHFT));
	emac_reg_w32(hw, EMAC_QSERDES, EMAC_QSERDES_TX_LANE_MODE,
		     QSERDES_TX_LANE_MODE);
	/* Ensure SerDes engine configuration is written to hw before powering
	 * it up
	 */
	wmb();

	emac_reg_w32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_SERDES_START,
		     SERDES_START);

	/* Ensure Rx/Tx SerDes engine power-up command is written to HW */
	wmb();

	for (i = 0; i < SERDES_START_WAIT_TIMES; i++) {
		if (emac_reg_r32(hw, EMAC_QSERDES, EMAC_QSERDES_COM_RESET_SM) &
		    QSERDES_READY)
			break;
		usleep_range(100, 200);
	}

	if (i == SERDES_START_WAIT_TIMES) {
		emac_err(adpt, "serdes failed to start\n");
		return -EIO;
	}
	/* Mask out all the SGMII Interrupt */
	emac_reg_w32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_INTERRUPT_MASK, 0);
	/* Ensure SGMII interrupts are masked out before clearing them */
	wmb();

	emac_hw_clear_sgmii_intr_status(hw, SGMII_PHY_INTERRUPT_ERR);

	return 0;
}

int emac_sgmii_v1_reset_impl(struct emac_adapter *adpt)
{
	struct emac_hw *hw = &adpt->hw;

	emac_reg_update32(hw, EMAC_CSR, EMAC_EMAC_WRAPPER_CSR2, PHY_RESET,
			  PHY_RESET);
	/* Ensure phy-reset command is written to HW before the release cmd */
	wmb();
	msleep(50);
	emac_reg_update32(hw, EMAC_CSR, EMAC_EMAC_WRAPPER_CSR2, PHY_RESET, 0);
	/* Ensure phy-reset release command is written to HW before initializing
	 * SGMII
	 */
	wmb();
	msleep(50);
	return emac_sgmii_v1_init(adpt);
}

void emac_sgmii_v1_reset(struct emac_adapter *adpt)
{
	emac_clk_set_rate(adpt, EMAC_CLK_125M, EMC_CLK_RATE_19_2MHZ);
	emac_sgmii_v1_reset_impl(adpt);
	emac_clk_set_rate(adpt, EMAC_CLK_125M, EMC_CLK_RATE_125MHZ);
}

int emac_sgmii_v1_init_ephy_nop(struct emac_hw *hw)
{
	return 0;
}

void emac_sgmii_v1_irq_enable(struct emac_adapter *adpt)
{
	emac_reg_w32(&adpt->hw, EMAC_SGMII_PHY,
		     emac_irq_cmn_tbl[EMAC_SGMII_PHY_IRQ].mask_reg,
		     adpt->irq[EMAC_SGMII_PHY_IRQ].mask);
}

void emac_sgmii_v1_irq_disable(struct emac_adapter *adpt)
{
	emac_reg_w32(&adpt->hw, EMAC_SGMII_PHY,
		     emac_irq_cmn_tbl[EMAC_SGMII_PHY_IRQ].mask_reg, 0);
}

int emac_sgmii_v1_link_setup_no_ephy(struct emac_adapter *adpt, u32 speed,
				     bool autoneg)
{
	adpt->hw.autoneg = autoneg;
	adpt->hw.autoneg_advertised = speed;
	/* The AN_ENABLE and SPEED_CFG can't change on fly. The SGMII_PHY has
	 * to be re-initialized.
	 */
	return emac_sgmii_v1_reset_impl(adpt);
}

int emac_sgmii_v1_autoneg_check(struct emac_hw *hw, u32 *speed, bool *link_up)
{
	u32 status;

	status = emac_reg_r32(hw, EMAC_SGMII_PHY,
			      EMAC_SGMII_PHY_AUTONEG1_STATUS) & 0xff;
	status <<= 8;
	status |= emac_reg_r32(hw, EMAC_SGMII_PHY,
			       EMAC_SGMII_PHY_AUTONEG0_STATUS) & 0xff;

	if (!(status & TXCFG_LINK)) {
		*link_up = false;
		*speed = EMAC_LINK_SPEED_UNKNOWN;
		return 0;
	}

	*link_up = true;

	switch (status & TXCFG_MODE_BMSK) {
	case TXCFG_1000_FULL:
		*speed = EMAC_LINK_SPEED_1GB_FULL;
		break;
	case TXCFG_100_FULL:
		*speed = EMAC_LINK_SPEED_100_FULL;
		break;
	case TXCFG_100_HALF:
		*speed = EMAC_LINK_SPEED_100_HALF;
		break;
	case TXCFG_10_FULL:
		*speed = EMAC_LINK_SPEED_10_FULL;
		break;
	case TXCFG_10_HALF:
		*speed = EMAC_LINK_SPEED_10_HALF;
		break;
	default:
		*speed = EMAC_LINK_SPEED_UNKNOWN;
		break;
	}
	return 0;
}

int emac_sgmii_v1_link_check_no_ephy(struct emac_adapter *adpt, u32 *speed,
				     bool *link_up)
{
	u32 val;
	struct emac_hw *hw = &adpt->hw;

	val = emac_reg_r32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_AUTONEG_CFG2);
	if (val & AN_ENABLE)
		return emac_sgmii_v1_autoneg_check(hw, speed, link_up);

	val = emac_reg_r32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_SPEED_CFG1);
	val &= DUPLEX_MODE | SPDMODE_BMSK;
	switch (val) {
	case DUPLEX_MODE | SPDMODE_1000:
		*speed = EMAC_LINK_SPEED_1GB_FULL;
		break;
	case DUPLEX_MODE | SPDMODE_100:
		*speed = EMAC_LINK_SPEED_100_FULL;
		break;
	case SPDMODE_100:
		*speed = EMAC_LINK_SPEED_100_HALF;
		break;
	case DUPLEX_MODE | SPDMODE_10:
		*speed = EMAC_LINK_SPEED_10_FULL;
		break;
	case SPDMODE_10:
		*speed = EMAC_LINK_SPEED_10_HALF;
		break;
	default:
		*speed = EMAC_LINK_SPEED_UNKNOWN;
		break;
	}
	*link_up = true;
	return 0;
}

irqreturn_t emac_sgmii_v1_isr(int _irq, void *data)
{
	struct emac_irq_per_dev *irq = data;
	struct emac_adapter *adpt = emac_irq_get_adpt(data);
	struct emac_hw *hw = &adpt->hw;
	u32 status;

	emac_dbg(adpt, intr, "receive sgmii interrupt\n");

	do {
		status = emac_reg_r32(hw, EMAC_SGMII_PHY,
				      EMAC_SGMII_PHY_INTERRUPT_STATUS);
		status &= irq->mask;
		if (!status)
			break;

		if (status & SGMII_PHY_INTERRUPT_ERR) {
			SET_FLAG(adpt, ADPT_TASK_CHK_SGMII_REQ);
			if (!TEST_FLAG(adpt, ADPT_STATE_DOWN))
				emac_task_schedule(adpt);
		}

		if (status & SGMII_ISR_AN_MASK)
			emac_check_lsc(adpt);

		if (emac_hw_clear_sgmii_intr_status(hw, status) != 0) {
			emac_warn(adpt, intr,
				  "failed to clear sgmii intr, status=0x%x\n",
				  status);
			/* reset */
			SET_FLAG(adpt, ADPT_TASK_REINIT_REQ);
			emac_task_schedule(adpt);
			break;
		}
	} while (1);

	return IRQ_HANDLED;
}

void emac_sgmii_v1_tx_clk_set_rate_nop(struct emac_adapter *adpt)
{
}

/* Check SGMII for error */
void emac_sgmii_v1_periodic_check(struct emac_adapter *adpt)
{
	struct emac_hw *hw = &adpt->hw;

	if (!TEST_FLAG(adpt, ADPT_TASK_CHK_SGMII_REQ))
		return;
	CLR_FLAG(adpt, ADPT_TASK_CHK_SGMII_REQ);

	/* ensure that no reset is in progress while link task is running */
	while (TEST_N_SET_FLAG(adpt, ADPT_STATE_RESETTING))
		msleep(20); /* Reset might take few 10s of ms */

	if (TEST_FLAG(adpt, ADPT_STATE_DOWN))
		goto sgmii_task_done;

	if (emac_reg_r32(hw, EMAC_SGMII_PHY, EMAC_SGMII_PHY_RX_CHK_STATUS)
	    & 0x40)
		goto sgmii_task_done;

	emac_err(adpt, "SGMII CDR not locked\n");

sgmii_task_done:
	CLR_FLAG(adpt, ADPT_STATE_RESETTING);
}

struct emac_phy_ops emac_sgmii_v1_ops = {
	.init			= emac_sgmii_v1_init,
	.reset			= emac_sgmii_v1_reset,
	.init_ephy		= emac_sgmii_v1_init_ephy_nop,
	.irq_enable		= emac_sgmii_v1_irq_enable,
	.irq_disable		= emac_sgmii_v1_irq_disable,
	.link_setup_no_ephy	= emac_sgmii_v1_link_setup_no_ephy,
	.link_check_no_ephy	= emac_sgmii_v1_link_check_no_ephy,
	.tx_clk_set_rate	= emac_sgmii_v1_tx_clk_set_rate_nop,
	.periodic_task		= emac_sgmii_v1_periodic_check,
};
