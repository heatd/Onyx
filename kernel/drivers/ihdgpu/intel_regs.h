/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _INTEL_REGS_H
#define _INTEL_REGS_H

/* Haswell PWR_WELL_CTL */
#define PWR_WELL_CTL_PW_REQ		(1U << 31)
#define PWR_WELL_CTL_PW_STATE		(1U << 30)

#define PWR_WELL_CTL1			0x45404
#define PWR_WELL_CTL2			0x45404

/* Skylake PWR_WELL_CTL */
#define PWR_WELL_CTL_MISC_IO_STATE	(1 << 0)
#define PWR_WELL_CTL_MISC_IO_PWREQ	(1 << 1)
#define PWR_WELL_CTL_DDIA_E_STATE	(1 << 2)
#define PWR_WELL_CTL_DDIA_E_PWREQ	(1 << 3)
#define PWR_WELL_CTL_DDIB_STATE		(1 << 4)
#define PWR_WELL_CTL_DDIB_PWREQ		(1 << 5)
#define PWR_WELL_CTL_DDIC_STATE		(1 << 6)
#define PWR_WELL_CTL_DDIC_PWREQ		(1 << 7)
#define PWR_WELL_CTL_DDID_STATE		(1 << 8)
#define PWR_WELL_CTL_DDID_PWREQ		(1 << 9)
#define PWR_WELL_CTL_PW1_STATE		(1 << 28)
#define PWR_WELL_CTL_PW1_REQ		(1 << 29)
#define PWR_WELL_CTL_PW2_STATE		(1 << 30)
#define PWR_WELL_CTL_PW2_REQ		(1U << 31)

#define FUSE_STATUS			0x42000
#define FUSE_STATUS_DOWNLOAD_STATUS	(1U << 31)
#define FUSE_STATUS_PG0_DISTRIB_STATUS	(1 << 27)
#define FUSE_STATUS_PG1_DISTRIB_STATUS	(1 << 26)
#define FUSE_STATUS_PG2_DISTRIB_STATUS	(1 << 25)

#define NDE_RSTWRN_OPT			0x46408
#define NDE_RST_PCH_HANDSHAKE_ENABLE	(1 << 4)

#define GPIO_PCH_BASE	0xc0000

#define GMBUS_BASE 0x5100

#define __GMBUS_CALC(ndx)	(GMBUS_BASE + ndx * 4)

/* GMBUS0 - Clock/Port select */
#define GMBUS0		__GMBUS_CALC(0)
/* GMBUS1 - Command/Status */
#define GMBUS1		__GMBUS_CALC(1)
/* GMBUS2 - Status */
#define GMBUS2		__GMBUS_CALC(2)
/* GMBUS3 - Data buffer */
#define GMBUS3		__GMBUS_CALC(3)
/* GMBUS4 - Int mask */
#define GMBUS4		__GMBUS_CALC(4)
/* GMBUS5 - 2 Byte index */
#define GMBUS5		__GMBUS_CALC(5)

#define GMBUS0_RATE_SELECT_50KHZ	(1 << 8)
#define GMBUS0_RATE_SELECT_100KHZ	(0)
#define GMBUS0_BYTE_COUNT_OVERRIDE	(1 << 6)

#define GMBUS_PIN_DISABLED	0
#define GMBUS_PIN_SSC		1
#define GMBUS_PIN_VGADDC	2
#define GMBUS_PIN_PANEL		3
#define GMBUS_PIN_DPC		4 /* HDMIC */
#define GMBUS_PIN_DPB		5 /* HDMIB */
#define GMBUS_PIN_DPD		6 /* HDMID */

#define GMBUS1_SW_CLR_INT		(1U << 31)
#define GMBUS1_ASSERT_SWRDY		(1U << 30)
#define GMBUS1_ENABLE_TIMEOUT		(1U << 29)

#define GMBUS1_BUS_CYCLE_NO_CYCLE		(0)
#define GMBUS1_BUS_CYCLE_NO_IDX_NO_STOP_WAIT	(1)
#define GMBUS1_BUS_CYCLE_IDX_NO_STOP_WAIT	(3)
#define GMBUS1_BUS_CYCLE_GEN_STOP		(4)
#define GMBUS1_BUS_CYCLE_NO_IDX_STOP		(5)
#define GMBUS1_BUS_CYCLE_IDX_STOP		(7)

#define GMBUS1_BUS_CYCLE_SELECT(x)	(x << 25)

#define GMBUS1_TOTAL_BYTE_COUNT(x)		(x << 16)
#define GMBUS1_SLAVE_REGISTER_IDX(x)		(x << 8)
#define GMBUS1_SLAVE_ADDR_AND_DIR(x)		(x)

#define GMBUS2_INUSE			(1 << 15)
#define GMBUS2_HW_WAIT_PHASE		(1 << 14)
#define GMBUS2_SLAVE_STALL_TIMEOUT	(1 << 13)
#define GMBUS2_GMBUS_INT_STATUS		(1 << 12)
#define GMBUS2_HW_RDY			(1 << 11)
#define GMBUS2_NAK_INDICATOR		(1 << 10)
#define GMBUS2_GMBUS_ACTIVE		(1 << 9)
#define GMBUS2_CURR_BYTE_COUNT(x)	(x & 0xff)

#define GMBUS4_HW_RDY		(1 << 0)
#define GMBUS4_WAIT_INT		(1 << 1)
#define GMBUS4_IDLE_INT		(1 << 2)
#define GMBUS4_NAK_INT		(1 << 3)
#define GMBUS4_SLAVE_STALL_INT	(1 << 4)

#define GMBUS5_2BYTE_IDX_EN		(1U << 31)
#define GMBUS5_2BYTE_SLAVE_IDX(x)	(x & 0xff)


#define DDI_AUX_CTL_BASE		0x64010
#define DDI_AUX_DATA_BASE		0x64014
#define DDI_AUX_OFFSET			0x000100

#define DDI_GET_REG(base, port)		(base + DDI_AUX_OFFSET * port) 


#define DDI_AUX_CTL_SEND_BUSY		(1U << 31)
#define DDI_AUX_CTL_DONE		(1 << 30)
#define DDI_AUX_CTL_IRQ_ON_DONE		(1 << 29)
#define DDI_AUX_CTL_TIMEOUT_ERROR	(1 << 28)
#define DDI_AUX_CTL_TIMEOUT_600US	(1 << 26)
#define DDI_AUX_CTL_TIMEOUT_800US	(1 << 27)
#define DDI_AUX_CTL_TIMEOUT_1600US	(1 << 26 | 1 << 27)
#define DDI_AUX_CTL_RECIEVE_ERROR	(1 << 25)

#define DDI_AUX_CTL_MESSAGE_SIZE(size)	(size << 20)

#define DP_AUX_I2C_WRITE		0x0
#define DP_AUX_I2C_READ			0x1

#define LCPLL_CTL			0x130040

#define LCPLL_CTL_HSW_PLL_DISABLE		(1U << 31)
#define LCPLL_CTL_HSW_PLL_LOCK			(1 << 30)
#define LCPLL_CTL_HSW_NON_SSC			(0 << 28)
#define LCPLL_CTL_HSW_CDCLK_450MHZ		(00 << 26)
#define LCPLL_CTL_HSW_CDCLK_ALTERNATE		(01 << 26)
#define LCPLL_CTL_HSW_CDCLK_DISABLE		(1 << 25)
#define LCPLL_CTL_HSW_ROOT_CD2X_CLK_DISABLE	(1 << 24)
#define LCPLL_CTL_HSW_CD2X_CLK_DISABLE		(1 << 23)
#define LCPLL_CTL_HSW_DISPLAY_PWR_DWN_ALLOW	(1 << 22)
#define LCPLL_CTL_HSW_CD_SOURCE_SELECT_FCLK	(1 << 21)
#define LCPLL_CTL_HSW_CD_SOURCE_SWITCHING	(1 << 20)
#define LCPLL_CTL_HSW_CD_SOURCE_FCLK		(1 << 19)
#define LCPLL_CTL_HSW_WRITE_ONCE_DEV3_SID	(1 << 5)
#define LCPLL_CTL_HSW_WRITE_ONCE_DEV3_SVID	(1 << 4)
#define LCPLL_CTL_HSW_WRITE_ONCE_DEV3_NEXT	(1 << 3)
#define LCPLL_CTL_HSW_WRITE_ONCE_DEV2_SUBID	(1 << 2)
#define LCPLL_CTL_HSW_WRITE_ONCE_DEV2_SUBVID	(1 << 1)
#define LCPLL_CTL_HSW_WRITE_ONCE_DEV2_SMISCISEL	(1 << 0)

#define PP_STATUS				0xC7200
#define PP_STATUS_HSW_PANEL_PWRON_STATUS	(1U << 31)
#define PP_STATUS_HSW_POWERING_UP		(1 << 28)
#define PP_STATUS_HSW_POWERING_DOWN		(1 << 29)
#define PP_STATUS_HSW_NONE			0
#define PP_STATUS_HSW_POWER_SEQUENCE_MASK	(1 << 29) | (1 << 28)
#define PP_STATUS_HSW_POWER_CYCLE_DELAY_ACTIVE	(1 << 27)

#define PP_STATUS				0xC7204

#define PP_STATUS_HSW_VDD_OVERRIDE		(1 << 3)
#define PP_STATUS_HSW_BACKLIGHT_ENABLE		(1 << 2)
#define PP_STATUS_HSW_POWER_DOWN_ON_RESET	(1 << 1)
#define PP_STATUS_HSW_POWER_STATE_TARGET_ON	(1 << 0)


/* Reminder: The below regs are named TRANS_* in Gen > HSW */
#define PIPE_HTOTAL				0x60000
#define PIPE_HBLANK				0x60004
#define PIPE_HSYNC				0x60008
#define PIPE_VTOTAL				0x6000C
#define PIPE_VBLANK				0x60010
#define PIPE_VSYNC				0x60014
/* TRANS_* ends here */

#define PIPE_SRCSZ				0x6001C
/* Values to help determine specific pipe regs (add pipe_idx * offset
 * to the above register values
*/
#define PIPE_OFFSET_PER_PIPE			0x01000
/* PIPE_EDP has completely separate registers */
#define PIPE_OFFSET_EDP				0x0f000


#define PIPE_HTOTAL_HACTIVE_MASK		(0xfff)
#define PIPE_HTOTAL_HTOTAL_SHIFT		16
#define PIPE_HBLANK_START_MASK			(0xfff)
#define PIPE_HBLANK_END_SHIFT			16
#define PIPE_HSYNC_START_MASK			(0xfff)
#define PIPE_HSYNC_END_SHIFT			16
#define PIPE_VTOTAL_VACTIVE_MASK		(0xfff)
#define PIPE_VTOTAL_VTOTAL_SHIFT		16
#define PIPE_VBLANK_START_MASK			(0xfff)
#define PIPE_VBLANK_END_SHIFT			16
#define PIPE_VSYNC_START_MASK			(0xfff)
#define PIPE_VSYNC_END_SHIFT			16
#define PIPE_SRCSZ_VERT_MASK			(0xfff)
#define PIPE_SRCSZ_HORIZ_SHIFT			16

#endif