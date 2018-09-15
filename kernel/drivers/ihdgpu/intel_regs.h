/*
* Copyright (c) 2018 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/

#ifndef _INTEL_REGS_H
#define _INTEL_REGS_H

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

#define GMBUS1_ASSERT_HWRDY		(1U << 31)
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

#endif