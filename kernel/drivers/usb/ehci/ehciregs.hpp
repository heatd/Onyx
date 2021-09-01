/*
* Copyright (c) 2019 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#pragma once

#include <onyx/hwregister.hpp>

enum ehci_cap_regs : mmio_range::register_offset
{
	CAPLENGTH = 0,
	HCIVERSION = 2,
	HCSPARAMS = 4,
	HCCPARAMS = 8,
	HCS_PORTROUTE = 0xc 
};

enum ehci_op_regs : mmio_range::register_offset
{
	USBCMD = 0,
	USBSTS = 4,
	USBINTR = 8,
	FRINDEX = 0xc,
	CTRLDSSEGMENT = 0x10,
	PERIODICLISTBASE = 0x14,
	ASYNCLISTADDR = 0x18,
	CONFIGFLAG = 0x40,
	PORTSC_BASE = 0x44 /* PORTSC(n) = PORTSC_BASE + (4 * (n - 1)) */
};

#define USBCMD_RUNSTOP					(1 << 0)
#define USBCMD_HCRESET					(1 << 1)
#define USBCMD_FRAME_LIST_MASK				0x3
#define USBCMD_FRAME_LIST_SHIFT				2
#define USBCMD_FRAME_LIST_1024				0
#define USBCMD_FRAME_LIST_512				1
#define USBCMD_FRAME_LIST_256				2
#define USBCMD_PERIODIC_SCHEDULE_ENABLE			(1 << 4)
#define USBCMD_ASYNCHRONOUS_SCHEDULE_ENABLE		(1 << 5)
#define USBCMD_INTERRUPT_ON_ASYNC_ADVANCE_DOORBELL	(1 << 6)
#define USBCMD_LIGHT_HOST_CONTROLLER_RESET		(1 << 7)
#define USBCMD_INTERRUPT_THRESHOLD_CONTROL(n) 		(n << 16)
#define USBCMD_GET_INTERRUPT_THRESHOLD_CONTROL(n)	((n >> 16) & 0x7f)

#define USBSTS_USBINT				(1 << 0)
#define USBSTS_USBERRINT			(1 << 1)
#define USBSTS_PORT_CHANGE_DETECT		(1 << 2)
#define USBSTS_FRAME_LIST_ROLLOVER		(1 << 3)
#define USBSTS_HOST_SYSTEM_ERROR		(1 << 4)
#define USBSTS_INTERRUPT_ON_SYSTEM_ADVANCE	(1 << 5)
#define USBSTS_HCHALTED				(1 << 12)
#define USBSTS_RECLAMATION			(1 << 13)
#define USBSTS_PERIODIC_SCHEDULE_STATUS		(1 << 14)
#define USBSTS_ASYNC_SCHEDULE_STATUS		(1 << 15)
