/*
 * Copyright (c) 2026 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _MII_H
#define _MII_H

/* Common set of MII registers, as specified by IEEE Std 802.3-2022 */
#define MII_BMCR              0
#define MII_BMST              1
#define MII_PHYID0            2
#define MII_PHYID1            3
#define MII_ADVERTISE         4
#define MII_LPA               5
#define MII_EXPANSION         6
#define MII_NPT               7
#define MII_1000BASE_T_CTRL   9
#define MII_1000BASE_T_STATUS 10

/* For MII_BMCR */
#define MII_BMCR_AUTONEG_ENABLE  (1 << 12)
#define MII_BMCR_RESTART_AUTONEG (1 << 9)

/* For MII_BMST */
#define MII_BMST_AUTONEG_COMPLETE (1 << 5)

/* For MII_ADVERTISE */
#define ADV_10BASE_HALF  (1 << 5)
#define ADV_10BASE_FULL  (1 << 6)
#define ADV_100BASE_HALF (1 << 7)
#define ADV_100BASE_FULL (1 << 8)

#define MII_1000T_CTRL_1000_HALF_DUPLEX (1 << 8)
#define MII_1000T_CTRL_1000_FULL_DUPLEX (1 << 9)
#endif
