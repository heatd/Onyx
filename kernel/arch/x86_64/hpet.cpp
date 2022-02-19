/*
 * Copyright (c) 2021 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <onyx/acpi.h>
#include <onyx/init.h>
#include <onyx/log.h>

#include <onyx/hwregister.hpp>
#include <onyx/memory.hpp>

#define HPET_EVENT_BLOCK_LENGTH 1024

#define HPET_ETB_CAP_ID 0x0000

#define HPET_ETB_CAP_COUNTER_CLK_PERIOD(x) (uint32_t)(x >> 32)
#define HPET_ETB_CAP_VENDOR_ID(x)          (uint16_t)(x >> 16)
#define HPET_ETB_CAP_LEG_RT_CAP            (1 << 15)
#define HPET_ETB_CAP_COUNT_SIZE_CAP        (1 << 13)
#define HPET_ETB_CAP_NUM_TIM_CAP(x)        (uint8_t)((x >> 8) & 0x1f) // This field is 5 bits long
#define HPET_ETB_CAP_REV_ID(x)             (uint8_t)(x)

#define HPET_ETB_GENERAL_CFG 0x0010
// Allows timer interrupts if enabled, and allows the main counter to run
#define HPET_GCFG_ENABLE_CNF (1 << 0)
// Supports LegacyReplacement route
// In LegacyReplacement route, Timer 0 is routed to IRQ2 and Timer 1 is routed to IRQ8
// (in the IO APIC)
#define HPET_GCFG_LEG_RT_CNF (1 << 1)

#define HPET_ETB_GENERAL_INT_STS       0x0020
// When the timer is set to level triggered, this bit is set by hardware if the timer
// interrupt is pending. The bit is cleared by writing 1 to it.
// When the timer is set to edge triggerd, this bit is ignored and 0 should be written to it.
#define HPET_GENERAL_INT_Tn_INT_STS(x) (1U << x)

#define HPET_ETB_MAIN_COUNTER 0x00f0

#define HPET_ETB_TIMER_REG_BASE(x) (0x100 + 0x20 * x)
// Configuration and capability register for timers
#define HPET_ETB_Tn_CFG(x)         (HPET_ETB_TIMER_REG_BASE(x) + 0x00)

// Bitfield of IRQs to where the timer's interrupt can be routed.
#define HPET_ETB_Tn_CFG_INT_ROUTE_CAP(x) (x >> 32)
// If 1 (read-only), the interrupt can be delivered through the FSB
// Note that FSB = MSI, for both the address and value.
#define HPET_ETB_Tn_CFG_INT_DEL_CAP      (1 << 15)
// If 1, FSB delivery is enabled.
#define HPET_ETB_Tn_CFG_FSB_EN_CFG       (1 << 14)
// 5-bit field that specifies the routing for the interrupt in the IO APIC
#define HPET_ETB_Tn_CFG_ROUTE_CFG(x)     ((x >> 9) & 0x1f)
// If 1, the timer is forced to 32-bit mode, even if it is 64-bit capable
#define HPET_ETB_Tn_CFG_32MODE_CFG       (1 << 8)
// ???
#define HPET_ETB_Tn_CFG_VAL_SET_CNF      (1 << 6)
// If 1, 64-bit capable
#define HPET_ETB_Tn_CFG_64BIT_CAP        (1 << 5)
// If 1, periodic mode capable
#define HPET_ETB_Tn_CFG_PER_INT_CAP      (1 << 4)
// If 1, the timer is set to periodic mode
#define HPET_ETB_Tn_CFG_TYPE_CONF        (1 << 3)
// If 1, interrupts are enabled for the timer
#define HPET_ETB_Tn_INT_EN_CONF          (1 << 2)
// If 1, interrupts are level triggered. If 0, interrupts are edge triggered
#define HPET_ETB_Tn_INT_TYPE_CONF        (1 << 1)

// Timer comparator register
// Note that on periodic, the value for the register is incremented by the last value
// written to it.
#define HPET_ETB_Tn_COMPARATOR_CONF(x) (HPET_ETB_TIMER_REG_BASE(x) + 0x08)

// Register that stores FSB/MSI interrupt data (addr + val)
#define HPET_ETB_Tn_FSB_INT(x)         (HPET_ETB_TIMER_REG_BASE(x) + 0x10)
// Address to where the FSB int message should be written to
#define HPET_ETB_Tn_FSB_INT_ADDR(addr) (((uint64_t) addr) << 32)
// Value that gets written during the FSB int message
#define HPET_ETB_Tn_FSB_INT_VAL(val)   ((uint32_t) val)

class hpet_timer
{
private:
    const ACPI_TABLE_HPET *hpet_;
    mmio_range event_timer_block_;
    uint8_t nr_timers;

public:
    /**
     * @brief Constructs a new HPET timer object
     *
     * @param hpet_table Pointer to the ACPI HPET table
     */
    hpet_timer(const ACPI_TABLE_HPET *hpet_table);

    /**
     * @brief Destroys the HPET timer object.
     *
     */
    ~hpet_timer()
    {
        auto range = event_timer_block_.as_ptr();
        if (range != nullptr)
        {
            // Was mapped, unmap it
            vm_munmap(&kernel_address_space, (void *) range, HPET_EVENT_BLOCK_LENGTH);
        }
    }

    DEFINE_MMIO_RW_FUNCTIONS(event_timer_block_);
    /**
     * @brief Initialises the HPET timer.
     *
     * Maps the event timer block and discovers timers, publishes timer objects.
     * @return True if success, false if not.
     */
    bool init();
};

/**
 * @brief Constructs a new HPET timer object
 *
 * @param hpet_table Pointer to the ACPI HPET table
 */
hpet_timer::hpet_timer(const ACPI_TABLE_HPET *hpet_table) : hpet_{hpet_table}, event_timer_block_{}
{
}

/**
 * @brief Initialises the HPET timer.
 *
 * Maps the event timer block and discovers timers, publishes timer objects.
 * @return True if success, false if not.
 */
bool hpet_timer::init()
{
    volatile void *evt_block = mmiomap((void *) hpet_->Address.Address, HPET_EVENT_BLOCK_LENGTH,
                                       VM_READ | VM_WRITE | VM_NOCACHE);

    if (!evt_block)
    {
        return false;
    }

    event_timer_block_.set_base(evt_block);

    uint64_t id_register = read64(HPET_ETB_CAP_ID);

    INFO("hpet", "Vendor id %x\n", HPET_ETB_CAP_VENDOR_ID(id_register));
    nr_timers = HPET_ETB_CAP_NUM_TIM_CAP(id_register);

    return true;
}

/**
 * @brief Initialises the HPET timers.
 *
 * Looks at the ACPI tables and initialises the HPET if such a table exists.
 *
 */
static void hpet_init()
{
    ACPI_TABLE_HPET *hpet_table;

    auto st = AcpiGetTable((char *) ACPI_SIG_HPET, 0, (ACPI_TABLE_HEADER **) &hpet_table);

    if (ACPI_FAILURE(st))
    {
        return;
    }

    INFO("hpet", "Found valid HPET firmware table\n");

    if (hpet_table->Address.SpaceId != ACPI_ADR_SPACE_SYSTEM_MEMORY)
    {
        ERROR("hpet", "Invalid HPET table: HPET must be in memory\n");
        return;
    }

    unique_ptr<hpet_timer> timer = make_unique<hpet_timer>(hpet_table);

    timer->init();
}

INIT_LEVEL_EARLY_PLATFORM_ENTRY(hpet_init);
