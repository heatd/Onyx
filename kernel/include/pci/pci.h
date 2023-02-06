/*
 * Copyright (c) 2016 - 2025 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the GPLv2 License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */
#ifndef _ONYX_PCI_H
#define _ONYX_PCI_H

#include <stdbool.h>
#include <stdint.h>

#include <onyx/compiler.h>
#include <onyx/dev.h>
#include <onyx/irq.h>
#include <onyx/port_io.h>
#include <onyx/spinlock.h>

#include <pci/pcie.h>

#include <onyx/expected.hpp>

#define PCI_NR_DEV 32

#define PCI_CONFIGURATION_SPACE_SIZE 256

#define PCI_BAR0        0x10
#define PCI_BARx(index) (PCI_BAR0 + 0x4 * index)

#define PCI_NR_BARS 6

#define PCI_REGISTER_VENDOR_ID           0x0
#define PCI_REGISTER_DEVICE_ID           0x2
#define PCI_REGISTER_COMMAND             0x4
#define PCI_REGISTER_STATUS              0x6
#define PCI_REGISTER_HEADER              0xe
#define PCI_REGISTER_REVISION_ID         0x8
#define PCI_REGISTER_PROGIF              0x9
#define PCI_REGISTER_SUBCLASS            0xa
#define PCI_REGISTER_CLASS               0xb
#define PCI_REGISTER_PRIMARY_BUS         0x18
#define PCI_REGISTER_SECONDARY_BUS       0x19
#define PCI_REGISTER_SUBORDINATE_BUS     0x1a
#define PCI_REGISTER_SUBSYSTEM_VID       0x2c
#define PCI_REGISTER_SUBSYSTEM_ID        0x2e
#define PCI_REGISTER_CAPABILTIES_POINTER 0x34
#define PCI_REGISTER_INTN                0x3c

#define PCI_REGISTER_IO_BASE          0x1c
#define PCI_REGISTER_IO_LIMIT         0x1d
#define PCI_REGISTER_MEMORY_BASE      0x20
#define PCI_REGISTER_MEMORY_LIMIT     0x22
#define PCI_REGISTER_PREF_MEMORY_BASE 0x24
#define PCI_REGISTER_PREF_MEMORY_LIM  0x26
#define PCI_REGISTER_UPPER_PREF_BASE  0x28
#define PCI_REGISTER_UPPER_PREF_LIM   0x2c
#define PCI_REGISTER_UPPER_IO_BASE    0x30
#define PCI_REGISTER_UPPER_IO_LIMIT   0x32

#define PCI_HEADER_MULTIFUNCTION 0x80
#define PCI_TYPE_MASK            0x7f
#define PCI_TYPE_REGULAR         0
#define PCI_TYPE_BRIDGE          1
#define PCI_TYPE_CARDBUS         2

#define CLASS_MASS_STORAGE_CONTROLLER          1
#define CLASS_NETWORK_CONTROLLER               2
#define CLASS_DISPLAY_CONTROLLER               3
#define CLASS_MULTIMEDIA_CONTROLLER            4
#define CLASS_MEMORY_CONTROLLER                5
#define CLASS_BRIDGE_DEVICE                    6
#define CLASS_COMMUNICATIONS_CONTROLLER        7
#define CLASS_BASE_SYSTEM_PERIPHERALS          8
#define CLASS_INPUT_DEVICES                    9
#define CLASS_DOCKING_STATIONS                 10
#define CLASS_PROCESSORS                       11
#define CLASS_SERIAL_BUS_CONTROLLER            12
#define CLASS_WIRELESS_CONTROLLER              13
#define CLASS_INTELIGENT_CONTROLLER            14
#define CLASS_SATELLITE_CONTROLLER             15
#define CLASS_ENCRYPTION_DECRYPTION_CONTROLLER 16
#define CLASS_DATA_AND_SIGNAL_CONTROLLER       17

#define PCI_COMMAND_IOSPACE               (1 << 0)
#define PCI_COMMAND_MEMORY_SPACE          (1 << 1)
#define PCI_COMMAND_BUS_MASTER            (1 << 2)
#define PCI_COMMAND_SPECIAL_CYCLES        (1 << 3)
#define PCI_COMMAND_MEMORY_WRITE_AND_INV  (1 << 4)
#define PCI_COMMAND_VGA_PALETTE_SNOOP     (1 << 5)
#define PCI_COMMAND_PARITY_ERROR_RESPONSE (1 << 6)
#define PCI_COMMAND_SERR_ENABLE           (1 << 8)
#define PCI_COMMAND_FAST_BACK2BACK        (1 << 9)
#define PCI_COMMAND_INTR_DISABLE          (1 << 10)

#define PCI_STATUS_INT_STATUS               (1 << 3)
#define PCI_STATUS_CAP_LIST_SUPPORTED       (1 << 4)
#define PCI_STATUS_66MHZ                    (1 << 5)
#define PCI_STATUS_FAST_BACK2BACK           (1 << 7)
#define PCI_STATUS_MASTER_DATA_PARITY_ERROR (1 << 8)
#define PCI_STATUS_DEVSEL_TIMING            ((1 << 9) | (1 << 10))
#define PCI_STATUS_SIGNALED_TARGET_ABORT    (1 << 11)
#define PCI_STATUS_RECEIVED_TARGET_ABORT    (1 << 12)
#define PCI_STATUS_RECEIVED_MASTER_ABORT    (1 << 13)
#define PCI_STATUS_SIGNALED_SYSTEM_ERROR    (1 << 14)
#define PCI_STATUS_DETECTED_PARITY_ERROR    (1 << 15)

#define PCI_CAP_ID_RESERVED                      (0)
#define PCI_CAP_ID_POWER_MANAGEMENT_INTERFACE    (1)
#define PCI_CAP_ID_AGP                           (2)
#define PCI_CAP_ID_VPD                           (3)
#define PCI_CAP_ID_SLOT_IDENT                    (4)
#define PCI_CAP_ID_MSI                           (5)
#define PCI_CAP_ID_COMPACTPCI_HOT_SWAP           (6)
#define PCI_CAP_ID_PCI_X                         (7)
#define PCI_CAP_ID_HYPER_TRANSPORT               (8)
#define PCI_CAP_ID_VENDOR                        (9)
#define PCI_CAP_ID_DEBUG_PORT                    (0xA)
#define PCI_CAP_ID_COMPACTPCI_CENTRAL_RSRC_CNTRL (0xB)
#define PCI_CAP_ID_PCI_HOTPLUG                   (0xC)
#define PCI_CAP_ID_BRIDGE_SUBSYS_VENDOR          (0xD)
#define PCI_CAP_ID_AGPX8                         (0xE)
#define PCI_CAP_ID_SECURE_DEVICE                 (0xF)
#define PCI_CAP_ID_PCI_EXPRESS                   (0x10)
#define PCI_CAP_ID_MSI_X                         (0x11)
#define PCI_CAP_ID_AF                            (0x13)

#define PCI_DRIVER_GENERIC  0
#define PCI_DRIVER_SPECIFIC 1

#define PCI_PMC_D1_SUPPORT (1 << 9)
#define PCI_PMC_D2_SUPPORT (1 << 10)

#define PCI_POWER_STATE_D0 (1 << 0)
#define PCI_POWER_STATE_D1 (1 << 1)
#define PCI_POWER_STATE_D2 (1 << 2)
#define PCI_POWER_STATE_D3 (1 << 3)

namespace pci
{

struct pci_irq
{
    bool level;
    bool active_high;
    uint32_t gsi;
};

struct device_address
{
    uint16_t segment;
    uint8_t bus;
    uint8_t device;
    uint8_t function;
};

static inline bool operator==(const device_address &lhs, const device_address &rhs)
{
    return lhs.segment == rhs.segment && lhs.bus == rhs.bus && lhs.device == rhs.device &&
           lhs.function == rhs.function;
}

struct pci_bar
{
    uint64_t address;
    size_t size;
    bool is_iorange;
    bool may_prefetch;
};

#define PCI_ID_BY_CLASS 0
#define PCI_ID_BY_ID    1

#define PCI_ANY_ID 0xff

struct pci_id
{
    uint16_t device_id;
    uint16_t vendor_id;
    uint8_t pci_class;
    uint8_t subclass;
    uint8_t progif;
    void *driver_data;
};

struct msix_table_entry
{
    u32 msg_addr;
    u32 msg_upper_addr;
    u32 msg_data;
    u32 msg_vec_ctl;
};

#define MSIX_VEC_CTL_MASKED (1 << 0)

class pci_bus;

class pci_device : public device
{
protected:
    uint16_t device_id, vendor_id;
    device_address address;
    uint8_t pci_class_, sub_class_, prog_if_;
    int type;
    bool has_power_management;
    uint8_t pm_cap_off;
    /* Given by PCI, we just cache it here */
    int supported_power_states;
    int current_power_state;
    pci_device *next;
    struct pci_irq pin_to_gsi[4];
    void *driver_data;
    pcie_allocation *alloc;

    void find_supported_capabilities();
    int wait_for_tp(off_t cap_start);
    int set_power_state(int power_state);

    bool enum_bars();

    pci_bus *get_pci_bus()
    {
        return (pci_bus *) bus;
    }

    bool bridge_supports_32bit_io();

    bool bridge_supports_64bit_prefetch();

    int bridge_set_io_window(u32 io_start, u32 io_end);

    int bridge_set_mem_window(u32 start, u32 end);

    int bridge_set_pref_mem_window(u64 start, u64 end);

    friend class pci_bus;
    friend class pci_root;

public:
    struct msix_table_entry *msix_table;
    u32 *msix_pba;
    bool msix_enabled;
    u32 nr_msix_vectors;
    u32 *msix_irqs;
    bool msi_enabled;
    u32 msi_base;
    u32 nr_msi_vectors;

    pci_device(const char *name, struct bus *b, device *parent, uint16_t did_, uint16_t vid_,
               const device_address &addr)
        : device{name, b, parent}, device_id{did_}, vendor_id{vid_}, address{addr}, pci_class_{},
          sub_class_{}, prog_if_{}, type{}, has_power_management{}, pm_cap_off{},
          supported_power_states{}, current_power_state{}, next{}, pin_to_gsi{},
          driver_data{}, alloc{}, msix_table{}, msix_pba{}, msix_enabled{false},
          nr_msix_vectors{0}, msix_irqs{NULL}, msi_enabled{false}, msi_base{}, nr_msi_vectors{}
    {
    }

    virtual ~pci_device()
    {
    }

    uint16_t did() const
    {
        return device_id;
    }

    uint16_t vid() const
    {
        return vendor_id;
    }

    uint8_t pci_class() const
    {
        return pci_class_;
    }

    uint8_t sub_class() const
    {
        return sub_class_;
    }

    uint8_t prog_if() const
    {
        return prog_if_;
    }

    uint32_t nr_bars() const
    {
        unsigned int nr_bars = 6;

        if (type == 1)
            nr_bars = 2;
        else if (type == 2)
            nr_bars = 1;
        return nr_bars;
    }

    void init();

    uint64_t read(uint16_t off, size_t size) const;
    void write(uint64_t value, uint16_t off, size_t size) const;

    uint16_t get_subsystem_id() const
    {
        return static_cast<uint16_t>(read(PCI_REGISTER_SUBSYSTEM_ID, sizeof(uint16_t)));
    }

    int reset_device();
    int enable_device();

    uint16_t get_intn() const;

    void enable_busmastering();
    void disable_busmastering();
    void enable_irq();
    void disable_irq();
    size_t find_capability(uint8_t cap, int instance = 0);
    int enable_msi(irq_t handler, void *cookie);
    expected<pci_bar, int> get_bar(unsigned int index);
    void *map_bar(unsigned int index, unsigned int caching);
    void set_bar(const pci_bar &bar, unsigned int index);

    device_address addr() const
    {
        return address;
    }

    uint16_t get_status() const;

    auto get_pin_to_gsi()
    {
        return pin_to_gsi;
    }

    void set_driver_data(void *data)
    {
        driver_data = data;
    }

    uint16_t header_type() const
    {
        return (uint16_t) read(PCI_REGISTER_HEADER, sizeof(uint16_t));
    }

    void set_alloc(pcie_allocation *alloc)
    {
        this->alloc = alloc;
    }

    /**
     * @brief Initialize the not-initialized bridge
     *
     */
    void init_bridge();

    /**
     * @brief Finish the bridge initialization
     *
     */
    void finish_bridge_init();

    /**
     * @brief Assign a value to a BAR
     *
     * @param bar
     * @param start
     */
    void assign_bar(unsigned int bar, u64 start);
};

#define PCI_ID_DEVICE(vendor, dev, drv_data)                                                \
    .device_id = dev, .vendor_id = vendor, .pci_class = PCI_ANY_ID, .subclass = PCI_ANY_ID, \
    .progif = PCI_ANY_ID, .driver_data = drv_data

#define PCI_ID_CLASS(c, s, p, drv_data)                                                           \
    .device_id = PCI_ANY_ID, .vendor_id = PCI_ANY_ID, .pci_class = c, .subclass = s, .progif = p, \
    .driver_data = drv_data

pci_device *get_device(const device_address &addr);

uint64_t read_config(const device_address &addr, uint16_t off, size_t size);
void write_config(const device_address &addr, uint64_t value, uint16_t off, size_t size);

void register_driver(struct driver *driver);
} // namespace pci

int pci_enable_msix(pci::pci_device *dev, unsigned int min_vecs, unsigned int max_vecs,
                    unsigned int flags);

int pci_alloc_irqs(pci::pci_device *dev, unsigned int min_vecs, unsigned int max_vecs,
                   unsigned int flags);

#define PCI_IRQ_INTX (1 << 0)
#define PCI_IRQ_MSI  (1 << 1)
#define PCI_IRQ_MSIX (1 << 2)

#define PCI_IRQ_DEFAULT (PCI_IRQ_INTX | PCI_IRQ_MSI | PCI_IRQ_MSIX)

int pci_get_irq(pci::pci_device *dev, unsigned int irq);
int pci_install_irq(pci::pci_device *dev, unsigned int irq, irq_t handler, unsigned int flags,
                    void *cookie, const char *name, ...);

int pci_get_nr_vectors(pci::pci_device *dev);

#endif
