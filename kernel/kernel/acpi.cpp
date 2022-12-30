/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <onyx/acpi.h>
#include <onyx/bus_type.h>
#include <onyx/clock.h>
#include <onyx/compiler.h>
#include <onyx/cpu.h>
#include <onyx/dev.h>
#include <onyx/init.h>
#include <onyx/limits.h>
#include <onyx/log.h>
#include <onyx/mutex.h>
#include <onyx/panic.h>
#include <onyx/platform.h>
#include <onyx/spinlock.h>
#include <onyx/vm.h>
#include <onyx/x86/apic.h>

#include <fixed_point/fixed_point.h>
#include <pci/pci.h>

#include <onyx/memory.hpp>

int acpi_init_timer();
static bool acpi_enabled = false;

static const acpi_exception_info acpi_gbl_exception_names_env[] = {
    EXCEP_TXT((char *) "AE_OK", (char *) "No error"),
    EXCEP_TXT((char *) "AE_ERROR", (char *) "Unspecified error"),
    EXCEP_TXT((char *) "AE_NO_ACPI_TABLES", (char *) "ACPI tables could not be found"),
    EXCEP_TXT((char *) "AE_NO_NAMESPACE", (char *) "A namespace has not been loaded"),
    EXCEP_TXT((char *) "AE_NO_MEMORY", (char *) "Insufficient dynamic memory"),
    EXCEP_TXT((char *) "AE_NOT_FOUND", (char *) "A requested entity is not found"),
    EXCEP_TXT((char *) "AE_NOT_EXIST", (char *) "A required entity does not exist"),
    EXCEP_TXT((char *) "AE_ALREADY_EXISTS", (char *) "An entity already exists"),
    EXCEP_TXT((char *) "AE_TYPE", (char *) "The object type is incorrect"),
    EXCEP_TXT((char *) "AE_NULL_OBJECT", (char *) "A required object was missing"),
    EXCEP_TXT((char *) "AE_NULL_ENTRY", (char *) "The requested object does not exist"),
    EXCEP_TXT((char *) "AE_BUFFER_OVERFLOW", (char *) "The buffer provided is too small"),
    EXCEP_TXT((char *) "AE_STACK_OVERFLOW", (char *) "An internal stack overflowed"),
    EXCEP_TXT((char *) "AE_STACK_UNDERFLOW", (char *) "An internal stack underflowed"),
    EXCEP_TXT((char *) "AE_NOT_IMPLEMENTED", (char *) "The feature is not implemented"),
    EXCEP_TXT((char *) "AE_SUPPORT", (char *) "The feature is not supported"),
    EXCEP_TXT((char *) "AE_LIMIT", (char *) "A predefined limit was exceeded"),
    EXCEP_TXT((char *) "AE_TIME", (char *) "A time limit or timeout expired"),
    EXCEP_TXT((char *) "AE_ACQUIRE_DEADLOCK",
              (char *) "Internal error, attempt was made to acquire a mutex in improper order"),
    EXCEP_TXT((char *) "AE_RELEASE_DEADLOCK",
              (char *) "Internal error, attempt was made to release a mutex in improper order"),
    EXCEP_TXT((char *) "AE_NOT_ACQUIRED",
              (char *) "An attempt to release a mutex or Global Lock without a previous acquire"),
    EXCEP_TXT((char *) "AE_ALREADY_ACQUIRED",
              (char *) "Internal error, attempt was made to acquire a mutex twice"),
    EXCEP_TXT((char *) "AE_NO_HARDWARE_RESPONSE",
              (char *) "Hardware did not respond after an I/O operation"),
    EXCEP_TXT((char *) "AE_NO_GLOBAL_LOCK", (char *) "There is no FACS Global Lock"),
    EXCEP_TXT((char *) "AE_ABORT_METHOD", (char *) "A control method was aborted"),
    EXCEP_TXT((char *) "AE_SAME_HANDLER",
              (char *) "Attempt was made to install the same handler that is already installed"),
    EXCEP_TXT((char *) "AE_NO_HANDLER", (char *) "A handler for the operation is not installed"),
    EXCEP_TXT((char *) "AE_OWNER_ID_LIMIT",
              (char *) "There are no more Owner IDs available for ACPI tables or control methods"),
    EXCEP_TXT((char *) "AE_NOT_CONFIGURED",
              (char *) "The interface is not part of the current subsystem configuration"),
    EXCEP_TXT((char *) "AE_ACCESS", (char *) "Permission denied for the requested operation")};

uint32_t acpi_shutdown()
{
    acpi_enter_sleep_state_prep(5);
    irq_save_and_disable();
    acpi_enter_sleep_state(5);

    panic("ACPI: Failed to enter sleep state! Panic'ing!");
    return 0;
}

extern "C" int __enter_sleep_state(uint8_t sleep_state);

unsigned int acpi_suspend()
{
    /* Prepare to enter S3 */
    acpi_status st = acpi_enter_sleep_state_prep(2);
    if (ACPI_FAILURE(st))
        return -EIO;
    irq_save_and_disable();
    /* We'll need to enter assembly in order to correctly save and restore
     * registers
     */
    if (__enter_sleep_state(2) < 0)
        return -1;
    return 0;
}

int acpi_shutdown_device(struct device *dev);
struct bus acpi_bus
{
    "acpi"
};

uint32_t acpi_execute_pic(int value)
{
    acpi_object arg;
    acpi_object_list list;

    arg.type = ACPI_TYPE_INTEGER;
    arg.integer.value = value;
    list.count = 1;
    list.pointer = &arg;

    return acpi_evaluate_object(ACPI_ROOT_OBJECT, (char *) "_PIC", &list, nullptr);
}

namespace acpi
{

bool is_enabled()
{
    return acpi_enabled;
}

acpi_status find_pci_buses(acpi_handle object, u32 nesting_level, void *context, void **ret)
{
    acpi_device_info *devinfo;
    acpi_status st = acpi_get_object_info(object, &devinfo);

    if (ACPI_FAILURE(st))
    {
        ERROR("acpi", "Error: AcpiGetObjectInfo failed!\n");
        return AE_ERROR;
    }

    if (devinfo->flags & ACPI_PCI_ROOT_BRIDGE)
    {
        find_root_pci_bus_t callback = (find_root_pci_bus_t) context;
        acpi_buffer buf;
        uint64_t segment, bus;
        acpi_object val;
        val.type = ACPI_TYPE_INTEGER;
        buf.pointer = &val;
        buf.length = sizeof(val);

        if (auto st = acpi_evaluate_object(object, (char *) "_SEG", nullptr, &buf);
            ACPI_FAILURE(st))
        {
            if (st == AE_NOT_FOUND)
            {
                // The spec says that if the method isn't found, we assume the segment is 0
                val.integer.value = 0;
            }
            else
            {
                ERROR("acpi", "Error evaluating _SEG for root bridge\n");
                free(devinfo);
                return st;
            }
        }

        segment = val.integer.value;

        buf.pointer = &val;
        buf.length = sizeof(val);

        if (auto st = acpi_evaluate_object(object, (char *) "_BBN", nullptr, &buf);
            ACPI_FAILURE(st))
        {
            if (st == AE_NOT_FOUND)
            {
                // Linux seems to assume the bus is 0
                val.integer.value = 0;
            }
            else
            {
                ERROR("acpi", "Error evaluating _BBN for root bridge status %x\n", st);
                free(devinfo);
                return st;
            }
        }

        bus = val.integer.value;

        // printk("Root bridge %04x:%02x\n", (uint16_t) segment, (uint8_t) bus);

        if (callback((uint16_t) segment, (uint8_t) bus, object) < 0)
        {
            free(devinfo);
            return AE_ERROR;
        }
    }

    free(devinfo);
    return st;
}

int find_root_pci_buses(find_root_pci_bus_t callback)
{
    if (!is_enabled())
        return 0;

    void *retval;
    acpi_status st = acpi_get_devices(nullptr, find_pci_buses, (void *) callback, &retval);
    if (ACPI_FAILURE(st))
    {
        ERROR("acpi", "Error while calling AcpiGetDevices: %s\n",
              acpi_gbl_exception_names_env[st].name);
        return -EIO;
    }

    return 0;
}

} // namespace acpi

static uintptr_t rsdp = 0;
uintptr_t get_rdsp_from_grub();
uint8_t acpi_tb_checksum(uint8_t *buffer, uint32_t len);

void acpi_find_rsdp()
{
#ifdef __x86_64__
    if (ACPI_FAILURE(acpi_find_root_pointer(&rsdp)))
    {
        rsdp = get_rdsp_from_grub();
    }
#endif
}

uintptr_t acpi_get_rsdp()
{
    return rsdp;
}

acpi_resource *acpi_get_resource(struct acpi_device *device, uint32_t type, unsigned int index)
{
    acpi_resource *res = device->resources;

    for (; res->type != ACPI_RESOURCE_TYPE_END_TAG; res = ACPI_NEXT_RESOURCE(res))
    {
        if (res->type == type && index-- == 0)
            return res;
    }

    return nullptr;
}

acpi_resource *acpi_get_resources(acpi_handle object)
{
    acpi_status st = 0;
    acpi_buffer buf;
    buf.length = ACPI_ALLOCATE_BUFFER;
    buf.pointer = nullptr;

    if (ACPI_FAILURE((st = acpi_get_current_resources(object, &buf))))
    {
        return nullptr;
    }

    return (acpi_resource *) buf.pointer;
}

/**
 * @brief Checks if the dev_resource code supports this ACPI_RESOURCE
 *
 * @param res Pointer to the ACPI resource
 * @return True if supported, else false.
 */
bool acpi_supports_resource_type(acpi_resource *res)
{
    switch (res->type)
    {
        // fallthrough
        case ACPI_RESOURCE_TYPE_ADDRESS16:
        case ACPI_RESOURCE_TYPE_ADDRESS32:
        case ACPI_RESOURCE_TYPE_ADDRESS64:
        case ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64:
        case ACPI_RESOURCE_TYPE_MEMORY24:
        case ACPI_RESOURCE_TYPE_MEMORY32:
        case ACPI_RESOURCE_TYPE_FIXED_MEMORY32:
        case ACPI_RESOURCE_TYPE_IRQ:
        case ACPI_RESOURCE_TYPE_EXTENDED_IRQ:
        case ACPI_RESOURCE_TYPE_IO:
        case ACPI_RESOURCE_TYPE_FIXED_IO:
            return true;

        default:
            return false;
    }
}

/**
 * @brief Converts an ACPI_RESOURCE into a dev_resource
 * Note: Doesn't handle IRQ resources since those are peculiar
 * in the sense that one ACPI_RESOURCE can describe multiple separate
 * IRQ vectors.
 *
 * @param acpires Pointer to the ACPI resource
 * @param res     Pointer to the dev_resource to be filled
 */
void acpi_resource_to_dev_resource(const acpi_resource *acpires, dev_resource *res)
{
    // TODO: Collect information for each resource (irq polarity, decode, cacheability, etc)
    acpi_resource_address64 res64;
    switch (acpires->type)
    {
        case ACPI_RESOURCE_TYPE_ADDRESS16:
        case ACPI_RESOURCE_TYPE_ADDRESS32:
        case ACPI_RESOURCE_TYPE_ADDRESS64:
            acpi_resource_to_address64((acpi_resource *) acpires, &res64);
            res->set_limits(res64.address.minimum, res64.address.maximum);
            if (res64.resource_type == ACPI_MEMORY_RANGE)
                res->flags() |= DEV_RESOURCE_FLAG_MEM;
            else if (res64.resource_type == ACPI_IO_RANGE)
                res->flags() |= DEV_RESOURCE_FLAG_IO_PORT;

            break;
        case ACPI_RESOURCE_TYPE_EXTENDED_ADDRESS64:
            res->set_limits(acpires->data.ext_address64.address.minimum,
                            acpires->data.ext_address64.address.maximum);
            if (acpires->data.ext_address64.resource_type == ACPI_MEMORY_RANGE)
                res->flags() |= DEV_RESOURCE_FLAG_MEM;
            else if (acpires->data.ext_address64.resource_type == ACPI_IO_RANGE)
                res->flags() |= DEV_RESOURCE_FLAG_IO_PORT;
            break;
        case ACPI_RESOURCE_TYPE_MEMORY24:
            res->set_limits(acpires->data.memory24.minimum, acpires->data.memory24.maximum);
            res->flags() |= DEV_RESOURCE_FLAG_MEM;
            break;
        case ACPI_RESOURCE_TYPE_MEMORY32:
            res->set_limits(acpires->data.memory32.minimum, acpires->data.memory32.maximum);
            res->flags() |= DEV_RESOURCE_FLAG_MEM;
            break;
        case ACPI_RESOURCE_TYPE_FIXED_MEMORY32:
            res->set_limits(acpires->data.fixed_memory32.address,
                            acpires->data.fixed_memory32.address +
                                acpires->data.fixed_memory32.address_length - 1);
            res->flags() |= DEV_RESOURCE_FLAG_MEM;
            break;
        case ACPI_RESOURCE_TYPE_IO:
            res->set_limits(acpires->data.io.minimum, acpires->data.io.maximum);
            res->flags() |= DEV_RESOURCE_FLAG_IO_PORT;
            break;
        case ACPI_RESOURCE_TYPE_FIXED_IO:
            res->set_limits(acpires->data.fixed_io.address,
                            acpires->data.fixed_io.address + acpires->data.fixed_io.address_length -
                                1);
            res->flags() |= DEV_RESOURCE_FLAG_IO_PORT;
            break;
    }
}

/**
 * @brief Converts an IRQ/Extended IRQ ACPI_RESOURCE into a dev_resource
 *
 * @param acpires Pointer to the ACPI resource
 * @param res     Pointer to the dev_resource to be filled
 * @param index   Index of the interrupt inside the acpi resource
 */
void acpi_irq_resource_to_dev_resource(const acpi_resource *acpires, dev_resource *res,
                                       uint8_t index)
{
    res->flags() |= DEV_RESOURCE_FLAG_IRQ;
    switch (acpires->type)
    {
        case ACPI_RESOURCE_TYPE_IRQ:
            res->set_limits(acpires->data.irq.interrupts[index],
                            acpires->data.irq.interrupts[index]);
            break;
        case ACPI_RESOURCE_TYPE_EXTENDED_IRQ:
            res->set_limits(acpires->data.extended_irq.interrupts[index],
                            acpires->data.extended_irq.interrupts[index]);
            break;
    }
}

expected<u32, acpi_status> acpi_exec_sta(acpi_handle object)
{
    union acpi_object obj;
    acpi_buffer out = {sizeof(obj), &obj};
    acpi_status st = acpi_evaluate_object(object, (char *) "_STA", nullptr, &out);

    if (ACPI_FAILURE(st))
    {
        // If _STA is not found, we assume all the bits are set (per the spec)
        if (st == AE_NOT_FOUND)
            return ACPI_STA_DEVICE_PRESENT | ACPI_STA_DEVICE_ENABLED | ACPI_STA_DEVICE_UI |
                   ACPI_STA_DEVICE_OK | ACPI_STA_BATTERY_PRESENT;
        return unexpected<acpi_status>{st};
    }

    if (obj.type != ACPI_TYPE_INTEGER)
    {
        return unexpected<acpi_status>{AE_BAD_VALUE};
    }

    return (u32) obj.integer.value;
}

bool acpi_is_present(acpi_handle object)
{
    auto ret = acpi_exec_sta(object);

    if (ret.has_error())
    {
        printf("acpi: error: acpi_exec_sta returned %u\n", ret.error());
        return false;
    }

    return (ret.value() & (ACPI_STA_DEVICE_PRESENT | ACPI_STA_DEVICE_FUNCTIONING)) ==
           (ACPI_STA_DEVICE_PRESENT | ACPI_STA_DEVICE_FUNCTIONING);
}

acpi_status acpi_add_device(acpi_handle object, u32 nesting_level, void *context,
                            void **returnvalue)
{
    bool free_id = false;

    if (!acpi_is_present(object))
        return AE_OK;

    acpi_device_info *info;
    acpi_status st;
    st = acpi_get_object_info(object, &info);
    if (ACPI_FAILURE(st))
    {
        ERROR("acpi", "AcpiGetObjectInfo() Failed\n");
        return AE_ERROR;
    }

    const char *id = nullptr;
    if (info->valid & ACPI_VALID_HID)
        id = info->hardware_id.string;
    else if (info->valid & ACPI_VALID_CID && info->compatible_id_list.count)
        id = info->compatible_id_list.ids[0].string;
    else
    {
        acpi_buffer buf;
        buf.length = ACPI_ALLOCATE_BUFFER;
        buf.pointer = nullptr;

        st = acpi_get_name(object, ACPI_FULL_PATHNAME, &buf);
        if (ACPI_FAILURE(st))
        {
            ERROR("acpi", "acpi_get_name() failed: error %x\n", st);
            return AE_ERROR;
        }
        free_id = true;

        id = (const char *) buf.pointer;
    }

    char *name = (char *) zalloc(PATH_MAX);
    if (!name)
        return AE_ERROR;

    snprintf(name, PATH_MAX, "%s", id);

    acpi_resource *resources = acpi_get_resources(object);

    // TODO: Resource releasing here is sloppy
    auto device = new acpi_device{name, &acpi_bus, nullptr, object, info, resources};
    if (!device)
    {
        free((void *) name);
        return AE_ERROR;
    }

    acpi_resource *res = device->resources;

    for (; res && res->type != ACPI_RESOURCE_TYPE_END_TAG; res = ACPI_NEXT_RESOURCE(res))
    {
        if (!acpi_supports_resource_type(res))
            continue;

        if (res->type == ACPI_RESOURCE_TYPE_IRQ || res->type == ACPI_RESOURCE_TYPE_EXTENDED_IRQ)
        {
            auto nr = res->type == ACPI_RESOURCE_TYPE_IRQ ? res->data.irq.interrupt_count
                                                          : res->data.extended_irq.interrupt_count;

            for (uint8_t i = 0; i < nr; i++)
            {
                unique_ptr<dev_resource> devres = make_unique<dev_resource>(0, 0, 0);
                if (!devres)
                {
                    delete device;
                    return AE_NO_MEMORY;
                }

                acpi_irq_resource_to_dev_resource(res, devres.get(), i);

                device->add_resource(devres.release());
            }
        }

        unique_ptr<dev_resource> devres = make_unique<dev_resource>(0, 0, 0);
        if (!devres)
        {
            delete device;
            return AE_NO_MEMORY;
        }

        acpi_resource_to_dev_resource(res, devres.get());

        device->add_resource(devres.release());
    }

    assert(device_init(device) == 0);

    bus_add_device(&acpi_bus, (struct device *) device);

    if (free_id)
        free((void *) id);
    return AE_OK;
}

void acpi_enumerate_devices()
{
    acpi_status st;
    /* Walk the namespace for devices */
    st = acpi_walk_namespace(ACPI_TYPE_DEVICE, ACPI_ROOT_OBJECT, ACPI_UINT32_MAX, acpi_add_device,
                             nullptr, nullptr, nullptr);
    if (ACPI_FAILURE(st))
    {
        ERROR("acpi", "Failed to walk the namespace\n");
    }
}

unsigned int acpi_power_event_handler(void *context)
{
    (void) context;
    return acpi_shutdown();
}

unsigned int acpi_suspend_event_handler(void *context)
{
    (void) context;
    return acpi_suspend();
}

acpi_status acpi_init_power()
{
    acpi_status st;

    if (ACPI_FAILURE((st = acpi_enable_event(ACPI_EVENT_POWER_BUTTON, 0))))
        return st;

    if (ACPI_FAILURE((st = acpi_install_fixed_event_handler(ACPI_EVENT_POWER_BUTTON,
                                                            acpi_power_event_handler, nullptr))))
        return st;

    if (ACPI_FAILURE((st = acpi_install_fixed_event_handler(ACPI_EVENT_SLEEP_BUTTON,
                                                            acpi_suspend_event_handler, nullptr))))
        return st;

    return AE_OK;
}

void acpi_initialise()
{
    acpi_find_rsdp();

    // ACPI is not available
    if (!rsdp)
        return;
    acpi_status st = acpi_initialize_subsystem();
    if (ACPI_FAILURE(st))
    {
        printk("Error: %s\n", acpi_gbl_exception_names_env[st].name);
        panic("ACPI subsystem initialization failed!");
    }

    st = acpi_initialize_tables(nullptr, 32, true);
    if (ACPI_FAILURE(st))
    {
        printk("Error: %s\n", acpi_gbl_exception_names_env[st].name);
        panic("ACPI table subsystem initialization failed!");
    }

    st = acpi_load_tables();
    if (ACPI_FAILURE(st))
        panic("acpi_load_tables failed!");

#ifdef __x86_64__
    ioapic_early_init();
#endif

    st = acpi_enable_subsystem(ACPI_FULL_INITIALIZATION);
    if (ACPI_FAILURE(st))
    {
        printk("Error: %s\n", acpi_gbl_exception_names_env[st].name);
        panic("acpi_enable_subsystem failed!");
    }

    st = acpi_initialize_objects(ACPI_FULL_INITIALIZATION);
    if (ACPI_FAILURE(st))
        panic("acpi_initialize_objects failed!");

    INFO("acpi", "initialized!\n");

    assert(bus_init(&acpi_bus) == 0);

    /* Enumerate every device */
    acpi_enumerate_devices();

    /* Register the acpi bus */
    bus_register(&acpi_bus);

    platform_init_acpi();

    acpi_init_power();

    acpi_enabled = true;
}

INIT_LEVEL_VERY_EARLY_PLATFORM_ENTRY(acpi_initialise);

uint32_t acpi_get_apic_id_lapic(acpi_subtable_header *madt)
{
    return ((acpi_madt_local_apic *) madt)->id;
}

static DECLARE_MUTEX(cpu_enum_lock);

static size_t ndx = 0;

// TODO: Parts of this are arch specific

acpi_status acpi_enumerate_per_cpu(acpi_handle object, u32 nesting_level, void *context,
                                   void **returnvalue)
{
    acpi_buffer buffer = {ACPI_ALLOCATE_BUFFER, nullptr};
    struct acpi_processor *processor = &((struct acpi_processor *) context)[ndx++];
    uint32_t apic_id = (uint32_t) -1;
    (void) apic_id;

    /* _MAT returns a segment of the MADT table */
    if (ACPI_FAILURE(acpi_evaluate_object(object, (char *) "_MAT", nullptr, &buffer)))
        return AE_ERROR;
    /* Get the APIC ID */
    acpi_object *obj = (acpi_object *) buffer.pointer;
    acpi_subtable_header *madt_table = (acpi_subtable_header *) obj->buffer.pointer;

    switch (madt_table->type)
    {
        case ACPI_MADT_TYPE_LOCAL_APIC:
            apic_id = acpi_get_apic_id_lapic(madt_table);
            break;
    }

    processor->object = object;

#if __x86_64__
    processor->apic_id = apic_id;
#endif

    ACPI_FREE(buffer.pointer);
    return AE_OK;
}

struct acpi_processor *acpi_enumerate_cpus()
{
    acpi_processor *processors = (acpi_processor *) malloc(sizeof(acpi_processor) * get_nr_cpus());
    if (!processors)
    {
        return nullptr;
    }

    memset(processors, 0, sizeof(struct acpi_processor) * get_nr_cpus());

    mutex_lock(&cpu_enum_lock);

    ndx = 0;
    /* Walk the namespace, looking for ACPI PROCESSOR objects */
    acpi_walk_namespace(ACPI_TYPE_PROCESSOR, ACPI_ROOT_OBJECT, ACPI_UINT32_MAX,
                        acpi_enumerate_per_cpu, nullptr, processors, nullptr);

    mutex_unlock(&cpu_enum_lock);
    return processors;
}

struct acpi_device *acpi_get_device(const char *id)
{
    return (struct acpi_device *) bus_find_device(&acpi_bus, id);
}

const char *power_states[] = {"_PS0", "_PS1", "_PS2", "_PS3"};

int acpi_set_device_power_state(struct acpi_device *device, unsigned int power_state)
{
    acpi_status st =
        acpi_evaluate_object(device->object, (char *) power_states[power_state], nullptr, nullptr);
    if (ACPI_FAILURE(st))
    {
        return 1;
    }

    return 0;
}

int acpi_shutdown_device(struct device *dev)
{
    assert(dev);
    return acpi_set_device_power_state((struct acpi_device *) dev, ACPI_POWER_STATE_D3);
}

uint64_t acpi_timer_get_ticks();
hrtime_t acpi_timer_get_elapsed_ns(hrtime_t old_ticks, hrtime_t new_ticks);
hrtime_t acpi_timer_get_ns();

struct clocksource acpi_timer_source = {.name = "acpi_pm_timer",
                                        .rating = 150,
                                        .rate = ACPI_PM_TIMER_FREQUENCY,
                                        .get_ticks = acpi_timer_get_ticks,
                                        .get_ns = acpi_timer_get_ns,
                                        .elapsed_ns = acpi_timer_get_elapsed_ns};

static struct fp_32_64 acpi_timer_ticks_per_ns;

hrtime_t acpi_timer_get_ns()
{
    uint32_t t;
    unsigned int res;
    uint32_t max = 0xffffffff;

    acpi_get_timer(&t);

    acpi_get_timer_resolution(&res);

    if (res == 24)
        max = 0x00ffffff;

    hrtime_t ns_since_rollover = u64_mul_u32_fp32_64(t, acpi_timer_ticks_per_ns);

    if (ns_since_rollover < acpi_timer_source.last_cycle)
    {
        acpi_timer_source.base += u64_mul_u32_fp32_64(max, acpi_timer_ticks_per_ns);
    }

    acpi_timer_source.last_cycle = ns_since_rollover;

    return acpi_timer_source.base + acpi_timer_source.monotonic_warp + ns_since_rollover;
}

#include <onyx/timer.h>

int acpi_init_timer()
{
    uint32_t ticks;
    acpi_status st = acpi_get_timer(&ticks);

    if (ACPI_FAILURE(st))
    {
        ERROR("acpi_pm_timer", "Couldn't get current ticks - there may be something "
                               "wrong with the ACPI PM Timer!\n");
        return -1;
    }

    fp_32_64_div_32_32(&acpi_timer_ticks_per_ns, NS_PER_SEC, ACPI_PM_TIMER_FREQUENCY);

    acpi_timer_source.monotonic_warp = -u64_mul_u32_fp32_64(ticks, acpi_timer_ticks_per_ns);
    acpi_timer_source.last_cycle = ticks;

    acpi_get_timer_resolution(&acpi_timer_source.resolution);
    acpi_timer_source.ticks_per_ns = &acpi_timer_ticks_per_ns;

    register_clock_source(&acpi_timer_source);

    hrtime_t t0 = clocksource_get_time();

    (void) t0;
    // while(true) {}
    return 0;
}

uint64_t acpi_timer_get_ticks()
{
    uint32_t ticks;
    acpi_get_timer(&ticks);
    return ticks;
}

hrtime_t acpi_timer_get_elapsed_ns(hrtime_t old_ticks_, hrtime_t new_ticks_)
{
    /* Forced to rewrite this because AcpiGetTimerDuration works with
     * microseconds instead of nanoseconds like we want
     */
    uint32_t delta = 0;

    /* Convert these to uint32_t's since the timer's resolution is 32-bit max. */
    uint32_t old_ticks = (uint32_t) old_ticks_;
    uint32_t new_ticks = (uint32_t) new_ticks_;

    if (old_ticks < new_ticks)
    {
        delta = new_ticks - old_ticks;
    }
    else if (old_ticks == new_ticks)
    {
        return 0;
    }
    else
    {
        unsigned int res;
        acpi_get_timer_resolution(&res);

        if (res == 24)
        {
            delta = ((0x00ffffff - old_ticks) + new_ticks) & 0x00ffffff;
        }
        else if (res == 32)
        {
            delta = (0xffffffff - old_ticks) + new_ticks;
        }
        else
        {
            ERROR("acpi_pm_timer", "Unknown timer resolution\n");
        }
    }

    unsigned int delta_time = delta * NS_PER_SEC / ACPI_PM_TIMER_FREQUENCY;
    return delta_time;
}

bool acpi_driver_supports_device(driver *driver, acpi_device *device)
{
    struct acpi_dev_id *dev_table = (acpi_dev_id *) driver->devids;

    for (; dev_table->devid != nullptr; dev_table++)
    {
        // Test the hardware id and class id for equality
        auto device_info = device->info;
        if (device_info->valid & ACPI_VALID_HID)
        {
            if (!strcmp(device_info->hardware_id.string, dev_table->devid))
                return true;
        }

        if (device_info->valid & ACPI_VALID_CID)
        {
            for (unsigned int i = 0; i < device_info->compatible_id_list.count; i++)
            {
                if (!strcmp(device_info->compatible_id_list.ids[i].string, dev_table->devid))
                    return true;
            }
        }

        if (!strcmp(device->name, dev_table->devid))
        {
            return true;
        }
    }

    return false;
}

bus_type acpi_type{"acpi"};

void acpi_bus_register_driver(struct driver *driver)
{
    acpi_type.add_driver(driver);

    // TODO: Move this to the bus implementation
    list_for_every (&acpi_bus.device_list_head)
    {
        acpi_device *dev = list_head_cpp<acpi_device>::self_from_list_head(l);
        if (acpi_driver_supports_device(driver, dev))
        {
            driver_register_device(driver, dev);
            if (driver->probe(dev) < 0)
                driver_deregister_device(driver, dev);
        }
    }
}
