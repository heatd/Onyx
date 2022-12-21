/*
 * Copyright (c) 2016 - 2022 Pedro Falcato
 * This file is part of Onyx, and is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
/* File: acpi_osl.cpp, It's here as the OS layer for ACPICA */

#include <assert.h>
#include <stdio.h>

#include <onyx/acpi.h>
#include <onyx/cpu.h>
#include <onyx/dpc.h>
#include <onyx/irq.h>
#include <onyx/limits.h>
#include <onyx/mm/slab.h>
#include <onyx/panic.h>
#include <onyx/port_io.h>
#include <onyx/scheduler.h>
#include <onyx/semaphore.h>
#include <onyx/task_switching.h>
#include <onyx/timer.h>
#include <onyx/vm.h>

#include <pci/pci.h>

uint64_t __pci_read(pci::pci_device *dev, uint16_t off, size_t size);

extern "C"
{

acpi_status acpi_os_initialize()
{
    printf("ACPI initializing!\n");
    return AE_OK;
}

acpi_status acpi_os_shutdown()
{
    return AE_OK;
}

acpi_physical_address acpi_os_get_root_pointer()
{
    return (acpi_physical_address) acpi_get_rsdp();
}

acpi_status acpi_os_predefined_override(const acpi_predefined_names *predefined_object,
                                        acpi_string *new_value)
{
    *new_value = nullptr;
    return AE_OK;
}

acpi_status acpi_os_table_override(acpi_table_header *existing_table, acpi_table_header **new_table)
{
    *new_table = nullptr;
    return AE_OK;
}

#define DEBUG_ACPICA 0

void *acpi_os_map_memory(acpi_physical_address physical_address, acpi_size length)
{
#if DEBUG_ACPICA
    printf("map %lx", PhysicalAddress);
#endif
    void *addrl = (void *) (physical_address + PHYS_BASE);
    return addrl;
}

void acpi_os_unmap_memory(void *where, acpi_size length)
{
    size_t pages = length / 4096;
    if (length % 4096)
        pages++;
    (void) where;
    (void) pages;
}

acpi_status acpi_os_get_physical_address(void *logical_address,
                                         acpi_physical_address *physical_address)
{
    *physical_address = (acpi_physical_address) virtual2phys(logical_address);
    return AE_OK;
}

void *acpi_os_allocate(acpi_size size)
{
    return malloc(size);
}

void acpi_os_free(void *memory)
{
    free(memory);
}

/* On the OSDev wiki it says it's never used, so I don't need to
 * implement this right now (all memory should be readable anyway)
 */
u8 acpi_os_readable(void *memory, acpi_size length)
{
    return true;
}
/* On the OSDev wiki it says it's never used, so I don't need to
 * implement this right now (all memory should be writable anyway)
 */
u8 acpi_os_writable(void *memory, acpi_size length)
{
    return true;
}

acpi_thread_id acpi_os_get_thread_id()
{
    thread_t *thread = get_current_thread();
    if (!thread)
        return 1;
    return get_current_thread()->id;
}

acpi_status acpi_os_execute(acpi_execute_type type, acpi_osd_exec_callback function, void *context)
{
    struct dpc_work w;
    w.context = context;
    w.funcptr = function;

    /* TODO: Something tells me these callbacks may sleep, and henceforth they're not
     * okay to use in dpc contexts, where latency is key.
     */

    /* My really crappy fix that doesn't fix a lot right now is to set the priority to LOW */
    if (dpc_schedule_work(&w, DPC_PRIORITY_LOW) < 0)
        return AE_NO_MEMORY;

    return AE_OK;
}

void acpi_os_wait_events_complete(void)
{
    /* TODO: This is impossible to implement right now */
}

void acpi_os_sleep(u64 milliseconds)
{
    /* Without this check, the kernel might crash at early boot, when we don't have a thread */
    if (get_current_thread())
        sched_sleep_ms(milliseconds);
}

void acpi_os_stall(u32 microseconds)
{
    hrtime_t orig_us = clocksource_get_time() / NS_PER_US;

    while ((clocksource_get_time() / NS_PER_US) - orig_us < microseconds)
        cpu_relax();
}

acpi_status acpi_os_create_mutex(acpi_mutex *out_handle)
{
    *out_handle = (mutex *) acpi_os_allocate_zeroed(sizeof(struct mutex));
    if (*out_handle == nullptr)
        return AE_NO_MEMORY;
    mutex_init((mutex *) *out_handle);
    return AE_OK;
}

void acpi_os_delete_mutex(acpi_mutex handle)
{
    free(handle);
}

// TODO: Implement Timeout
acpi_status acpi_os_acquire_mutex(acpi_mutex handle, u16 timeout)
{
    mutex_lock((mutex *) handle);
    return AE_OK;
}

void acpi_os_release_mutex(acpi_mutex handle)
{
    mutex_unlock((mutex *) handle);
}

acpi_status acpi_os_create_semaphore(u32 max_units, u32 initial_units, acpi_semaphore *out_handle)
{
    *out_handle = (semaphore *) acpi_os_allocate_zeroed(sizeof(struct semaphore));
    if (*out_handle == nullptr)
        return AE_NO_MEMORY;
    sem_init((semaphore *) *out_handle, initial_units);
    return AE_OK;
}

acpi_status acpi_os_delete_semaphore(acpi_semaphore handle)
{
    free(handle);
    return AE_OK;
}

/* TODO: Same as above, Timeout. */
acpi_status acpi_os_wait_semaphore(acpi_semaphore handle, u32 units, u16 timeout)
{
    while (units--)
        sem_wait((semaphore *) handle);

    return AE_OK;
}

acpi_status acpi_os_signal_semaphore(acpi_semaphore handle, u32 units)
{
    while (units--)
        sem_signal((semaphore *) handle);
    return AE_OK;
}

acpi_status acpi_os_create_lock(acpi_spinlock *out_handle)
{
    *out_handle = (spinlock *) acpi_os_allocate_zeroed(sizeof(struct spinlock));
    if (*out_handle == nullptr)
        return AE_NO_MEMORY;

    spinlock_init((spinlock *) *out_handle);
    return AE_OK;
}

void acpi_os_delete_lock(acpi_spinlock handle)
{
    free(handle);
}

acpi_cpu_flags acpi_os_acquire_lock(acpi_spinlock handle)
{
    return spin_lock_irqsave((spinlock *) handle);
}

void acpi_os_release_lock(acpi_spinlock handle, acpi_cpu_flags flags)
{
    spin_unlock_irqrestore((spinlock *) handle, flags);
}

acpi_osd_handler service_rout;

irqstatus_t acpi_sci_irq(struct irq_context *ctx, void *cookie)
{
    service_rout(cookie);
    return IRQ_HANDLED;
}

struct driver acpi_driver = {.name = "acpi", .bus_type_node = {&acpi_driver}};

extern bus acpi_bus;
static struct device acpi_dev
{
    "acpi_sci", &acpi_bus, nullptr
};

acpi_status acpi_os_install_interrupt_handler(u32 interrupt_level, acpi_osd_handler handler,
                                              void *context)
{
    acpi_dev.driver_ = &acpi_driver;
    assert(install_irq(interrupt_level, acpi_sci_irq, &acpi_dev, IRQ_FLAG_REGULAR, context) == 0);
    service_rout = handler;

    return AE_OK;
}

acpi_status acpi_os_remove_interrupt_handler(u32 interrupt_number, acpi_osd_handler handler)
{
    free_irq(interrupt_number, &acpi_dev);
    service_rout = nullptr;
    return AE_OK;
}

acpi_status acpi_os_read_memory(acpi_physical_address address, u64 *value, u32 width)
{
    void *ptr;
    ptr = acpi_os_map_memory(address, 4096);
    *value = *(u64 *) ptr;
    if (width == 8)
        *value &= 0xFF;
    else if (width == 16)
        *value &= 0xFFFF;
    else if (width == 32)
        *value &= 0xFFFFFFFF;
    acpi_os_unmap_memory(ptr, 4096);
    return AE_OK;
}

acpi_status acpi_os_write_memory(acpi_physical_address address, u64 value, u32 width)
{
    u64 *ptr;
    ptr = (u64 *) acpi_os_map_memory(address, 4096);
    if (width == 8)
        *ptr = value & 0xFF;
    else if (width == 16)
        *ptr = value & 0xFFFF;
    else if (width == 32)
        *ptr = value & 0xFFFFFFFF;
    else
        *ptr = value;
    return AE_OK;
}

acpi_status acpi_os_read_port(acpi_io_address address, u32 *value, u32 width)
{
    if (width == 8)
        *value = inb(address);
    else if (width == 16)
        *value = inw(address);
    else if (width == 32)
        *value = inl(address);
    return AE_OK;
}

acpi_status acpi_os_write_port(acpi_io_address address, u32 value, u32 width)
{
    if (width == 8)
        outb(address, (uint8_t) value);
    else if (width == 16)
        outw(address, (uint16_t) value);
    else if (width == 32)
        outl(address, value);
    return AE_OK;
}

acpi_status acpi_os_write_pci_configuration(acpi_pci_id *pci_id, u32 reg, u64 value, u32 width)
{
    pci::device_address addr;
    addr.segment = pci_id->segment;
    addr.bus = (uint8_t) pci_id->bus;
    addr.device = (uint8_t) pci_id->device;
    addr.function = (uint8_t) pci_id->function;

    pci::write_config(addr, value, reg, width / 8);
    return AE_OK;
}

acpi_status acpi_os_read_pci_configuration(acpi_pci_id *pci_id, u32 reg, u64 *value, u32 width)
{
    pci::device_address addr;
    addr.segment = pci_id->segment;
    addr.bus = (uint8_t) pci_id->bus;
    addr.device = (uint8_t) pci_id->device;
    addr.function = (uint8_t) pci_id->function;

    *value = pci::read_config(addr, (uint16_t) reg, width / 8);
    return AE_OK;
}

acpi_status acpi_os_physical_table_override(acpi_table_header *existing_table,
                                            acpi_physical_address *new_address,
                                            u32 *new_table_length)
{
    *new_address = 0;
    return AE_OK;
}

void acpi_os_printf(const char *format, ...)
{
    va_list params;
    va_start(params, format);
    vprintf(format, params);
    va_end(params);
}

acpi_status acpi_os_signal(u32 function, void *info)
{
    panic("Acpi Signal called!");
    return AE_OK;
}

u64 acpi_os_get_timer(void)
{
    /* Time is returned in 100ns units */
    return clocksource_get_time() / 100;
}

acpi_status acpi_os_terminate()
{
    return AE_OK;
}

void acpi_os_vprintf(const char *fmt, va_list args)
{
    vprintf(fmt, args);
}

acpi_status acpi_os_enter_sleep(u8 sleep_state, u32 rega_value, u32 regb_value)
{
    return AE_OK;
}

acpi_status acpi_os_create_cache(char *cache_name, u16 object_size, u16 max_depth,
                                 acpi_cache_t **return_cache)
{
    *return_cache = kmem_cache_create(cache_name, object_size, 0, 0, nullptr);
    if (*return_cache == nullptr)
        return AE_NO_MEMORY;
    return AE_OK;
}

acpi_status acpi_os_purge_cache(acpi_cache_t *cache)
{
    kmem_cache_purge(cache);
    return AE_OK;
}

acpi_status acpi_os_delete_cache(acpi_cache_t *cache)
{
    kmem_cache_destroy(cache);
    return AE_OK;
}

acpi_status acpi_os_release_object(acpi_cache_t *cache, void *object)
{
    kmem_cache_free(cache, object);
    return AE_OK;
}

void *acpi_os_acquire_object(acpi_cache_t *cache)
{
    auto ptr = kmem_cache_alloc(cache, 0);
    if (ptr)
    {
        memset(ptr, 0, cache->objsize);
    }

    return ptr;
}
}
