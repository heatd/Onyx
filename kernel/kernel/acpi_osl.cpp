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

ACPI_STATUS AcpiOsInitialize()
{
    printf("ACPI initializing!\n");
    return AE_OK;
}

ACPI_STATUS AcpiOsShutdown()
{
    return AE_OK;
}

ACPI_PHYSICAL_ADDRESS AcpiOsGetRootPointer()
{
    return (ACPI_PHYSICAL_ADDRESS) acpi_get_rsdp();
}

ACPI_STATUS AcpiOsPredefinedOverride(const ACPI_PREDEFINED_NAMES *PredefinedObject,
                                     ACPI_STRING *NewValue)
{
    *NewValue = nullptr;
    return AE_OK;
}

ACPI_STATUS AcpiOsTableOverride(ACPI_TABLE_HEADER *ExistingTable, ACPI_TABLE_HEADER **NewTable)
{
    *NewTable = nullptr;
    return AE_OK;
}

#define DEBUG_ACPICA 0

void *AcpiOsMapMemory(ACPI_PHYSICAL_ADDRESS PhysicalAddress, ACPI_SIZE Length)
{
#if DEBUG_ACPICA
    printf("map %lx", PhysicalAddress);
#endif
    void *addrl = (void *) (PhysicalAddress + PHYS_BASE);
    return addrl;
}

void AcpiOsUnmapMemory(void *where, ACPI_SIZE Length)
{
    size_t pages = Length / 4096;
    if (Length % 4096)
        pages++;
    (void) where;
    (void) pages;
}

ACPI_STATUS AcpiOsGetPhysicalAddress(void *LogicalAddress, ACPI_PHYSICAL_ADDRESS *PhysicalAddress)
{
    *PhysicalAddress = (ACPI_PHYSICAL_ADDRESS) virtual2phys(LogicalAddress);
    return AE_OK;
}

void *AcpiOsAllocate(ACPI_SIZE Size)
{
    return malloc(Size);
}

void AcpiOsFree(void *Memory)
{
    free(Memory);
}

/* On the OSDev wiki it says it's never used, so I don't need to
 * implement this right now (all memory should be readable anyway)
 */
BOOLEAN AcpiOsReadable(void *Memory, ACPI_SIZE Length)
{
    return true;
}
/* On the OSDev wiki it says it's never used, so I don't need to
 * implement this right now (all memory should be writable anyway)
 */
BOOLEAN AcpiOsWritable(void *Memory, ACPI_SIZE Length)
{
    return true;
}

ACPI_THREAD_ID AcpiOsGetThreadId()
{
    thread_t *thread = get_current_thread();
    if (!thread)
        return 1;
    return get_current_thread()->id;
}

ACPI_STATUS AcpiOsExecute(ACPI_EXECUTE_TYPE Type, ACPI_OSD_EXEC_CALLBACK Function, void *Context)
{
    struct dpc_work w;
    w.context = Context;
    w.funcptr = Function;

    /* TODO: Something tells me these callbacks may sleep, and henceforth they're not
     * okay to use in dpc contexts, where latency is key.
     */

    /* My really crappy fix that doesn't fix a lot right now is to set the priority to LOW */
    if (dpc_schedule_work(&w, DPC_PRIORITY_LOW) < 0)
        return AE_NO_MEMORY;

    return AE_OK;
}

void AcpiOsWaitEventsComplete(void)
{
    /* TODO: This is impossible to implement right now */
}

void AcpiOsSleep(UINT64 Milliseconds)
{
    /* Without this check, the kernel might crash at early boot, when we don't have a thread */
    if (get_current_thread())
        sched_sleep_ms(Milliseconds);
}

void AcpiOsStall(UINT32 Microseconds)
{
    hrtime_t orig_us = clocksource_get_time() / NS_PER_US;

    while ((clocksource_get_time() / NS_PER_US) - orig_us < Microseconds)
        cpu_relax();
}

/* Do all these undefs to satisfy vscode, whose intellisense defines __linux__, etc */
#undef AcpiOsCreateMutex
#undef AcpiOsDeleteMutex
#undef AcpiOsAcquireMutex
#undef AcpiOsReleaseMutex

ACPI_STATUS AcpiOsCreateMutex(ACPI_MUTEX *OutHandle)
{
    *OutHandle = (mutex *) AcpiOsAllocateZeroed(sizeof(struct mutex));
    if (*OutHandle == nullptr)
        return AE_NO_MEMORY;
    mutex_init((mutex *) *OutHandle);
    return AE_OK;
}

void AcpiOsDeleteMutex(ACPI_MUTEX Handle)
{
    free(Handle);
}

// TODO: Implement Timeout
ACPI_STATUS AcpiOsAcquireMutex(ACPI_MUTEX Handle, UINT16 Timeout)
{
    mutex_lock((mutex *) Handle);
    return AE_OK;
}

void AcpiOsReleaseMutex(ACPI_MUTEX Handle)
{
    mutex_unlock((mutex *) Handle);
}

ACPI_STATUS AcpiOsCreateSemaphore(UINT32 MaxUnits, UINT32 InitialUnits, ACPI_SEMAPHORE *OutHandle)
{
    *OutHandle = (semaphore *) AcpiOsAllocateZeroed(sizeof(struct semaphore));
    if (*OutHandle == nullptr)
        return AE_NO_MEMORY;
    sem_init((semaphore *) *OutHandle, InitialUnits);
    return AE_OK;
}

ACPI_STATUS AcpiOsDeleteSemaphore(ACPI_SEMAPHORE Handle)
{
    free(Handle);
    return AE_OK;
}

/* TODO: Same as above, Timeout. */
ACPI_STATUS AcpiOsWaitSemaphore(ACPI_SEMAPHORE Handle, UINT32 Units, UINT16 Timeout)
{
    while (Units--)
        sem_wait((semaphore *) Handle);

    return AE_OK;
}

ACPI_STATUS AcpiOsSignalSemaphore(ACPI_SEMAPHORE Handle, UINT32 Units)
{
    while (Units--)
        sem_signal((semaphore *) Handle);
    return AE_OK;
}

ACPI_STATUS AcpiOsCreateLock(ACPI_SPINLOCK *OutHandle)
{
    *OutHandle = (spinlock *) AcpiOsAllocateZeroed(sizeof(struct spinlock));
    if (*OutHandle == nullptr)
        return AE_NO_MEMORY;

    spinlock_init((spinlock *) *OutHandle);
    return AE_OK;
}

void AcpiOsDeleteLock(ACPI_SPINLOCK Handle)
{
    free(Handle);
}

ACPI_CPU_FLAGS AcpiOsAcquireLock(ACPI_SPINLOCK Handle)
{
    return spin_lock_irqsave((spinlock *) Handle);
}

void AcpiOsReleaseLock(ACPI_SPINLOCK Handle, ACPI_CPU_FLAGS Flags)
{
    spin_unlock_irqrestore((spinlock *) Handle, Flags);
}

ACPI_OSD_HANDLER ServiceRout;

irqstatus_t acpi_sci_irq(struct irq_context *ctx, void *cookie)
{
    ServiceRout(cookie);
    return IRQ_HANDLED;
}

struct driver acpi_driver = {.name = "acpi", .bus_type_node = {&acpi_driver}};

extern bus acpi_bus;
static struct device acpi_dev
{
    "acpi_sci", &acpi_bus, nullptr
};

ACPI_STATUS AcpiOsInstallInterruptHandler(UINT32 InterruptLevel, ACPI_OSD_HANDLER Handler,
                                          void *Context)
{
    acpi_dev.driver_ = &acpi_driver;
    assert(install_irq(InterruptLevel, acpi_sci_irq, &acpi_dev, IRQ_FLAG_REGULAR, Context) == 0);
    ServiceRout = Handler;

    return AE_OK;
}

ACPI_STATUS AcpiOsRemoveInterruptHandler(UINT32 InterruptNumber, ACPI_OSD_HANDLER Handler)
{
    free_irq(InterruptNumber, &acpi_dev);
    ServiceRout = nullptr;
    return AE_OK;
}

ACPI_STATUS AcpiOsReadMemory(ACPI_PHYSICAL_ADDRESS Address, UINT64 *Value, UINT32 Width)
{
    void *ptr;
    ptr = AcpiOsMapMemory(Address, 4096);
    *Value = *(UINT64 *) ptr;
    if (Width == 8)
        *Value &= 0xFF;
    else if (Width == 16)
        *Value &= 0xFFFF;
    else if (Width == 32)
        *Value &= 0xFFFFFFFF;
    AcpiOsUnmapMemory(ptr, 4096);
    return AE_OK;
}

ACPI_STATUS AcpiOsWriteMemory(ACPI_PHYSICAL_ADDRESS Address, UINT64 Value, UINT32 Width)
{
    UINT64 *ptr;
    ptr = (UINT64 *) AcpiOsMapMemory(Address, 4096);
    if (Width == 8)
        *ptr = Value & 0xFF;
    else if (Width == 16)
        *ptr = Value & 0xFFFF;
    else if (Width == 32)
        *ptr = Value & 0xFFFFFFFF;
    else
        *ptr = Value;
    return AE_OK;
}

ACPI_STATUS AcpiOsReadPort(ACPI_IO_ADDRESS Address, UINT32 *Value, UINT32 Width)
{
    if (Width == 8)
        *Value = inb(Address);
    else if (Width == 16)
        *Value = inw(Address);
    else if (Width == 32)
        *Value = inl(Address);
    return AE_OK;
}

ACPI_STATUS AcpiOsWritePort(ACPI_IO_ADDRESS Address, UINT32 Value, UINT32 Width)
{
    if (Width == 8)
        outb(Address, (uint8_t) Value);
    else if (Width == 16)
        outw(Address, (uint16_t) Value);
    else if (Width == 32)
        outl(Address, Value);
    return AE_OK;
}

ACPI_STATUS AcpiOsWritePciConfiguration(ACPI_PCI_ID *PciId, UINT32 Register, UINT64 Value,
                                        UINT32 Width)
{
    pci::device_address addr;
    addr.segment = PciId->Segment;
    addr.bus = (uint8_t) PciId->Bus;
    addr.device = (uint8_t) PciId->Device;
    addr.function = (uint8_t) PciId->Function;

    pci::write_config(addr, Value, Register, Width / 8);
    return AE_OK;
}

ACPI_STATUS AcpiOsReadPciConfiguration(ACPI_PCI_ID *PciId, UINT32 Register, UINT64 *Value,
                                       UINT32 Width)
{
    pci::device_address addr;
    addr.segment = PciId->Segment;
    addr.bus = (uint8_t) PciId->Bus;
    addr.device = (uint8_t) PciId->Device;
    addr.function = (uint8_t) PciId->Function;

    *Value = pci::read_config(addr, (uint16_t) Register, Width / 8);
    return AE_OK;
}

ACPI_STATUS AcpiOsPhysicalTableOverride(ACPI_TABLE_HEADER *ExistingTable,
                                        ACPI_PHYSICAL_ADDRESS *NewAddress, UINT32 *NewTableLength)
{
    *NewAddress = 0;
    return AE_OK;
}

void AcpiOsPrintf(const char *Format, ...)
{
    va_list params;
    va_start(params, Format);
    vprintf(Format, params);
    va_end(params);
}

ACPI_STATUS AcpiOsSignal(UINT32 Function, void *Info)
{
    panic("Acpi Signal called!");
    return AE_OK;
}

UINT64 AcpiOsGetTimer(void)
{
    /* Time is returned in 100ns units */
    return clocksource_get_time() / 100;
}

ACPI_STATUS
AcpiOsTerminate()
{
    return AE_OK;
}

void AcpiOsVprintf(const char *Fmt, va_list Args)
{
    vprintf(Fmt, Args);
}

ACPI_STATUS AcpiOsEnterSleep(UINT8 SleepState, UINT32 RegaValue, UINT32 RegbValue)
{
    return AE_OK;
}

ACPI_STATUS
AcpiOsCreateCache(char *CacheName, UINT16 ObjectSize, UINT16 MaxDepth, ACPI_CACHE_T **ReturnCache)
{
    *ReturnCache = kmem_cache_create(CacheName, ObjectSize, 0, 0, nullptr);
    if (*ReturnCache == nullptr)
        return AE_NO_MEMORY;
    return AE_OK;
}

ACPI_STATUS
AcpiOsPurgeCache(ACPI_CACHE_T *Cache)
{
    kmem_cache_purge(Cache);
    return AE_OK;
}

ACPI_STATUS
AcpiOsDeleteCache(ACPI_CACHE_T *Cache)
{
    kmem_cache_destroy(Cache);
    return AE_OK;
}

ACPI_STATUS
AcpiOsReleaseObject(ACPI_CACHE_T *Cache, void *Object)
{
    kmem_cache_free(Cache, Object);
    return AE_OK;
}

void *AcpiOsAcquireObject(ACPI_CACHE_T *Cache)
{
    auto ptr = kmem_cache_alloc(Cache, 0);
    if (ptr)
    {
        memset(ptr, 0, Cache->objsize);
    }

    return ptr;
}
}
