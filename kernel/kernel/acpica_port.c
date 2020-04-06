/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
/* File: acpica_port.c. It's here as the OS layer for ACPICA */

#include <stdio.h>
#include <acpi.h>
#include <limits.h>
#include <assert.h>

#include <onyx/vm.h>
#include <onyx/irq.h>
#include <onyx/portio.h>
#include <onyx/panic.h>
#include <onyx/task_switching.h>
#include <onyx/timer.h>
#include <onyx/slab.h>
#include <onyx/acpi.h>
#include <onyx/cpu.h>

#include <pci/pci.h>

void spinlock_lock(unsigned long*);
void spinlock_unlock(unsigned long*);
int printf(const char *, ...);
extern const uint16_t CONFIG_ADDRESS;
extern const uint16_t CONFIG_DATA;

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

ACPI_STATUS AcpiOsPredefinedOverride(const ACPI_PREDEFINED_NAMES *PredefinedObject, ACPI_STRING *NewValue)
{
	*NewValue = NULL;
	return AE_OK;
}

ACPI_STATUS AcpiOsTableOverride(ACPI_TABLE_HEADER *ExistingTable, ACPI_TABLE_HEADER **NewTable)
{
	*NewTable = NULL;
	return AE_OK;
}

#define DEBUG_ACPICA 0

void *AcpiOsMapMemory(ACPI_PHYSICAL_ADDRESS PhysicalAddress, ACPI_SIZE Length)
{
#if DEBUG_ACPICA
	printf("map %lx", PhysicalAddress);
#endif
	void *addrl = (void*)(PhysicalAddress + PHYS_BASE);
	return addrl;
}

void AcpiOsUnmapMemory(void *where, ACPI_SIZE Length)
{
	size_t pages = Length / 4096;
	if(Length % 4096)
		pages++;
	(void)where;
	//Memory::Unmap(where, pages);
	//Memory::ReleaseLockedPages(where);
}

ACPI_STATUS AcpiOsGetPhysicalAddress(void *LogicalAddress, ACPI_PHYSICAL_ADDRESS *PhysicalAddress)
{
	*PhysicalAddress = (ACPI_PHYSICAL_ADDRESS)virtual2phys(LogicalAddress);
	return AE_OK;
}

#include <onyx/mm/kasan.h>

void *AcpiOsAllocate(ACPI_SIZE Size)
{	
	void *ptr = malloc(Size);
	if(!ptr)
		printf("Allocation failed with size %lu\n", Size);
	return ptr;
}

void AcpiOsFree(void *Memory)
{
	free(Memory);
}
// On the OSDev wiki it says it's never used, so I don't need to implement this right now(all memory should be readable anyway)
BOOLEAN AcpiOsReadable(void * Memory, ACPI_SIZE Length)
{
	return 1;
}
// On the OSDev wiki it says it's never used, so I don't need to implement this right now(all memory should be writable anyway)
BOOLEAN AcpiOsWritable(void * Memory, ACPI_SIZE Length)
{
	return 1;
}
ACPI_THREAD_ID AcpiOsGetThreadId()
{
	thread_t *thread = get_current_thread();
	if(!thread)
		return 1;
	return get_current_thread()->id;
}
ACPI_STATUS AcpiOsExecute(ACPI_EXECUTE_TYPE Type, ACPI_OSD_EXEC_CALLBACK Function, void * Context)
{
	printk("Hello");
	thread_t *thread = NULL;
	if(!(thread = sched_create_thread((thread_callback_t) Function, 1, Context)))
		return AE_NO_MEMORY;
	sched_start_thread(thread);
	return AE_OK;
}

void AcpiOsSleep(UINT64 Milliseconds)
{
	/* Without this check, the kernel might crash at early boot, when we don't have a thread */
	if(get_current_thread())
		sched_sleep_ms(Milliseconds);
}

void AcpiOsStall(UINT32 Microseconds)
{
	uint64_t orig_us = get_microseconds();

	while(get_microseconds() != orig_us + Microseconds)
		cpu_relax();
}

ACPI_STATUS AcpiOsCreateMutex(ACPI_MUTEX *OutHandle)
{
	*OutHandle = AcpiOsAllocateZeroed(sizeof(ACPI_MUTEX));
	if(*OutHandle == NULL)	return AE_NO_MEMORY;
	return AE_OK;
}

void AcpiOsDeleteMutex(ACPI_MUTEX Handle)
{
	free(Handle);
}

// TODO: Implement Timeout
ACPI_STATUS AcpiOsAcquireMutex(ACPI_MUTEX Handle, UINT16 Timeout)
{
	spinlock_lock((unsigned long*) Handle);
	return AE_OK;
}

void AcpiOsReleaseMutex(ACPI_MUTEX Handle)
{
	spinlock_unlock((unsigned long*) Handle);
}

// TODO: Implement Semaphores (should be pretty simple)
ACPI_STATUS AcpiOsCreateSemaphore(UINT32 MaxUnits, UINT32 InitialUnits, ACPI_SEMAPHORE * OutHandle)
{
	*OutHandle = AcpiOsAllocateZeroed(sizeof(ACPI_MUTEX));
	if(*OutHandle == NULL) return AE_NO_MEMORY;
	return AE_OK;
}

ACPI_STATUS AcpiOsDeleteSemaphore(ACPI_SEMAPHORE Handle)
{
	free(Handle);
	return AE_OK;
}

ACPI_STATUS AcpiOsWaitSemaphore(ACPI_SEMAPHORE Handle, UINT32 Units, UINT16 Timeout)
{
	return AE_OK;
}

ACPI_STATUS AcpiOsSignalSemaphore(ACPI_SEMAPHORE Handle, UINT32 Units)
{
	return AE_OK;
}

ACPI_STATUS AcpiOsCreateLock(ACPI_SPINLOCK *OutHandle)
{
	*OutHandle = AcpiOsAllocateZeroed(sizeof(ACPI_SPINLOCK));
	if(*OutHandle == NULL) return AE_NO_MEMORY;
	return AE_OK;
}

void AcpiOsDeleteLock(ACPI_HANDLE Handle)
{
	free(Handle);
}

ACPI_CPU_FLAGS AcpiOsAcquireLock(ACPI_SPINLOCK Handle)
{
	spinlock_lock((unsigned long*)Handle);
	return 0;
}

void AcpiOsReleaseLock(ACPI_SPINLOCK Handle, ACPI_CPU_FLAGS Flags)
{
	spinlock_unlock((unsigned long*)Handle);
}

ACPI_OSD_HANDLER ServiceRout;

irqstatus_t acpi_sci_irq(struct irq_context *ctx, void *cookie)
{
	ServiceRout(cookie);
	return IRQ_HANDLED;
}

struct driver acpi_driver =
{
	.name = "acpi"
};

static struct device dev =
{
	.name = "acpi_sci",
	.driver = &acpi_driver
};

ACPI_STATUS AcpiOsInstallInterruptHandler(UINT32 InterruptLevel, ACPI_OSD_HANDLER Handler, void *Context)
{
	assert(install_irq(InterruptLevel, acpi_sci_irq, &dev,
		IRQ_FLAG_REGULAR, Context) == 0);
	ServiceRout = Handler;

	return AE_OK;
}

ACPI_STATUS AcpiOsRemoveInterruptHandler(UINT32 InterruptNumber, ACPI_OSD_HANDLER Handler)
{
	free_irq(InterruptNumber, &dev);
	ServiceRout = NULL;
	return AE_OK;
}

ACPI_STATUS AcpiOsReadMemory ( ACPI_PHYSICAL_ADDRESS Address, UINT64 *Value, UINT32 Width)
{
	void *ptr;
	ptr = AcpiOsMapMemory(Address, 4096);
	*Value = *(UINT64*) ptr;
	if(Width == 8)
		*Value &= 0xFF;
	else if(Width == 16)
		*Value &= 0xFFFF;
	else if(Width == 32)
		*Value &= 0xFFFFFFFF;
	AcpiOsUnmapMemory(ptr, 4096);
	return AE_OK;
}

ACPI_STATUS AcpiOsWriteMemory ( ACPI_PHYSICAL_ADDRESS Address, UINT64 Value, UINT32 Width)
{
	UINT64 *ptr;
	ptr = (UINT64*)AcpiOsMapMemory(Address, 4096);
	if(Width == 8)
		*ptr = Value & 0xFF;
	else if(Width == 16)
		*ptr = Value & 0xFFFF;
	else if(Width == 32)
		*ptr = Value & 0xFFFFFFFF;
	else
		*ptr = Value;
	return AE_OK;
}

ACPI_STATUS AcpiOsReadPort (ACPI_IO_ADDRESS Address, UINT32 *Value, UINT32 Width)
{
	if(Width == 8)
		*Value = inb(Address);
	else if(Width == 16)
		*Value = inw(Address);
	else if(Width == 32)
		*Value = inl(Address);
	return AE_OK;
}

ACPI_STATUS AcpiOsWritePort (ACPI_IO_ADDRESS Address, UINT32 Value, UINT32 Width)
{
	if(Width == 8)
		outb(Address, (uint8_t)Value);
	else if(Width == 16)
		outw(Address, (uint16_t)Value);
	else if(Width == 32)
		outl(Address, Value);
	return AE_OK;
}

ACPI_STATUS AcpiOsWritePciConfiguration (ACPI_PCI_ID *PciId, UINT32 Register, UINT64 Value, UINT32 Width)
{
	if(Width == 8)
		__pci_write_byte(PciId->Bus, PciId->Device, PciId->Function, Register, (uint8_t)Value);
	if(Width == 16)
		__pci_write_word(PciId->Bus, PciId->Device, PciId->Function, Register, (uint16_t)Value);
	if(Width == 32)
		__pci_write_dword(PciId->Bus, PciId->Device, PciId->Function, Register, (uint32_t)Value);
	if(Width == 64)
		__pci_write_qword(PciId->Bus, PciId->Device, PciId->Function, Register, Value);
	return AE_OK;
}

uint64_t __pci_read(struct pci_device *dev, uint16_t off, size_t size);

ACPI_STATUS AcpiOsReadPciConfiguration(ACPI_PCI_ID *PciId, UINT32 Register, UINT64 *Value, UINT32 Width)
{
	struct pci_device_address addr;
	addr.segment = PciId->Segment;
	addr.bus = (uint8_t) PciId->Bus;
	addr.device = (uint8_t) PciId->Device;
	addr.function = (uint8_t) PciId->Function;
	struct pci_device *dev = pci_get_dev(&addr);
	if(!dev)
	{
		struct pci_device fake_dev;
		fake_dev.segment = addr.segment;
		fake_dev.bus = addr.bus;
		fake_dev.device = addr.device;
		fake_dev.function = addr.function;
		fake_dev.read = __pci_read;
		*Value = pci_read(&fake_dev, (uint16_t) Register, Width / 8);

		return AE_OK;
	}
	
	*Value = pci_read(dev, (uint16_t) Register, Width / 8);
	return AE_OK;
}

ACPI_STATUS
AcpiOsPhysicalTableOverride (
ACPI_TABLE_HEADER * ExistingTable,
ACPI_PHYSICAL_ADDRESS *NewAddress,
UINT32 * NewTableLength)
{
	*NewAddress = 0;
	return AE_OK;
}

void AcpiOsPrintf (
const char *Format, ...)
{
	va_list params;
	va_start(params, Format);
	vprintf(Format, params);
	va_end(params);
}

void
AcpiOsWaitEventsComplete (
void)
{
	return;
}

ACPI_STATUS
AcpiOsSignal (
UINT32 Function,
void *Info)
{
	panic("Acpi Signal called!");
	return AE_OK;
}

UINT64
AcpiOsGetTimer (
void)
{
	return get_tick_count();
}

ACPI_STATUS
AcpiOsTerminate()
{
	return AE_OK;
}

int isprint(int ch)
{
	return 1;
}

void
AcpiOsVprintf(const char *Fmt, va_list Args)
{
	vprintf(Fmt, Args);
}

ACPI_STATUS
AcpiOsEnterSleep (
    UINT8                   SleepState,
    UINT32                  RegaValue,
    UINT32                  RegbValue)
    {
	    return AE_OK;
    }

#if 0
ACPI_STATUS
AcpiOsCreateCache (
    char                    *CacheName,
    UINT16                  ObjectSize,
    UINT16                  MaxDepth,
    ACPI_CACHE_T        **ReturnCache)
{
	*ReturnCache = slab_create(CacheName, ObjectSize, 0, 0, NULL, NULL);
	return AE_OK;
}

ACPI_STATUS
AcpiOsPurgeCache (
    ACPI_CACHE_T        *Cache)
{
	slab_purge(Cache);
	return AE_OK;
}

ACPI_STATUS
AcpiOsDeleteCache (
    ACPI_CACHE_T        *Cache)
{
	slab_destroy(Cache);
	return AE_OK;

}

ACPI_STATUS
AcpiOsReleaseObject (
    ACPI_CACHE_T        *Cache,
    void                    *Object)
    {
	slab_free(Cache, Object);
    	return AE_OK;
    }

void *
AcpiOsAcquireObject (
    ACPI_CACHE_T        *Cache)
{
	return slab_allocate(Cache);
}
#endif