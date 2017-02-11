/*----------------------------------------------------------------------
 * Copyright (C) 2016, 2017 Pedro Falcato
 *
 * This file is part of Spartix, and is made available under
 * the terms of the GNU General Public License version 2.
 *
 * You can redistribute it and/or modify it under the terms of the GNU
 * General Public License version 2 as published by the Free Software
 * Foundation.
 *----------------------------------------------------------------------*/
/* File: acpica_port.c. It's here as the OS layer for ACPICA */
#include <stdio.h>
#include <acpi.h>

#include <kernel/vmm.h>
#include <kernel/irq.h>
#include <kernel/portio.h>
#include <kernel/panic.h>
#include <kernel/task_switching.h>
#include <kernel/timer.h>
#include <kernel/slab.h>

#include <drivers/pci.h>
#include <drivers/rtc.h>

void mutex_lock(unsigned long*);
void mutex_unlock(unsigned long*);
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
extern uintptr_t rsdp;
ACPI_PHYSICAL_ADDRESS AcpiOsGetRootPointer()
{
	return (ACPI_PHYSICAL_ADDRESS)rsdp;
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
void *AcpiOsMapMemory(ACPI_PHYSICAL_ADDRESS PhysicalAddress, ACPI_SIZE Length)
{
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
void *AcpiOsAllocate(ACPI_SIZE Size)
{	
	void *ptr = malloc(Size);
	if(!ptr)
		printf("Allocation failed with size %d\n", Size);
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
	if(!sched_create_thread((thread_callback_t)Function, 1, Context))
		return AE_NO_MEMORY;
	return AE_OK;
}
void AcpiOsSleep(UINT64 Milliseconds)
{
	/* Without this check, the kernel might crash at early boot, when we don't have a thread */
	if(get_current_thread())
		sched_sleep(Milliseconds);
}
void AcpiOsStall(UINT32 Microseconds)
{
	uint64_t orig_us = get_microseconds();

	while(get_microseconds() != orig_us + Microseconds)
		__asm__ __volatile__("pause");
}
ACPI_STATUS AcpiOsCreateMutex(ACPI_MUTEX *OutHandle)
{
	*OutHandle = AcpiOsAllocate(sizeof(ACPI_MUTEX));
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
	*OutHandle = AcpiOsAllocate(sizeof(ACPI_MUTEX));
	if(*OutHandle == NULL) return AE_NO_MEMORY;
	memset(*OutHandle, 0, sizeof(ACPI_MUTEX));
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
	*OutHandle = AcpiOsAllocate(sizeof(ACPI_SPINLOCK));
	if(*OutHandle == NULL) return AE_NO_MEMORY;
	memset(*OutHandle, 0, sizeof(ACPI_SPINLOCK));
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
void *ctx;
static uintptr_t acpi_irq(registers_t *regs)
{
	ServiceRout(ctx);
	return 0;
}
ACPI_STATUS AcpiOsInstallInterruptHandler(UINT32 InterruptLevel, ACPI_OSD_HANDLER Handler, void *Context)
{
	irq_install_handler(InterruptLevel, acpi_irq);
	ServiceRout = Handler;
	ctx = Context;
	return AE_OK;
}
ACPI_STATUS AcpiOsRemoveInterruptHandler(UINT32 InterruptNumber, ACPI_OSD_HANDLER Handler)
{
	irq_uninstall_handler(InterruptNumber, acpi_irq);
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
ACPI_STATUS AcpiOsWriteMemory ( ACPI_PHYSICAL_ADDRESS Address, UINT64 Value, UINT32 Width )
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

void pci_write_byte(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint8_t data)
{
	uint32_t address;
	uint32_t lbus  = (uint32_t)bus;
	uint32_t lslot = (uint32_t)slot;
	uint32_t lfunc = (uint32_t)func;

	/* create configuration address as per Figure 1 */
	address = (uint32_t)((lbus << 16) | (lslot << 11) |
		  (lfunc << 8) | (offset & 0xfc) | ((uint32_t)0x80000000));

	/* write out the address */
	outl (CONFIG_ADDRESS, address);
	/* read in the data */
	outb(CONFIG_DATA, data);
}

void pci_write_qword(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint64_t data)
{
	uint32_t address;
	uint32_t lbus  = (uint32_t)bus;
	uint32_t lslot = (uint32_t)slot;
	uint32_t lfunc = (uint32_t)func;

	/* create configuration address as per Figure 1 */
	address = (uint32_t)((lbus << 16) | (lslot << 11) |
		  (lfunc << 8) | (offset & 0xfc) | ((uint32_t)0x80000000));

	/* write out the address */
	outl (CONFIG_ADDRESS, address);
	/* read in the data */
	outl(CONFIG_DATA, data & 0xFFFFFFFF);
	address = (uint32_t)((lbus << 16) | (lslot << 11) |
		  (lfunc << 8) | ((offset+4) & 0xfc) | ((uint32_t)0x80000000));

	/* write out the address */
	outl (CONFIG_ADDRESS, address);
	outl(CONFIG_DATA, data & 0xFFFFFFFF00000000);
}
ACPI_STATUS AcpiOsWritePciConfiguration (ACPI_PCI_ID *PciId, UINT32 Register, UINT64 Value, UINT32 Width)
{
	if(Width == 8)
		pci_write_byte(PciId->Bus, PciId->Device, PciId->Function, Register, (uint8_t)Value);
	if(Width == 16)
		pci_write_word(PciId->Bus, PciId->Device, PciId->Function, Register, (uint16_t)Value);
	if(Width == 32)
		pci_write_dword(PciId->Bus, PciId->Device, PciId->Function, Register, (uint32_t)Value);
	if(Width == 64)
		pci_write_qword(PciId->Bus, PciId->Device, PciId->Function, Register, Value);

	return AE_OK;
}
ACPI_STATUS AcpiOsReadPciConfiguration (ACPI_PCI_ID *PciId, UINT32 Register, UINT64 *Value, UINT32 Width)
{
	uint64_t mask = 0xFF;
	switch(Width)
	{
		case 16:
			mask = 0xFFFF;
			break;
		case 32:
			mask = 0xFFFFFFFF;
			break;
		case 64:
			mask = 0xFFFFFFFFFFFFFFFF;
			break;
	}
	UINT64 val = (UINT64)pci_config_read_dword(PciId->Bus, PciId->Device, PciId->Function, Register) & mask;
	switch(Width)
	{
		case 8:
			*((UINT8*)Value) = val;
			break;
		case 16:
			*((UINT16*)Value) = val;
			break;
		case 32:
			*((UINT32*)Value) = val;
			break;
		case 64:
			*((UINT64*)Value) = val;
			break;
	}
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
	return;
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
	//vprintf(Fmt, Args);
}
#if 0
ACPI_STATUS
AcpiOsCreateCache (
    char                    *CacheName,
    UINT16                  ObjectSize,
    UINT16                  MaxDepth,
    ACPI_CACHE_T        **ReturnCache)
{
	*ReturnCache = slab_create(CacheName, ObjectSize, MaxDepth, 0);
	return AE_OK;
}
ACPI_STATUS
AcpiOsPurgeCache (
    ACPI_CACHE_T        *Cache)
{
	return AE_OK;
}
ACPI_STATUS
AcpiOsDeleteCache (
    ACPI_CACHE_T        *Cache)
{
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
