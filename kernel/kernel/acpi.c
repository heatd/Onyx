/*
* Copyright (c) 2016, 2017 Pedro Falcato
* This file is part of Onyx, and is released under the terms of the MIT License
* check LICENSE at the root directory for more information
*/
#include <acpi.h>
#include <stdio.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include <kernel/mutex.h>
#include <kernel/spinlock.h>
#include <kernel/acpi.h>
#include <kernel/log.h>
#include <kernel/compiler.h>
#include <kernel/vmm.h>
#include <kernel/panic.h>
#include <kernel/log.h>
#include <kernel/cpu.h>
#include <kernel/pnp.h>

static const ACPI_EXCEPTION_INFO    AcpiGbl_ExceptionNames_Env[] =
{
    EXCEP_TXT ((char*)"AE_OK",                         (char*)"No error"),
    EXCEP_TXT ((char*)"AE_ERROR",                      (char*)"Unspecified error"),
    EXCEP_TXT ((char*)"AE_NO_ACPI_TABLES",             (char*)"ACPI tables could not be found"),
    EXCEP_TXT ((char*)"AE_NO_NAMESPACE",               (char*)"A namespace has not been loaded"),
    EXCEP_TXT ((char*)"AE_NO_MEMORY",                  (char*)"Insufficient dynamic memory"),
    EXCEP_TXT ((char*)"AE_NOT_FOUND",                 (char*) "A requested entity is not found"),
    EXCEP_TXT ((char*)"AE_NOT_EXIST",                  (char*)"A required entity does not exist"),
    EXCEP_TXT ((char*)"AE_ALREADY_EXISTS",             (char*)"An entity already exists"),
    EXCEP_TXT ((char*)"AE_TYPE",                       (char*)"The object type is incorrect"),
    EXCEP_TXT ((char*)"AE_NULL_OBJECT",               (char*) "A required object was missing"),
    EXCEP_TXT ((char*)"AE_NULL_ENTRY",                 (char*)"The requested object does not exist"),
    EXCEP_TXT ((char*)"AE_BUFFER_OVERFLOW",            (char*)"The buffer provided is too small"),
    EXCEP_TXT ((char*)"AE_STACK_OVERFLOW",             (char*)"An internal stack overflowed"),
    EXCEP_TXT ((char*)"AE_STACK_UNDERFLOW",            (char*)"An internal stack underflowed"),
    EXCEP_TXT ((char*)"AE_NOT_IMPLEMENTED",            (char*)"The feature is not implemented"),
    EXCEP_TXT ((char*)"AE_SUPPORT",                   (char*) "The feature is not supported"),
    EXCEP_TXT ((char*)"AE_LIMIT",                     (char*) "A predefined limit was exceeded"),
    EXCEP_TXT ((char*)"AE_TIME",                       (char*)"A time limit or timeout expired"),
    EXCEP_TXT ((char*)"AE_ACQUIRE_DEADLOCK",           (char*)"Internal error, attempt was made to acquire a mutex in improper order"),
    EXCEP_TXT ((char*)"AE_RELEASE_DEADLOCK",           (char*)"Internal error, attempt was made to release a mutex in improper order"),
    EXCEP_TXT ((char*)"AE_NOT_ACQUIRED",               (char*)"An attempt to release a mutex or Global Lock without a previous acquire"),
    EXCEP_TXT ((char*)"AE_ALREADY_ACQUIRED",           (char*)"Internal error, attempt was made to acquire a mutex twice"),
    EXCEP_TXT ((char*)"AE_NO_HARDWARE_RESPONSE",       (char*)"Hardware did not respond after an I/O operation"),
    EXCEP_TXT ((char*)"AE_NO_GLOBAL_LOCK",             (char*)"There is no FACS Global Lock"),
    EXCEP_TXT ((char*)"AE_ABORT_METHOD",               (char*)"A control method was aborted"),
    EXCEP_TXT ((char*)"AE_SAME_HANDLER",              (char*) "Attempt was made to install the same handler that is already installed"),
    EXCEP_TXT ((char*)"AE_NO_HANDLER",                (char*) "A handler for the operation is not installed"),
    EXCEP_TXT ((char*)"AE_OWNER_ID_LIMIT",             (char*)"There are no more Owner IDs available for ACPI tables or control methods"),
    EXCEP_TXT ((char*)"AE_NOT_CONFIGURED",             (char*)"The interface is not part of the current subsystem configuration"),
    EXCEP_TXT ((char*)"AE_ACCESS",                     (char*)"Permission denied for the requested operation")
};
uint32_t acpi_shutdown(void *context)
{
	UNUSED_PARAMETER(context);
	AcpiEnterSleepStatePrep(5);
	DISABLE_INTERRUPTS();
	AcpiEnterSleepState(5);
	panic("ACPI: Failed to enter sleep state! Panic'ing!");
	return 0;
}
static ACPI_HANDLE root_bridge;
static ACPI_DEVICE_INFO *root_bridge_info;

ACPI_STATUS acpi_walk_irq(ACPI_HANDLE object, UINT32 nestingLevel, void *context, void **returnvalue)
{
	ACPI_DEVICE_INFO *devinfo;
	ACPI_STATUS st = AcpiGetObjectInfo(object, &devinfo);

	// TODO: Build a device tree off this information (with PCI as well)
	if(ACPI_FAILURE(st))
	{
		ERROR("acpi", "Error: AcpiGetObjectInfo failed!\n");
		return AE_ERROR;
	}
	//pnp_register_dev_acpi(devinfo);
	if(devinfo->Flags & ACPI_PCI_ROOT_BRIDGE)
	{
		root_bridge = object;
		root_bridge_info = devinfo;
	}
	else
		free(devinfo);
	return AE_OK;
}
uint32_t acpi_execute_pic(int value)
{
	ACPI_OBJECT arg;
	ACPI_OBJECT_LIST list;
	
	arg.Type = ACPI_TYPE_INTEGER;
	arg.Integer.Value = value;
	list.Count = 1;
	list.Pointer = &arg;

	return AcpiEvaluateObject(ACPI_ROOT_OBJECT, (char*)"_PIC", &list, NULL);
}
static ACPI_PCI_ROUTING_TABLE *routing_table = NULL;
int acpi_get_irq_routing_tables()
{
	void* retval;
	ACPI_STATUS st = AcpiGetDevices(NULL, acpi_walk_irq, NULL, &retval);
	if(ACPI_FAILURE(st))
	{
		ERROR("acpi", "Error while calling AcpiGetDevices: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
		return 1;
	} 
	ACPI_BUFFER buf;
	buf.Length = ACPI_ALLOCATE_BUFFER;
	buf.Pointer = NULL;
	
	st = AcpiGetIrqRoutingTable(root_bridge, &buf);
	if(ACPI_FAILURE(st))
	{
		printk("st: %u\n", st & ~AE_CODE_MASK);
		ERROR("acpi", "Error while calling AcpiGetIrqRoutingTable: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
		return 1;
	}
	routing_table = (ACPI_PCI_ROUTING_TABLE*) buf.Pointer;
	
	return 0;
}
static spinlock_t irq_rout_lock;
int acpi_get_irq_routing_for_dev(uint8_t bus, uint8_t device, uint8_t function)
{
	acquire_spinlock(&irq_rout_lock);
	ACPI_PCI_ROUTING_TABLE *it = routing_table;
	for(; it->Length != 0; it = (ACPI_PCI_ROUTING_TABLE*)ACPI_NEXT_RESOURCE(it))
	{
		if(device != (it->Address >> 16))
			continue;
		if(it->Source[0] == 0)
		{
			release_spinlock(&irq_rout_lock);
			return it->SourceIndex+1;
		}
		else
		{
			ACPI_HANDLE link_obj;
			ACPI_STATUS st = AcpiGetHandle(root_bridge, it->Source, &link_obj);

			if(ACPI_FAILURE(st))
			{
				ERROR("acpi", "Error while calling AcpiGetHandle: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
				release_spinlock(&irq_rout_lock);
				return -1;
			}
			ACPI_BUFFER buf;
			buf.Length = ACPI_ALLOCATE_BUFFER;
			buf.Pointer = NULL;
			
			st = AcpiGetCurrentResources(link_obj, &buf);
			if(ACPI_FAILURE(st))
			{
				ERROR("acpi", "Error while calling AcpiGetCurrentResources: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
				release_spinlock(&irq_rout_lock);
				return -1;
			}
			
			for(ACPI_RESOURCE *res = (ACPI_RESOURCE*) buf.Pointer; res->Type != ACPI_RESOURCE_TYPE_END_TAG; res = ACPI_NEXT_RESOURCE(res))
			{
				switch(res->Type)
				{
					case ACPI_RESOURCE_TYPE_IRQ:
					{
						release_spinlock(&irq_rout_lock);
						return res->Data.Irq.Interrupts[0]+1;
					}
					case ACPI_RESOURCE_TYPE_EXTENDED_IRQ:
					{
						release_spinlock(&irq_rout_lock);
						return res->Data.ExtendedIrq.Interrupts[0]+1;
					}
				}
			}
			release_spinlock(&irq_rout_lock);
		}
	}
	release_spinlock(&irq_rout_lock);
	return -1;
}
static uintptr_t rsdp = 0;
uint8_t AcpiTbChecksum(uint8_t *buffer, uint32_t len);
void acpi_find_rsdp(void)
{
	/* Find the RSDP(needed for ACPI and ACPICA) */
	for(int i = 0; i < 0x100000/16; i++)
	{
		if(!memcmp((char*)(PHYS_BASE + 0x000E0000 + i * 16),(char*)"RSD PTR ", 8))
		{
			uint8_t *addr = (uint8_t*)(PHYS_BASE + 0x000E0000 + i * 16);
			if(AcpiTbChecksum(addr, sizeof(ACPI_TABLE_RSDP)))
				continue;
			rsdp = addr - (uint8_t*)PHYS_BASE;
			break;
		}
	}
}
uintptr_t acpi_get_rsdp(void)
{
	return rsdp;
}
int acpi_initialize(void)
{
	acpi_find_rsdp();
	ACPI_STATUS st = AcpiInitializeSubsystem();
	if(ACPI_FAILURE(st))
	{
		printf("Error: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
		panic("ACPI subsystem initialization failed!");
	}	
	st = AcpiInitializeTables(NULL, 32, true);
	if(ACPI_FAILURE(st))
	{
		printf("Error: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
		panic("ACPI table subsystem initialization failed!");
	}
	st = AcpiLoadTables();
	if(ACPI_FAILURE(st))
		panic("AcpiLoadTables failed!");
	
	st = AcpiEnableSubsystem (ACPI_FULL_INITIALIZATION);
	if (ACPI_FAILURE (st))
		panic("AcpiEnableSubsystem failed!");
	st = AcpiInitializeObjects (ACPI_FULL_INITIALIZATION);
	if(ACPI_FAILURE(st))
		panic("AcpiInitializeObjects failed!");

	INFO("acpi", "initialized!\n");
	return 0;
}
uint32_t acpi_get_apic_id_lapic(ACPI_SUBTABLE_HEADER *madt)
{
	return ((ACPI_MADT_LOCAL_APIC*) madt)->Id;
}
static mutex_t cpu_enum_lock;
static size_t __ndx = 0;
ACPI_STATUS acpi_enumerate_per_cpu(ACPI_HANDLE object, UINT32 nestingLevel, void *context, void **returnvalue)
{
	ACPI_BUFFER buffer = { ACPI_ALLOCATE_BUFFER, NULL};
	struct acpi_processor *processor = &((struct acpi_processor *) context)[__ndx++];
	uint32_t apic_id = (uint32_t) -1;

	/* _MAT returns a segment of the MADT table */
	if(ACPI_FAILURE(AcpiEvaluateObject(object, "_MAT", NULL, &buffer)))
		return AE_ERROR;
	/* Get the APIC ID */
	ACPI_OBJECT *obj = (ACPI_OBJECT*) buffer.Pointer;
	ACPI_SUBTABLE_HEADER *madt = (ACPI_SUBTABLE_HEADER *) obj->Buffer.Pointer;
	
	switch(madt->Type)
	{
		case ACPI_MADT_TYPE_LOCAL_APIC:
			apic_id = acpi_get_apic_id_lapic(madt);
			break;
	}
	processor->object = object;
	processor->apic_id = apic_id;
	ACPI_FREE(buffer.Pointer);
	return AE_OK;
}
struct acpi_processor *acpi_enumerate_cpus(void)
{
	struct acpi_processor *processors = malloc(sizeof(struct acpi_processor) * get_nr_cpus());
	if(!processors)
	{
		return NULL;
	}
	memset(processors, 0, sizeof(struct acpi_processor) * get_nr_cpus());

	mutex_lock(&cpu_enum_lock);
	__ndx = 0;
	/* Walk the namespace, looking for ACPI PROCESSOR objects */
	AcpiWalkNamespace(ACPI_TYPE_PROCESSOR, ACPI_ROOT_OBJECT,
				    ACPI_UINT32_MAX,
				    acpi_enumerate_per_cpu,
				    NULL, processors, NULL);
	mutex_unlock(&cpu_enum_lock);
	return processors;
}
