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
#include <assert.h>

#include <onyx/mutex.h>
#include <onyx/spinlock.h>
#include <onyx/acpi.h>
#include <onyx/log.h>
#include <onyx/compiler.h>
#include <onyx/vmm.h>
#include <onyx/panic.h>
#include <onyx/log.h>
#include <onyx/cpu.h>
#include <onyx/pnp.h>
#include <onyx/dev.h>
#include <onyx/apic.h>

#include <drivers/pci.h>

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
extern int __enter_sleep_state(uint8_t sleep_state);
unsigned int acpi_suspend(void *context)
{
	UNUSED_PARAMETER(context);
	/* Prepare to enter S3 */
	ACPI_STATUS st = AcpiEnterSleepStatePrep(2);
	if(ACPI_FAILURE(st))
		return 1;
	DISABLE_INTERRUPTS();
	/* We'll need to enter assembly in order to correctly save and restore registers */
	if(__enter_sleep_state(2) < 0)
		return -1;
	return 0;
}
static ACPI_HANDLE root_bridge;
static ACPI_DEVICE_INFO *root_bridge_info;
int acpi_shutdown_device(struct device *dev);
static struct bus acpi_bus = 
{
	.name = "acpi",
	.shutdown = acpi_shutdown_device
};
ACPI_STATUS acpi_walk_irq(ACPI_HANDLE object, UINT32 nestingLevel, void *context, void **returnvalue)
{
	ACPI_DEVICE_INFO *devinfo;
	ACPI_STATUS st = AcpiGetObjectInfo(object, &devinfo);

	if(ACPI_FAILURE(st))
	{
		ERROR("acpi", "Error: AcpiGetObjectInfo failed!\n");
		return AE_ERROR;
	}

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

int enumerate_pci_irq_routing(ACPI_PCI_ROUTING_TABLE *table, struct bus *bus, ACPI_HANDLE handle)
{
	ACPI_PCI_ROUTING_TABLE *it = table;
	for(; it->Length != 0; it = (ACPI_PCI_ROUTING_TABLE*)ACPI_NEXT_RESOURCE(it))
	{
		uint8_t device = it->Address >> 16;
		struct pci_device_address addr = {0};
		addr.device = device;
		struct pci_device *dev = get_pcidev(&addr);
		if(!dev)
			continue;
		uint32_t pin = it->Pin;
		uint32_t gsi = -1;
		bool level = true;
		bool active_high = false;

		if(it->Source[0] == 0)
		{
			gsi = it->SourceIndex;
		}
		else
		{
			ACPI_HANDLE link_obj;
			ACPI_STATUS st = AcpiGetHandle(handle, it->Source, &link_obj);

			if(ACPI_FAILURE(st))
			{
				ERROR("acpi", "Error while calling AcpiGetHandle: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
				return -1;
			}
			ACPI_BUFFER buf;
			buf.Length = ACPI_ALLOCATE_BUFFER;
			buf.Pointer = NULL;

			st = AcpiGetCurrentResources(link_obj, &buf);
			if(ACPI_FAILURE(st))
			{
				ERROR("acpi", "Error while calling AcpiGetCurrentResources: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
				return -1;
			}
			
			for(ACPI_RESOURCE *res = (ACPI_RESOURCE*) buf.Pointer; res->Type != ACPI_RESOURCE_TYPE_END_TAG; res = ACPI_NEXT_RESOURCE(res))
			{
				if(res->Type == ACPI_RESOURCE_TYPE_IRQ)
				{
					level = res->Data.Irq.Polarity == 0 ? true : false;
					active_high = res->Data.Irq.Triggering == 0 ? true : false;
					gsi = res->Data.Irq.Interrupts[it->SourceIndex];
					break;
				}
				else if(res->Type == ACPI_RESOURCE_TYPE_EXTENDED_IRQ)
				{
					level = res->Data.ExtendedIrq.Polarity == 0 ? true : false;
					active_high = res->Data.ExtendedIrq.Triggering == 0 ? true : false;
					gsi = res->Data.ExtendedIrq.Interrupts[it->SourceIndex];
					break;
				}
			}
			free(buf.Pointer);
		}
		dev->pin_to_gsi[pin].level = level;
		dev->pin_to_gsi[pin].active_high = active_high;
		dev->pin_to_gsi[pin].gsi = gsi;
	}
	return 0;
}

ACPI_STATUS acpi_find_pci_buses(ACPI_HANDLE object, UINT32 nestingLevel, void *context, void **returnvalue)
{
	ACPI_DEVICE_INFO *devinfo;
	ACPI_STATUS st = AcpiGetObjectInfo(object, &devinfo);

	if(ACPI_FAILURE(st))
	{
		ERROR("acpi", "Error: AcpiGetObjectInfo failed!\n");
		return AE_ERROR;
	}

	if(devinfo->Flags & ACPI_PCI_ROOT_BRIDGE)
	{
		ACPI_BUFFER buffer = {0};
		buffer.Length = ACPI_ALLOCATE_BUFFER;
		if((st = AcpiGetIrqRoutingTable(object, &buffer)) != AE_OK)
		{
			ERROR("acpi", "Error: AcpiGetIrqRoutingTable failed!\n");
			return st;
		}
		ACPI_PCI_ROUTING_TABLE *rout = buffer.Pointer;
		enumerate_pci_irq_routing(rout, context, object);
		free(rout);
	}

	free(devinfo);
	return AE_OK;
}

int acpi_get_irq_routing_tables(struct bus *bus)
{
	void* retval;
	ACPI_STATUS st = AcpiGetDevices(NULL, acpi_find_pci_buses, bus, &retval);
	if(ACPI_FAILURE(st))
	{
		ERROR("acpi", "Error while calling AcpiGetDevices: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
		return 1;
	}
	return 0;
}

int acpi_get_irq_routing_info(struct bus *bus)
{
	if(acpi_get_irq_routing_tables(bus))
		return -1;
	return 0;
}

static uintptr_t rsdp = 0;
uintptr_t get_rdsp_from_grub(void);
uint8_t AcpiTbChecksum(uint8_t *buffer, uint32_t len);
void acpi_find_rsdp(void)
{
	if(ACPI_FAILURE(AcpiFindRootPointer(&rsdp)))
	{
		rsdp = get_rdsp_from_grub();
	}
}
uintptr_t acpi_get_rsdp(void)
{
	return rsdp;
}
ACPI_STATUS acpi_add_device(ACPI_HANDLE object, UINT32 nestingLevel, void *context, void **returnvalue)
{
	ACPI_DEVICE_INFO *info;
	ACPI_STATUS st;
	st = AcpiGetObjectInfo(object, &info);
	if(ACPI_FAILURE(st))
	{
		ERROR("acpi", "AcpiGetObjectInfo() Failed\n");
		return AE_ERROR;
	}
	const char *id = NULL;
	if(info->Valid & ACPI_VALID_HID)
		id = info->HardwareId.String;
	else if (info->Valid & ACPI_VALID_UID)
		id = info->UniqueId.String;
	else if(info->Valid & ACPI_VALID_CID)
		id = info->ClassCode.String;
	else
		id = "Unknown";
	char *name = malloc(200);
	if(!name)
		return AE_ERROR;
	memset(name, 0, 200);
	snprintf(name, 200, "%s", id);

	struct acpi_device *device = malloc(sizeof(struct acpi_device));
	if(!device)
		return AE_ERROR;
	memset(device, 0, sizeof(struct acpi_device));
	device->dev.name = name;
	device->object = object;
	device->info = info;
	bus_add_device(&acpi_bus, (struct device*) device);

	return AE_OK;
}
void acpi_enumerate_devices(void)
{
	ACPI_STATUS st;
	/* Walk the namespace for devices */
	st = AcpiWalkNamespace(ACPI_TYPE_DEVICE, ACPI_ROOT_OBJECT,
				    ACPI_UINT32_MAX,
				    acpi_add_device,
				    NULL, NULL, NULL);
	if(ACPI_FAILURE(st))
	{
		ERROR("acpi", "Failed to walk the namespace\n");
	}
}
int acpi_initialize(void)
{
	acpi_find_rsdp();
	ACPI_STATUS st = AcpiInitializeSubsystem();
	if(ACPI_FAILURE(st))
	{
		printk("Error: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
		panic("ACPI subsystem initialization failed!");
	}
	st = AcpiInitializeTables(NULL, 32, true);
	if(ACPI_FAILURE(st))
	{
		printk("Error: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
		panic("ACPI table subsystem initialization failed!");
	}
	st = AcpiLoadTables();
	if(ACPI_FAILURE(st))
		panic("AcpiLoadTables failed!");
	ioapic_early_init();
	st = AcpiEnableSubsystem(ACPI_FULL_INITIALIZATION);
	if (ACPI_FAILURE(st))
	{
		printk("Error: %s\n", AcpiGbl_ExceptionNames_Env[st].Name);
		panic("AcpiEnableSubsystem failed!");
	}
	st = AcpiInitializeObjects (ACPI_FULL_INITIALIZATION);
	if(ACPI_FAILURE(st))
		panic("AcpiInitializeObjects failed!");

	INFO("acpi", "initialized!\n");
	/* Register the acpi bus */
	bus_register(&acpi_bus);
	/* Enumerate every device */
	acpi_enumerate_devices();

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
struct acpi_device *acpi_get_device(const char *id)
{
	return (struct acpi_device*) bus_find_device(&acpi_bus, id);
}
char *power_states[] =
{
	"_PS0",
	"_PS1",
	"_PS2",
	"_PS3"
};
int acpi_set_device_power_state(struct acpi_device *device, unsigned int power_state)
{
	ACPI_STATUS st = AcpiEvaluateObject(device->object, power_states[power_state], NULL, NULL);
	if(ACPI_FAILURE(st))
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
